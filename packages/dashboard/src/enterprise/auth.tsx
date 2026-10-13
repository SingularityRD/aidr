import { type ReactNode, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { useT } from "../i18n/I18nProvider";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { setPostAuthReturnTo } from "../ui/return-to";
import type { SessionSnapshot } from "../ui/session";
import { useSessionSnapshot } from "../ui/use-session";

/**
 * Outcome of the last action. Kept as a typed value rather than inferred from
 * the message text: the previous `status.includes("Failed") || status.includes("error")`
 * check styled any other failure — including a missing Edge Function — as a
 * neutral, success-looking notice.
 */
interface AuthStatus {
	tone: "success" | "error";
	message: string;
}

type AssuranceLevel = "aal1" | "aal2";

/**
 * The typed assurance report `identity-security` returns for `action: "status"`.
 *
 * The control plane refuses MFA-gated actions with `403 mfa_required` until the
 * access token carries `aal2`. Until this surface existed the dashboard had no
 * way to reach that level, so those actions were a dead end. Only the fields the
 * function documents are read here; nothing is re-derived from message text.
 */
interface IdentityAssurance {
	requireMfa: boolean;
	currentLevel: AssuranceLevel | null;
	nextLevel: AssuranceLevel | null;
	accessAllowed: boolean;
}

/**
 * Whether protected children may render.
 *
 * `blocked` is a first-class state, not an error string: a report the dashboard
 * cannot trust — a missing Edge Function, a malformed body, an `ok` that is not
 * literally `true` — withholds access instead of falling back to the pre-MFA
 * session.
 */
type StepUpState =
	| { kind: "checking" }
	| { kind: "clear" }
	| { kind: "challenge" }
	| { kind: "enroll" }
	| { kind: "blocked" };

function assuranceLevel(value: unknown): AssuranceLevel | null {
	return value === "aal1" || value === "aal2" ? value : null;
}

/**
 * Parse the assurance report, failing closed. An empty 200, a body without the
 * documented fields or a literal `ok: true` must never be read as "aal2".
 */
function parseAssurance(payload: unknown): IdentityAssurance | null {
	if (!payload || typeof payload !== "object") return null;
	const report = payload as Record<string, unknown>;
	if (report.ok !== true) return null;
	if (typeof report.require_mfa !== "boolean" || typeof report.access_allowed !== "boolean") {
		return null;
	}
	return {
		requireMfa: report.require_mfa,
		currentLevel: assuranceLevel(report.current_assurance),
		nextLevel: assuranceLevel(report.next_assurance),
		accessAllowed: report.access_allowed,
	};
}

interface Enrollment {
	factorId: string;
	secret: string | null;
	uri: string | null;
}

export interface EnterpriseAuthProps {
	/**
	 * Protected screens. When provided, they render only after the control plane
	 * reports the session is allowed; without them this component is the
	 * invite-acceptance surface it always was.
	 */
	children?: ReactNode;
	/**
	 * Tenant whose identity policy is enforced. The server falls back to the
	 * caller's own tenant when this is omitted, so a screen that belongs to a
	 * specific team should pass its id.
	 */
	tenantId?: string;
	/** Require AAL2 for a sensitive action even when the tenant-wide policy permits AAL1. */
	forceMfa?: boolean;
}

export function EnterpriseAuth(props: EnterpriseAuthProps = {}) {
	const { snapshot, generation, refresh, isCurrent } = useSessionSnapshot();
	// A key is an authorization boundary, not a cache key. React discards clear
	// state AND factor secrets before rendering a different tenant/principal/token.
	const binding = JSON.stringify([
		props.tenantId ?? null,
		props.forceMfa ?? false,
		snapshot?.session?.user.id ?? null,
		snapshot?.session?.access_token ?? null,
		generation,
	]);
	return (
		<BoundEnterpriseAuth
			key={binding}
			{...props}
			snapshot={snapshot}
			refreshSession={refresh}
			isCurrent={isCurrent}
		/>
	);
}

function BoundEnterpriseAuth({
	children,
	tenantId,
	forceMfa = false,
	snapshot,
	refreshSession,
	isCurrent,
}: EnterpriseAuthProps & {
	snapshot: SessionSnapshot | null;
	refreshSession: () => Promise<void>;
	isCurrent: () => boolean;
}) {
	const t = useT();
	// The assurance check reads the translator through a ref so a language
	// switch never re-runs it.
	const translator = useRef(t);
	translator.current = t;
	const navigate = useNavigate();
	const routerLocation = useLocation();
	const [searchParams] = useSearchParams();
	const [status, setStatus] = useState<AuthStatus | null>(null);
	const [busy, setBusy] = useState(false);
	const [stepUp, setStepUp] = useState<StepUpState>({ kind: "checking" });
	const [code, setCode] = useState("");
	const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
	const gated = Boolean(children);

	const returnTo = (searchParams.get("returnTo") ?? "/onboarding").trim();
	const inviteToken = (searchParams.get("invite") ?? "").trim();

	// A signed-out invitee has no session yet, so the invitation has to survive
	// the OAuth round trip. Without this the token was dropped on the way to the
	// provider and the "Accept Invitation" panel was gone when the user came
	// back — the invitation could never actually be accepted.
	const postAuthPath = inviteToken
		? `${routerLocation.pathname}?invite=${encodeURIComponent(inviteToken)}`
		: returnTo;

	const session = snapshot?.session ?? null;

	const active = useRef(true);
	const assuranceRequest = useRef(0);
	const bindingIsCurrent = useCallback(() => active.current && isCurrent(), [isCurrent]);
	useLayoutEffect(() => {
		active.current = true;
		return () => {
			active.current = false;
			++assuranceRequest.current;
		};
	}, []);

	const checkAssurance = useCallback(async () => {
		if (!bindingIsCurrent() || !session) return;
		const request = ++assuranceRequest.current;
		setStepUp({ kind: "checking" });
		try {
			const { data, error } = await supabase.functions.invoke("identity-security", {
				body: { action: "status", ...(tenantId ? { tenant_id: tenantId } : {}) },
				headers: { Authorization: `Bearer ${session.access_token}` },
			});
			if (!bindingIsCurrent() || request !== assuranceRequest.current) return;
			if (error) throw error;
			const assurance = parseAssurance(data);
			if (!assurance) {
				throw new Error(
					'the "identity-security" Edge Function did not report an assurance level (expected {"ok":true,"require_mfa":…,"access_allowed":…}). Access is withheld.',
				);
			}
			if (tenantId && data.tenant_id !== tenantId)
				throw new Error("The assurance report belongs to another tenant. Access is withheld.");
			if (
				assurance.accessAllowed &&
				((!assurance.requireMfa && !forceMfa) || assurance.currentLevel === "aal2")
			) {
				setStepUp({ kind: "clear" });
				return;
			}
			// `next_assurance: "aal2"` is the server telling us a verified factor
			// exists to challenge; anything else has to enroll one first.
			setStepUp(assurance.nextLevel === "aal2" ? { kind: "challenge" } : { kind: "enroll" });
		} catch {
			if (!bindingIsCurrent() || request !== assuranceRequest.current) return;
			setStepUp({ kind: "blocked" });
			setStatus({
				tone: "error",
				message: translator.current("ea.assuranceFailed"),
			});
		}
	}, [tenantId, forceMfa, session, bindingIsCurrent]);

	useEffect(() => {
		if (!gated || !snapshot) return;
		if (!session) {
			setStepUp({ kind: "checking" });
			return;
		}
		void checkAssurance();
	}, [gated, snapshot, session, checkAssurance]);

	async function signInWithProvider(provider: "github" | "gitlab") {
		setBusy(true);
		setStatus(null);

		try {
			if (postAuthPath) setPostAuthReturnTo(postAuthPath);

			const redirectTo = `${window.location.origin}/auth/callback`;
			const { error } = await supabase.auth.signInWithOAuth({
				provider,
				options: {
					redirectTo,
					scopes: provider === "github" ? "read:org" : "read_api",
				},
			});

			if (error) {
				setStatus({
					tone: "error",
					message: readErrorMessage(error, t("ea.signInFailed")),
				});
			}
		} catch (cause) {
			setStatus({
				tone: "error",
				message: readErrorMessage(cause, t("ea.signInNotStarted")),
			});
		} finally {
			setBusy(false);
		}
	}

	async function handleTeamInviteAccept(token: string) {
		// Session resolution remounts this binding. Never start acceptance on the
		// pre-session surface or let an old account's response redirect a new one.
		if (busy || !session || !bindingIsCurrent()) return;
		setBusy(true);
		setStatus(null);

		try {
			const { data, error } = await supabase.functions.invoke("oauth-callback", {
				body: { invite_token: token },
				headers: { Authorization: `Bearer ${session.access_token}` },
			});
			if (!bindingIsCurrent()) return;

			if (error) {
				throw new Error(readErrorMessage(error, t("ea.inviteNotAccepted")));
			}

			const response = (data ?? null) as { ok?: unknown; error?: unknown } | null;
			if (response?.error) throw new Error(String(response.error));

			// Fail closed on an unconfirmed response: an empty 200 must not be
			// reported as an accepted invitation.
			if (response?.ok !== true) {
				throw new Error(
					'the "oauth-callback" Edge Function did not confirm the invitation (expected {"ok":true}). The invitation was not accepted.',
				);
			}

			setStatus({ tone: "success", message: t("ea.inviteAccepted") });
			setTimeout(() => {
				if (bindingIsCurrent()) navigate("/team");
			}, 1500);
		} catch (err) {
			if (bindingIsCurrent()) {
				setStatus({ tone: "error", message: readErrorMessage(err, t("ea.inviteFailed")) });
			}
		} finally {
			if (bindingIsCurrent()) setBusy(false);
		}
	}

	/**
	 * Resolve the verified TOTP factor to challenge. The factor list is the
	 * client's own view; the server's assurance report remains the authority on
	 * whether access is granted.
	 */
	async function verifiedFactorId(): Promise<string> {
		const { data, error } = await supabase.auth.mfa.listFactors();
		if (error) throw error;
		const verified = (data?.totp ?? []).find((factor) => factor.status === "verified");
		if (verified) return verified.id;
		const fallback = (data?.all ?? []).find(
			(factor) => factor.factor_type === "totp" && factor.status === "verified",
		);
		if (fallback) return fallback.id;
		throw new Error(t("ea.noFactor"));
	}

	async function startEnrollment() {
		setBusy(true);
		setStatus(null);
		try {
			const { data, error } = await supabase.auth.mfa.enroll({
				factorType: "totp",
				friendlyName: "AIDR control plane",
			});
			if (!bindingIsCurrent()) return;
			if (error) throw error;
			if (!data || data.type !== "totp") {
				throw new Error("The authentication service did not start a TOTP enrollment.");
			}
			setEnrollment({ factorId: data.id, secret: data.totp.secret, uri: data.totp.uri });
			setStatus({
				tone: "success",
				message: t("ea.addSecret"),
			});
		} catch (cause) {
			setStatus({
				tone: "error",
				message: readErrorMessage(cause, t("ea.enrollFailed")),
			});
		} finally {
			setBusy(false);
		}
	}

	async function verifyFactor() {
		if (busy || !code.trim()) return;
		setBusy(true);
		setStatus(null);
		try {
			const factorId = enrollment?.factorId ?? (await verifiedFactorId());
			if (!bindingIsCurrent()) return;
			const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({
				factorId,
			});
			if (!bindingIsCurrent()) return;
			if (challengeError) throw challengeError;
			const challengeId = challenge?.id;
			if (!challengeId) {
				throw new Error("The authentication service returned no challenge identifier.");
			}
			const { error: verifyError } = await supabase.auth.mfa.verify({
				factorId,
				challengeId,
				code: code.trim(),
			});
			if (!bindingIsCurrent()) return;
			if (verifyError) throw verifyError;
			setCode("");
			setEnrollment(null);
			// Verification rotates the token. Discard this binding and check the
			// new token server-side; a client verify result never grants access.
			await refreshSession();
		} catch (cause) {
			setCode("");
			setStatus({
				tone: "error",
				message: readErrorMessage(cause, t("ea.codeRejected")),
			});
		} finally {
			setBusy(false);
		}
	}

	async function cancelStepUp() {
		// Close before awaiting sign-out, even if it fails or a status is delayed.
		active.current = false;
		++assuranceRequest.current;
		setStepUp({ kind: "blocked" });
		setEnrollment(null);
		setCode("");
		setBusy(true);
		try {
			const { error } = await supabase.auth.signOut();
			if (error) throw error;
			setEnrollment(null);
			setCode("");
			setStepUp({ kind: "blocked" });
			setStatus({
				tone: "error",
				message: t("ea.cancelled"),
			});
		} catch (cause) {
			setCode("");
			setStepUp({ kind: "blocked" });
			setStatus({
				tone: "error",
				message: readErrorMessage(cause, t("ea.cancelledOpen")),
			});
		} finally {
			setBusy(false);
		}
	}

	function statusNotice() {
		if (!status) return null;
		return (
			<div
				className={`notice ${status.tone === "error" ? "notice-danger" : ""}`}
				role={status.tone === "error" ? "alert" : "status"}
				aria-live="assertive"
				style={{ marginTop: "16px" }}
			>
				{status.message}
			</div>
		);
	}

	function codeField() {
		return (
			<form
				onSubmit={(event) => {
					event.preventDefault();
					void verifyFactor();
				}}
			>
				<label className="label" htmlFor="auth-mfa-code">
					{t("ea.code")}
				</label>
				<input
					id="auth-mfa-code"
					className="input mono"
					type="text"
					inputMode="numeric"
					autoComplete="one-time-code"
					required
					maxLength={10}
					value={code}
					onChange={(event) => setCode(event.target.value)}
				/>
				<button
					className="button auth-submit"
					type="submit"
					disabled={busy || !code.trim()}
					style={{ marginTop: "12px" }}
				>
					{busy ? t("ea.verifying") : t("ea.verify")}
				</button>
			</form>
		);
	}

	function enrollmentPrompt(state: "challenge" | "enroll") {
		const primary = state === "enroll";
		return (
			<div style={{ marginTop: "16px" }}>
				{primary ? <p className="muted">{t("ea.noEnrolled")}</p> : null}
				<button
					className={`button${primary ? "" : " button-secondary"}`}
					type="button"
					disabled={busy}
					onClick={() => void startEnrollment()}
				>
					{busy ? t("ea.starting") : primary ? t("ea.setUp") : t("ea.enrollNew")}
				</button>
			</div>
		);
	}

	function enrollmentSecret() {
		if (!enrollment) return null;
		return (
			<div style={{ marginTop: "16px" }}>
				<p className="muted">{t("ea.addThisSecret")}</p>
				<code className="mono" style={{ display: "block", wordBreak: "break-all" }}>
					{enrollment.secret ?? t("ea.noSecret")}
				</code>
				{enrollment.uri ? (
					<p className="muted" style={{ wordBreak: "break-all" }}>
						{enrollment.uri}
					</p>
				) : null}
			</div>
		);
	}

	function stepUpPanel(state: "challenge" | "enroll") {
		return (
			<div className="card">
				<h1>{t("ea.mfaRequired")}</h1>
				<p className="muted">
					{forceMfa ? t("ea.actionNeedsFactor") : t("ea.tenantNeedsFactor")} {t("ea.aal1")}
				</p>

				{enrollment ? enrollmentSecret() : enrollmentPrompt(state)}

				{(state === "challenge" || enrollment) && (
					<div style={{ marginTop: "16px" }}>{codeField()}</div>
				)}

				<div style={{ marginTop: "16px" }}>
					<button
						className="button button-secondary"
						type="button"
						disabled={busy}
						onClick={() => void cancelStepUp()}
					>
						{t("ea.cancelSignOut")}
					</button>
				</div>

				{statusNotice()}

				<div style={{ marginTop: "20px", fontSize: "12px", color: "var(--muted)" }}>
					<p>{t("ea.recoveryNote")}</p>
				</div>
			</div>
		);
	}

	function signInSurface() {
		const configuredMethods = window.__AIDR_CONFIG__?.authMethods;
		return (
			<div className="card">
				<h1>{t("ea.title")}</h1>
				<p className="muted">{t("ea.lead")}</p>

				{!session && configuredMethods?.length === 0 ? (
					<p className="notice" role="status">
						{t("ea.notConfigured")}
					</p>
				) : null}

				{!session && configuredMethods?.length !== 0 ? (
					<div className="row" style={{ flexDirection: "column", gap: "12px", marginTop: "20px" }}>
						<Link className="button" to={`/login?returnTo=${encodeURIComponent(postAuthPath)}`}>
							{t("ea.configured")}
						</Link>
						{!configuredMethods || configuredMethods.includes("github") ? (
							<button
								className="button"
								type="button"
								disabled={busy}
								onClick={() => void signInWithProvider("github")}
								style={{
									background: "linear-gradient(180deg, #24292f, #1a1f24)",
									borderColor: "rgba(36, 41, 47, 0.5)",
								}}
							>
								<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor">
									<path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0016 8c0-4.42-3.58-8-8-8z" />
								</svg>
								{t("ea.github")}
							</button>
						) : null}

						{!configuredMethods || configuredMethods.includes("gitlab") ? (
							<button
								className="button"
								type="button"
								disabled={busy}
								onClick={() => void signInWithProvider("gitlab")}
								style={{
									background: "linear-gradient(180deg, #fc6d26, #e24329)",
									borderColor: "rgba(252, 109, 38, 0.5)",
								}}
							>
								<svg width="18" height="18" viewBox="0 0 16 16" fill="currentColor">
									<path d="M15.97 9.058l-.895-2.756-.01-.024-1.8-5.552a.653.653 0 00-1.24 0l-1.8 5.552-.009.024-.895 2.756-.007.023-2.55 7.847a.653.653 0 001.043.74l3.045-2.344 3.044 2.344a.653.653 0 001.043-.74l-2.55-7.847-.007-.023zM11.9 6.303l1.115 3.434H10.77l1.13-3.434zm-3.8 0l1.13 3.434H6.97l1.13-3.434zm0-2.827l1.13 3.434H6.97l1.13-3.434zM5.052 9.737l.83-2.558.86 2.558H5.052zm3.111 4.713L5.527 11.42l2.636-2.03 2.636 2.03-2.636 2.03zm3.8-4.713l.86-2.558.83 2.558h-1.69z" />
								</svg>
								{t("ea.gitlab")}
							</button>
						) : null}
					</div>
				) : null}

				{session && !inviteToken ? (
					<div className="stack" style={{ marginTop: "20px" }}>
						<p>{t("ea.signedIn")}</p>
						<Link className="button" to="/dashboard">
							{t("ea.openDashboard")}
						</Link>
					</div>
				) : null}

				{/* Team invite acceptance */}
				{inviteToken && (
					<div
						style={{ marginTop: "24px", paddingTop: "20px", borderTop: "1px solid var(--border)" }}
					>
						<h3 style={{ marginTop: 0 }}>{t("ea.invite")}</h3>
						<p className="muted">{t("ea.inviteLead")}</p>
						<button
							className="button"
							type="button"
							disabled={busy || !session || !bindingIsCurrent()}
							onClick={() => void handleTeamInviteAccept(inviteToken)}
						>
							{t("ea.accept")}
						</button>
					</div>
				)}

				{statusNotice()}

				<div style={{ marginTop: "20px", fontSize: "12px", color: "var(--muted)" }}>
					<p>{t("ea.syncNote")}</p>
				</div>
			</div>
		);
	}

	if (!gated) return signInSurface();
	// An unresolved session never falls through to protected children: the
	// pre-MFA session must not be treated as authorization to render them.
	if (!snapshot) {
		return (
			<div className="card" role="status" aria-live="polite">
				<h1>{t("ea.verifyingAssurance")}</h1>
				<p className="muted">{t("ea.reading")}</p>
				{statusNotice()}
			</div>
		);
	}
	if (!session) return signInSurface();

	switch (stepUp.kind) {
		case "clear":
			return <>{children}</>;
		case "challenge":
			return stepUpPanel("challenge");
		case "enroll":
			return stepUpPanel("enroll");
		case "blocked":
			return (
				<div className="card">
					<h1>{t("ea.notCompleted")}</h1>
					<p className="muted">{t("ea.notCompletedLead")}</p>
					{statusNotice()}
				</div>
			);
		default:
			return (
				<div className="card" role="status" aria-live="polite">
					<h1>{t("ea.verifyingAssurance")}</h1>
					<p className="muted">{t("ea.checking")}</p>

					{statusNotice()}
				</div>
			);
	}
}
