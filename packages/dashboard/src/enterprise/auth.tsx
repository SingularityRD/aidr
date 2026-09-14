import { type ReactNode, useCallback, useEffect, useState } from "react";
import { useLocation, useNavigate, useSearchParams } from "react-router-dom";
import { readErrorMessage } from "../lib/errors";
import { supabase } from "../lib/supabase";
import { type SessionSnapshot, readSession } from "../ui/session";
import { setPostAuthReturnTo } from "../ui/return-to";

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
}

export function EnterpriseAuth({ children, tenantId }: EnterpriseAuthProps = {}) {
	const navigate = useNavigate();
	const routerLocation = useLocation();
	const [searchParams] = useSearchParams();
	const [status, setStatus] = useState<AuthStatus | null>(null);
	const [busy, setBusy] = useState(false);
	const [snapshot, setSnapshot] = useState<SessionSnapshot | null>(null);
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

	useEffect(() => {
		let cancelled = false;
		const apply = (next: SessionSnapshot) => {
			if (!cancelled) setSnapshot(next);
		};
		readSession()
			.then(apply)
			.catch((cause: unknown) => {
				if (cancelled) return;
				setSnapshot(null);
				setStatus({
					tone: "error",
					message: readErrorMessage(cause, "Your session could not be read. Sign in again."),
				});
			});
		const { data } = supabase.auth.onAuthStateChange(() => {
			readSession()
				.then(apply)
				.catch(() => {
					if (!cancelled) setSnapshot(null);
				});
		});
		return () => {
			cancelled = true;
			data.subscription.unsubscribe();
		};
	}, []);

	const checkAssurance = useCallback(async () => {
		setStepUp({ kind: "checking" });
		try {
			const { data, error } = await supabase.functions.invoke("identity-security", {
				body: { action: "status", ...(tenantId ? { tenant_id: tenantId } : {}) },
			});
			if (error) throw error;
			const assurance = parseAssurance(data);
			if (!assurance) {
				throw new Error(
					'the "identity-security" Edge Function did not report an assurance level (expected {"ok":true,"require_mfa":…,"access_allowed":…}). Access is withheld.',
				);
			}
			if (assurance.accessAllowed) {
				setStepUp({ kind: "clear" });
				return;
			}
			// `next_assurance: "aal2"` is the server telling us a verified factor
			// exists to challenge; anything else has to enroll one first.
			setStepUp(assurance.nextLevel === "aal2" ? { kind: "challenge" } : { kind: "enroll" });
		} catch (cause) {
			setStepUp({ kind: "blocked" });
			setStatus({
				tone: "error",
				message: readErrorMessage(
					cause,
					"Session assurance could not be verified. No protected screen was opened.",
				),
			});
		}
	}, [tenantId]);

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
				setStatus({ tone: "error", message: error.message });
			}
		} catch (cause) {
			setStatus({
				tone: "error",
				message: readErrorMessage(cause, "Sign-in could not be started."),
			});
		} finally {
			setBusy(false);
		}
	}

	async function handleTeamInviteAccept(token: string) {
		setBusy(true);
		setStatus(null);

		try {
			const { data, error } = await supabase.functions.invoke("oauth-callback", {
				body: { invite_token: token },
			});

			if (error) {
				throw new Error(
					`the "oauth-callback" Edge Function is unavailable (${error.message}). The invitation was not accepted.`,
				);
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

			setStatus({ tone: "success", message: "Team invitation accepted! Redirecting..." });
			setTimeout(() => navigate("/team"), 1500);
		} catch (err) {
			setStatus({ tone: "error", message: readErrorMessage(err, "Failed to accept invitation") });
		} finally {
			setBusy(false);
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
		throw new Error(
			"No verified authenticator factor is available for this account. Set one up to continue.",
		);
	}

	async function startEnrollment() {
		setBusy(true);
		setStatus(null);
		try {
			const { data, error } = await supabase.auth.mfa.enroll({
				factorType: "totp",
				friendlyName: "AIDR control plane",
			});
			if (error) throw error;
			if (!data || data.type !== "totp") {
				throw new Error("The authentication service did not start a TOTP enrollment.");
			}
			setEnrollment({ factorId: data.id, secret: data.totp.secret, uri: data.totp.uri });
			setStatus({
				tone: "success",
				message:
					"Add the secret below to your authenticator app, then enter the generated code to finish.",
			});
		} catch (cause) {
			setStatus({
				tone: "error",
				message: readErrorMessage(cause, "Authenticator enrollment could not be started."),
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
			const { data: challenge, error: challengeError } = await supabase.auth.mfa.challenge({
				factorId,
			});
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
			if (verifyError) throw verifyError;
			setCode("");
			setEnrollment(null);
			// Re-read the server's report: the client's own verify result is not
			// evidence that the control plane now accepts this session.
			await checkAssurance();
		} catch (cause) {
			setCode("");
			setStatus({
				tone: "error",
				message: readErrorMessage(
					cause,
					"The verification code was rejected. No protected screen was opened.",
				),
			});
		} finally {
			setBusy(false);
		}
	}

	async function cancelStepUp() {
		setBusy(true);
		try {
			const { error } = await supabase.auth.signOut();
			if (error) throw error;
			setEnrollment(null);
			setCode("");
			setStepUp({ kind: "blocked" });
			setStatus({
				tone: "error",
				message:
					"Multi-factor authentication was cancelled. The session was ended and no protected screen was opened.",
			});
		} catch (cause) {
			setCode("");
			setStepUp({ kind: "blocked" });
			setStatus({
				tone: "error",
				message: readErrorMessage(
					cause,
					"Multi-factor authentication was cancelled and this session could not be ended. Sign out to continue.",
				),
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
					Authenticator code
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
					{busy ? "Verifying…" : "Verify and continue"}
				</button>
			</form>
		);
	}

	function enrollmentPrompt(state: "challenge" | "enroll") {
		const primary = state === "enroll";
		return (
			<div style={{ marginTop: "16px" }}>
				{primary ? (
					<p className="muted">
						No verified authenticator factor is enrolled for this account. Enrollment is performed
						by the configured Supabase Auth service.
					</p>
				) : null}
				<button
					className={`button${primary ? "" : " button-secondary"}`}
					type="button"
					disabled={busy}
					onClick={() => void startEnrollment()}
				>
					{busy
						? "Starting…"
						: primary
							? "Set up authenticator app"
							: "Enroll a new authenticator app"}
				</button>
			</div>
		);
	}

	function enrollmentSecret() {
		if (!enrollment) return null;
		return (
			<div style={{ marginTop: "16px" }}>
				<p className="muted">Add this secret to your authenticator app:</p>
				<code className="mono" style={{ display: "block", wordBreak: "break-all" }}>
					{enrollment.secret ?? "The Auth service returned no secret; use the enrollment URI."}
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
				<h1>Multi-factor authentication required</h1>
				<p className="muted">
					This tenant requires a second factor before its managed screens can be opened. The control
					plane reports the session at assurance level aal1.
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
						Cancel and sign out
					</button>
				</div>

				{statusNotice()}

				<div style={{ marginTop: "20px", fontSize: "12px", color: "var(--muted)" }}>
					<p>
						Break-glass recovery codes and password recovery remain available from the recovery page
						if this factor is lost.
					</p>
				</div>
			</div>
		);
	}

	function signInSurface() {
		return (
			<div className="card">
				<h1>Enterprise Sign In</h1>
				<p className="muted">
					Sign in with your GitHub or GitLab account to access team features. Organization sync is
					automatic.
				</p>

				<div className="row" style={{ flexDirection: "column", gap: "12px", marginTop: "20px" }}>
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
						Continue with GitHub
					</button>

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
						Continue with GitLab
					</button>
				</div>

				{/* Team invite acceptance */}
				{inviteToken && (
					<div
						style={{ marginTop: "24px", paddingTop: "20px", borderTop: "1px solid var(--border)" }}
					>
						<h3 style={{ marginTop: 0 }}>Team Invitation</h3>
						<p className="muted">
							You&apos;ve been invited to join a team. Accept the invitation to continue.
						</p>
						<button
							className="button"
							type="button"
							disabled={busy}
							onClick={() => void handleTeamInviteAccept(inviteToken)}
						>
							Accept Invitation
						</button>
					</div>
				)}

				{statusNotice()}

				<div style={{ marginTop: "20px", fontSize: "12px", color: "var(--muted)" }}>
					<p>
						By signing in, you agree to sync your organization membership. Only public organization
						data is accessed.
					</p>
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
				<h1>Verifying session assurance</h1>
				<p className="muted">
					Reading the signed-in session before any protected screen is rendered.
				</p>
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
					<h1>Multi-factor authentication was not completed</h1>
					<p className="muted">
						No protected screen was opened. Sign in again and satisfy the second factor before
						continuing.
					</p>
					{statusNotice()}
				</div>
			);
		default:
			return (
				<div className="card" role="status" aria-live="polite">
					<h1>Verifying session assurance</h1>
					<p className="muted">
						Checking whether this session satisfies the tenant&apos;s multi-factor requirement. No
						protected screen is rendered until the control plane confirms it.
					</p>
					{statusNotice()}
				</div>
			);
	}
}
