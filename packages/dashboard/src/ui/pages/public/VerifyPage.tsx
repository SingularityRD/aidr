import { useEffect, useMemo, useRef, useState } from "react";

import { Link, useNavigate, useSearchParams } from "react-router-dom";
import type { DashboardMessageKey } from "../../../i18n/en";
import { englishT, type Translate, useRichT, useT } from "../../../i18n/I18nProvider";
import { readErrorMessage } from "../../../lib/errors";
import { supabase } from "../../../lib/supabase";
import { getSession } from "../../session";

/** `m:ss` remaining until the authorization window closes. */
function formatRemaining(remainingMs: number | null): string {
	if (remainingMs === null) return "";
	const total = Math.max(0, Math.ceil(remainingMs / 1000));
	const minutes = Math.floor(total / 60);
	const seconds = total % 60;
	return `${minutes}:${String(seconds).padStart(2, "0")}`;
}

/** The code's own deadline, or null when the service reported no usable one. */
function usableExpiry(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) && parsed > Date.now() ? value : null;
}

/** Canonical user code: upper-case without separators (ABCD-2345 == abcd2345). */
function canonicalUserCode(value: string): string {
	return value.replace(/[\s-]/g, "").toUpperCase();
}

type FunctionsResponse = { data?: unknown; error?: { message?: string } | null };

/**
 * Parses the `device-verify` response. A durable success requires a usable
 * expiry: without one the page cannot say when the code dies.
 */
function verifyOutcome(
	res: FunctionsResponse,
	t: Translate = englishT,
): { expiresAt: string } | { error: string } {
	if (res.error) return { error: readErrorMessage(res.error, t("vf.failed")) };
	const data = (res.data ?? {}) as Record<string, unknown>;
	if (data.ok !== true) return { error: t("vf.failed") };
	const expiresAt = usableExpiry(data.expires_at);
	return expiresAt ? { expiresAt } : { error: t("vf.noExpiry") };
}

/** What device-start recorded about the device that asked for this code. */
export type DeviceRequest = {
	sessionId: string;
	userCode: string;
	requestedAt: string;
	expiresAt: string;
	requesterIp: string | null;
	runtime: string | null;
	runtimeVersion: string | null;
	os: string | null;
	hostname: string | null;
	requestedScope: string;
};

function text(value: unknown): string | null {
	return typeof value === "string" && value.length > 0 ? value : null;
}

/** Strict parse of the `device-verify` lookup answer; null when unusable. */
function parseDeviceRequest(data: unknown): DeviceRequest | null {
	if (!data || typeof data !== "object") return null;
	const body = data as Record<string, unknown>;
	const device = body.device as Record<string, unknown> | undefined;
	if (body.ok !== true || !device || typeof device !== "object") return null;
	const sessionId = text(device.device_session_id);
	const userCode = text(device.user_code);
	const requestedAt = text(device.requested_at);
	const expiresAt = usableExpiry(device.expires_at);
	if (
		!sessionId ||
		!userCode ||
		!requestedAt ||
		!Number.isFinite(Date.parse(requestedAt)) ||
		!expiresAt
	) {
		return null;
	}
	return {
		sessionId,
		userCode,
		requestedAt,
		expiresAt,
		requesterIp: text(device.requester_ip),
		runtime: text(device.runtime),
		runtimeVersion: text(device.runtime_version),
		os: text(device.os),
		hostname: text(device.hostname),
		requestedScope: text(device.requested_scope) ?? "tenant",
	};
}

function minutesAgo(iso: string, t: Translate): string {
	const minutes = Math.max(0, Math.round((Date.now() - Date.parse(iso)) / 60_000));
	if (minutes === 0) return t("vf.justNow");
	return minutes === 1 ? t("vf.minuteAgo") : t("vf.minutesAgo", { count: minutes });
}

const SCOPE_LABEL: Record<string, DashboardMessageKey> = {
	tenant: "vf.scopeTenant",
};

function scopeLabel(scope: string, t: Translate): string {
	const key = Object.hasOwn(SCOPE_LABEL, scope) ? SCOPE_LABEL[scope] : undefined;
	return key ? t(key) : scope;
}

function deviceDescription(device: DeviceRequest, t: Translate): string {
	const runtime = device.runtime
		? `${device.runtime}${device.runtimeVersion ? ` ${device.runtimeVersion}` : ""}`
		: null;
	const parts = [
		device.hostname ? t("vf.host", { name: device.hostname }) : null,
		device.os ? t("vf.os", { name: device.os }) : null,
		runtime,
	].filter(Boolean);
	return parts.length > 0 ? parts.join(" · ") : t("vf.notReported");
}

/** Step 2: what the user reviews before binding the device (CP-1). */
function DeviceRequestPanel({
	device,
	linkCode,
	teamName,
	confirmed,
	busy,
	onConfirm,
	onAuthorize,
	onCancel,
}: {
	device: DeviceRequest;
	linkCode: string;
	teamName: string;
	confirmed: boolean;
	busy: boolean;
	onConfirm: (value: boolean) => void;
	onAuthorize: () => void;
	onCancel: () => void;
}) {
	const t = useT();
	const richT = useRichT();
	return (
		<div className="stack" data-testid="device-request">
			<div className="notice notice-danger">
				{richT("vf.warning", {
					lead: <b>{t("vf.warningLead")}</b>,
					team: teamName || t("vf.thisTeam"),
				})}
			</div>
			{linkCode && linkCode !== device.userCode ? (
				<div className="notice notice-warning">{t("vf.codeMismatch")}</div>
			) : null}
			<dl className="small">
				<dt>{t("vf.code")}</dt>
				<dd className="mono">{device.userCode}</dd>
				<dt>{t("vf.requested")}</dt>
				<dd>
					{new Date(device.requestedAt).toLocaleString()} ({minutesAgo(device.requestedAt, t)})
				</dd>
				<dt>{t("vf.ip")}</dt>
				<dd className="mono">{device.requesterIp ?? t("vf.notRecorded")}</dd>
				<dt>{t("vf.device")}</dt>
				<dd>{deviceDescription(device, t)}</dd>
				<dt>{t("vf.access")}</dt>
				<dd>{scopeLabel(device.requestedScope, t)}</dd>
				<dt>{t("vf.team")}</dt>
				<dd>{teamName}</dd>
			</dl>
			<label className="label" style={{ display: "flex", gap: 8, alignItems: "center" }}>
				<input
					type="checkbox"
					checked={confirmed}
					disabled={busy}
					onChange={(e) => onConfirm(e.target.checked)}
				/>
				{t("vf.confirm")}
			</label>
			<div className="row">
				<button
					className="button"
					type="button"
					disabled={busy || !confirmed}
					onClick={onAuthorize}
				>
					{t("vf.authorize")}
				</button>
				<button
					className="button button-secondary"
					type="button"
					disabled={busy}
					onClick={onCancel}
				>
					{t("common.cancel")}
				</button>
			</div>
		</div>
	);
}

export function VerifyPage() {
	const t = useT();
	const richT = useRichT();
	// The session loader reads the translator through a ref so a language switch does not refetch.
	const translator = useRef(t);
	translator.current = t;
	const navigate = useNavigate();
	const [params] = useSearchParams();
	// A code in the link is never trusted on its own: the user must type the code
	// their device shows (RFC 8628 §5.4 remote phishing).
	const linkCode = canonicalUserCode(params.get("code") ?? "");

	const [userCode, setUserCode] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [device, setDevice] = useState<DeviceRequest | null>(null);
	const [confirmed, setConfirmed] = useState(false);
	const [ok, setOk] = useState(false);
	const [expired, setExpired] = useState(false);
	const [expiresAt, setExpiresAt] = useState<string | null>(null);
	const [remainingMs, setRemainingMs] = useState<number | null>(null);
	const [hasSession, setHasSession] = useState<boolean | null>(null);
	const [teams, setTeams] = useState<{ id: string; name: string }[]>([]);
	const [teamId, setTeamId] = useState("");
	const preferredTeam = params.get("team") ?? "";

	useEffect(() => {
		let cancelled = false;
		const t = translator.current;
		async function load() {
			let signedIn = false;
			try {
				const sess = await getSession();
				signedIn = Boolean(sess);
				if (!cancelled) setHasSession(signedIn);
				if (!sess || cancelled) return;
				const identity = await supabase.auth.getUser();
				if (identity.error || !identity.data.user) throw new Error(t("vf.sessionUnverified"));
				const result = await supabase
					.from("team_members")
					.select("role,teams!inner(id,name)")
					.eq("user_id", identity.data.user.id);
				if (cancelled) return;
				if (result.error) throw new Error(t("vf.teamsFailed"));
				const available = (
					(result.data ?? []) as unknown as {
						role: string;
						teams: { id: string; name: string } | null;
					}[]
				).flatMap((row) =>
					row.teams && ["owner", "admin", "member"].includes(row.role) ? [row.teams] : [],
				);
				setTeams(available);
				// The team stays visible and is restated in the confirmation step.
				setTeamId(
					available.some((team) => team.id === preferredTeam)
						? preferredTeam
						: available.length === 1
							? (available[0]?.id ?? "")
							: "",
				);
			} catch (cause) {
				if (!cancelled) {
					setHasSession(signedIn);
					setError(readErrorMessage(cause, t("vf.sessionCheckFailed")));
				}
			}
		}
		load();
		return () => {
			cancelled = true;
		};
	}, [preferredTeam]);

	const typed = useMemo(() => canonicalUserCode(userCode), [userCode]);
	const teamName = teams.find((team) => team.id === teamId)?.name ?? "";
	const signInReturnTo = linkCode ? `/verify?code=${encodeURIComponent(linkCode)}` : "/verify";
	const signInPath = `/login?returnTo=${encodeURIComponent(signInReturnTo)}`;

	// The authorization window is owned by the device session, not by this page.
	// When it closes the agent can no longer finish enrollment with this code, so
	// the success claim is withdrawn instead of being left on screen.
	useEffect(() => {
		if (!expiresAt) {
			setRemainingMs(null);
			return;
		}
		const deadline = Date.parse(expiresAt);
		if (!Number.isFinite(deadline)) {
			setRemainingMs(null);
			return;
		}
		const tick = () => {
			const left = deadline - Date.now();
			if (left > 0) {
				setRemainingMs(left);
				return;
			}
			setRemainingMs(0);
			setExpiresAt(null);
			setOk(false);
			setExpired(true);
			setUserCode("");
		};
		tick();
		const timer = window.setInterval(tick, 500);
		return () => window.clearInterval(timer);
	}, [expiresAt]);

	function resetDecision() {
		setDevice(null);
		setConfirmed(false);
	}

	async function signedInOrRedirect(): Promise<boolean> {
		const sess = await getSession();
		if (sess) return true;
		navigate(signInPath);
		return false;
	}

	/** Step 1: show who asked for this code. Nothing is bound yet. */
	async function lookup() {
		setBusy(true);
		setError(null);
		setOk(false);
		setExpired(false);
		setExpiresAt(null);
		resetDecision();
		try {
			if (!(await signedInOrRedirect())) return;
			if (!teamId) throw new Error(t("vf.selectTeamError"));
			const res = (await supabase.functions.invoke("device-verify", {
				method: "POST",
				headers: { "X-AIDR-Tenant-ID": teamId },
				body: { action: "lookup", user_code: typed },
			})) as FunctionsResponse;
			if (res.error) {
				setError(readErrorMessage(res.error, t("vf.notChecked")));
				return;
			}
			const found = parseDeviceRequest(res.data);
			if (!found || found.userCode !== typed) {
				setError(t("vf.notDescribed"));
				return;
			}
			setDevice(found);
		} catch (cause) {
			setError(readErrorMessage(cause, t("vf.unavailable")));
		} finally {
			setBusy(false);
		}
	}

	/** Step 2: bind exactly the session the user reviewed and confirmed. */
	async function authorize() {
		if (!device || !confirmed) return;
		setBusy(true);
		setError(null);
		try {
			if (!(await signedInOrRedirect())) return;
			const outcome = verifyOutcome(
				await supabase.functions.invoke("device-verify", {
					method: "POST",
					headers: { "X-AIDR-Tenant-ID": teamId },
					body: {
						action: "authorize",
						user_code: device.userCode,
						device_session_id: device.sessionId,
						confirmed: true,
					},
				}),
				t,
			);
			if ("error" in outcome) {
				setError(outcome.error);
				return;
			}
			resetDecision();
			setExpiresAt(outcome.expiresAt);
			setOk(true);
		} catch (cause) {
			setError(readErrorMessage(cause, t("vf.unavailable")));
		} finally {
			setBusy(false);
		}
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>{t("vf.authorize")}</h1>
				<p className="muted">{t("vf.lead")}</p>

				{linkCode && !ok ? (
					<div className="notice notice-warning" data-testid="link-code-notice">
						{t("vf.linkNotice")}
					</div>
				) : null}

				<label className="label" htmlFor="device-user-code">
					{t("vf.code")}
					<input
						id="device-user-code"
						className="input mono"
						value={userCode}
						onChange={(e) => {
							setUserCode(e.target.value);
							resetDecision();
						}}
						// i18n-exempt: sample code format
						placeholder="ABCD-EFGH"
						autoCapitalize="characters"
						autoCorrect="off"
						autoComplete="off"
						disabled={busy || ok}
					/>
				</label>
				{hasSession && (
					<label className="label" htmlFor="enrollment-team">
						{t("vf.teamReceiving")}
						<select
							id="enrollment-team"
							className="input"
							value={teamId}
							disabled={busy || ok}
							onChange={(event) => {
								setTeamId(event.target.value);
								resetDecision();
							}}
						>
							<option value="">{t("vf.selectTeam")}</option>
							{teams.map((team) => (
								<option key={team.id} value={team.id}>
									{team.name}
								</option>
							))}
						</select>
					</label>
				)}

				{device ? null : (
					<div className="row">
						<button
							className="button"
							type="button"
							disabled={busy || ok || typed.length !== 8 || (hasSession === true && !teamId)}
							onClick={lookup}
						>
							{t("vf.continue")}
						</button>

						{hasSession ? null : (
							<Link className="button button-secondary" to={signInPath}>
								{t("vf.signIn")}
							</Link>
						)}
					</div>
				)}

				{device && !ok ? (
					<DeviceRequestPanel
						device={device}
						linkCode={linkCode}
						teamName={teamName}
						confirmed={confirmed}
						busy={busy}
						onConfirm={setConfirmed}
						onAuthorize={authorize}
						onCancel={resetDecision}
					/>
				) : null}

				{ok ? (
					<div className="notice">
						<div>{richT("vf.authorized", { lead: <b>{t("vf.authorizedLead")}</b> })}</div>
						<div className="muted small" role="status" aria-live="polite" style={{ marginTop: 8 }}>
							{t("vf.expiresIn", { time: formatRemaining(remainingMs) })}
						</div>
					</div>
				) : null}

				{!ok && (expired || error) ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						<div className="mono">{expired ? t("vf.expired") : error}</div>
						<div className="muted small" style={{ marginTop: 8 }}>
							{t("vf.help")}
						</div>
						<div className="row" style={{ marginTop: 12 }}>
							<Link className="button button-secondary" to="/onboarding">
								{t("vf.returnOnboarding")}
							</Link>
							<Link className="button button-secondary" to="/support">
								{t("vf.contactSupport")}
							</Link>
						</div>
					</div>
				) : null}
			</div>
		</div>
	);
}
