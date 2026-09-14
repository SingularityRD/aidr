import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
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

/**
 * A replacement is only usable when it is a fresh, unexpired code that differs
 * from the one that lapsed.
 */
function replacementCode(data: Record<string, unknown>, previous: string): string | null {
	const code = typeof data.user_code === "string" ? data.user_code.trim().toUpperCase() : "";
	if (!code || !usableExpiry(data.expires_at) || code === previous) return null;
	return code;
}

type FunctionsResponse = { data?: unknown; error?: { message?: string } | null };

/**
 * Parses the `device-verify` response. A durable success requires a usable
 * expiry: without one the page cannot say when the code dies.
 */
function verifyOutcome(res: FunctionsResponse): { expiresAt: string } | { error: string } {
	if (res.error) return { error: res.error.message ?? "Verification failed." };
	const data = (res.data ?? {}) as Record<string, unknown>;
	if (data.ok !== true) return { error: "Verification failed." };
	const expiresAt = usableExpiry(data.expires_at);
	return expiresAt
		? { expiresAt }
		: { error: "The authorization service did not report a usable code expiry. Retry." };
}

export function VerifyPage() {
	const navigate = useNavigate();
	const [params] = useSearchParams();
	const initial = (params.get("code") ?? "").trim();

	const [userCode, setUserCode] = useState(initial);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
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
		async function load() {
			try {
				const sess = await getSession();
				if (!cancelled) setHasSession(Boolean(sess));
				if (!sess || cancelled) return;
				const identity = await supabase.auth.getUser();
				if (identity.error || !identity.data.user) throw new Error("Your session could not be verified.");
				const result = await supabase.from("team_members").select("role,teams!inner(id,name)").eq("user_id", identity.data.user.id);
				if (cancelled) return;
				if (result.error) throw new Error("Your teams could not be loaded. Refresh to retry.");
				const available = ((result.data ?? []) as unknown as { role: string; teams: { id: string; name: string } | null }[]).filter(row => row.teams && ["owner", "admin", "member"].includes(row.role)).map(row => row.teams!);
				setTeams(available);
				setTeamId(available.some(team => team.id === preferredTeam) ? preferredTeam : available.length === 1 ? available[0]?.id ?? "" : "");
			} catch (cause) {
				if (!cancelled) {
					setHasSession(false);
					setError(cause instanceof Error ? cause.message : "Unable to check your session.");
				}
			}
		}
		load();
		return () => {
			cancelled = true;
		};
	}, [preferredTeam]);

	const trimmed = useMemo(() => userCode.trim().toUpperCase(), [userCode]);
	const signInReturnTo = trimmed ? `/verify?code=${encodeURIComponent(trimmed)}` : "/verify";

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
		};
		tick();
		const timer = window.setInterval(tick, 500);
		return () => window.clearInterval(timer);
	}, [expiresAt]);

	async function authorize() {
		setBusy(true);
		setError(null);
		setOk(false);
		setExpired(false);
		setExpiresAt(null);
		setRemainingMs(null);
		try {
			const sess = await getSession();
			if (!sess) {
				const rt = `/verify?code=${encodeURIComponent(trimmed)}`;
				navigate(`/login?returnTo=${encodeURIComponent(rt)}`);
				return;
			}
			if (!teamId) throw new Error("Select the team receiving this device.");

			const outcome = verifyOutcome(
				await supabase.functions.invoke("device-verify", {
					method: "POST",
					headers: { "X-AIDR-Tenant-ID": teamId },
					body: { user_code: trimmed },
				}),
			);
			if ("error" in outcome) {
				setError(outcome.error);
				return;
			}
			setExpiresAt(outcome.expiresAt);
			setOk(true);
		} catch (cause) {
			setError(
				cause instanceof Error ? cause.message : "Device authorization is unavailable.",
			);
		} finally {
			setBusy(false);
		}
	}

	// Re-issue mints a fresh short-lived code and drops the old one entirely, so
	// an expired code can never be authorized again from this page.
	async function reissue() {
		setBusy(true);
		setError(null);
		setOk(false);
		setExpired(false);
		setExpiresAt(null);
		setRemainingMs(null);
		try {
			const res = await supabase.functions.invoke("device-start", { method: "POST" });
			if (res.error || res.data?.ok !== true) {
				setError(res.error?.message ?? "The authorization service did not return a replacement code.");
				return;
			}
			const data = (res.data ?? {}) as Record<string, unknown>;
			const next = replacementCode(data, trimmed);
			if (!next) {
				setError("The authorization service did not return a usable replacement code. Retry.");
				return;
			}
			setUserCode(next);
		} catch (cause) {
			setError(cause instanceof Error ? cause.message : "A replacement code could not be issued.");
		} finally {
			setBusy(false);
		}
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>Authorize device</h1>
				<p className="muted">
					Enter the short code shown by your agent runtime. This links your local installation to
					your account.
				</p>

				<label className="label" htmlFor="device-user-code">
					Code
					<input
						id="device-user-code"
						className="input mono"
						value={userCode}
						onChange={(e) => setUserCode(e.target.value)}
						placeholder="ABCD-EFGH"
						autoCapitalize="characters"
						autoCorrect="off"
					/>
				</label>
				{hasSession && <label className="label" htmlFor="enrollment-team">Team receiving this device
					<select id="enrollment-team" className="input" value={teamId} disabled={busy || ok} onChange={(event) => setTeamId(event.target.value)}>
						<option value="">Select a team</option>
						{teams.map(team => <option key={team.id} value={team.id}>{team.name}</option>)}
					</select>
				</label>}

				<div className="row">
					<button
						className="button"
						type="button"
						disabled={busy || ok || !trimmed || (hasSession === true && !teamId)}
						onClick={authorize}
					>
						Authorize
					</button>

					{hasSession ? null : (
						<Link
							className="button button-secondary"
							to={`/login?returnTo=${encodeURIComponent(signInReturnTo)}`}
						>
							Sign in
						</Link>
					)}
				</div>

				{ok ? (
					<div className="notice">
						<div>
							<b>Authorized.</b> Return to your agent. It should complete enrollment automatically.
						</div>
						<div className="muted small" role="status" aria-live="polite" style={{ marginTop: 8 }}>
							Code expires in {formatRemaining(remainingMs)}
						</div>
					</div>
				) : null}

				{!ok && (expired || error) ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						<div className="mono">
							{expired
								? "This code expired before enrollment finished. Issue a replacement code and authorize it again."
								: error}
						</div>
						<div className="muted small" style={{ marginTop: 8 }}>
							Need access? Apply for the pilot.
						</div>
						<div className="row" style={{ marginTop: 12 }}>
							<button
								className="button button-secondary"
								type="button"
								disabled={busy}
								onClick={reissue}
							>
								Issue a replacement code
							</button>
							<Link className="button button-secondary" to="/pilot">
								Request pilot
							</Link>
						</div>
					</div>
				) : null}
			</div>
		</div>
	);
}
