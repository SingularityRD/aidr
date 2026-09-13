import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { supabase } from "../../../lib/supabase";
import { getSession } from "../../session";

export function VerifyPage() {
	const navigate = useNavigate();
	const [params] = useSearchParams();
	const initial = (params.get("code") ?? "").trim();

	const [userCode, setUserCode] = useState(initial);
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);
	const [ok, setOk] = useState(false);
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
						onClick={async () => {
							setBusy(true);
							setError(null);
							setOk(false);
							try {
								const sess = await getSession();
								if (!sess) {
									const rt = `/verify?code=${encodeURIComponent(trimmed)}`;
									navigate(`/login?returnTo=${encodeURIComponent(rt)}`);
									return;
								}
								if (!teamId) throw new Error("Select the team receiving this device.");

								const res = await supabase.functions.invoke("device-verify", {
									method: "POST",
									headers: { "X-AIDR-Tenant-ID": teamId },
									body: { user_code: trimmed },
								});
								if (res.error) {
									setError(res.error.message);
									return;
								}
								const data = (res.data ?? {}) as Record<string, unknown>;
								if (data.ok === true) setOk(true);
								else setError("Verification failed.");
							} catch (cause) {
								setError(
									cause instanceof Error ? cause.message : "Device authorization is unavailable.",
								);
							} finally {
								setBusy(false);
							}
						}}
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
					</div>
				) : null}

				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						<div className="mono">{error}</div>
						<div className="muted small" style={{ marginTop: 8 }}>
							Need access? Apply for the pilot.
						</div>
						<div className="row" style={{ marginTop: 12 }}>
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
