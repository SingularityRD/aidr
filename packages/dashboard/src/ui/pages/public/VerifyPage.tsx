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

	useEffect(() => {
		let cancelled = false;
		async function load() {
			const sess = await getSession();
			if (!cancelled) setHasSession(Boolean(sess));
		}
		load();
		return () => {
			cancelled = true;
		};
	}, []);

	const trimmed = useMemo(() => userCode.trim().toUpperCase(), [userCode]);

	return (
		<div className="stack">
			<div className="card">
				<h1>Authorize device</h1>
				<p className="muted">
					Enter the short code shown by your agent runtime. This links your local installation to
					your account.
				</p>

				<label className="label">
					Code
					<input
						className="input mono"
						value={userCode}
						onChange={(e) => setUserCode(e.target.value)}
						placeholder="ABCD-EFGH"
						autoCapitalize="characters"
						autoCorrect="off"
					/>
				</label>

				<div className="row">
					<button
						className="button"
						type="button"
						disabled={busy || !trimmed}
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

								const res = await supabase.functions.invoke("device-verify", {
									method: "POST",
									body: { user_code: trimmed },
								});
								if (res.error) {
									setError(res.error.message);
									return;
								}
								const data = (res.data ?? {}) as Record<string, unknown>;
								if (data.ok === true) setOk(true);
								else setError("Verification failed.");
							} finally {
								setBusy(false);
							}
						}}
					>
						Authorize
					</button>

					{hasSession ? null : (
						<Link className="button button-secondary" to="/login?returnTo=/verify">
							Sign in
						</Link>
					)}
				</div>

				{ok ? (
					<div className="notice">
						<div>
							<b>Authorized.</b> Return to your agent. It should complete enrollment automatically.
						</div>
						<div className="muted small" style={{ marginTop: 8 }}>
							If you haven’t been approved for the pilot yet, authorization may be blocked.
						</div>
						<div className="row" style={{ marginTop: 12 }}>
							<Link className="button button-secondary" to="/pilot">
								View pilot status
							</Link>
						</div>
					</div>
				) : null}

				{error ? (
					<div className="notice notice-danger">
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
