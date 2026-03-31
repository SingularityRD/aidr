import { useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { supabase } from "../../../lib/supabase";
import { getSession } from "../../session";

type PilotStatus =
	| { status: "none" }
	| { status: "pending" }
	| { status: "approved"; cohort?: string | null }
	| { status: "denied" };

export function PilotPage() {
	const navigate = useNavigate();
	const [sessionReady, setSessionReady] = useState(false);
	const [hasSession, setHasSession] = useState(false);
	const [status, setStatus] = useState<PilotStatus>({ status: "none" });
	const [useCase, setUseCase] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	const trimmed = useMemo(() => useCase.trim(), [useCase]);

	useEffect(() => {
		let cancelled = false;
		async function load() {
			const sess = await getSession();
			if (cancelled) return;
			setHasSession(Boolean(sess));
			setSessionReady(true);
			if (!sess) return;

			const res = await supabase.functions.invoke("pilot-status", { method: "GET" });
			if (!res.error) {
				const data = (res.data ?? {}) as Record<string, unknown>;
				const st = String(data.status ?? "none");
				if (st === "pending" || st === "approved" || st === "denied") {
					setStatus({
						status: st as "pending" | "approved" | "denied",
						cohort: typeof data.cohort === "string" ? data.cohort : null,
					} as PilotStatus);
				} else {
					setStatus({ status: "none" });
				}
			}
		}
		load();
		return () => {
			cancelled = true;
		};
	}, []);

	if (!sessionReady) {
		return (
			<div className="card">
				<div className="muted">Loading…</div>
			</div>
		);
	}

	return (
		<div className="stack">
			<div className="card">
				<h1>Free Pilot</h1>
				<p className="muted">
					Pilot access is approval-gated to keep support responsive and reduce false positives. Once
					approved, you can enroll 1 agent for free.
				</p>

				{!hasSession ? (
					<div className="row" style={{ marginTop: 12 }}>
						<Link className="button" to="/login?returnTo=/pilot">
							Sign in to apply
						</Link>
					</div>
				) : (
					<div className="notice">
						<div className="muted small">Your status</div>
						<div className="mono">
							{status.status}
							{status.status === "approved" && status.cohort ? ` (${status.cohort})` : ""}
						</div>
						{status.status === "approved" ? (
							<div className="row" style={{ marginTop: 10 }}>
								<button className="button" type="button" onClick={() => navigate("/onboarding")}>
									Start onboarding
								</button>
							</div>
						) : null}
					</div>
				)}
			</div>

			{hasSession ? (
				<div className="card">
					<h2>Apply</h2>
					<p className="muted">Tell us what you’re protecting (runtime, tools, threat model).</p>
					<label className="label">
						Use case
						<textarea
							className="input"
							style={{ minHeight: 140, resize: "vertical" }}
							value={useCase}
							onChange={(e) => setUseCase(e.target.value)}
							placeholder="Claude Code/Cursor/OpenClaw/OpenCode, tools, constraints, risks…"
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
								try {
									const res = await supabase.functions.invoke("pilot-apply", {
										method: "POST",
										body: { message: trimmed },
									});
									if (res.error) {
										setError(res.error.message);
										return;
									}
									setStatus({ status: "pending" });
								} finally {
									setBusy(false);
								}
							}}
						>
							Submit application
						</button>
						<Link className="button button-secondary" to="/waitlist">
							Join waitlist
						</Link>
					</div>

					{error ? <div className="notice notice-danger">{error}</div> : null}
				</div>
			) : null}
		</div>
	);
}
