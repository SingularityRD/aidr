import { useEffect, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { supabase } from "../../../lib/supabase";
import { getSession } from "../../session";

type PilotStatus =
	| { status: "none" }
	| { status: "pending" }
	| { status: "approved"; cohort?: string | null }
	| { status: "denied" };

// Apply for pilot function - calls edge function
async function applyForPilot(email: string, _org: string, useCase: string): Promise<void> {
	const res = await supabase.functions.invoke("pilot-apply", {
		method: "POST",
		body: { email, org: _org, useCase },
	});
	if (res.error || res.data?.ok !== true) {
		throw new Error(res.error?.message || "The pilot service did not confirm the application.");
	}
}

export function PilotPage() {
	const navigate = useNavigate();
	const [sessionReady, setSessionReady] = useState(false);
	const [hasSession, setHasSession] = useState(false);
	const [status, setStatus] = useState<PilotStatus>({ status: "none" });
	const [useCase, setUseCase] = useState("");
	const [email, setEmail] = useState("");
	const [busy, setBusy] = useState(false);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		async function load() {
			try {
				const sess = await getSession();
				if (cancelled) return;
				setHasSession(Boolean(sess));
				setSessionReady(true);
				if (!sess) return;

				// Get user email from session
				const userEmail = sess.user?.email || "";
				setEmail(userEmail);

				const res = await supabase.functions.invoke("pilot-status", { method: "GET" });
				if (res.error || res.data?.ok !== true || cancelled) {
					if (!cancelled) setError(res.error?.message ?? "Pilot status response is invalid.");
					return;
				}

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
			} catch (cause) {
				if (!cancelled) {
					setError(cause instanceof Error ? cause.message : "Unable to load pilot status.");
					setSessionReady(true);
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
					<p className="muted">Tell us what you're protecting (runtime, tools, threat model).</p>
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
							type="submit"
							className="button"
							disabled={busy || !useCase.trim()}
							onClick={async () => {
								setBusy(true);
								setError(null);
								try {
									await applyForPilot(email, "", useCase);
									setStatus({ status: "pending" });
								} catch (e) {
									setError(e instanceof Error ? e.message : "Failed to submit");
								} finally {
									setBusy(false);
								}
							}}
						>
							Submit application
						</button>
					</div>

					{error ? (
						<div className="notice notice-danger" role="alert">
							{error}
						</div>
					) : null}
				</div>
			) : null}
		</div>
	);
}
