import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../../lib/supabase";
import { getSession } from "../session";

type AgentRow = {
	id: string;
	iid: string;
	display_name: string | null;
	agent_runtime: string | null;
	last_seen: string;
};

type EventRow = {
	id: number;
	type: string;
	created_at: string;
	agent_id: string;
	payload: Record<string, unknown>;
};

const CONNECTED_WINDOW_MS = 10 * 60 * 1000;

function isConnected(agent: AgentRow): boolean {
	const seen = Date.parse(agent.last_seen);
	return Number.isFinite(seen) && Date.now() - seen <= CONNECTED_WINDOW_MS;
}

function eventSummary(event: EventRow): string {
	if (event.type === "runtime_verdict") {
		const tool =
			typeof event.payload?.tool_name === "string" ? String(event.payload.tool_name) : "tool";
		const verdict =
			typeof event.payload?.verdict === "string" ? String(event.payload.verdict) : "unknown";
		return `${tool}: ${verdict}`;
	}
	if (event.type === "plugin_scan") {
		const key =
			typeof event.payload?.plugin_key === "string" ? String(event.payload.plugin_key) : "plugin";
		const count = Number(event.payload?.findings_count ?? 0);
		return `${key}: ${count} finding(s)`;
	}
	return JSON.stringify(event.payload ?? {}).slice(0, 80);
}

function verdictOf(event: EventRow): string | null {
	if (event.type !== "runtime_verdict") return null;
	return typeof event.payload?.verdict === "string" ? String(event.payload.verdict) : null;
}

export function DashboardPage() {
	const [email, setEmail] = useState<string | null>(null);
	// null = not loaded / unavailable (fail-closed); [] = a real, empty result.
	const [agents, setAgents] = useState<AgentRow[] | null>(null);
	const [events, setEvents] = useState<EventRow[] | null>(null);
	const [pendingTokens, setPendingTokens] = useState<number | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;

		async function load() {
			const [agentsRes, eventsRes] = await Promise.all([
				supabase
					.from("agents")
					.select("id,iid,display_name,agent_runtime,last_seen")
					.order("last_seen", { ascending: false }),
				supabase
					.from("events")
					.select("id,type,created_at,agent_id,payload")
					.order("created_at", { ascending: false })
					.limit(500),
			]);

			if (cancelled) return;

			const problems: string[] = [];
			if (agentsRes.error) {
				problems.push(agentsRes.error.message);
				setAgents(null);
			} else {
				setAgents((agentsRes.data ?? []) as AgentRow[]);
			}

			if (eventsRes.error) {
				problems.push(eventsRes.error.message);
				setEvents(null);
			} else {
				setEvents((eventsRes.data ?? []) as EventRow[]);
			}

			// Set the error once per cycle so a persistent failure keeps a stable
			// alert instead of unmounting/remounting it on every poll tick.
			setError(problems.length > 0 ? problems.join(" ") : null);

			// Outstanding enrollment tokens require pilot approval; render a
			// fail-closed "—" instead of inventing a number when unavailable.
			try {
				const enrollRes = await supabase.functions.invoke("enrollment-tokens", { method: "GET" });
				if (cancelled) return;
				if (enrollRes.error) {
					setPendingTokens(null);
				} else {
					const data = (enrollRes.data ?? {}) as {
						tokens?: Array<{ consumed_at: string | null; expires_at: string }>;
					};
					const tokens = Array.isArray(data.tokens) ? data.tokens : [];
					setPendingTokens(
						tokens.filter((t) => !t.consumed_at && Date.parse(t.expires_at) > Date.now()).length,
					);
				}
			} catch {
				if (!cancelled) setPendingTokens(null);
			}
		}

		async function loadSession() {
			try {
				const session = await getSession();
				if (!cancelled) setEmail(session?.user?.email ?? null);
			} catch {
				if (!cancelled) setEmail(null);
			}
		}

		load();
		loadSession();
		const t = setInterval(load, 6000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, []);

	const connectedCount = useMemo(() => (agents ?? []).filter(isConnected).length, [agents]);
	const denyCount = useMemo(
		() => (events ?? []).filter((e) => verdictOf(e) === "deny").length,
		[events],
	);
	const askCount = useMemo(
		() => (events ?? []).filter((e) => verdictOf(e) === "ask").length,
		[events],
	);
	const latestHeartbeat = useMemo(() => {
		const stamps = (agents ?? []).map((a) => Date.parse(a.last_seen)).filter(Number.isFinite);
		return stamps.length > 0 ? new Date(Math.max(...stamps)) : null;
	}, [agents]);

	const liveAgents = (agents ?? []).slice(0, 5);
	const recentEvents = (events ?? []).slice(0, 6);

	return (
		<div className="stack">
			<section className="card console-hero">
				<div className="console-hero-grid">
					<div>
						<p className="eyebrow">AIDR control plane</p>
						<h1>Observe every agent decision from one secure dashboard.</h1>
						<p className="muted" style={{ marginTop: 8 }}>
							Start with prompt-based onboarding, approve a device code once, then track agent
							health, policy verdicts, and risky actions as they happen.
						</p>
						<div className="row" style={{ marginTop: 16 }}>
							<Link className="button" to="/onboarding">
								Connect agent
							</Link>
							<Link className="button button-secondary" to="/verify">
								Verify code
							</Link>
							<Link className="button button-secondary" to="/settings">
								Privacy settings
							</Link>
						</div>
					</div>
					<div>
						<div className="session-box">
							<div className="muted small">Signed in as</div>
							<div className="mono" style={{ marginTop: 2, overflowWrap: "anywhere" }}>
								{email ?? "unknown"}
							</div>
							<div className="muted small" style={{ marginTop: 10 }}>
								Latest heartbeat
							</div>
							<div className="mono" style={{ marginTop: 2 }}>
								{latestHeartbeat
									? latestHeartbeat.toLocaleString()
									: agents === null
										? "unavailable"
										: "no agents yet"}
							</div>
						</div>
					</div>
				</div>
				{error ? (
					<div
						className="notice notice-danger"
						role="alert"
						aria-live="assertive"
						style={{ marginTop: 14 }}
					>
						{error}
					</div>
				) : null}
			</section>

			<section className="grid" aria-label="Fleet counters">
				<div className="card stat-card">
					<div className="stat-label">Agents</div>
					<div className="stat-value">{agents === null ? "—" : agents.length}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Connected</div>
					<div className="stat-value">{agents === null ? "—" : connectedCount}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Pending</div>
					<div className="stat-value">{pendingTokens ?? "—"}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Events</div>
					<div className="stat-value">{events === null ? "—" : events.length}</div>
					<div className="stat-hint">latest 500</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Deny</div>
					<div className="stat-value">{events === null ? "—" : denyCount}</div>
					<div className="stat-hint">latest 500</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">Ask</div>
					<div className="stat-value">{events === null ? "—" : askCount}</div>
					<div className="stat-hint">latest 500</div>
				</div>
			</section>

			<section className="cols">
				<div className="card">
					<div className="panel-head">
						<h2>Live agents</h2>
						<Link className="view-all" to="/agents">
							View all
						</Link>
					</div>
					<p className="muted small">Connected installations and their current health.</p>
					<div className="table-wrap">
						<table className="table">
							<thead>
								<tr>
									<th>Agent</th>
									<th>Runtime</th>
									<th>State</th>
								</tr>
							</thead>
							<tbody>
								{liveAgents.map((agent) => (
									<tr key={agent.id}>
										<td>
											<Link className="mono" to={`/agents/${agent.id}`}>
												{agent.display_name ?? agent.iid.slice(0, 12)}
											</Link>
										</td>
										<td className="muted">{agent.agent_runtime ?? "unknown"}</td>
										<td>
											{isConnected(agent) ? (
												<span className="badge badge-success">connected</span>
											) : (
												<span className="badge badge-neutral">stale</span>
											)}
										</td>
									</tr>
								))}
								{liveAgents.length === 0 ? (
									<tr>
										<td colSpan={3} className="muted">
											{agents === null ? (
												"Agent data is unavailable right now."
											) : (
												<>
													No agents yet. Use <Link to="/onboarding">Connect</Link> to enroll your
													first runtime.
												</>
											)}
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>

				<div className="card">
					<div className="panel-head">
						<h2>Recent events</h2>
						<Link className="view-all" to="/events">
							View all
						</Link>
					</div>
					<p className="muted small">The latest allow, ask, and deny decisions from your agents.</p>
					<div className="table-wrap">
						<table className="table">
							<thead>
								<tr>
									<th>Time</th>
									<th>Type</th>
									<th>Summary</th>
								</tr>
							</thead>
							<tbody>
								{recentEvents.map((event) => (
									<tr key={event.id}>
										<td className="mono muted">
											{new Date(event.created_at).toLocaleTimeString()}
										</td>
										<td>
											<span className="badge badge-neutral badge-plain mono">{event.type}</span>
										</td>
										<td className="mono">{eventSummary(event)}</td>
									</tr>
								))}
								{recentEvents.length === 0 ? (
									<tr>
										<td colSpan={3} className="muted">
											{events === null
												? "Event data is unavailable right now."
												: "No events recorded yet."}
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>
			</section>
		</div>
	);
}
