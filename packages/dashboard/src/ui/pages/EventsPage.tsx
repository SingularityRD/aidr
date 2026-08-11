import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { supabase } from "../../lib/supabase";

type AgentRow = {
	id: string;
	iid: string;
	display_name: string | null;
	agent_runtime: string | null;
};

type EventRow = {
	id: number;
	type: string;
	created_at: string;
	agent_id: string;
	payload: Record<string, unknown>;
};

function verdictBadgeClass(verdict: string): string {
	if (verdict === "deny") return "badge badge-deny";
	if (verdict === "ask") return "badge badge-ask";
	if (verdict === "allow") return "badge badge-allow";
	return "badge badge-neutral";
}

function summarize(event: EventRow): string {
	if (event.type === "runtime_verdict") {
		const tool =
			typeof event.payload?.tool_name === "string" ? String(event.payload.tool_name) : "tool";
		const severity =
			typeof event.payload?.severity === "string" ? String(event.payload.severity) : "";
		return `${tool}${severity ? ` (${severity})` : ""}`;
	}
	if (event.type === "plugin_scan") {
		const key =
			typeof event.payload?.plugin_key === "string" ? String(event.payload.plugin_key) : "plugin";
		const count = Number(event.payload?.findings_count ?? 0);
		return `${key}: ${count} finding(s)`;
	}
	return JSON.stringify(event.payload ?? {}).slice(0, 120);
}

export function EventsPage() {
	const [agents, setAgents] = useState<Map<string, AgentRow>>(new Map());
	// null = not loaded / unavailable (fail-closed); [] = a real, empty feed.
	const [events, setEvents] = useState<EventRow[] | null>(null);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;

		async function load() {
			const [eventsRes, agentsRes] = await Promise.all([
				supabase
					.from("events")
					.select("id,type,created_at,agent_id,payload")
					.order("created_at", { ascending: false })
					.limit(500),
				supabase
					.from("agents")
					.select("id,iid,display_name,agent_runtime")
					.order("last_seen", { ascending: false }),
			]);

			if (cancelled) return;

			const problems: string[] = [];
			if (eventsRes.error) {
				problems.push(eventsRes.error.message);
				setEvents(null);
			} else {
				setEvents((eventsRes.data ?? []) as EventRow[]);
			}

			if (agentsRes.error) problems.push(agentsRes.error.message);
			else {
				const map = new Map<string, AgentRow>();
				for (const agent of (agentsRes.data ?? []) as AgentRow[]) {
					map.set(agent.id, agent);
				}
				setAgents(map);
			}

			// One setError per cycle keeps the alert stable across poll ticks.
			setError(problems.length > 0 ? problems.join(" ") : null);
		}

		load();
		const t = setInterval(load, 6000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, []);

	const verdictCounts = useMemo(() => {
		const counts = { allow: 0, ask: 0, deny: 0 };
		for (const event of events ?? []) {
			if (event.type !== "runtime_verdict") continue;
			const verdict = typeof event.payload?.verdict === "string" ? event.payload.verdict : "";
			if (verdict === "allow") counts.allow += 1;
			if (verdict === "ask") counts.ask += 1;
			if (verdict === "deny") counts.deny += 1;
		}
		return counts;
	}, [events]);

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start" }}>
					<div>
						<h1>Events</h1>
						<p className="muted">
							The raw telemetry feed: every allow, ask, and deny decision plus plugin scan results
							reported by your agents (latest 500).
						</p>
					</div>
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => location.reload()}
					>
						Refresh
					</button>
				</div>
				{events !== null ? (
					<div className="row" style={{ marginTop: 12 }}>
						<span className="badge badge-deny">{verdictCounts.deny} deny</span>
						<span className="badge badge-ask">{verdictCounts.ask} ask</span>
						<span className="badge badge-allow">{verdictCounts.allow} allow</span>
					</div>
				) : null}
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			<div className="card">
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>Time</th>
								<th>Agent</th>
								<th>Type</th>
								<th>Verdict</th>
								<th>Summary</th>
							</tr>
						</thead>
						<tbody>
							{(events ?? []).map((event) => {
								const agent = agents.get(event.agent_id);
								const agentName = agent?.display_name ?? agent?.iid?.slice(0, 12) ?? event.agent_id;
								const verdict =
									event.type === "runtime_verdict" && typeof event.payload?.verdict === "string"
										? String(event.payload.verdict)
										: null;
								return (
									<tr key={event.id}>
										<td className="mono">{new Date(event.created_at).toLocaleString()}</td>
										<td>
											{agent ? (
												<Link className="mono" to={`/agents/${agent.id}`}>
													{agentName}
												</Link>
											) : (
												<span className="mono">{agentName}</span>
											)}
											{agent?.agent_runtime ? (
												<div className="muted small">{agent.agent_runtime}</div>
											) : null}
										</td>
										<td>
											<span className="badge badge-neutral badge-plain mono">{event.type}</span>
										</td>
										<td>
											{verdict ? (
												<span className={verdictBadgeClass(verdict)}>{verdict}</span>
											) : (
												<span className="muted small">—</span>
											)}
										</td>
										<td className="mono">{summarize(event)}</td>
									</tr>
								);
							})}
							{events === null || events.length === 0 ? (
								<tr>
									<td colSpan={5} className="muted">
										{events === null
											? "Event data is unavailable right now."
											: "No events yet. Connected agents report decisions here as they happen."}
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
			</div>
		</div>
	);
}
