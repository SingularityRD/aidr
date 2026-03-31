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

function isIncidentLikeEvent(e: EventRow): boolean {
	if (e.type === "plugin_scan") {
		const count = Number(e.payload?.findings_count ?? 0);
		return count > 0;
	}

	if (e.type === "runtime_verdict") {
		const verdict = String(e.payload?.verdict ?? "");
		return verdict === "deny" || verdict === "ask";
	}

	// Future: core may emit explicit incident events.
	if (e.type === "incident") return true;
	if (e.type === "incident_record") return true;

	return false;
}

function summarize(e: EventRow): string {
	if (e.type === "plugin_scan") {
		const key = typeof e.payload?.plugin_key === "string" ? String(e.payload.plugin_key) : "plugin";
		const count = Number(e.payload?.findings_count ?? 0);
		return `${key}: ${count} finding(s)`;
	}
	if (e.type === "runtime_verdict") {
		const tool = typeof e.payload?.tool_name === "string" ? String(e.payload.tool_name) : "tool";
		const verdict = typeof e.payload?.verdict === "string" ? String(e.payload.verdict) : "unknown";
		const severity = typeof e.payload?.severity === "string" ? String(e.payload.severity) : "";
		return `${tool}: ${verdict}${severity ? ` (${severity})` : ""}`;
	}
	if (e.type === "incident") {
		const tool = typeof e.payload?.tool_name === "string" ? String(e.payload.tool_name) : "tool";
		const decision =
			typeof e.payload?.decision === "string" ? String(e.payload.decision) : "unknown";
		const severity = typeof e.payload?.severity === "string" ? String(e.payload.severity) : "";
		const reasons = Array.isArray(e.payload?.reasons) ? (e.payload.reasons as unknown[]) : [];
		const reason0 = typeof reasons[0] === "string" ? String(reasons[0]) : "";
		return `${tool}: ${decision}${severity ? ` (${severity})` : ""}${reason0 ? ` — ${reason0}` : ""}`;
	}
	if (e.type === "incident_record") {
		const incident = (e.payload?.incident ?? null) as Record<string, unknown> | null;
		const severity =
			incident && typeof incident.severity === "string" ? String(incident.severity) : "";
		const status = incident && typeof incident.status === "string" ? String(incident.status) : "";
		const events = incident && Array.isArray(incident.events) ? incident.events : [];
		const n = events.length;
		return `correlated incident${severity ? ` (${severity})` : ""}${status ? ` [${status}]` : ""} — ${n} event(s)`;
	}
	return JSON.stringify(e.payload).slice(0, 120);
}

export function IncidentsPage() {
	const [agents, setAgents] = useState<Map<string, AgentRow>>(new Map());
	const [events, setEvents] = useState<EventRow[]>([]);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;

		async function load() {
			setError(null);
			const [eventsRes, agentsRes] = await Promise.all([
				(async () => {
					const res = await supabase
						.from("incident_events")
						.select("id,type,created_at,agent_id,payload")
						.order("created_at", { ascending: false })
						.limit(500);
					if (!res.error) return res;

					// Back-compat: if the view hasn't been deployed yet, derive incidents from raw events.
					const fallback = await supabase
						.from("events")
						.select("id,type,created_at,agent_id,payload")
						.order("created_at", { ascending: false })
						.limit(500);
					return fallback;
				})(),
				supabase
					.from("agents")
					.select("id,iid,display_name,agent_runtime")
					.order("last_seen", { ascending: false }),
			]);

			if (cancelled) return;

			if (eventsRes.error) setError(eventsRes.error.message);
			else setEvents((eventsRes.data ?? []) as EventRow[]);

			if (agentsRes.error) setError(agentsRes.error.message);
			else {
				const map = new Map<string, AgentRow>();
				for (const a of (agentsRes.data ?? []) as AgentRow[]) {
					map.set(a.id, a);
				}
				setAgents(map);
			}
		}

		load();
		const t = setInterval(load, 6000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, []);

	const incidentEvents = useMemo(() => events.filter(isIncidentLikeEvent), [events]);

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between">
					<div>
						<h1>Incidents</h1>
						<p className="muted">
							Derived from telemetry events (blocked/ask verdicts, plugin scan findings, and
							explicit incident records when emitted).
						</p>
					</div>
					<button
						className="button button-secondary"
						type="button"
						onClick={() => location.reload()}
					>
						Refresh
					</button>
				</div>
				{error ? <div className="notice notice-danger">{error}</div> : null}
			</div>

			<div className="card">
				<table className="table">
					<thead>
						<tr>
							<th>Time</th>
							<th>Agent</th>
							<th>Type</th>
							<th>Summary</th>
						</tr>
					</thead>
					<tbody>
						{incidentEvents.map((e) => {
							const agent = agents.get(e.agent_id);
							const agentName = agent?.display_name ?? agent?.iid?.slice(0, 12) ?? e.agent_id;
							return (
								<tr key={e.id}>
									<td className="mono">{new Date(e.created_at).toLocaleString()}</td>
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
									<td className="mono">{e.type}</td>
									<td className="mono">{summarize(e)}</td>
								</tr>
							);
						})}
						{incidentEvents.length === 0 ? (
							<tr>
								<td colSpan={4} className="muted">
									No incidents yet.
								</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
		</div>
	);
}
