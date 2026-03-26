import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { supabase } from "../../lib/supabase";

type AgentRow = {
	id: string;
	iid: string;
	display_name: string | null;
	agent_runtime: string | null;
	agent_runtime_version: string | null;
	first_seen: string;
	last_seen: string;
};

type EventRow = {
	id: number;
	type: string;
	created_at: string;
	payload: Record<string, unknown>;
};

export function AgentDetailPage() {
	const { agentId } = useParams();
	const [agent, setAgent] = useState<AgentRow | null>(null);
	const [events, setEvents] = useState<EventRow[]>([]);
	const [error, setError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		if (!agentId) return;

		async function load() {
			setError(null);
			const [agentRes, eventsRes] = await Promise.all([
				supabase
					.from("agents")
					.select(
						"id,iid,display_name,agent_runtime,agent_runtime_version,first_seen,last_seen",
					)
					.eq("id", agentId)
					.maybeSingle(),
				supabase
					.from("events")
					.select("id,type,created_at,payload")
					.eq("agent_id", agentId)
					.order("created_at", { ascending: false })
					.limit(200),
			]);

			if (cancelled) return;
			if (agentRes.error) setError(agentRes.error.message);
			else setAgent((agentRes.data ?? null) as AgentRow | null);

			if (eventsRes.error) setError(eventsRes.error.message);
			else setEvents((eventsRes.data ?? []) as EventRow[]);
		}

		load();
		const t = setInterval(load, 3000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, [agentId]);

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between">
					<div>
						<h1>Agent</h1>
						<p className="muted">
							<Link to="/agents">← Back</Link>
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

				{agent ? (
					<div className="grid">
						<div>
							<div className="muted small">Name</div>
							<div className="mono">{agent.display_name ?? agent.iid}</div>
						</div>
						<div>
							<div className="muted small">Runtime</div>
							<div className="mono">
								{agent.agent_runtime ?? "unknown"} {agent.agent_runtime_version ?? ""}
							</div>
						</div>
						<div>
							<div className="muted small">Last seen</div>
							<div className="mono">{new Date(agent.last_seen).toLocaleString()}</div>
						</div>
					</div>
				) : (
					<div className="muted">Loading…</div>
				)}
			</div>

			<div className="card">
				<h2>Recent events</h2>
				<table className="table">
					<thead>
						<tr>
							<th>Time</th>
							<th>Type</th>
							<th>Summary</th>
						</tr>
					</thead>
					<tbody>
						{events.map((e) => (
							<tr key={e.id}>
								<td className="mono">{new Date(e.created_at).toLocaleString()}</td>
								<td className="mono">{e.type}</td>
								<td className="mono">
									{typeof e.payload?.["tool_name"] === "string"
										? `${String(e.payload["tool_name"])}: ${String(e.payload["verdict"] ?? "")}`
										: JSON.stringify(e.payload).slice(0, 120)}
								</td>
							</tr>
						))}
						{events.length === 0 ? (
							<tr>
								<td colSpan={3} className="muted">
									No events yet.
								</td>
							</tr>
						) : null}
					</tbody>
				</table>
			</div>
		</div>
	);
}
