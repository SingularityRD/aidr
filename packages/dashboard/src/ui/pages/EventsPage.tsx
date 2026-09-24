import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
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
	return "Additional event details are not shown.";
}

export function EventsPage() {
	const { currentTeam, isLoading } = useTeam();
	if (isLoading) return <div role="status">Resolving the managed tenant…</div>;
	if (!currentTeam) return <div role="alert">Select a team to view events.</div>;
	return <TenantEventsPage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantEventsPage({ tenantId }: { tenantId: string }) {
	const [agents, setAgents] = useState<Map<string, AgentRow>>(new Map());
	// null = not loaded / unavailable (fail-closed); [] = a real, empty feed.
	const [events, setEvents] = useState<EventRow[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loaded, setLoaded] = useState(false);

	useEffect(() => {
		let cancelled = false;
		let inFlight = false;

		async function load() {
			if (inFlight) return;
			inFlight = true;
			try {
				const [eventsRes, agentsRes] = await Promise.all([
					supabase
						.from("events")
						.select("id,type,created_at,agent_id,payload")
						.eq("tenant_id", tenantId)
						.order("created_at", { ascending: false })
						.limit(500),
					supabase
						.from("agents")
						.select("id,iid,display_name,agent_runtime")
						.eq("tenant_id", tenantId)
						.order("last_seen", { ascending: false }),
				]);

				if (cancelled) return;

				const problems: string[] = [];
				if (eventsRes.error || !Array.isArray(eventsRes.data)) {
					problems.push(readErrorMessage(eventsRes.error, "Failed to load events"));
					setEvents(null);
				} else {
					setEvents(eventsRes.data as EventRow[]);
				}

				if (agentsRes.error || !Array.isArray(agentsRes.data)) {
					problems.push(readErrorMessage(agentsRes.error, "Failed to load agents"));
					setAgents(new Map());
				} else {
					const map = new Map<string, AgentRow>();
					for (const agent of agentsRes.data as AgentRow[]) {
						map.set(agent.id, agent);
					}
					setAgents(map);
				}

				// One setError per cycle keeps the alert stable across poll ticks.
				setError(problems.length > 0 ? problems.join(" ") : null);
			} catch {
				if (cancelled) return;
				setEvents(null);
				setAgents(new Map());
				setError("Failed to load events");
			} finally {
				inFlight = false;
				if (!cancelled) setLoaded(true);
			}
		}

		load();
		const t = setInterval(load, 6000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, [tenantId]);

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
							The latest 500 events received from this team's agents. With default reporting, ask
							and deny verdicts are uploaded; allow verdicts require clean-verdict reporting.
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
											? loaded
												? "Event data is unavailable right now."
												: "Loading events…"
											: "No events received yet. Check agent enrollment and telemetry delivery."}
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
