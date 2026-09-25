import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { type EvidenceAuditRow, EvidenceView } from "../../enterprise/evidence-view";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import { FrameworkTags } from "../framework-coverage";

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

function isMissingTableError(error: { code?: string; message?: string }, table: string): boolean {
	return (
		error.code === "PGRST205" ||
		error.code === "42P01" ||
		new RegExp(`${table}.*(?:not exist|missing)`, "i").test(error.message ?? "")
	);
}

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
	return "Additional incident details are not shown.";
}

export function IncidentsPage() {
	const { currentTeam, isLoading } = useTeam();
	if (isLoading) return <div role="status">Resolving the managed tenant…</div>;
	if (!currentTeam) return <div role="alert">Select a team to view incidents.</div>;
	return <TenantIncidentsPage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantIncidentsPage({ tenantId }: { tenantId: string }) {
	const [agents, setAgents] = useState<Map<string, AgentRow>>(new Map());
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
					(async () => {
						const res = await supabase
							.from("incident_events")
							.select("id,type,created_at,agent_id,payload")
							.eq("tenant_id", tenantId)
							.order("created_at", { ascending: false })
							.limit(500);
						if (!res.error) return res;

						// Back-compat only when the derived view is genuinely absent. Keep
						// network/permission errors visible rather than showing incomplete data.
						if (!isMissingTableError(res.error, "incident_events")) return res;
						const fallback = await supabase
							.from("events")
							.select("id,type,created_at,agent_id,payload")
							.eq("tenant_id", tenantId)
							.order("created_at", { ascending: false })
							.limit(500);
						return fallback;
					})(),
					supabase
						.from("agents")
						.select("id,iid,display_name,agent_runtime")
						.eq("tenant_id", tenantId)
						.order("last_seen", { ascending: false }),
				]);

				if (cancelled) return;
				const problems: string[] = [];

				if (eventsRes.error || !Array.isArray(eventsRes.data)) {
					problems.push(readErrorMessage(eventsRes.error, "Failed to load incidents"));
					setEvents(null);
				} else setEvents(eventsRes.data as EventRow[]);

				if (agentsRes.error || !Array.isArray(agentsRes.data)) {
					problems.push(readErrorMessage(agentsRes.error, "Failed to load agents"));
					setAgents(new Map());
				} else {
					const map = new Map<string, AgentRow>();
					for (const a of agentsRes.data as AgentRow[]) {
						map.set(a.id, a);
					}
					setAgents(map);
				}
				setError(problems.length > 0 ? problems.join(" ") : null);
			} catch {
				if (cancelled) return;
				setEvents(null);
				setAgents(new Map());
				setError("Failed to load incidents");
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

	const incidentEvents = useMemo(() => (events ?? []).filter(isIncidentLikeEvent), [events]);

	// The evidence view groups each payload correlation id within its producing
	// agent, so it is fed the same incident-like rows the table shows.
	// A record whose payload carries no id is reported as uncorrelated there
	// rather than merged into a neighbouring incident.
	const evidenceRows = useMemo<EvidenceAuditRow[]>(
		() =>
			incidentEvents.map((event) => {
				const observedAt = Date.parse(event.created_at);
				return {
					id: String(event.id),
					action: event.type,
					timestampMs: Number.isFinite(observedAt) ? observedAt : 0,
					agentId: event.agent_id,
					payload: event.payload,
				};
			}),
		[incidentEvents],
	);

	const denyCount = useMemo(
		() =>
			incidentEvents.filter(
				(e) => e.type === "runtime_verdict" && String(e.payload?.verdict ?? "") === "deny",
			).length,
		[incidentEvents],
	);
	const askCount = useMemo(
		() =>
			incidentEvents.filter(
				(e) => e.type === "runtime_verdict" && String(e.payload?.verdict ?? "") === "ask",
			).length,
		[incidentEvents],
	);
	const scanCount = useMemo(
		() => incidentEvents.filter((e) => e.type === "plugin_scan").length,
		[incidentEvents],
	);

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start" }}>
					<div>
						<h1>Incidents</h1>
						<p className="muted">
							Potential incidents derived from received blocked and approval-required verdicts.
							Counts cover the latest 500 events, not the complete local incident history.
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
					<div className="row" style={{ marginTop: 14 }}>
						<span className="badge badge-deny">{denyCount} blocked</span>
						<span className="badge badge-ask">{askCount} approval required</span>
						<span className="badge badge-info">{scanCount} scan findings</span>
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
										<td>
											<span className="badge badge-neutral badge-plain mono">{e.type}</span>
										</td>
										<td className="mono">
											{summarize(e)}
											{e.type === "runtime_verdict" || e.type === "incident" ? (
												<FrameworkTags ruleId={e.payload?.matched_threat_id} />
											) : null}
										</td>
									</tr>
								);
							})}
							{incidentEvents.length === 0 ? (
								<tr>
									<td colSpan={4} className="muted">
										{events === null
											? loaded
												? "Incident data is unavailable right now."
												: "Loading incidents…"
											: "No incidents yet."}
									</td>
								</tr>
							) : null}
						</tbody>
					</table>
				</div>
			</div>

			<EvidenceView rows={evidenceRows} error={error} isLoading={!loaded && error === null} />
		</div>
	);
}
