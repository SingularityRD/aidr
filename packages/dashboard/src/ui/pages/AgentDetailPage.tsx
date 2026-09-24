import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";

type AgentRow = {
	id: string;
	tenant_id: string;
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

type EntitlementSnapshotRow = {
	updated_at: string;
	entitlement: Record<string, unknown>;
};

function isMissingTableError(error: { code?: string; message?: string }, table: string): boolean {
	return (
		error.code === "PGRST205" ||
		error.code === "42P01" ||
		new RegExp(`${table}.*(?:not exist|missing)`, "i").test(error.message ?? "")
	);
}

function verdictBadgeClass(verdict: string): string {
	if (verdict === "deny") return "badge badge-deny";
	if (verdict === "ask") return "badge badge-ask";
	if (verdict === "allow") return "badge badge-allow";
	return "badge badge-neutral";
}

export function AgentDetailPage() {
	const { agentId } = useParams();
	const { currentTeam, isLoading } = useTeam();
	if (isLoading) return <div role="status">Resolving the managed tenant…</div>;
	const tenantId = currentTeam?.id;
	return (
		<AgentDetailForId
			key={`${tenantId ?? ""}:${agentId ?? ""}`}
			agentId={agentId}
			tenantId={tenantId}
		/>
	);
}

function AgentDetailForId({
	agentId,
	tenantId,
}: {
	agentId: string | undefined;
	tenantId: string | undefined;
}) {
	const [agent, setAgent] = useState<AgentRow | null>(null);
	const [events, setEvents] = useState<EventRow[] | null>(null);
	const [entitlementSnapshot, setEntitlementSnapshot] = useState<EntitlementSnapshotRow | null>(
		null,
	);
	const [error, setError] = useState<string | null>(null);
	const [loaded, setLoaded] = useState(false);

	useEffect(() => {
		let cancelled = false;
		if (typeof agentId !== "string" || agentId.length === 0) {
			setError("Agent identifier is missing.");
			setLoaded(true);
			return;
		}
		if (!tenantId) {
			setError("Select a team to view this agent.");
			setLoaded(true);
			return;
		}
		const currentAgentId: string = agentId;
		const currentTenantId: string = tenantId;
		let inFlight = false;

		async function load() {
			if (inFlight) return;
			inFlight = true;
			try {
				const [agentRes, eventsRes] = await Promise.all([
					supabase
						.from("agents")
						.select(
							"id,tenant_id,iid,display_name,agent_runtime,agent_runtime_version,first_seen,last_seen",
						)
						.eq("id", currentAgentId)
						.eq("tenant_id", currentTenantId)
						.maybeSingle(),
					supabase
						.from("events")
						.select("id,type,created_at,payload")
						.eq("agent_id", currentAgentId)
						.eq("tenant_id", currentTenantId)
						.order("created_at", { ascending: false })
						.limit(200),
				]);

				if (cancelled) return;
				const problems: string[] = [];
				const returnedAgent = (agentRes.data ?? null) as AgentRow | null;
				const scopedAgent = returnedAgent?.tenant_id === currentTenantId ? returnedAgent : null;
				if (agentRes.error) {
					problems.push(readErrorMessage(agentRes.error, "Failed to load agent"));
					setAgent(null);
					setEntitlementSnapshot(null);
				} else {
					const a = scopedAgent;
					setAgent(a);

					// Optional: show the latest entitlement snapshot persisted by ingest/enroll (if deployed).
					if (a?.iid && a.tenant_id) {
						const snapRes = await supabase
							.from("entitlement_snapshots")
							.select("updated_at,entitlement")
							.eq("tenant_id", currentTenantId)
							.eq("iid", a.iid)
							.maybeSingle();
						if (snapRes.error) {
							// Back-compat: ignore only when the optional table is genuinely absent.
							if (!isMissingTableError(snapRes.error, "entitlement_snapshots")) {
								problems.push(readErrorMessage(snapRes.error, "Failed to load agent entitlement"));
							}
							setEntitlementSnapshot(null);
						} else {
							setEntitlementSnapshot((snapRes.data ?? null) as EntitlementSnapshotRow | null);
						}
						if (cancelled) return;
					} else {
						setEntitlementSnapshot(null);
					}
				}

				if (eventsRes.error || agentRes.error || (scopedAgent && !Array.isArray(eventsRes.data))) {
					if (eventsRes.error)
						problems.push(readErrorMessage(eventsRes.error, "Failed to load agent events"));
					else if (scopedAgent && !Array.isArray(eventsRes.data))
						problems.push("Failed to load agent events");
					setEvents(null);
				} else setEvents(scopedAgent ? (eventsRes.data as EventRow[]) : []);
				setError(problems.length > 0 ? problems.join(" ") : null);
			} catch {
				if (cancelled) return;
				setAgent(null);
				setEvents(null);
				setEntitlementSnapshot(null);
				setError("Failed to load agent");
			} finally {
				inFlight = false;
				if (!cancelled) setLoaded(true);
			}
		}

		load();
		const t = setInterval(load, 3000);
		return () => {
			cancelled = true;
			clearInterval(t);
		};
	}, [agentId, tenantId]);

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start" }}>
					<div>
						<p className="eyebrow">
							<Link to="/agents" style={{ textDecoration: "none" }}>
								← Agents
							</Link>
						</p>
						<h1>Agent</h1>
					</div>
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => location.reload()}
					>
						Refresh
					</button>
				</div>

				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}

				{agent ? (
					<>
						<div className="grid" style={{ marginTop: 14 }}>
							<div className="stat-card">
								<div className="stat-label">Name</div>
								<div className="mono" style={{ fontSize: 15 }}>
									{agent.display_name ?? agent.iid}
								</div>
							</div>
							<div className="stat-card">
								<div className="stat-label">Runtime</div>
								<div>
									<span className="badge badge-neutral badge-plain">
										{agent.agent_runtime ?? "unknown"}
									</span>{" "}
									<span className="mono muted small">{agent.agent_runtime_version ?? ""}</span>
								</div>
							</div>
							<div className="stat-card">
								<div className="stat-label">Last seen</div>
								<div className="mono" style={{ fontSize: 15 }}>
									{new Date(agent.last_seen).toLocaleString()}
								</div>
							</div>
						</div>

						{entitlementSnapshot ? (
							<div className="notice" style={{ marginTop: 14 }}>
								<div className="muted small">Entitlement snapshot</div>
								<div className="mono">
									{typeof entitlementSnapshot.entitlement.subscription_tier === "string"
										? String(entitlementSnapshot.entitlement.subscription_tier)
										: "unknown"}{" "}
									| allowed: {Number(entitlementSnapshot.entitlement.allowed_agents ?? 0) || 0} |
									expires:{" "}
									{typeof entitlementSnapshot.entitlement.expires_at === "string"
										? new Date(String(entitlementSnapshot.entitlement.expires_at)).toLocaleString()
										: "unknown"}
								</div>
								<div className="muted small" style={{ marginTop: 6 }}>
									Updated: {new Date(entitlementSnapshot.updated_at).toLocaleString()}
								</div>
							</div>
						) : (
							<div className="muted small" style={{ marginTop: 12 }}>
								No entitlement snapshot yet.
							</div>
						)}
					</>
				) : !loaded ? (
					<div className="row" style={{ marginTop: 14 }}>
						<span className="spinner" aria-hidden="true" />
						<span className="muted">Loading…</span>
					</div>
				) : (
					<div className="muted" style={{ marginTop: 14 }}>
						{error ? "Agent data is unavailable right now." : "Agent not found."}
					</div>
				)}
			</div>

			<div className="card">
				<h2>Recent events</h2>
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
							{(events ?? []).map((e) => {
								const verdict = typeof e.payload?.verdict === "string" ? e.payload.verdict : null;
								return (
									<tr key={e.id}>
										<td className="mono">{new Date(e.created_at).toLocaleString()}</td>
										<td>
											<span className="badge badge-neutral badge-plain mono">{e.type}</span>
										</td>
										<td className="mono">
											{verdict ? (
												<span className={verdictBadgeClass(verdict)} style={{ marginRight: 8 }}>
													{verdict}
												</span>
											) : null}
											{e.type === "runtime_verdict" && typeof e.payload?.tool_name === "string"
												? `${String(e.payload.tool_name)}: ${String(e.payload.verdict ?? "")}`
												: "Additional event details are not shown."}
										</td>
									</tr>
								);
							})}
							{events === null || events.length === 0 ? (
								<tr>
									<td colSpan={3} className="muted">
										{events === null
											? loaded
												? "Event data is unavailable right now."
												: "Loading events…"
											: "No events yet."}
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
