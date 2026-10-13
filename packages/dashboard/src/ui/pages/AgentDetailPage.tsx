import { useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import { useT } from "../../i18n/I18nProvider";
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
	const t = useT();
	if (isLoading) return <div role="status">{t("layout.resolvingTenant")}</div>;
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
	const t = useT();
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
			setError(t("agent.missingId"));
			setLoaded(true);
			return;
		}
		if (!tenantId) {
			setError(t("agent.noTeam"));
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
					problems.push(readErrorMessage(agentRes.error, t("agent.loadFailed")));
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
								problems.push(readErrorMessage(snapRes.error, t("agent.entitlementFailed")));
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
						problems.push(readErrorMessage(eventsRes.error, t("agent.eventsFailed")));
					else if (scopedAgent && !Array.isArray(eventsRes.data))
						problems.push(t("agent.eventsFailed"));
					setEvents(null);
				} else setEvents(scopedAgent ? (eventsRes.data as EventRow[]) : []);
				setError(problems.length > 0 ? problems.join(" ") : null);
			} catch {
				if (cancelled) return;
				setAgent(null);
				setEvents(null);
				setEntitlementSnapshot(null);
				setError(t("agent.loadFailed"));
			} finally {
				inFlight = false;
				if (!cancelled) setLoaded(true);
			}
		}

		load();
		const timer = setInterval(load, 3000);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	}, [agentId, tenantId]);

	return (
		<div className="stack">
			<div className="card">
				<div className="row space-between" style={{ alignItems: "flex-start" }}>
					<div>
						<p className="eyebrow">
							<Link to="/agents" style={{ textDecoration: "none" }}>
								{t("agent.back")}
							</Link>
						</p>
						<h1>{t("agent.title")}</h1>
					</div>
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => location.reload()}
					>
						{t("common.refresh")}
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
								<div className="stat-label">{t("common.name")}</div>
								<div className="mono" style={{ fontSize: 15 }}>
									{agent.display_name ?? agent.iid}
								</div>
							</div>
							<div className="stat-card">
								<div className="stat-label">{t("agents.runtime")}</div>
								<div>
									<span className="badge badge-neutral badge-plain">
										{agent.agent_runtime ?? t("common.unknown")}
									</span>{" "}
									<span className="mono muted small">{agent.agent_runtime_version ?? ""}</span>
								</div>
							</div>
							<div className="stat-card">
								<div className="stat-label">{t("agents.lastSeen")}</div>
								<div className="mono" style={{ fontSize: 15 }}>
									{new Date(agent.last_seen).toLocaleString()}
								</div>
							</div>
						</div>

						{entitlementSnapshot ? (
							<div className="notice" style={{ marginTop: 14 }}>
								<div className="muted small">{t("agent.entitlement")}</div>
								<div className="mono">
									{t("agent.entitlementLine", {
										tier:
											typeof entitlementSnapshot.entitlement.subscription_tier === "string"
												? String(entitlementSnapshot.entitlement.subscription_tier)
												: t("common.unknown"),
										allowed: Number(entitlementSnapshot.entitlement.allowed_agents ?? 0) || 0,
										expires:
											typeof entitlementSnapshot.entitlement.expires_at === "string"
												? new Date(
														String(entitlementSnapshot.entitlement.expires_at),
													).toLocaleString()
												: t("common.unknown"),
									})}
								</div>
								<div className="muted small" style={{ marginTop: 6 }}>
									{t("agent.updated", {
										time: new Date(entitlementSnapshot.updated_at).toLocaleString(),
									})}
								</div>
							</div>
						) : (
							<div className="muted small" style={{ marginTop: 12 }}>
								{t("agent.noEntitlement")}
							</div>
						)}
					</>
				) : !loaded ? (
					<div className="row" style={{ marginTop: 14 }}>
						<span className="spinner" aria-hidden="true" />
						<span className="muted">{t("common.loading")}</span>
					</div>
				) : (
					<div className="muted" style={{ marginTop: 14 }}>
						{error ? t("agent.unavailableNow") : t("agent.notFound")}
					</div>
				)}
			</div>

			<div className="card">
				<h2>{t("agent.recentEvents")}</h2>
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("agent.time")}</th>
								<th>{t("notify.table.type")}</th>
								<th>{t("agent.summary")}</th>
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
												: t("agent.noDetails")}
										</td>
									</tr>
								);
							})}
							{events === null || events.length === 0 ? (
								<tr>
									<td colSpan={3} className="muted">
										{events === null
											? loaded
												? t("agent.eventsUnavailable")
												: t("agent.loadingEvents")
											: t("agent.noEvents")}
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
