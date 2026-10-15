import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { type EvidenceAuditRow, EvidenceView } from "../../enterprise/evidence-view";
import { type TeamMember, useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import {
	effectiveStatus,
	isSnoozed,
	listTriage,
	type TriageList,
	type TriageRow,
	triageErrorMessage,
} from "../../lib/incidents";
import { supabase } from "../../lib/supabase";
import { FrameworkTags } from "../framework-coverage";
import { TRIAGE_FILTERS, TriageCells, type TriageFilter, TriagePanel } from "../incident-triage";
import { pluginScanFindingsCount, pluginScanSummary } from "../plugin-scan";

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
		// An unknown finding count is not evidence of a clean scan: surface it for review.
		const count = pluginScanFindingsCount(e.payload);
		return count === null || count > 0;
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

const CANARY_RULE_ID = /^(?:AIDR|OUT)-CANARY-\d{3}$/;

/**
 * Canary credential triggers arrive as ordinary verdict/incident events; the
 * ingest projection keeps `source` and `matched_threat_id`, which name them.
 */
export function isCanaryTrigger(e: Pick<EventRow, "payload">): boolean {
	const rule = e.payload?.matched_threat_id;
	return e.payload?.source === "canary" || (typeof rule === "string" && CANARY_RULE_ID.test(rule));
}

const VERDICT_LABEL: Record<string, DashboardMessageKey> = {
	allow: "verdict.allow",
	deny: "verdict.deny",
	ask: "verdict.ask",
};

function verdictLabel(verdict: string, t: Translate): string {
	const key = VERDICT_LABEL[verdict];
	return key ? t(key) : verdict;
}

function summarize(e: EventRow, t: Translate): string {
	if (e.type === "plugin_scan") return pluginScanSummary(e.payload);
	if (e.type === "runtime_verdict") {
		const tool =
			typeof e.payload?.tool_name === "string" ? String(e.payload.tool_name) : t("activity.tool");
		const verdict =
			typeof e.payload?.verdict === "string"
				? verdictLabel(String(e.payload.verdict), t)
				: t("common.unknown");
		const severity = typeof e.payload?.severity === "string" ? String(e.payload.severity) : "";
		return `${tool}: ${verdict}${severity ? ` (${severity})` : ""}`;
	}
	if (e.type === "incident") {
		const tool =
			typeof e.payload?.tool_name === "string" ? String(e.payload.tool_name) : t("activity.tool");
		const decision =
			typeof e.payload?.decision === "string"
				? verdictLabel(String(e.payload.decision), t)
				: t("common.unknown");
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
		return `${t("incidents.correlated")}${severity ? ` (${severity})` : ""}${status ? ` [${status}]` : ""} — ${t("incidents.eventCount", { count: n })}`;
	}
	return t("incidents.noDetails");
}

export function IncidentsPage() {
	const { currentTeam, isLoading } = useTeam();
	const t = useT();
	if (isLoading) return <div role="status">{t("layout.resolvingTenant")}</div>;
	if (!currentTeam) return <div role="alert">{t("incidents.noTeam")}</div>;
	return <TenantIncidentsPage key={currentTeam.id} tenantId={currentTeam.id} />;
}

const TRIAGE_FILTER_LABEL: Readonly<Record<TriageFilter, DashboardMessageKey>> = {
	active: "inc.filter.active",
	snoozed: "inc.filter.snoozed",
	closed: "inc.filter.closed",
	all: "inc.filter.all",
};

function matchesFilter(filter: TriageFilter, row: TriageRow | undefined, nowMs: number): boolean {
	const status = effectiveStatus(row);
	const closed = status === "resolved" || status === "false_positive";
	switch (filter) {
		case "active":
			return !closed && !isSnoozed(row, nowMs);
		case "snoozed":
			return isSnoozed(row, nowMs);
		case "closed":
			return closed;
		default:
			return true;
	}
}

function IncidentRow(props: {
	event: EventRow;
	agent: AgentRow | undefined;
	triage: TriageList;
	nowMs: number;
	members: TeamMember[];
	onManage: (eventId: number) => void;
}) {
	const t = useT();
	const { event: e, agent } = props;
	const agentName = agent?.display_name ?? agent?.iid?.slice(0, 12) ?? e.agent_id;
	return (
		<tr>
			<td className="mono">{new Date(e.created_at).toLocaleString()}</td>
			<td>
				{agent ? (
					<Link className="mono" to={`/agents/${agent.id}`}>
						{agentName}
					</Link>
				) : (
					<span className="mono">{agentName}</span>
				)}
				{agent?.agent_runtime ? <div className="muted small">{agent.agent_runtime}</div> : null}
			</td>
			<td>
				<span className="badge badge-neutral badge-plain mono">{e.type}</span>
				{isCanaryTrigger(e) ? (
					<div>
						<span className="badge badge-deny">{t("incidents.canary")}</span>
					</div>
				) : null}
			</td>
			<td className="mono">
				{summarize(e, t)}
				{e.type === "runtime_verdict" || e.type === "incident" ? (
					<FrameworkTags ruleId={e.payload?.matched_threat_id} />
				) : null}
			</td>
			<TriageCells
				eventId={e.id}
				row={props.triage.rows.get(e.id)}
				nowMs={props.nowMs}
				members={props.members}
				canTriage={props.triage.canTriage}
				onManage={props.onManage}
			/>
		</tr>
	);
}

/** Triage state of the workspace's incidents, re-read every 30 seconds. */
function useIncidentTriage(tenantId: string) {
	const [triage, setTriage] = useState<TriageList>({ canTriage: false, rows: new Map() });
	const [triageError, setTriageError] = useState<string | null>(null);

	useEffect(() => {
		let cancelled = false;
		const load = async () => {
			const result = await listTriage(tenantId);
			if (cancelled) return;
			if (result.ok) {
				setTriage(result.value);
				setTriageError(null);
			} else setTriageError(result.error);
		};
		void load();
		const timer = setInterval(() => void load(), 30_000);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	}, [tenantId]);

	const onSaved = useCallback((row: TriageRow) => {
		setTriage((previous) => {
			const rows = new Map(previous.rows);
			rows.set(row.eventId, row);
			return { ...previous, rows };
		});
	}, []);

	return { triage, triageError, onSaved };
}

function emptyMessage(
	t: Translate,
	events: EventRow[] | null,
	loaded: boolean,
	incidents: number,
): string {
	if (events === null) return loaded ? t("incidents.unavailable") : t("incidents.loading");
	return incidents > 0 ? t("inc.noneInFilter") : t("incidents.empty");
}

function TenantIncidentsPage({ tenantId }: { tenantId: string }) {
	const t = useT();
	const team = useTeam();
	const members = team.members ?? [];
	const currentUserId = team.currentUserId ?? "";
	const [agents, setAgents] = useState<Map<string, AgentRow>>(new Map());
	const [events, setEvents] = useState<EventRow[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loaded, setLoaded] = useState(false);
	const { triage, triageError, onSaved } = useIncidentTriage(tenantId);
	const [filter, setFilter] = useState<TriageFilter>("active");
	const [mineOnly, setMineOnly] = useState(false);
	const [selected, setSelected] = useState<number | null>(null);

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
					problems.push(readErrorMessage(eventsRes.error, t("incidents.loadFailed")));
					setEvents(null);
				} else setEvents(eventsRes.data as EventRow[]);

				if (agentsRes.error || !Array.isArray(agentsRes.data)) {
					problems.push(readErrorMessage(agentsRes.error, t("agents.loadFailed")));
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
				setError(t("incidents.loadFailed"));
			} finally {
				inFlight = false;
				if (!cancelled) setLoaded(true);
			}
		}

		load();
		const timer = setInterval(load, 6000);
		return () => {
			cancelled = true;
			clearInterval(timer);
		};
	}, [tenantId]);

	const incidentEvents = useMemo(() => (events ?? []).filter(isIncidentLikeEvent), [events]);
	const nowMs = Date.now();
	const visibleEvents = incidentEvents.filter((e) => {
		const row = triage.rows.get(e.id);
		if (!matchesFilter(filter, row, nowMs)) return false;
		return !mineOnly || row?.ownerUserId === currentUserId;
	});
	const selectedEvent =
		selected === null ? null : (incidentEvents.find((e) => e.id === selected) ?? null);

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
						<h1>{t("nav.incidents")}</h1>
						<p className="muted">{t("incidents.intro")}</p>
					</div>
					<button
						className="button button-secondary button-sm"
						type="button"
						onClick={() => location.reload()}
					>
						{t("common.refresh")}
					</button>
				</div>
				{events !== null ? (
					<div className="row" style={{ marginTop: 14 }}>
						<span className="badge badge-deny">
							{t("incidents.count.blocked", { count: denyCount })}
						</span>
						<span className="badge badge-ask">{t("incidents.count.ask", { count: askCount })}</span>
						<span className="badge badge-info">
							{t("incidents.count.scans", { count: scanCount })}
						</span>
					</div>
				) : null}
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
				{triageError ? (
					<div className="notice notice-error" role="alert">
						{t("inc.triageUnavailable", { reason: triageErrorMessage(triageError, t) })}
					</div>
				) : null}
				<div className="row" style={{ marginTop: 14, alignItems: "center" }}>
					<label>
						{t("inc.show")}{" "}
						<select value={filter} onChange={(e) => setFilter(e.target.value as TriageFilter)}>
							{TRIAGE_FILTERS.map((value) => (
								<option key={value} value={value}>
									{t(TRIAGE_FILTER_LABEL[value])}
								</option>
							))}
						</select>
					</label>
					<label>
						<input
							type="checkbox"
							checked={mineOnly}
							onChange={(e) => setMineOnly(e.target.checked)}
						/>{" "}
						{t("inc.mine")}
					</label>
				</div>
			</div>

			{selectedEvent ? (
				<TriagePanel
					key={selectedEvent.id}
					tenantId={tenantId}
					eventId={selectedEvent.id}
					agentId={selectedEvent.agent_id}
					summary={summarize(selectedEvent, t)}
					ruleId={selectedEvent.payload?.matched_threat_id}
					triage={triage.rows.get(selectedEvent.id)}
					canTriage={triage.canTriage}
					members={members}
					onClose={() => setSelected(null)}
					onSaved={onSaved}
				/>
			) : null}

			<div className="card">
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("activity.time")}</th>
								<th>{t("activity.agent")}</th>
								<th>{t("activity.type")}</th>
								<th>{t("activity.summary")}</th>
								<th>{t("inc.col.status")}</th>
								<th>{t("inc.col.owner")}</th>
								<th />
							</tr>
						</thead>
						<tbody>
							{visibleEvents.map((e) => (
								<IncidentRow
									key={e.id}
									event={e}
									agent={agents.get(e.agent_id)}
									triage={triage}
									nowMs={nowMs}
									members={members}
									onManage={setSelected}
								/>
							))}
							{visibleEvents.length === 0 ? (
								<tr>
									<td colSpan={7} className="muted">
										{emptyMessage(t, events, loaded, incidentEvents.length)}
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
