import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import {
	applyEventFilters,
	EVENT_DECISIONS,
	EVENT_RANGES,
	EVENT_ROW_LIMIT,
	EVENT_SEVERITIES,
	EVENT_TYPES,
	type EventFilters,
	eventFiltersActive,
	eventsCsv,
	fileStamp,
	isValidRuleId,
	readEventFilters,
	saveFile,
	writeEventFilters,
} from "../fleet-view";
import { FrameworkTags } from "../framework-coverage";
import { pluginScanSummary } from "../plugin-scan";
import { privacyEventSummary } from "../privacy-guard";
import { shadowAiEventSummary } from "../shadow-ai";

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

const VERDICT_LABEL: Record<string, DashboardMessageKey> = {
	allow: "verdict.allow",
	deny: "verdict.deny",
	ask: "verdict.ask",
};

const RANGE_LABEL: Record<EventFilters["range"], DashboardMessageKey> = {
	all: "events.range.all",
	"1h": "events.range.1h",
	"24h": "events.range.24h",
	"7d": "events.range.7d",
	"30d": "events.range.30d",
};

const DECISION_LABEL: Record<(typeof EVENT_DECISIONS)[number], DashboardMessageKey> = {
	allow: "verdict.allow",
	ask: "verdict.ask",
	deny: "verdict.deny",
};

const SEVERITY_LABEL: Record<(typeof EVENT_SEVERITIES)[number], DashboardMessageKey> = {
	info: "common.severity.info",
	warning: "common.severity.warning",
	high: "common.severity.high",
	critical: "common.severity.critical",
};

function summarize(event: EventRow, t: Translate): string {
	if (event.type === "runtime_verdict") {
		const tool =
			typeof event.payload?.tool_name === "string"
				? String(event.payload.tool_name)
				: t("activity.tool");
		const severity =
			typeof event.payload?.severity === "string" ? String(event.payload.severity) : "";
		return `${tool}${severity ? ` (${severity})` : ""}`;
	}
	if (event.type === "plugin_scan") return pluginScanSummary(event.payload);
	if (event.type === "privacy_scan") return privacyEventSummary(event.payload);
	if (event.type === "shadow_ai_usage") return shadowAiEventSummary(event.payload);
	return t("events.noDetails");
}

export function EventsPage() {
	const { currentTeam, isLoading } = useTeam();
	const t = useT();
	if (isLoading) return <div role="status">{t("layout.resolvingTenant")}</div>;
	if (!currentTeam) return <div role="alert">{t("events.noTeam")}</div>;
	return <TenantEventsPage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantEventsPage({ tenantId }: { tenantId: string }) {
	const t = useT();
	const [agents, setAgents] = useState<Map<string, AgentRow>>(new Map());
	// null = not loaded / unavailable (fail-closed); [] = a real, empty feed.
	const [events, setEvents] = useState<EventRow[] | null>(null);
	const [error, setError] = useState<string | null>(null);
	const [loaded, setLoaded] = useState(false);
	const [searchParams, setSearchParams] = useSearchParams();
	const filterKey = writeEventFilters(readEventFilters(searchParams)).toString();
	const filters = useMemo(() => readEventFilters(new URLSearchParams(filterKey)), [filterKey]);
	const [ruleDraft, setRuleDraft] = useState(filters.rule);
	useEffect(() => setRuleDraft(filters.rule), [filters.rule]);
	const updateFilters = useCallback(
		(change: Partial<EventFilters>) =>
			setSearchParams(writeEventFilters({ ...filters, ...change }), { replace: true }),
		[filters, setSearchParams],
	);

	useEffect(() => {
		let cancelled = false;
		let inFlight = false;
		// A new filter set must never show the previous filter's rows as its result.
		setEvents(null);
		setLoaded(false);

		async function load() {
			if (inFlight) return;
			inFlight = true;
			try {
				const [eventsRes, agentsRes] = await Promise.all([
					applyEventFilters(
						supabase
							.from("events")
							.select("id,type,created_at,agent_id,payload")
							.eq("tenant_id", tenantId),
						filters,
						Date.now(),
					)
						.order("created_at", { ascending: false })
						.limit(EVENT_ROW_LIMIT),
					supabase
						.from("agents")
						.select("id,iid,display_name,agent_runtime")
						.eq("tenant_id", tenantId)
						.order("last_seen", { ascending: false }),
				]);

				if (cancelled) return;

				const problems: string[] = [];
				if (eventsRes.error || !Array.isArray(eventsRes.data)) {
					problems.push(readErrorMessage(eventsRes.error, t("events.loadFailed")));
					setEvents(null);
				} else {
					setEvents(eventsRes.data as EventRow[]);
				}

				if (agentsRes.error || !Array.isArray(agentsRes.data)) {
					problems.push(readErrorMessage(agentsRes.error, t("agents.loadFailed")));
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
				setError(t("events.loadFailed"));
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
	}, [tenantId, filters]);

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
						<h1>{t("nav.events")}</h1>
						<p className="muted">{t("events.intro")}</p>
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
					<div className="row" style={{ marginTop: 12 }}>
						<span className="badge badge-deny">
							{t("events.count.deny", { count: verdictCounts.deny })}
						</span>
						<span className="badge badge-ask">
							{t("events.count.ask", { count: verdictCounts.ask })}
						</span>
						<span className="badge badge-allow">
							{t("events.count.allow", { count: verdictCounts.allow })}
						</span>
					</div>
				) : null}
				{error ? (
					<div className="notice notice-danger" role="alert" aria-live="assertive">
						{error}
					</div>
				) : null}
			</div>

			<div className="card">
				<div className="row" style={{ gap: 12, flexWrap: "wrap", alignItems: "flex-end" }}>
					<label>
						<span className="small">{t("events.filter.range")}</span>{" "}
						<select
							className="input"
							value={filters.range}
							onChange={(event) =>
								updateFilters({ range: event.currentTarget.value as EventFilters["range"] })
							}
						>
							{EVENT_RANGES.map((range) => (
								<option key={range} value={range}>
									{t(RANGE_LABEL[range])}
								</option>
							))}
						</select>
					</label>
					<label>
						<span className="small">{t("activity.type")}</span>{" "}
						<select
							className="input"
							value={filters.type}
							onChange={(event) => updateFilters({ type: event.currentTarget.value })}
						>
							<option value="">{t("events.filter.typeAll")}</option>
							{EVENT_TYPES.map((type) => (
								<option key={type} value={type}>
									{type}
								</option>
							))}
						</select>
					</label>
					<label>
						<span className="small">{t("activity.verdict")}</span>{" "}
						<select
							className="input"
							value={filters.decision}
							onChange={(event) => updateFilters({ decision: event.currentTarget.value })}
						>
							<option value="">{t("events.filter.decisionAll")}</option>
							{EVENT_DECISIONS.map((decision) => (
								<option key={decision} value={decision}>
									{t(DECISION_LABEL[decision])}
								</option>
							))}
						</select>
					</label>
					<label>
						<span className="small">{t("events.filter.severity")}</span>{" "}
						<select
							className="input"
							value={filters.severity}
							onChange={(event) => updateFilters({ severity: event.currentTarget.value })}
						>
							<option value="">{t("events.filter.severityAll")}</option>
							{EVENT_SEVERITIES.map((severity) => (
								<option key={severity} value={severity}>
									{t(SEVERITY_LABEL[severity])}
								</option>
							))}
						</select>
					</label>
					<label>
						<span className="small">{t("activity.agent")}</span>{" "}
						<select
							className="input"
							value={filters.agent}
							onChange={(event) => updateFilters({ agent: event.currentTarget.value })}
						>
							<option value="">{t("events.filter.agentAll")}</option>
							{filters.agent && !agents.has(filters.agent) ? (
								<option value={filters.agent}>{filters.agent}</option>
							) : null}
							{[...agents.values()].map((agent) => (
								<option key={agent.id} value={agent.id}>
									{agent.display_name ?? agent.iid.slice(0, 12)}
								</option>
							))}
						</select>
					</label>
					<form
						className="row"
						style={{ gap: 6, alignItems: "flex-end" }}
						onSubmit={(event) => {
							event.preventDefault();
							const rule = ruleDraft.trim();
							if (isValidRuleId(rule)) updateFilters({ rule });
						}}
					>
						<label>
							<span className="small">{t("events.filter.rule")}</span>{" "}
							<input
								className="input mono"
								value={ruleDraft}
								maxLength={128}
								aria-invalid={!isValidRuleId(ruleDraft.trim())}
								onChange={(event) => setRuleDraft(event.currentTarget.value)}
							/>
						</label>
						<button
							className="button button-secondary button-sm"
							type="submit"
							disabled={!isValidRuleId(ruleDraft.trim())}
						>
							{t("events.filter.apply")}
						</button>
					</form>
					{eventFiltersActive(filters) ? (
						<button
							className="button button-secondary button-sm"
							type="button"
							onClick={() => setSearchParams(new URLSearchParams(), { replace: true })}
						>
							{t("events.filter.clear")}
						</button>
					) : null}
				</div>
				{!isValidRuleId(ruleDraft.trim()) ? (
					<div className="muted small" role="status" style={{ marginTop: 6 }}>
						{t("events.filter.ruleInvalid")}
					</div>
				) : null}
				<div className="row" style={{ gap: 8, marginTop: 10, flexWrap: "wrap" }}>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={!events || events.length === 0}
						title={t("events.export.hint", { count: events?.length ?? 0 })}
						onClick={() => {
							if (!events) return;
							saveFile(
								`aidr-events-${fileStamp(Date.now())}.csv`,
								eventsCsv(events, agents),
								"text/csv;charset=utf-8",
							);
						}}
					>
						{t("events.export.csv")}
					</button>
					<button
						className="button button-secondary button-sm"
						type="button"
						disabled={!events || events.length === 0}
						title={t("events.export.hint", { count: events?.length ?? 0 })}
						onClick={() => {
							if (!events) return;
							saveFile(
								`aidr-events-${fileStamp(Date.now())}.json`,
								`${JSON.stringify({ filters: writeEventFilters(filters).toString(), events }, null, 2)}\n`,
								"application/json",
							);
						}}
					>
						{t("events.export.json")}
					</button>
				</div>
				{events && events.length >= EVENT_ROW_LIMIT ? (
					<div className="notice notice-warning" role="status" style={{ marginTop: 10 }}>
						{t("events.capped", { count: EVENT_ROW_LIMIT })}
					</div>
				) : null}
				<div className="table-wrap">
					<table className="table">
						<thead>
							<tr>
								<th>{t("activity.time")}</th>
								<th>{t("activity.agent")}</th>
								<th>{t("activity.type")}</th>
								<th>{t("activity.verdict")}</th>
								<th>{t("activity.summary")}</th>
							</tr>
						</thead>
						<tbody>
							{(events ?? []).map((event) => {
								const agent = agents.get(event.agent_id);
								const agentName = agent?.display_name ?? agent?.iid?.slice(0, 12) ?? event.agent_id;
								// Browser Guard events carry the contract's generic decision (masked => allow).
								const browserEvent =
									event.type === "privacy_scan" || event.type === "shadow_ai_usage";
								const verdictField = browserEvent ? "decision" : "verdict";
								const verdict =
									(event.type === "runtime_verdict" || browserEvent) &&
									typeof event.payload?.[verdictField] === "string"
										? String(event.payload[verdictField])
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
												<span className={verdictBadgeClass(verdict)}>
													{VERDICT_LABEL[verdict] ? t(VERDICT_LABEL[verdict]) : verdict}
												</span>
											) : (
												<span className="muted small">—</span>
											)}
										</td>
										<td className="mono">
											{summarize(event, t)}
											{event.type === "runtime_verdict" ? (
												<FrameworkTags ruleId={event.payload?.matched_threat_id} />
											) : null}
										</td>
									</tr>
								);
							})}
							{events === null || events.length === 0 ? (
								<tr>
									<td colSpan={5} className="muted">
										{events === null
											? loaded
												? t("events.unavailable")
												: t("events.loading")
											: eventFiltersActive(filters)
												? t("events.filter.none")
												: t("events.empty")}
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
