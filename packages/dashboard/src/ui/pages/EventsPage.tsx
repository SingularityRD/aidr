import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { type Translate, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
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
