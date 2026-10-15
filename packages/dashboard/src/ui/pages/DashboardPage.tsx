import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { useTeam } from "../../enterprise/team-provider";
import type { DashboardMessageKey } from "../../i18n/en";
import { englishT, type Translate, useRichT, useT } from "../../i18n/I18nProvider";
import { readErrorMessage } from "../../lib/errors";
import { supabase } from "../../lib/supabase";
import { dashboardAgentFreshness } from "../dashboard-freshness";
import { pluginScanSummary } from "../plugin-scan";
import { privacyEventSummary } from "../privacy-guard";
import { getSession } from "../session";
import { shadowAiEventSummary } from "../shadow-ai";

type AgentRow = {
	id: string;
	iid: string;
	display_name: string | null;
	agent_runtime: string | null;
	last_seen: string | null;
};

type EventRow = {
	id: number;
	type: string;
	created_at: string;
	agent_id: string;
	payload: Record<string, unknown> | null;
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNullableString(value: unknown): value is string | null {
	return value === null || typeof value === "string";
}

function isAgentRow(value: unknown): value is AgentRow {
	return (
		isRecord(value) &&
		typeof value.id === "string" &&
		typeof value.iid === "string" &&
		isNullableString(value.display_name) &&
		isNullableString(value.agent_runtime) &&
		isNullableString(value.last_seen)
	);
}

function isEventRow(value: unknown): value is EventRow {
	return (
		isRecord(value) &&
		typeof value.id === "number" &&
		Number.isFinite(value.id) &&
		typeof value.type === "string" &&
		typeof value.created_at === "string" &&
		Number.isFinite(Date.parse(value.created_at)) &&
		typeof value.agent_id === "string" &&
		(value.payload === null || isRecord(value.payload))
	);
}

function queryRows<T>(result: unknown, isRow: (value: unknown) => value is T): T[] {
	if (isRecord(result) && isRecord(result.error) && typeof result.error.message === "string") {
		throw new Error(readErrorMessage(result.error, englishT("dash.queryFailed")));
	}
	if (
		!isRecord(result) ||
		result.error !== null ||
		!Array.isArray(result.data) ||
		!result.data.every(isRow)
	) {
		throw new Error(englishT("dash.malformed"));
	}
	return result.data;
}

/**
 * PostgREST caps a response at `max_rows` (1000), so the agent list is an
 * explicit page of the most recent heartbeats and the total comes from an exact
 * count. A count that is missing or smaller than the page is malformed.
 */
export const AGENT_ROW_LIMIT = 1000;

type AgentPage = { rows: AgentRow[]; total: number };

function queryAgentPage(result: unknown): AgentPage {
	const rows = queryRows(result, isAgentRow);
	const total = isRecord(result) ? result.count : undefined;
	if (typeof total !== "number" || !Number.isSafeInteger(total) || total < rows.length) {
		throw new Error(englishT("dash.malformed"));
	}
	return { rows, total };
}

const VERDICT_LABEL: Record<string, DashboardMessageKey> = {
	allow: "verdict.allow",
	deny: "verdict.deny",
	ask: "verdict.ask",
};

const FRESHNESS_LABEL: Record<string, DashboardMessageKey> = {
	fresh: "dash.fresh",
	stale: "dash.stale",
	unknown: "dash.unknown",
};

function eventSummary(event: EventRow, t: Translate): string {
	if (event.type === "runtime_verdict") {
		const tool =
			typeof event.payload?.tool_name === "string"
				? String(event.payload.tool_name)
				: t("activity.tool");
		const raw = typeof event.payload?.verdict === "string" ? String(event.payload.verdict) : null;
		const key = raw ? VERDICT_LABEL[raw] : undefined;
		return `${tool}: ${key ? t(key) : (raw ?? t("common.unknown"))}`;
	}
	if (event.type === "plugin_scan") return pluginScanSummary(event.payload);
	if (event.type === "privacy_scan") return privacyEventSummary(event.payload);
	if (event.type === "shadow_ai_usage") return shadowAiEventSummary(event.payload);
	return t("events.noDetails");
}

function verdictOf(event: EventRow): string | null {
	if (event.type !== "runtime_verdict") return null;
	return typeof event.payload?.verdict === "string" ? String(event.payload.verdict) : null;
}

export function DashboardPage() {
	const { currentTeam, isLoading } = useTeam();
	const t = useT();
	if (isLoading) return <div role="status">{t("layout.resolvingTenant")}</div>;
	if (!currentTeam) return <div role="alert">{t("dash.noTeam")}</div>;
	return <TenantDashboardPage key={currentTeam.id} tenantId={currentTeam.id} />;
}

function TenantDashboardPage({ tenantId }: { tenantId: string }) {
	const t = useT();
	const richT = useRichT();
	const [email, setEmail] = useState<string | null>(null);
	// null = not loaded / unavailable (fail-closed); [] = a real, empty result.
	const [agentPage, setAgentPage] = useState<AgentPage | null>(null);
	const [events, setEvents] = useState<EventRow[] | null>(null);
	const [pendingTokens, setPendingTokens] = useState<number | null>(null);
	const [agentError, setAgentError] = useState<string | null>(null);
	const [eventError, setEventError] = useState<string | null>(null);
	const [pendingError, setPendingError] = useState<string | null>(null);
	const [nowMs, setNowMs] = useState(() => Date.now());
	const error = [agentError, eventError, pendingError].filter(Boolean).join(" ");

	useEffect(() => {
		let cancelled = false;
		const timers: ReturnType<typeof setInterval>[] = [];
		const deadlines = new Set<ReturnType<typeof setTimeout>>();

		// Poll sources independently. A read has 15 seconds to settle before it
		// becomes unavailable; late responses cannot overwrite a newer poll.
		function poll<T>(
			read: () => Promise<T>,
			setData: (data: T | null) => void,
			setProblem?: (problem: string | null) => void,
		) {
			let loading = false;
			async function load() {
				if (loading) return;
				loading = true;
				let deadline: ReturnType<typeof setTimeout> | undefined;
				try {
					const timeout = new Promise<never>((_resolve, reject) => {
						deadline = setTimeout(() => reject(new Error(t("dash.timeout"))), 15_000);
						deadlines.add(deadline);
					});
					const data = await Promise.race([read(), timeout]);
					if (!cancelled) {
						setData(data);
						setProblem?.(null);
					}
				} catch (cause) {
					if (!cancelled) {
						setData(null);
						setProblem?.(readErrorMessage(cause, t("dash.queryFailed")));
					}
				} finally {
					if (deadline !== undefined) {
						clearTimeout(deadline);
						deadlines.delete(deadline);
					}
					loading = false;
				}
			}
			void load();
			timers.push(setInterval(() => void load(), 6000));
		}

		poll(
			async () =>
				queryAgentPage(
					await supabase
						.from("agents")
						.select("id,iid,display_name,agent_runtime,last_seen", { count: "exact" })
						.eq("tenant_id", tenantId)
						.order("last_seen", { ascending: false, nullsFirst: false })
						.limit(AGENT_ROW_LIMIT),
				),
			setAgentPage,
			setAgentError,
		);
		poll(
			async () =>
				queryRows(
					await supabase
						.from("events")
						.select("id,type,created_at,agent_id,payload")
						.eq("tenant_id", tenantId)
						.order("created_at", { ascending: false })
						.limit(500),
					isEventRow,
				),
			setEvents,
			setEventError,
		);

		// Outstanding enrollment tokens require pilot approval; unavailable or
		// malformed results must not become a made-up zero.
		poll(
			async () => {
				const result = await supabase.functions.invoke("enrollment-tokens", {
					method: "GET",
					headers: { "X-AIDR-Tenant-ID": tenantId },
				});
				if (
					!isRecord(result) ||
					result.error !== null ||
					!isRecord(result.data) ||
					result.data.ok !== true ||
					!Array.isArray(result.data.tokens)
				) {
					throw new Error(t("dash.tokensUnavailable"));
				}
				const tokens = result.data.tokens;
				const now = Date.now();
				return tokens.filter((token: unknown) => {
					if (
						!isRecord(token) ||
						!isNullableString(token.consumed_at) ||
						(token.consumed_at !== null && !Number.isFinite(Date.parse(token.consumed_at))) ||
						typeof token.expires_at !== "string" ||
						!Number.isFinite(Date.parse(token.expires_at))
					) {
						throw new Error(t("dash.tokenMalformed"));
					}
					return token.consumed_at === null && Date.parse(token.expires_at) > now;
				}).length;
			},
			setPendingTokens,
			setPendingError,
		);

		async function loadSession() {
			try {
				const session = await getSession();
				if (!cancelled) setEmail(session?.user?.email ?? null);
			} catch {
				if (!cancelled) setEmail(null);
			}
		}

		void loadSession();
		// Age existing evidence even when polls return the same array or hang.
		timers.push(setInterval(() => setNowMs(Date.now()), 1000));
		return () => {
			cancelled = true;
			for (const timer of timers) clearInterval(timer);
			for (const deadline of deadlines) clearTimeout(deadline);
		};
	}, [tenantId]);

	const agents = agentPage?.rows ?? null;
	// Counters and rows consume exactly the same clock-based classification.
	const agentSnapshot = useMemo(
		() =>
			(agents ?? []).map((agent) => ({
				agent,
				freshness: dashboardAgentFreshness(agent.last_seen, nowMs),
			})),
		[agents, nowMs],
	);
	const connectedCount = agentSnapshot.filter(({ freshness }) => freshness === "fresh").length;
	// Rows are ordered newest heartbeat first, so agents beyond the page are older
	// than its last row. Only when that last row is still fresh can connected
	// agents exist beyond the page; the count is then a lower bound.
	const connectedIsLowerBound =
		agentPage !== null &&
		agentPage.total > agentPage.rows.length &&
		agentSnapshot.at(-1)?.freshness === "fresh";
	const denyCount = useMemo(
		() => (events ?? []).filter((e) => verdictOf(e) === "deny").length,
		[events],
	);
	const askCount = useMemo(
		() => (events ?? []).filter((e) => verdictOf(e) === "ask").length,
		[events],
	);
	const latestHeartbeat = useMemo(() => {
		const stamps = (agents ?? [])
			.map((agent) =>
				typeof agent.last_seen === "string" ? Date.parse(agent.last_seen) : Number.NaN,
			)
			.filter((stamp) => Number.isFinite(stamp) && stamp <= nowMs);
		return stamps.length > 0 ? new Date(Math.max(...stamps)) : null;
	}, [agents, nowMs]);

	const liveAgents = agentSnapshot.slice(0, 5);
	const recentEvents = (events ?? []).slice(0, 6);

	return (
		<div className="stack">
			<section className="card console-hero">
				<div className="console-hero-grid">
					<div>
						<p className="eyebrow">{t("dash.eyebrow")}</p>
						<h1>{t("nav.dashboard")}</h1>
						<p style={{ marginTop: 4 }}>{t("dash.lead")}</p>
						<p className="muted" style={{ marginTop: 8 }}>
							{t("dash.intro")}
						</p>
						<div className="row" style={{ marginTop: 16 }}>
							<Link className="button" to="/onboarding">
								{t("dash.connect")}
							</Link>
							<Link className="button button-secondary" to="/verify">
								{t("dash.verify")}
							</Link>
							<Link className="button button-secondary" to="/settings">
								{t("dash.privacy")}
							</Link>
						</div>
					</div>
					<div>
						<div className="session-box">
							<div className="muted small">{t("dash.signedInAs")}</div>
							<div className="mono" style={{ marginTop: 2, overflowWrap: "anywhere" }}>
								{email ?? t("common.unknown")}
							</div>
							<div className="muted small" style={{ marginTop: 10 }}>
								{t("dash.heartbeat")}
							</div>
							<div className="mono" style={{ marginTop: 2 }}>
								{latestHeartbeat
									? latestHeartbeat.toLocaleString()
									: agents?.length === 0
										? t("dash.noAgentsYet")
										: t("common.unavailable")}
							</div>
						</div>
					</div>
				</div>
				{error ? (
					<div
						className="notice notice-danger"
						role="alert"
						aria-live="assertive"
						style={{ marginTop: 14 }}
					>
						{error}
					</div>
				) : null}
			</section>

			<section className="grid" aria-label={t("dash.counters")}>
				<div className="card stat-card">
					<div className="stat-label">{t("dash.agents")}</div>
					<div className="stat-value">{agentPage === null ? "—" : agentPage.total}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("dash.connected")}</div>
					<div className="stat-value">
						{agentPage === null ? "—" : `${connectedCount}${connectedIsLowerBound ? "+" : ""}`}
					</div>
					{connectedIsLowerBound ? (
						<div className="stat-hint">{t("dash.atLeast", { count: AGENT_ROW_LIMIT })}</div>
					) : null}
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("dash.pending")}</div>
					<div className="stat-value">{pendingTokens ?? "—"}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("dash.events")}</div>
					<div className="stat-value">{events === null ? "—" : events.length}</div>
					<div className="stat-hint">{t("dash.latest500")}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("dash.blocked")}</div>
					<div className="stat-value">{events === null ? "—" : denyCount}</div>
					<div className="stat-hint">{t("dash.latest500")}</div>
				</div>
				<div className="card stat-card">
					<div className="stat-label">{t("dash.needsApproval")}</div>
					<div className="stat-value">{events === null ? "—" : askCount}</div>
					<div className="stat-hint">{t("dash.latest500")}</div>
				</div>
			</section>

			<section className="cols">
				<div className="card">
					<div className="panel-head">
						<h2>{t("dash.liveAgents")}</h2>
						<Link className="view-all" to="/agents">
							{t("dash.viewAll")}
						</Link>
					</div>
					<p className="muted small">{t("dash.liveIntro")}</p>
					<div className="table-wrap">
						<table className="table">
							<thead>
								<tr>
									<th>{t("activity.agent")}</th>
									<th>{t("agents.runtime")}</th>
									<th>{t("dash.state")}</th>
								</tr>
							</thead>
							<tbody>
								{liveAgents.map(({ agent, freshness }) => (
									<tr key={agent.id}>
										<td>
											<Link className="mono" to={`/agents/${agent.id}`}>
												{agent.display_name ?? agent.iid.slice(0, 12)}
											</Link>
										</td>
										<td className="muted">{agent.agent_runtime ?? t("common.unknown")}</td>
										<td>
											<span
												className={`badge ${freshness === "fresh" ? "badge-success" : "badge-neutral"}`}
											>
												{FRESHNESS_LABEL[freshness] ? t(FRESHNESS_LABEL[freshness]) : freshness}
											</span>
										</td>
									</tr>
								))}
								{liveAgents.length === 0 ? (
									<tr>
										<td colSpan={3} className="muted">
											{agents === null
												? t("dash.agentsUnavailable")
												: richT("dash.noAgents", {
														link: <Link to="/onboarding">{t("nav.onboarding")}</Link>,
													})}
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>

				<div className="card">
					<div className="panel-head">
						<h2>{t("dash.recentEvents")}</h2>
						<Link className="view-all" to="/events">
							{t("dash.viewAll")}
						</Link>
					</div>
					<p className="muted small">{t("dash.recentIntro")}</p>
					<div className="table-wrap">
						<table className="table">
							<thead>
								<tr>
									<th>{t("activity.time")}</th>
									<th>{t("activity.type")}</th>
									<th>{t("activity.summary")}</th>
								</tr>
							</thead>
							<tbody>
								{recentEvents.map((event) => (
									<tr key={event.id}>
										<td className="mono muted">
											{new Date(event.created_at).toLocaleTimeString()}
										</td>
										<td>
											<span className="badge badge-neutral badge-plain mono">{event.type}</span>
										</td>
										<td className="mono">{eventSummary(event, t)}</td>
									</tr>
								))}
								{recentEvents.length === 0 ? (
									<tr>
										<td colSpan={3} className="muted">
											{events === null ? t("dash.eventsUnavailable") : t("dash.noEvents")}
										</td>
									</tr>
								) : null}
							</tbody>
						</table>
					</div>
				</div>
			</section>
		</div>
	);
}
