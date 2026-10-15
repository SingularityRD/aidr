/**
 * Pure helpers for the agent (fleet) list and the event feed: URL-persisted
 * filters, stale-agent classification and client-side CSV/JSON export of the
 * rows already loaded under the caller's row-level security.
 *
 * Exports contain only rows the page has already received from the server for
 * the signed-in member; they add no access. Every filter value read from the
 * URL is validated against an allowlist or a strict pattern so a crafted link
 * cannot inject a PostgREST filter expression.
 */
import { type Cell, csvField } from "./compliance-export";

/**
 * An active agent not seen for this long is "stale". Matches the default
 * `agent_offline_minutes` (240) of the agent-offline alert channel, and the
 * hourly `aidr heartbeat` cadence leaves several missed beats of margin.
 */
export const STALE_AFTER_MS = 4 * 60 * 60 * 1000;

export type AgentHealth = "active" | "stale" | "retired";

export function agentHealth(
	agent: { last_seen: string; retired_at?: string | null },
	now: number,
): AgentHealth {
	if (agent.retired_at) return "retired";
	const seen = Date.parse(agent.last_seen);
	if (!Number.isFinite(seen) || now - seen > STALE_AFTER_MS) return "stale";
	return "active";
}

export const AGENT_STATUS_FILTERS = ["all", "active", "stale", "retired"] as const;
export type AgentStatusFilter = (typeof AGENT_STATUS_FILTERS)[number];
export const AGENT_SORTS = ["last_seen_desc", "last_seen_asc", "name"] as const;
export type AgentSort = (typeof AGENT_SORTS)[number];
export const AGENT_PAGE_SIZE = 50;

export type AgentFilters = {
	q: string;
	status: AgentStatusFilter;
	runtime: string;
	sort: AgentSort;
	page: number;
};

function oneOf<T extends string>(value: string | null, allowed: readonly T[], fallback: T): T {
	return value !== null && (allowed as readonly string[]).includes(value) ? (value as T) : fallback;
}

function optional(value: string | null, allowed: readonly string[]): string {
	return value !== null && allowed.includes(value) ? value : "";
}

const RUNTIME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;

export function readAgentFilters(params: URLSearchParams): AgentFilters {
	const runtime = params.get("runtime") ?? "";
	const page = Number(params.get("page") ?? "1");
	return {
		q: (params.get("q") ?? "").slice(0, 128),
		status: oneOf(params.get("status"), AGENT_STATUS_FILTERS, "all"),
		runtime: RUNTIME_PATTERN.test(runtime) ? runtime : "",
		sort: oneOf(params.get("sort"), AGENT_SORTS, "last_seen_desc"),
		page: Number.isSafeInteger(page) && page >= 1 ? page : 1,
	};
}

/** Writes non-default values only, so a plain /agents link stays clean. */
export function writeAgentFilters(filters: AgentFilters): URLSearchParams {
	const params = new URLSearchParams();
	if (filters.q.trim()) params.set("q", filters.q);
	if (filters.status !== "all") params.set("status", filters.status);
	if (filters.runtime) params.set("runtime", filters.runtime);
	if (filters.sort !== "last_seen_desc") params.set("sort", filters.sort);
	if (filters.page > 1) params.set("page", String(filters.page));
	return params;
}

export type FleetAgent = {
	id: string;
	iid: string;
	display_name: string | null;
	agent_runtime: string | null;
	agent_runtime_version: string | null;
	first_seen: string;
	last_seen: string;
	retired_at?: string | null;
	retired_reason?: "manual" | "offline" | null;
};

export function filterAgents<T extends FleetAgent>(
	agents: readonly T[],
	filters: AgentFilters,
	now: number,
): T[] {
	const needle = filters.q.trim().toLowerCase();
	const out = agents.filter((agent) => {
		if (filters.status !== "all" && agentHealth(agent, now) !== filters.status) return false;
		if (filters.runtime && agent.agent_runtime !== filters.runtime) return false;
		if (!needle) return true;
		return [
			agent.display_name,
			agent.iid,
			agent.agent_runtime,
			agent.agent_runtime_version,
			agent.id,
		]
			.filter((value): value is string => typeof value === "string")
			.some((value) => value.toLowerCase().includes(needle));
	});
	const name = (agent: FleetAgent) => (agent.display_name ?? agent.iid).toLowerCase();
	out.sort((a, b) => {
		if (filters.sort === "name") return name(a).localeCompare(name(b));
		const diff = Date.parse(a.last_seen) - Date.parse(b.last_seen);
		return filters.sort === "last_seen_asc" ? diff : -diff;
	});
	return out;
}

export function toCsv(headers: readonly string[], rows: readonly Cell[][]): string {
	return `${[headers, ...rows].map((row) => row.map(csvField).join(",")).join("\r\n")}\r\n`;
}

export function agentsCsv(agents: readonly FleetAgent[], now: number): string {
	return toCsv(
		[
			"id",
			"iid",
			"display_name",
			"runtime",
			"runtime_version",
			"status",
			"first_seen",
			"last_seen",
			"retired_at",
			"retired_reason",
		],
		agents.map((agent) => [
			agent.id,
			agent.iid,
			agent.display_name,
			agent.agent_runtime,
			agent.agent_runtime_version,
			agentHealth(agent, now),
			agent.first_seen,
			agent.last_seen,
			agent.retired_at ?? null,
			agent.retired_reason ?? null,
		]),
	);
}

// ── Event feed ───────────────────────────────────────────────────────────

export const EVENT_RANGES = ["all", "1h", "24h", "7d", "30d"] as const;
export type EventRange = (typeof EVENT_RANGES)[number];
const RANGE_MS: Record<Exclude<EventRange, "all">, number> = {
	"1h": 60 * 60 * 1000,
	"24h": 24 * 60 * 60 * 1000,
	"7d": 7 * 24 * 60 * 60 * 1000,
	"30d": 30 * 24 * 60 * 60 * 1000,
};

/** Mirrors the ingest allowlist (supabase/functions/ingest/events.ts + posture.ts). */
export const EVENT_TYPES = [
	"runtime_verdict",
	"incident",
	"plugin_scan",
	"plugin_scan_finding",
	"runtime_policy_cache",
	"privacy_scan",
	"aup_acknowledgement",
	"shadow_ai_usage",
	"infra_scan_finding",
	"mcp_inventory_finding",
	"agent_posture_finding",
] as const;
export const EVENT_DECISIONS = ["allow", "ask", "deny"] as const;
/** Severities accepted by ingest for runtime verdicts. */
export const EVENT_SEVERITIES = ["info", "warning", "high", "critical"] as const;
/** The server caps one page at this many rows. */
export const EVENT_ROW_LIMIT = 500;

export type EventFilters = {
	range: EventRange;
	type: string;
	decision: string;
	severity: string;
	agent: string;
	rule: string;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function readEventFilters(params: URLSearchParams): EventFilters {
	const agent = params.get("agent") ?? "";
	const rule = (params.get("rule") ?? "").trim();
	return {
		range: oneOf(params.get("range"), EVENT_RANGES, "all"),
		type: optional(params.get("type"), EVENT_TYPES),
		decision: optional(params.get("decision"), EVENT_DECISIONS),
		severity: optional(params.get("severity"), EVENT_SEVERITIES),
		agent: UUID.test(agent) ? agent.toLowerCase() : "",
		rule: RULE_ID.test(rule) ? rule : "",
	};
}

export function writeEventFilters(filters: EventFilters): URLSearchParams {
	const params = new URLSearchParams();
	if (filters.range !== "all") params.set("range", filters.range);
	for (const key of ["type", "decision", "severity", "agent", "rule"] as const) {
		if (filters[key]) params.set(key, filters[key]);
	}
	return params;
}

export function isValidRuleId(value: string): boolean {
	return value === "" || RULE_ID.test(value);
}

export function eventFiltersActive(filters: EventFilters): boolean {
	return writeEventFilters(filters).toString() !== "";
}

/** Lower bound for created_at, or null for "all time". */
export function eventRangeStart(range: EventRange, now: number): string | null {
	return range === "all" ? null : new Date(now - RANGE_MS[range]).toISOString();
}

/**
 * Minimal structural view of the postgrest builder methods the event filters
 * use, so the helper stays testable without the Supabase client.
 */
export type FilterableQuery<Q> = {
	eq(column: string, value: string): Q;
	gte(column: string, value: string): Q;
	or(filters: string): Q;
};

/**
 * Applies validated filters server-side so the 500-row page is the latest 500
 * MATCHING events, not a client-side subset of the latest 500 overall.
 * Runtime verdicts carry `payload.verdict`; Browser Guard events carry
 * `payload.decision`. Decision values come from a fixed allowlist, so the
 * `or()` expression cannot be injected.
 */
export function applyEventFilters<Q extends FilterableQuery<Q>>(
	query: Q,
	filters: EventFilters,
	now: number,
): Q {
	let next = query;
	const since = eventRangeStart(filters.range, now);
	if (since) next = next.gte("created_at", since);
	if (filters.type) next = next.eq("type", filters.type);
	if (filters.agent) next = next.eq("agent_id", filters.agent);
	if ((EVENT_DECISIONS as readonly string[]).includes(filters.decision))
		next = next.or(
			`payload->>verdict.eq.${filters.decision},payload->>decision.eq.${filters.decision}`,
		);
	if ((EVENT_SEVERITIES as readonly string[]).includes(filters.severity))
		next = next.eq("payload->>severity", filters.severity);
	if (filters.rule && RULE_ID.test(filters.rule))
		next = next.eq("payload->>matched_threat_id", filters.rule);
	return next;
}

export type FeedEvent = {
	id: number;
	type: string;
	created_at: string;
	agent_id: string;
	payload: Record<string, unknown>;
};

export function eventDecision(event: FeedEvent): string | null {
	const field =
		event.type === "privacy_scan" || event.type === "shadow_ai_usage" ? "decision" : "verdict";
	const value = event.payload?.[field];
	return typeof value === "string" ? value : null;
}

function text(value: unknown): string | null {
	return typeof value === "string" ? value : null;
}

export function eventsCsv(
	events: readonly FeedEvent[],
	agents: ReadonlyMap<
		string,
		{ display_name: string | null; iid: string; agent_runtime: string | null }
	>,
): string {
	return toCsv(
		[
			"id",
			"created_at",
			"type",
			"decision",
			"severity",
			"tool_name",
			"rule_id",
			"agent_id",
			"agent_name",
			"agent_runtime",
		],
		events.map((event) => {
			const agent = agents.get(event.agent_id);
			return [
				event.id,
				event.created_at,
				event.type,
				eventDecision(event),
				text(event.payload?.severity),
				text(event.payload?.tool_name),
				text(event.payload?.matched_threat_id),
				event.agent_id,
				agent ? (agent.display_name ?? agent.iid) : null,
				agent?.agent_runtime ?? null,
			];
		}),
	);
}

export function saveFile(name: string, content: string, type: string): void {
	const url = URL.createObjectURL(new Blob([content], { type }));
	const anchor = document.createElement("a");
	anchor.href = url;
	anchor.download = name;
	anchor.rel = "noopener";
	document.body.append(anchor);
	anchor.click();
	anchor.remove();
	setTimeout(() => URL.revokeObjectURL(url), 0);
}

/** UTC timestamp safe for file names. */
export function fileStamp(now: number): string {
	return new Date(now).toISOString().replace(/[:.]/g, "-");
}
