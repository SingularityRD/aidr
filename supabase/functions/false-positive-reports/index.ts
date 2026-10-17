// Developer false-positive reports (`aidr report-fp <actionId>`).
//
// Connector / CLI (tenant API key, scope `tenant` only; ingest-only keys refused):
//   POST /false-positive-reports
//        { feedback_id, record_hash, iid, agent_runtime, action_id, rule_id,
//          decision, severity, category, tool, reason_code, rationale,
//          occurred_at }
//        -> 201 { report_id, created }        idempotent on (tenant, feedback_id)
//
// `feedback_id` and `record_hash` come from the client's
// false-positive-feedback record (packages/core/src/false-positive-feedback.ts),
// so the same statement always lands on the same row. The body carries ids, the
// rule, the decision and a bounded, already-redacted note: never the command,
// file content, URL or a secret. Reports are read in the dashboard by tenant
// members (RLS); nothing here changes a policy or suppresses a detection.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { apiKeyRateSubject, authenticateTenantApiKeyBudgeted } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 8192;
const FEEDBACK_ID = /^fpfb_[0-9a-f]{64}$/;
const HASH = /^[0-9a-f]{64}$/;
const ACTION_ID = /^[a-f0-9]{8,128}$/;
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const RUNTIME = /^[a-z0-9][a-z0-9_.-]{0,31}$/;
const CATEGORY = /^[a-z0-9][a-z0-9_.-]{0,63}$/;
const CONTROL = /\p{Cc}/u;
const INVISIBLE = /[\p{Cf}\p{Zl}\p{Zp}]/u;
const SEVERITIES = new Set(["info", "warning", "critical", "high", "medium", "low"]);
export const FALSE_POSITIVE_REASON_CODES = new Set([
	"benign_automation",
	"benign_maintenance",
	"expected_egress",
	"expected_file_write",
	"legitimate_mcp_tool",
	"developer_test",
	"environment_specific",
	"insufficient_context",
	"policy_too_strict",
	"other",
]);
const BODY_KEYS = [
	"feedback_id", "record_hash", "iid", "agent_runtime", "action_id", "rule_id", "decision",
	"severity", "category", "tool", "reason_code", "rationale", "occurred_at",
];
export const RATIONALE_MAX = 1000;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

// deno-lint-ignore no-explicit-any
type DatabaseClient = ReturnType<typeof createClient<any, "public">>;

export interface FalsePositiveReportsDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

export interface FalsePositiveReport {
	feedbackId: string;
	recordHash: string;
	iid: string;
	agentRuntime: string | null;
	actionId: string;
	ruleId: string | null;
	decision: "deny" | "ask";
	severity: string | null;
	category: string | null;
	tool: string | null;
	reasonCode: string;
	rationale: string;
	occurredAt: string | null;
}

type ParseResult<T> = { ok: true; value: T } | { ok: false; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown, max: number, min = 1): string | null {
	if (typeof value !== "string" || CONTROL.test(value) || INVISIBLE.test(value)) return null;
	return value.length >= min && value.length <= max ? value : null;
}

function optional(value: unknown, pattern: RegExp): string | null | false {
	if (value === undefined || value === null) return null;
	return typeof value === "string" && pattern.test(value) ? value : false;
}

/** Strict body schema: unknown keys, bad ids and free text with control characters are refused. */
export function parseReportBody(value: unknown, nowMs: number): ParseResult<FalsePositiveReport> {
	if (!isRecord(value) || !Object.keys(value).every((key) => BODY_KEYS.includes(key))) {
		return { ok: false, error: "invalid_request" };
	}
	const feedbackId = typeof value.feedback_id === "string" && FEEDBACK_ID.test(value.feedback_id)
		? value.feedback_id
		: null;
	const recordHash = typeof value.record_hash === "string" && HASH.test(value.record_hash) ? value.record_hash : null;
	const iid = text(value.iid, 128);
	const actionId = typeof value.action_id === "string" && ACTION_ID.test(value.action_id) ? value.action_id : null;
	const decision = value.decision === "deny" || value.decision === "ask" ? value.decision : null;
	const reasonCode = typeof value.reason_code === "string" && FALSE_POSITIVE_REASON_CODES.has(value.reason_code)
		? value.reason_code
		: null;
	const rationale = value.rationale === undefined ? "" : text(value.rationale, RATIONALE_MAX, 0);
	if (!feedbackId || !recordHash || !iid || !actionId || !decision || !reasonCode || rationale === null) {
		return { ok: false, error: "invalid_request" };
	}
	const agentRuntime = optional(value.agent_runtime, RUNTIME);
	const ruleId = optional(value.rule_id, RULE_ID);
	const category = optional(value.category, CATEGORY);
	const severity = value.severity === undefined || value.severity === null
		? null
		: typeof value.severity === "string" && SEVERITIES.has(value.severity)
			? value.severity
			: false;
	const tool = value.tool === undefined || value.tool === null ? null : text(value.tool, 64) ?? false;
	if (agentRuntime === false || ruleId === false || category === false || severity === false || tool === false) {
		return { ok: false, error: "invalid_request" };
	}
	let occurredAt: string | null = null;
	if (value.occurred_at !== undefined && value.occurred_at !== null) {
		const ms = typeof value.occurred_at === "string" ? Date.parse(value.occurred_at) : Number.NaN;
		// A report about the future, or older than a year, is not a report of a block.
		if (!Number.isFinite(ms) || ms > nowMs + 5 * 60_000 || ms < nowMs - 366 * 86_400_000) {
			return { ok: false, error: "invalid_occurred_at" };
		}
		occurredAt = new Date(ms).toISOString();
	}
	return {
		ok: true,
		value: {
			feedbackId,
			recordHash,
			iid,
			agentRuntime,
			actionId,
			ruleId,
			decision,
			severity,
			category,
			tool,
			reasonCode,
			rationale,
			occurredAt,
		},
	};
}

async function handleCreate(req: Request, db: DatabaseClient, token: string, value: unknown, nowMs: number) {
	const body = parseReportBody(value, nowMs);
	if (!body.ok) return corsJson(req, 400, { error: body.error });
	const auth = await authenticateTenantApiKeyBudgeted(db, token, "false-positive-reports", nowMs);
	if (!auth.ok) return corsJson(req, auth.status, { error: auth.error });
	const rate = await consumeTenantRateLimit(db, {
		tenantId: auth.tenantId,
		subject: auth.apiKeyId ?? apiKeyRateSubject(auth),
		endpoint: "false-positive-reports:create",
		perSubject: 60,
		perTenant: 2000,
		now: nowMs,
	});
	if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
	const report = body.value;
	const row = {
		tenant_id: auth.tenantId,
		feedback_id: report.feedbackId,
		record_hash: report.recordHash,
		iid: report.iid,
		api_key_id: auth.apiKeyId ?? null,
		agent_runtime: report.agentRuntime,
		action_id: report.actionId,
		rule_id: report.ruleId,
		decision: report.decision,
		severity: report.severity,
		category: report.category,
		tool: report.tool,
		reason_code: report.reasonCode,
		rationale: report.rationale,
		occurred_at: report.occurredAt,
	};
	const inserted = await db
		.from("false_positive_reports")
		.upsert(row, { onConflict: "tenant_id,feedback_id", ignoreDuplicates: true })
		.select("id");
	if (inserted.error) {
		return corsJson(req, 503, { error: "false_positive_report_unavailable" }, rateLimitHeaders(rate));
	}
	const created = Array.isArray(inserted.data) && inserted.data.length > 0;
	let reportId = created ? (inserted.data[0] as { id?: unknown }).id : undefined;
	if (!created) {
		const existing = await db
			.from("false_positive_reports")
			.select("id")
			.eq("tenant_id", auth.tenantId)
			.eq("feedback_id", report.feedbackId)
			.maybeSingle();
		if (existing.error || !existing.data) {
			return corsJson(req, 503, { error: "false_positive_report_unavailable" }, rateLimitHeaders(rate));
		}
		reportId = (existing.data as { id?: unknown }).id;
	}
	if (typeof reportId !== "string") {
		return corsJson(req, 503, { error: "false_positive_report_unavailable" }, rateLimitHeaders(rate));
	}
	return corsJson(req, created ? 201 : 200, { report_id: reportId, created }, rateLimitHeaders(rate));
}

export function createFalsePositiveReportsHandler(deps: FalsePositiveReportsDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("false-positive-reports", config.error, (status, body) => corsJson(req, status, body));
		}
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_api_key" });
		try {
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			return await handleCreate(req, db, token, parsed.value, now());
		} catch {
			return corsJson(req, 503, { error: "false_positive_report_unavailable" });
		}
	};
}

const falsePositiveReports = createFalsePositiveReportsHandler();
Deno.serve(falsePositiveReports);
