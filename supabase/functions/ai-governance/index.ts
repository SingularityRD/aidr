// AI governance: asset register, intake, exceptions, periodic review,
// four-eyes policy change control and the tenant's Browser Guard settings
// delivered in the signed browser-guard-policy document (docs/ai-governance.md).
//
// POST /ai-governance { action, tenant_id, ... }   Supabase session only.
//
// Every request: session -> identity barrier (tenant MFA/SSO policy, global
// revocation) -> live membership and active tenant -> per-action role ->
// AAL2 for every decision and register change -> tenant rate limit -> one
// service-role RPC that re-checks role and state under row locks and writes
// the audit rows in the same transaction. Nothing here is callable by an
// agent: there is no API-key path, and approval decisions are always made by
// a person other than the requester (enforced again by check constraints).
//
// Every failure is closed: an unreadable session, policy, membership,
// assurance level, rate-limit counter or RPC result refuses the request.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import {
	AI_GOVERNANCE_MAX_BODY_BYTES,
	GOVERNANCE_ACTIONS,
	GOVERNANCE_RATE_LIMITS,
	type GovernanceCommand,
	type GovernanceRole,
	governanceErrorCode,
	governanceRpcStatus,
	isRecord,
	parseGovernanceRequest,
} from "../_shared/ai-governance.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const CHANGE_REQUEST_COLUMNS =
	"id,tenant_id,change_kind,base_version,expected_revision_version,target_version,payload,payload_sha256,summary,status,requested_by,created_at,expires_at,decided_by,decided_at,decision_reason,closed_at,applied_version,outcome_code";

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

// Untyped schema: every result is validated at runtime before use.
type DatabaseClient = SupabaseClient;
type RpcError = { code?: string; message?: string } | null;

export interface AiGovernanceDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

function rpcFailure(req: Request, error: RpcError, headers: Record<string, string>): Response {
	const status = governanceRpcStatus(error?.code);
	const code = governanceErrorCode(error?.message);
	const fallback = status === 403 ? "governance_forbidden"
		: status === 404 ? "not_found"
		: status === 409 ? "governance_conflict"
		: status === 400 ? "invalid_request"
		: status === 429 ? "governance_quota"
		: "governance_unavailable";
	return corsJson(req, status, { error: status === 503 ? fallback : code ?? fallback }, headers);
}

/** Map a decide RPC's non-applied outcome to a conflict response. */
function decisionOutcome(req: Request, data: Record<string, unknown>, headers: Record<string, string>): Response | null {
	switch (data.outcome) {
		case "already_final":
			return corsJson(req, 409, { error: "request_final", status: data.status }, headers);
		case "expired":
			return corsJson(req, 409, { error: "request_expired", status: "expired" }, headers);
		case "not_active":
			return corsJson(req, 409, { error: "exception_not_active", status: data.status }, headers);
		case "superseded":
			return corsJson(req, 409, {
				error: "policy_change_superseded",
				status: "superseded",
				outcome_code: data.outcome_code ?? null,
			}, headers);
		case "failed":
			return corsJson(req, 409, {
				error: "policy_change_failed",
				status: "failed",
				outcome_code: data.outcome_code ?? null,
			}, headers);
		default:
			return null;
	}
}

function stringList(value: unknown): string[] | null {
	return Array.isArray(value) && value.length <= 1000 && value.every((item) => typeof item === "string")
		? (value as string[])
		: null;
}

async function enforcementPreview(req: Request, db: DatabaseClient, tenantId: string, headers: Record<string, string>) {
	const [overlay, published] = await Promise.all([
		db.rpc("ai_governance_policy_overlay", { p_tenant_id: tenantId, p_user_id: null, p_agent_id: null }),
		db.from("tenant_runtime_policies").select("version").eq("tenant_id", tenantId).maybeSingle(),
	]);
	if (overlay.error || published.error || !isRecord(overlay.data)) {
		return corsJson(req, 503, { error: "governance_unavailable" }, headers);
	}
	const deny = stringList(overlay.data.mcp_deny_servers);
	const approval = stringList(overlay.data.mcp_require_approval_servers);
	const sites = stringList(overlay.data.browser_guard_blocked_sites);
	if (!deny || !approval || !sites) return corsJson(req, 503, { error: "governance_unavailable" }, headers);
	const version = (published.data as { version?: unknown } | null)?.version;
	return corsJson(req, 200, {
		ok: true,
		connector_overlay: { mcp_deny_servers: deny, mcp_require_approval_servers: approval },
		browser_guard_managed_policy: { blockedSites: sites },
		runtime_policy_version: Number.isSafeInteger(version) ? version : 0,
	}, headers);
}

async function policyChangeDetail(
	req: Request,
	db: DatabaseClient,
	tenantId: string,
	requestId: string,
	headers: Record<string, string>,
) {
	const { data, error } = await db.from("policy_change_requests").select(CHANGE_REQUEST_COLUMNS)
		.eq("id", requestId).eq("tenant_id", tenantId).maybeSingle();
	if (error) return corsJson(req, 503, { error: "governance_unavailable" }, headers);
	if (!isRecord(data) || data.tenant_id !== tenantId) return corsJson(req, 404, { error: "not_found" }, headers);
	const kind = String(data.change_kind);
	let current: { version: number; policy: unknown } | null = null;
	if (kind !== "disable_four_eyes") {
		const table = kind === "dlp_publish" ? "tenant_dlp_policies"
			: kind === "agent_profiles_stage" ? "tenant_agent_profiles" : "tenant_runtime_policies";
		const read = await db.from(table).select("version,policy").eq("tenant_id", tenantId).maybeSingle();
		if (read.error) return corsJson(req, 503, { error: "governance_unavailable" }, headers);
		const row = read.data as { version?: unknown; policy?: unknown } | null;
		current = row && Number.isSafeInteger(row.version)
			? { version: row.version as number, policy: row.policy ?? null }
			: { version: 0, policy: null };
	}
	const payload = isRecord(data.payload) ? data.payload : {};
	const { payload: _payload, ...request } = data;
	return corsJson(req, 200, {
		ok: true,
		request,
		proposed: {
			policy: payload.policy ?? null,
			...(Array.isArray(payload.agent_ids) ? { agent_ids: payload.agent_ids } : {}),
			...(Array.isArray(payload.rings) ? { rings: payload.rings } : {}),
			...(isRecord(payload.expected_document) ? { expected_document: payload.expected_document } : {}),
			...(Number.isSafeInteger(payload.restored_from) ? { restored_from: payload.restored_from } : {}),
		},
		current,
	}, headers);
}

function rpcFor(command: GovernanceCommand, tenantId: string, userId: string): { name: string; args: Record<string, unknown> } | null {
	switch (command.action) {
		case "upsert_asset":
			return { name: "upsert_ai_asset", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_asset_id: command.assetId,
				p_expected_version: command.expectedVersion, p_fields: command.fields,
			} };
		case "import_candidates":
			return { name: "import_ai_asset_candidates", args: { p_tenant_id: tenantId, p_actor_user_id: userId, p_limit: 200 } };
		case "link_evidence":
			return { name: "link_ai_asset_evidence", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_asset_id: command.assetId,
				p_kind: command.kind, p_ref: command.ref, p_link: command.link,
			} };
		case "review_asset":
			return { name: "review_ai_asset", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_asset_id: command.assetId,
				p_next_review_due: command.nextReviewDue,
			} };
		case "set_reviewer":
			return { name: "set_ai_governance_reviewer", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_user_id: command.userId, p_designated: command.designated,
			} };
		case "submit_intake":
			return { name: "submit_ai_intake_request", args: { p_tenant_id: tenantId, p_actor_user_id: userId, p_fields: command.fields } };
		case "decide_intake":
			return { name: "decide_ai_intake_request", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_request_id: command.requestId,
				p_decision: command.decision, p_reason: command.reason,
			} };
		case "request_exception":
			return { name: "request_ai_governance_exception", args: { p_tenant_id: tenantId, p_actor_user_id: userId, p_fields: command.fields } };
		case "decide_exception":
			return { name: "decide_ai_governance_exception", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_exception_id: command.exceptionId,
				p_decision: command.decision, p_reason: command.reason,
			} };
		case "revoke_exception":
			return { name: "revoke_ai_governance_exception", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_exception_id: command.exceptionId, p_reason: command.reason,
			} };
		case "cancel_request":
			return { name: "cancel_ai_governance_request", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_kind: command.kind, p_request_id: command.requestId,
			} };
		case "update_settings":
			return { name: "update_ai_governance_settings", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_policy_four_eyes: command.policyFourEyes,
				p_default_review_days: command.defaultReviewDays,
			} };
		case "update_browser_guard_settings":
			return { name: "update_browser_guard_settings", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_require_native_ner: command.requireNativeNer,
			} };
		case "update_approval_settings":
			return { name: "update_approval_settings", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_require_distinct_approver: command.requireDistinctApprover,
			} };
		case "decide_policy_change":
			return { name: "decide_policy_change_request", args: {
				p_tenant_id: tenantId, p_actor_user_id: userId, p_request_id: command.requestId,
				p_decision: command.decision, p_reason: command.reason,
			} };
		default:
			return null;
	}
}

export function createAiGovernanceHandler(deps: AiGovernanceDeps = {}) {
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
			return configFailure("ai-governance", config.error, (status, body) => corsJson(req, status, body));
		}
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const parsed = await readBoundedJson(req, AI_GOVERNANCE_MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const request = parseGovernanceRequest(parsed.value);
		if (!request.ok) return corsJson(req, 400, { error: request.error });
		const { tenantId, command } = request;
		const rule = GOVERNANCE_ACTIONS[command.action];

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

			const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
				db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle(),
				db.from("tenants").select("id,status").eq("id", tenantId).maybeSingle(),
			]);
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "") as GovernanceRole;
			if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) ||
				!["owner", "admin", "member", "viewer"].includes(role) || !tenant) {
				return corsJson(req, 403, { error: "workspace_forbidden" });
			}
			if ((tenant as { status?: unknown }).status !== "active") {
				return corsJson(req, 409, { error: "workspace_not_active" });
			}
			if (!rule.roles.includes(role)) return corsJson(req, 403, { error: "governance_role_insufficient" });
			if (rule.aal2) {
				const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
				if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
				if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });
			}

			const limits = GOVERNANCE_RATE_LIMITS[rule.bucket];
			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: `ai-governance:${rule.bucket}`,
				...limits,
				now: now(),
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			const headers = rateLimitHeaders(rate);

			if (command.action === "enforcement_preview") return await enforcementPreview(req, db, tenantId, headers);
			if (command.action === "policy_change_detail") {
				return await policyChangeDetail(req, db, tenantId, command.requestId, headers);
			}
			const call = rpcFor(command, tenantId, userId);
			if (!call) return corsJson(req, 400, { error: "invalid_action" }, headers);
			const { data, error } = await db.rpc(call.name, call.args);
			if (error) return rpcFailure(req, error as RpcError, headers);
			if (!isRecord(data)) return corsJson(req, 503, { error: "governance_unavailable" }, headers);
			const outcome = decisionOutcome(req, data, headers);
			if (outcome) return outcome;
			return corsJson(req, 200, { ok: true, ...data }, headers);
		} catch {
			return corsJson(req, 503, { error: "governance_unavailable" });
		}
	};
}

const aiGovernance = createAiGovernanceHandler();
Deno.serve(aiGovernance);
