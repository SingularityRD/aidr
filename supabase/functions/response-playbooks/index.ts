import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import {
	configFailure,
	loadConfig,
	type EnvReader,
} from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import {
	consumeTenantRateLimit,
	rateLimitHeaders,
	readBoundedJson,
} from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import { jwtIssuedAtMs } from "../identity-security/logic.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_REQUEST_BODY_BYTES = 4096;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const PLAYBOOK_ID = "agent_containment_v1" as const;
const AUTOMATION_SECRET = /^aidr_rsp_[a-f0-9]{64}$/;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type ReadTable<Row extends Record<string, unknown>> = { Row: Row; Insert: never; Update: never; Relationships: [] };
type StartArgs = {
	p_tenant_id: string; p_actor_user_id: string; p_agent_id: string; p_incident_id: string;
	p_playbook_id: string; p_reason: string; p_idempotency_key: string; p_ttl_seconds: number;
};
type ResponsePlaybooksDatabase = {
	public: {
		Tables: {
			tenant_members: ReadTable<{ tenant_id: string; user_id: string; role: string; expires_at: string | null }>;
			tenants: ReadTable<{ id: string; status: string }>;
		};
		Views: Record<string, never>;
		Functions: {
			start_fleet_response_playbook: { Args: StartArgs; Returns: Record<string, unknown> };
			trigger_fleet_response_playbook: { Args: StartArgs & { p_trigger_source: "alarm" | "soar" }; Returns: Record<string, unknown> };
			get_fleet_response_playbook: { Args: { p_tenant_id: string; p_run_id: string }; Returns: Record<string, unknown> | null };
			create_response_automation_grant: { Args: {
				p_tenant_id: string; p_actor_user_id: string; p_agent_id: string; p_source: "alarm" | "soar";
				p_reason: string; p_max_ttl_seconds: number; p_grant_expires_in_seconds: number;
				p_secret_hash: string; p_validated_session_issued_at: string;
			}; Returns: Record<string, unknown> };
			revoke_response_automation_grant: { Args: {
				p_tenant_id: string; p_actor_user_id: string; p_grant_id: string; p_reason: string; p_validated_session_issued_at: string;
			}; Returns: Record<string, unknown> };
			trigger_response_automation_playbook: { Args: {
				p_tenant_id: string; p_grant_id: string; p_secret_hash: string; p_incident_id: string;
				p_reason: string; p_ttl_seconds: number;
			}; Returns: Record<string, unknown> };
		};
		Enums: Record<string, never>;
		CompositeTypes: Record<string, never>;
	};
};
type DatabaseClient = SupabaseClient<ResponsePlaybooksDatabase>;

export interface ResponsePlaybooksDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

type StartRequest = {
	action: "start";
	tenantId: string;
	agentId: string;
	// Operator-supplied reference only; this API has no AIDR incident record to validate it against.
	incidentReference: string;
	playbookId: typeof PLAYBOOK_ID;
	reason: string;
	idempotencyKey: string;
	ttlSeconds: number;
};

type StatusRequest = { action: "status"; tenantId: string; runId: string };
type TriggerRequest = Omit<StartRequest, "action"> & { action: "trigger"; triggerSource: "alarm" | "soar" };
type GrantRequest = {
	action: "grant_automation"; tenantId: string; agentId: string; triggerSource: "alarm" | "soar";
	reason: string; maxTtlSeconds: number; grantExpiresInSeconds: number;
};
type RevokeRequest = { action: "revoke_automation"; tenantId: string; grantId: string; reason: string };
type AutomationRequest = {
	action: "trigger_automation"; tenantId: string; grantId: string;
	incidentReference: string; reason: string; ttlSeconds: number;
};
type PlaybookRequest = StartRequest | TriggerRequest | StatusRequest | GrantRequest | RevokeRequest | AutomationRequest;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isUuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value);
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(value, key)) &&
		Object.keys(value).every((key) => allowed.has(key));
}

export function parsePlaybookRequest(value: unknown):
	| { ok: true; request: PlaybookRequest }
	| { ok: false; error: string } {
	if (!isRecord(value) || typeof value.action !== "string") {
		return { ok: false, error: "invalid_request" };
	}
	if (["grant_automation", "revoke_automation", "trigger_automation"].includes(value.action)) {
		const required = value.action === "grant_automation"
			? ["action", "tenant_id", "agent_id", "playbook_id", "trigger_source", "reason"]
			: ["action", "tenant_id", "grant_id", "reason", ...(value.action === "trigger_automation" ? ["incident_reference"] : [])];
		const optional = value.action === "grant_automation" ? ["max_ttl_seconds", "grant_expires_in_seconds"]
			: value.action === "trigger_automation" ? ["ttl_seconds"] : [];
		if (!exactKeys(value, required, optional) || !isUuid(value.tenant_id)) return { ok: false, error: "invalid_request" };
		if (typeof value.reason !== "string" || value.reason.trim().length < 12 || value.reason.trim().length > 500 ||
			/[\u0000-\u001f\u007f]/.test(value.reason)) return { ok: false, error: "invalid_reason" };
		const reason = value.reason.trim();
		if (value.action === "grant_automation") {
			if (!isUuid(value.agent_id)) return { ok: false, error: "invalid_request" };
			if (value.playbook_id !== PLAYBOOK_ID) return { ok: false, error: "unsupported_playbook" };
			if (value.trigger_source !== "alarm" && value.trigger_source !== "soar") return { ok: false, error: "invalid_trigger_source" };
			const maxTtlSeconds = value.max_ttl_seconds === undefined ? 300 : value.max_ttl_seconds;
			const grantExpiresInSeconds = value.grant_expires_in_seconds === undefined ? 86400 : value.grant_expires_in_seconds;
			if (typeof maxTtlSeconds !== "number" || !Number.isSafeInteger(maxTtlSeconds) || maxTtlSeconds < 30 || maxTtlSeconds > 900) {
				return { ok: false, error: "invalid_max_ttl_seconds" };
			}
			if (typeof grantExpiresInSeconds !== "number" || !Number.isSafeInteger(grantExpiresInSeconds) ||
				grantExpiresInSeconds < 60 || grantExpiresInSeconds > 7776000) return { ok: false, error: "invalid_grant_expiry" };
			return { ok: true, request: { action: "grant_automation", tenantId: value.tenant_id.toLowerCase(), agentId: value.agent_id.toLowerCase(),
				triggerSource: value.trigger_source, reason, maxTtlSeconds, grantExpiresInSeconds } };
		}
		if (!isUuid(value.grant_id)) return { ok: false, error: "invalid_request" };
		if (value.action === "revoke_automation") return { ok: true, request: {
			action: "revoke_automation", tenantId: value.tenant_id.toLowerCase(), grantId: value.grant_id.toLowerCase(), reason,
		} };
		if (!isUuid(value.incident_reference)) return { ok: false, error: "invalid_request" };
		const ttlSeconds = value.ttl_seconds === undefined ? 300 : value.ttl_seconds;
		if (typeof ttlSeconds !== "number" || !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 900) {
			return { ok: false, error: "invalid_ttl_seconds" };
		}
		return { ok: true, request: { action: "trigger_automation", tenantId: value.tenant_id.toLowerCase(), grantId: value.grant_id.toLowerCase(),
			incidentReference: value.incident_reference.toLowerCase(), reason, ttlSeconds } };
	}
	if (value.action === "start" || value.action === "trigger") {
		if (!exactKeys(value, [
			"action", "tenant_id", "agent_id", "incident_reference", "playbook_id", "reason", "idempotency_key",
			...(value.action === "trigger" ? ["trigger_source"] : []),
		], ["ttl_seconds"])) return { ok: false, error: "invalid_request" };
		if (!isUuid(value.tenant_id) || !isUuid(value.agent_id) || !isUuid(value.incident_reference)) {
			return { ok: false, error: "invalid_request" };
		}
		if (value.playbook_id !== PLAYBOOK_ID) return { ok: false, error: "unsupported_playbook" };
		if (typeof value.reason !== "string" || value.reason.trim().length < 12 || value.reason.trim().length > 500) {
			return { ok: false, error: "invalid_reason" };
		}
		if (typeof value.idempotency_key !== "string" || !IDEMPOTENCY_KEY.test(value.idempotency_key)) {
			return { ok: false, error: "invalid_idempotency_key" };
		}
		const ttlSeconds = value.ttl_seconds === undefined ? 300 : value.ttl_seconds;
		if (typeof ttlSeconds !== "number" || !Number.isSafeInteger(ttlSeconds) || ttlSeconds < 30 || ttlSeconds > 3600) {
			return { ok: false, error: "invalid_ttl_seconds" };
		}
		const request: StartRequest = {
			action: "start",
			tenantId: value.tenant_id,
			agentId: value.agent_id,
			incidentReference: value.incident_reference,
			playbookId: PLAYBOOK_ID,
			reason: value.reason.trim(),
			idempotencyKey: value.idempotency_key,
			ttlSeconds: Number(ttlSeconds),
		};
		if (value.action === "start") return { ok: true, request };
		if (value.trigger_source !== "alarm" && value.trigger_source !== "soar") {
			return { ok: false, error: "invalid_trigger_source" };
		}
		return { ok: true, request: { ...request, action: "trigger", triggerSource: value.trigger_source } };
	}
	if (value.action === "status") {
		if (!exactKeys(value, ["action", "tenant_id", "run_id"]) ||
			!isUuid(value.tenant_id) || !isUuid(value.run_id)) {
			return { ok: false, error: "invalid_request" };
		}
		return { ok: true, request: { action: "status", tenantId: value.tenant_id, runId: value.run_id } };
	}
	return { ok: false, error: "invalid_action" };
}

function bearerToken(req: Request): string | null {
	const match = (req.headers.get("Authorization") ?? "").match(/^Bearer\s+(.+)$/i);
	return match?.[1]?.trim() || null;
}

async function secretHash(secret: string): Promise<string> {
	const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(secret));
	return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function grantMetadata(data: unknown, tenantId: string): Record<string, unknown> | null {
	if (!isRecord(data) || !isUuid(data.grant_id) || data.tenant_id !== tenantId || !isUuid(data.agent_id) ||
		!isUuid(data.created_by) || data.playbook_id !== PLAYBOOK_ID ||
		(data.trigger_source !== "alarm" && data.trigger_source !== "soar") ||
		!Number.isSafeInteger(data.max_ttl_seconds) || Number(data.max_ttl_seconds) < 30 || Number(data.max_ttl_seconds) > 900 ||
		typeof data.created_at !== "string" || typeof data.expires_at !== "string" ||
		(data.revoked_at !== null && typeof data.revoked_at !== "string")) return null;
	return Object.fromEntries(["grant_id", "tenant_id", "agent_id", "playbook_id", "trigger_source", "created_by",
		"max_ttl_seconds", "created_at", "expires_at", "revoked_at"].map((key) => [key, data[key]]));
}

function automationRun(data: unknown, request: AutomationRequest): Record<string, unknown> | null {
	if (!isRecord(data) || !isUuid(data.id) || data.tenant_id !== request.tenantId ||
		data.incident_reference !== request.incidentReference || !isUuid(data.agent_id) || !isUuid(data.actor_user_id) ||
		data.playbook_id !== PLAYBOOK_ID || typeof data.state !== "string" || !Array.isArray(data.steps) || data.steps.length > 2) return null;
	const result = Object.fromEntries(["id", "tenant_id", "actor_user_id", "agent_id", "incident_reference", "playbook_id",
		"reason", "state", "current_step", "expires_at", "result_code", "created_at", "completed_at"].map((key) => [key, data[key]]));
	const steps = data.steps.map((step) => isRecord(step) ? Object.fromEntries([
		"step_id", "ordinal", "command_type", "command_id", "state", "result_code", "expires_at",
	].map((key) => [key, step[key]])) : null);
	return steps.includes(null) ? null : { ...result, steps };
}

async function authorizeOperator(
	db: DatabaseClient,
	token: string,
	tenantId: string,
	now: number,
): Promise<{ ok: true; userId: string } | { ok: false; status: number; error: string }> {
	const { data: auth, error: authError } = await db.auth.getUser(token);
	if (authError || !auth.user?.id) return { ok: false, status: 401, error: "invalid_access_token" };
	const userId = auth.user.id;
	const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
	if (!barrier.ok) return { ok: false, status: barrier.status, error: barrier.error };

	const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
		db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId)
			.eq("user_id", userId).maybeSingle(),
		db.from("tenants").select("status").eq("id", tenantId).maybeSingle(),
	]);
	if (memberError || tenantError) return { ok: false, status: 503, error: "authorization_unavailable" };
	if (!membershipActive(member, now) || tenant?.status !== "active" ||
		!(["owner", "admin"] as string[]).includes(String(member?.role ?? ""))) {
		return { ok: false, status: 403, error: "response_playbook_operator_forbidden" };
	}
	const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
	if (assuranceError || !assurance) return { ok: false, status: 503, error: "assurance_unavailable" };
	if (assurance.currentLevel !== "aal2") return { ok: false, status: 403, error: "mfa_required_for_response_playbook" };
	return { ok: true, userId };
}

function rpcFailure(req: Request, error: { code?: string } | null): Response {
	if (error?.code === "42501") return corsJson(req, 403, { error: "response_playbook_operator_forbidden" });
	if (error?.code === "22023") return corsJson(req, 400, { error: "invalid_response_playbook" });
	if (error?.code === "PT409" || error?.code === "23505") {
		return corsJson(req, 409, { error: "response_playbook_conflict" });
	}
	return corsJson(req, 503, { error: "response_playbook_unavailable" });
}

export function createResponsePlaybooksHandler(deps: ResponsePlaybooksDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient<ResponsePlaybooksDatabase>(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("response-playbooks", config.error, (status, body) => corsJson(req, status, body));
		}

		const parsed = await readBoundedJson(req, MAX_REQUEST_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const request = parsePlaybookRequest(parsed.value);
		if (!request.ok) return corsJson(req, 400, { error: request.error });
		const tenantHeader = req.headers.get("X-AIDR-Tenant-ID");
		if (tenantHeader !== null) {
			const header = tenantHeader.trim();
			if (!isUuid(header)) return corsJson(req, 400, { error: "invalid_tenant" });
			if (header.toLowerCase() !== request.request.tenantId.toLowerCase()) {
				return corsJson(req, 403, { error: "tenant_mismatch" });
			}
		}
		const token = bearerToken(req);
		if (!token && request.request.action !== "trigger_automation") return corsJson(req, 401, { error: "missing_access_token" });

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			if (request.request.action === "trigger_automation") {
				// The tenant bucket also bounds random grant IDs and invalid secrets before any grant lookup.
				const rate = await consumeTenantRateLimit(db, { tenantId: request.request.tenantId, subject: request.request.grantId,
					endpoint: "response-playbooks", perSubject: 30, perTenant: 600 });
				if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
				if (!token || !AUTOMATION_SECRET.test(token)) return corsJson(req, 403, { error: "automation_forbidden" });
				const { data, error } = await db.rpc("trigger_response_automation_playbook", {
					p_tenant_id: request.request.tenantId, p_grant_id: request.request.grantId, p_secret_hash: await secretHash(token),
					p_incident_id: request.request.incidentReference, p_reason: request.request.reason, p_ttl_seconds: request.request.ttlSeconds,
				});
				if (error) {
					const conflict = error.code === "PT409" || error.code === "23505";
					return corsJson(req, error.code === "42501" ? 403 : conflict ? 409 : 503, {
						error: error.code === "42501" ? "automation_forbidden" : conflict ? "automation_conflict" : "response_playbook_unavailable",
					});
				}
				const run = automationRun(data, request.request);
				if (!run) return corsJson(req, 503, { error: "response_playbook_unavailable" });
				return corsJson(req, 200, { ok: true, run }, { ...rateLimitHeaders(rate), "Cache-Control": "no-store" });
			}
			const identity = await authorizeOperator(db, token!, request.request.tenantId, now());
			if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
			const rate = await consumeTenantRateLimit(db, {
				tenantId: request.request.tenantId,
				subject: identity.userId,
				endpoint: "response-playbooks",
				perSubject: 30,
				perTenant: 600,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			let validatedSessionIssuedAt: string | null = null;
			if (request.request.action === "grant_automation" || request.request.action === "revoke_automation") {
				// Claims are read only after getUser has authenticated this exact JWT.
				const issuedAt = jwtIssuedAtMs(token!);
				if (issuedAt === null || !Number.isSafeInteger(issuedAt) || issuedAt % 1000 !== 0 ||
					issuedAt > now() + 60_000 || !Number.isFinite(new Date(issuedAt).getTime())) {
					return corsJson(req, 401, { error: "invalid_access_token" });
				}
				validatedSessionIssuedAt = new Date(issuedAt).toISOString();
			}
			if (request.request.action === "grant_automation") {
				const secret = "aidr_rsp_" + Array.from(crypto.getRandomValues(new Uint8Array(32)), (byte) => byte.toString(16).padStart(2, "0")).join("");
				const { data, error } = await db.rpc("create_response_automation_grant", {
					p_tenant_id: request.request.tenantId, p_actor_user_id: identity.userId, p_agent_id: request.request.agentId,
					p_source: request.request.triggerSource, p_reason: request.request.reason, p_max_ttl_seconds: request.request.maxTtlSeconds,
					p_grant_expires_in_seconds: request.request.grantExpiresInSeconds, p_secret_hash: await secretHash(secret),
					p_validated_session_issued_at: validatedSessionIssuedAt!,
				});
				if (error) return rpcFailure(req, error);
				const grant = grantMetadata(data, request.request.tenantId);
				if (!grant || grant.agent_id !== request.request.agentId || grant.created_by !== identity.userId ||
					grant.trigger_source !== request.request.triggerSource || grant.max_ttl_seconds !== request.request.maxTtlSeconds || grant.revoked_at !== null) {
					return corsJson(req, 503, { error: "response_playbook_unavailable" });
				}
				return corsJson(req, 200, { ok: true, grant, automation_secret: secret }, { ...rateLimitHeaders(rate), "Cache-Control": "no-store" });
			}
			if (request.request.action === "revoke_automation") {
				const { data, error } = await db.rpc("revoke_response_automation_grant", {
					p_tenant_id: request.request.tenantId, p_actor_user_id: identity.userId,
					p_grant_id: request.request.grantId, p_reason: request.request.reason,
					p_validated_session_issued_at: validatedSessionIssuedAt!,
				});
				if (error) return rpcFailure(req, error);
				const grant = grantMetadata(data, request.request.tenantId);
				if (!grant || grant.grant_id !== request.request.grantId || grant.revoked_at === null) {
					return corsJson(req, 503, { error: "response_playbook_unavailable" });
				}
				return corsJson(req, 200, { ok: true, grant }, { ...rateLimitHeaders(rate), "Cache-Control": "no-store" });
			}

			if (request.request.action === "start" || request.request.action === "trigger") {
				const args = {
					p_tenant_id: request.request.tenantId,
					p_actor_user_id: identity.userId,
					p_agent_id: request.request.agentId,
					p_incident_id: request.request.incidentReference,
					p_playbook_id: request.request.playbookId,
					p_reason: request.request.reason,
					p_idempotency_key: request.request.idempotencyKey,
					p_ttl_seconds: request.request.ttlSeconds,
				};
				const { data, error } = request.request.action === "trigger"
					? await db.rpc("trigger_fleet_response_playbook", { ...args, p_trigger_source: request.request.triggerSource })
					: await db.rpc("start_fleet_response_playbook", args);
				if (error) return rpcFailure(req, error);
				if (!isRecord(data) || typeof data.id !== "string" || typeof data.state !== "string") {
					return corsJson(req, 503, { error: "response_playbook_unavailable" });
				}
				return corsJson(req, 200, { ok: true, run: data }, rateLimitHeaders(rate));
			}

			const { data, error } = await db.rpc("get_fleet_response_playbook", {
				p_tenant_id: request.request.tenantId,
				p_run_id: request.request.runId,
			});
			if (error) return rpcFailure(req, error);
			if (!isRecord(data)) return corsJson(req, 404, { error: "response_playbook_not_found" });
			return corsJson(req, 200, { ok: true, run: data }, rateLimitHeaders(rate));
		} catch {
			return corsJson(req, 503, { error: "response_playbook_unavailable" });
		}
	};
}

const playbooks = createResponsePlaybooksHandler();
Deno.serve(playbooks);
