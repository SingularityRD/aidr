import { createClient } from "npm:@supabase/supabase-js@2.116.0";
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

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_REQUEST_BODY_BYTES = 4096;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const IDEMPOTENCY_KEY = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const PLAYBOOK_ID = "agent_containment_v1" as const;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return globalThis.process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient>;

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
type PlaybookRequest = StartRequest | StatusRequest;

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
	if (value.action === "start") {
		if (!exactKeys(value, [
			"action", "tenant_id", "agent_id", "incident_reference", "playbook_id", "reason", "idempotency_key",
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
		return {
			ok: true,
			request: {
				action: "start",
				tenantId: value.tenant_id,
				agentId: value.agent_id,
				incidentReference: value.incident_reference,
				playbookId: PLAYBOOK_ID,
				reason: value.reason.trim(),
				idempotencyKey: value.idempotency_key,
				ttlSeconds: Number(ttlSeconds),
			},
		};
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
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
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
		if (!request.ok) {
			const status = request.error === "invalid_action" ? 400 : 400;
			return corsJson(req, status, { error: request.error });
		}
		const token = bearerToken(req);
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const identity = await authorizeOperator(db, token, request.request.tenantId, now());
			if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
			const rate = await consumeTenantRateLimit(db, {
				tenantId: request.request.tenantId,
				subject: identity.userId,
				endpoint: "response-playbooks",
				perSubject: 30,
				perTenant: 600,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));

			if (request.request.action === "start") {
				const { data, error } = await db.rpc("start_fleet_response_playbook", {
					p_tenant_id: request.request.tenantId,
					p_actor_user_id: identity.userId,
					p_agent_id: request.request.agentId,
					p_incident_id: request.request.incidentReference,
					p_playbook_id: request.request.playbookId,
					p_reason: request.request.reason,
					p_idempotency_key: request.request.idempotencyKey,
					p_ttl_seconds: request.request.ttlSeconds,
				});
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
