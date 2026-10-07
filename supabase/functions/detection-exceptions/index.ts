// Time-limited detection exceptions for managed tenants (docs/configuration.md,
// "Detection exceptions").
//
// POST /detection-exceptions { action: "list" | "create" | "revoke", tenant_id, ... }
// Supabase session only.
//
// Every request: session -> identity barrier (tenant MFA/SSO policy, global
// revocation) -> live membership in an active tenant -> owner/admin role ->
// AAL2 (every action, listing included: the list names which detections are
// relaxed for whom) -> tenant rate limit -> one service-role RPC that re-checks
// role and input under a tenant lock and writes the audit row in the same
// transaction. There is no API-key path, so no agent can create, list or revoke
// an exception. Connectors receive active exceptions only inside the
// Ed25519-signed runtime policy (see `policy/index.ts`).
//
// Every failure is closed.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import {
	DETECTION_EXCEPTIONS_MAX_BODY_BYTES,
	type DetectionExceptionCommand,
	detectionExceptionErrorCode,
	detectionExceptionRpcStatus,
	parseDetectionExceptionRequest,
} from "../_shared/detection-exceptions.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const LIST_COLUMNS =
	"id,rule_id,artifact_sha256,subject_kind,subject_user_id,subject_agent_id,subject_repo,reason,created_by,created_at,expires_at,revoked_by,revoked_at,revoke_reason";
const RATE_LIMITS = {
	list: { perSubject: 120, perTenant: 2_000 },
	write: { perSubject: 30, perTenant: 300 },
} as const;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type DatabaseClient = SupabaseClient;
type RpcError = { code?: string; message?: string } | null;

export interface DetectionExceptionsDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

function rpcCall(
	command: Exclude<DetectionExceptionCommand, { action: "list" }>,
	tenantId: string,
	userId: string,
): { name: string; args: Record<string, unknown> } {
	return command.action === "create"
		? { name: "create_detection_exception", args: { p_tenant_id: tenantId, p_actor_user_id: userId, p_fields: command.fields } }
		: {
				name: "revoke_detection_exception",
				args: { p_tenant_id: tenantId, p_actor_user_id: userId, p_exception_id: command.exceptionId, p_reason: command.reason },
			};
}

export function createDetectionExceptionsHandler(deps: DetectionExceptionsDeps = {}) {
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
			return configFailure("detection-exceptions", config.error, (status, body) => corsJson(req, status, body));
		}
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const parsed = await readBoundedJson(req, DETECTION_EXCEPTIONS_MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const request = parseDetectionExceptionRequest(parsed.value, now());
		if (!request.ok) return corsJson(req, 400, { error: request.error });
		const { tenantId, command } = request;

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
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) || !tenant) {
				return corsJson(req, 403, { error: "workspace_forbidden" });
			}
			if ((tenant as { status?: unknown }).status !== "active") {
				return corsJson(req, 409, { error: "workspace_not_active" });
			}
			if (role !== "owner" && role !== "admin") return corsJson(req, 403, { error: "detection_exception_role_insufficient" });
			const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
			if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
			if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

			const bucket = command.action === "list" ? "list" : "write";
			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: `detection-exceptions:${bucket}`,
				...RATE_LIMITS[bucket],
				now: now(),
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
			const headers = rateLimitHeaders(rate);

			if (command.action === "list") {
				const { data, error } = await db
					.from("detection_exceptions")
					.select(LIST_COLUMNS)
					.eq("tenant_id", tenantId)
					.order("created_at", { ascending: false })
					.limit(500);
				if (error || !Array.isArray(data)) return corsJson(req, 503, { error: "detection_exceptions_unavailable" }, headers);
				return corsJson(req, 200, { ok: true, exceptions: data, now: new Date(now()).toISOString() }, headers);
			}

			const call = rpcCall(command, tenantId, userId);
			const { data, error } = await db.rpc(call.name, call.args);
			if (error) {
				const rpcError = error as RpcError;
				return corsJson(req, detectionExceptionRpcStatus(rpcError?.code), {
					error: detectionExceptionErrorCode(rpcError?.message) ?? "detection_exceptions_unavailable",
				}, headers);
			}
			if (typeof data !== "object" || data === null || Array.isArray(data)) {
				return corsJson(req, 503, { error: "detection_exceptions_unavailable" }, headers);
			}
			return corsJson(req, 200, { ok: true, ...(data as Record<string, unknown>) }, headers);
		} catch {
			return corsJson(req, 503, { error: "detection_exceptions_unavailable" });
		}
	};
}

const detectionExceptions = createDetectionExceptionsHandler();
Deno.serve(detectionExceptions);
