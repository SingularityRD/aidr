// Supabase Edge Function: POST /functions/v1/agent-lifecycle
//
// Auth: Authorization: Bearer <supabase_access_token> (AAL2 required)
//
// Seat lifecycle for enrolled devices (C8):
//   { action: "retire", tenant_id, agent_id, note? }
//       Retire one agent: its seat is freed and every API key bound to it
//       (the device key issued at enrollment) is revoked. Local detection on
//       the device is unaffected; the device stops syncing with the control
//       plane. The same installation id can enroll again later; it then needs
//       a free seat like any new device.
//   { action: "set_auto_retire", tenant_id, days }
//       days = 7..365 retires agents not seen for that many days (scheduled
//       maintenance); days = null switches automatic retirement off.
//
// Authorization is re-derived on every request: session, identity barrier,
// active owner/admin membership and AAL2 here, and owner/admin membership
// again inside the service-role RPC under the tenant lock. Every failure is
// closed. Each change writes an admin_audit_logs receipt in the same
// transaction as the change.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 2048;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const CONTROL = /\p{Cc}/u;
/** Mirrors the agent_retirement_settings check constraint. */
export const AUTO_RETIRE_BOUNDS = Object.freeze({ min: 7, max: 365 });

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient<any, "public">>;

export interface AgentLifecycleDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

export type AgentLifecycleCommand =
	| { action: "retire"; tenantId: string; agentId: string; note: string | null }
	| { action: "set_auto_retire"; tenantId: string; days: number | null };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
	return Object.keys(value).every((key) => allowed.includes(key));
}

export function parseAgentLifecycleCommand(
	value: unknown,
): { ok: true; command: AgentLifecycleCommand } | { ok: false; error: string } {
	if (!isRecord(value) || typeof value.tenant_id !== "string" || !UUID.test(value.tenant_id)) {
		return { ok: false, error: "invalid_request" };
	}
	const tenantId = value.tenant_id.toLowerCase();
	if (value.action === "retire") {
		if (!onlyKeys(value, ["action", "tenant_id", "agent_id", "note"])) return { ok: false, error: "invalid_request" };
		if (typeof value.agent_id !== "string" || !UUID.test(value.agent_id)) return { ok: false, error: "invalid_agent" };
		let note: string | null = null;
		if (value.note !== undefined && value.note !== null) {
			if (typeof value.note !== "string" || CONTROL.test(value.note) || value.note.trim().length > 200) {
				return { ok: false, error: "invalid_note" };
			}
			note = value.note.trim() || null;
		}
		return { ok: true, command: { action: "retire", tenantId, agentId: value.agent_id.toLowerCase(), note } };
	}
	if (value.action === "set_auto_retire") {
		if (!onlyKeys(value, ["action", "tenant_id", "days"]) || !("days" in value)) {
			return { ok: false, error: "invalid_request" };
		}
		const days = value.days;
		if (days !== null && (typeof days !== "number" || !Number.isSafeInteger(days) ||
			days < AUTO_RETIRE_BOUNDS.min || days > AUTO_RETIRE_BOUNDS.max)) {
			return { ok: false, error: "invalid_days" };
		}
		return { ok: true, command: { action: "set_auto_retire", tenantId, days: days as number | null } };
	}
	return { ok: false, error: "invalid_action" };
}

function rpcFailure(req: Request, error: { code?: string; message?: string }): Response {
	if (error.code === "42501") return corsJson(req, 403, { error: "workspace_role_insufficient" });
	if (error.code === "P0002") return corsJson(req, 404, { error: "agent_not_found" });
	if (error.code === "22023") return corsJson(req, 400, { error: "invalid_request" });
	return corsJson(req, 503, { error: "agent_lifecycle_unavailable" });
}

export function createAgentLifecycleHandler(deps: AgentLifecycleDeps = {}) {
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
			return configFailure("agent-lifecycle", config.error, (status, body) => corsJson(req, status, body));
		}
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const result = parseAgentLifecycleCommand(parsed.value);
		if (!result.ok) return corsJson(req, 400, { error: result.error });
		const command = result.command;

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const barrier = await checkIdentityBarrier(db, token, userId, command.tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

			const { data: member, error: memberError } = await db.from("tenant_members")
				.select("role,expires_at").eq("tenant_id", command.tenantId).eq("user_id", userId).maybeSingle();
			if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, now())) {
				return corsJson(req, 403, { error: "workspace_forbidden" });
			}
			if (role !== "owner" && role !== "admin") return corsJson(req, 403, { error: "workspace_role_insufficient" });

			// Retiring a device revokes its credential: always a step-up action.
			const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
			if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
			if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

			const rate = await consumeTenantRateLimit(db, {
				tenantId: command.tenantId,
				subject: userId,
				endpoint: "agent-lifecycle",
				perSubject: 60,
				perTenant: 300,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));

			if (command.action === "retire") {
				const { data, error } = await db.rpc("retire_agent", {
					p_actor_user_id: userId,
					p_tenant_id: command.tenantId,
					p_agent_id: command.agentId,
					p_note: command.note,
				});
				if (error) return rpcFailure(req, error);
				if (!isRecord(data) || data.agent_id !== command.agentId ||
					(data.status !== "retired" && data.status !== "already_retired")) {
					return corsJson(req, 503, { error: "agent_lifecycle_unavailable" });
				}
				return corsJson(req, 200, {
					ok: true,
					status: data.status,
					agent_id: command.agentId,
					revoked_keys: Number.isSafeInteger(data.revoked_keys) ? data.revoked_keys : 0,
				}, rateLimitHeaders(rate));
			}

			const { data, error } = await db.rpc("set_agent_auto_retirement", {
				p_actor_user_id: userId,
				p_tenant_id: command.tenantId,
				p_days: command.days,
			});
			if (error) return rpcFailure(req, error);
			if (!isRecord(data) || data.status !== "configured" || data.auto_retire_offline_days !== command.days) {
				return corsJson(req, 503, { error: "agent_lifecycle_unavailable" });
			}
			return corsJson(req, 200, { ok: true, auto_retire_offline_days: command.days }, rateLimitHeaders(rate));
		} catch {
			return corsJson(req, 503, { error: "agent_lifecycle_unavailable" });
		}
	};
}

Deno.serve(createAgentLifecycleHandler());
