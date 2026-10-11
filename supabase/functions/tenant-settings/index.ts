// Workspace settings for the dashboard (GET read, PATCH update/close).
//
// GET   Header X-AIDR-Tenant-ID. Any active member reads the workspace name,
//       status, retention and what their role may change.
// PATCH { tenant_id, action: "update", name?, retention_days?, confirm_retention_reduction? }
//       owner/admin at AAL2 for a rename; a retention CHANGE is owner-only and
//       goes through the bounded, plan-checked retention setter inside the RPC
//       (class floors, plan maximum, offboarding refusal, tenant lock).
//       Shortening retention needs an explicit confirmation because it makes
//       older telemetry eligible for deletion. The RPC repeats that check
//       against the stored telemetry policy, and never lowers any other
//       retention class (owners shorten those per class).
// PATCH { tenant_id, action: "close", confirm_name }
//       owner at AAL2, with the exact current workspace name typed back.
//       Delegates to the audited offboarding lifecycle.
//
// Authorization is re-derived on the server for every request and repeated
// inside the service-role RPCs under row locks; nothing in the body grants a
// role. Every failure is closed: an unreadable membership, tenant, assurance
// level or rate-limit counter refuses the request.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 4096;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
// Control characters are rejected outright (same rule as cloud signup naming).
const CONTROL = /\p{Cc}/u;

/** Mirrors the `tenants.retention_days` check constraint (shape of stored values). */
export const RETENTION_BOUNDS = Object.freeze({ min: 1, max: 3650 });
/**
 * What a workspace retention change may request: the telemetry row of
 * `public.retention_policy_bounds`. The RPC enforces it (and the plan maximum)
 * again under the tenant lock; this is the advertised range.
 */
export const WORKSPACE_RETENTION_BOUNDS = Object.freeze({ min: 7, max: 3650 });
export const WORKSPACE_NAME_MAX = 200;

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

export interface TenantSettingsDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

export type SettingsCommand =
	| {
			action: "update";
			tenantId: string;
			name?: string;
			retentionDays?: number;
			confirmRetentionReduction: boolean;
	  }
	| { action: "close"; tenantId: string; confirmName: string };

type TenantRow = {
	id: string;
	name: string;
	kind: string;
	status: string;
	retention_days: number;
	created_at: string;
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function onlyKeys(value: Record<string, unknown>, allowed: readonly string[]): boolean {
	return Object.keys(value).every((key) => allowed.includes(key));
}

export function normalizeWorkspaceName(value: unknown): string | null {
	if (typeof value !== "string" || CONTROL.test(value)) return null;
	const trimmed = value.trim();
	return trimmed.length >= 1 && trimmed.length <= WORKSPACE_NAME_MAX ? trimmed : null;
}

export function validRetentionDays(value: unknown): value is number {
	return (
		typeof value === "number" &&
		Number.isSafeInteger(value) &&
		value >= RETENTION_BOUNDS.min &&
		value <= RETENTION_BOUNDS.max
	);
}

export function validRequestedRetentionDays(value: unknown): value is number {
	return validRetentionDays(value) && value >= WORKSPACE_RETENTION_BOUNDS.min && value <= WORKSPACE_RETENTION_BOUNDS.max;
}

export function parseSettingsCommand(value: unknown): { ok: true; command: SettingsCommand } | { ok: false; error: string } {
	if (!isRecord(value) || typeof value.tenant_id !== "string" || !UUID.test(value.tenant_id)) {
		return { ok: false, error: "invalid_request" };
	}
	const tenantId = value.tenant_id.toLowerCase();
	if (value.action === "update") {
		if (!onlyKeys(value, ["action", "tenant_id", "name", "retention_days", "confirm_retention_reduction"])) {
			return { ok: false, error: "invalid_request" };
		}
		if (value.name === undefined && value.retention_days === undefined) {
			return { ok: false, error: "no_changes" };
		}
		let name: string | undefined;
		if (value.name !== undefined) {
			const normalized = normalizeWorkspaceName(value.name);
			if (normalized === null) return { ok: false, error: "invalid_workspace_name" };
			name = normalized;
		}
		if (value.retention_days !== undefined && !validRequestedRetentionDays(value.retention_days)) {
			return { ok: false, error: "invalid_retention_days" };
		}
		if (value.confirm_retention_reduction !== undefined && typeof value.confirm_retention_reduction !== "boolean") {
			return { ok: false, error: "invalid_request" };
		}
		return {
			ok: true,
			command: {
				action: "update",
				tenantId,
				...(name !== undefined ? { name } : {}),
				...(value.retention_days !== undefined ? { retentionDays: value.retention_days as number } : {}),
				confirmRetentionReduction: value.confirm_retention_reduction === true,
			},
		};
	}
	if (value.action === "close") {
		if (!onlyKeys(value, ["action", "tenant_id", "confirm_name"]) || typeof value.confirm_name !== "string" ||
			value.confirm_name.length > WORKSPACE_NAME_MAX + 64) {
			return { ok: false, error: "invalid_request" };
		}
		return { ok: true, command: { action: "close", tenantId, confirmName: value.confirm_name } };
	}
	return { ok: false, error: "invalid_action" };
}

function workspaceView(tenant: TenantRow) {
	return {
		id: tenant.id,
		name: tenant.name,
		kind: tenant.kind,
		status: tenant.status,
		retention_days: tenant.retention_days,
		created_at: tenant.created_at,
	};
}

function validTenantRow(value: unknown, tenantId: string): value is TenantRow {
	return isRecord(value) && value.id === tenantId && typeof value.name === "string" &&
		typeof value.kind === "string" && typeof value.status === "string" &&
		Number.isSafeInteger(value.retention_days) && typeof value.created_at === "string";
}

/** Retention refusals raised by the bounded setter, surfaced with a stable code. */
function retentionFailure(req: Request, error: { code?: string; message?: string }): Response | null {
	const message = error.message ?? "";
	if (error.code === "42501" && message.includes("retention_admin_owner_required")) {
		return corsJson(req, 403, { error: "workspace_role_insufficient" });
	}
	if (error.code === "22023") {
		const reason = /retention_days_out_of_bounds|retention_days_exceeds_plan|retention_class_not_configurable/.exec(message)?.[0];
		if (reason) return corsJson(req, 400, { error: "invalid_retention_days", reason });
	}
	if (error.code === "55000" && message.includes("retention_change_refused_offboarding")) {
		return corsJson(req, 409, { error: "retention_change_refused_offboarding" });
	}
	// The RPC compares the request with the stored telemetry policy under the
	// tenant lock; the pre-check above only sees tenants.retention_days.
	if (error.code === "55000" && message.includes("retention_reduction_unconfirmed")) {
		return corsJson(req, 409, { error: "retention_reduction_unconfirmed" });
	}
	return null;
}

function rpcFailure(req: Request, error: { code?: string } | null, fallback: string): Response {
	if (error?.code === "42501") return corsJson(req, 403, { error: "workspace_forbidden" });
	if (error?.code === "55000") return corsJson(req, 409, { error: "workspace_not_active" });
	return corsJson(req, 503, { error: fallback });
}

export function createTenantSettingsHandler(deps: TenantSettingsDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "PATCH") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("tenant-settings", config.error, (status, body) => corsJson(req, status, body));
		}

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });

		let command: SettingsCommand | null = null;
		let tenantId: string;
		if (req.method === "GET") {
			const header = (req.headers.get("X-AIDR-Tenant-ID") ?? "").trim();
			if (!UUID.test(header)) return corsJson(req, 400, { error: "invalid_request" });
			tenantId = header.toLowerCase();
		} else {
			const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
			if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
			const result = parseSettingsCommand(parsed.value);
			if (!result.ok) return corsJson(req, 400, { error: result.error });
			command = result.command;
			tenantId = command.tenantId;
		}

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

			const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
				db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle(),
				db.from("tenants").select("id,name,kind,status,retention_days,created_at").eq("id", tenantId).maybeSingle(),
			]);
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, now()) ||
				!["owner", "admin", "member", "viewer"].includes(role)) {
				return corsJson(req, 403, { error: "workspace_forbidden" });
			}
			if (!tenant || tenant.status === "closed") return corsJson(req, 403, { error: "workspace_forbidden" });
			if (!validTenantRow(tenant, tenantId)) return corsJson(req, 503, { error: "workspace_unavailable" });

			const active = tenant.status === "active";
			if (!command) {
				return corsJson(req, 200, {
					ok: true,
					workspace: workspaceView(tenant),
					role,
					permissions: {
						can_edit: active && (role === "owner" || role === "admin"),
						can_edit_retention: active && role === "owner",
						can_close: active && role === "owner",
						requires_aal2: true,
					},
					retention_bounds: WORKSPACE_RETENTION_BOUNDS,
				});
			}

			// Admins may rename; changing retention (like closure) is an owner
			// decision. The RPC re-checks both under the tenant lock.
			const changesRetention = command.action === "update" && command.retentionDays !== undefined &&
				command.retentionDays !== tenant.retention_days;
			const allowed = command.action === "close" || changesRetention
				? role === "owner"
				: role === "owner" || role === "admin";
			if (!allowed) return corsJson(req, 403, { error: "workspace_role_insufficient" });
			if (!active) return corsJson(req, 409, { error: "workspace_not_active" });
			// Workspace changes are privileged: require step-up even when the
			// tenant's general MFA policy is optional.
			const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
			if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
			if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: "tenant-settings",
				perSubject: 20,
				perTenant: 100,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));

			if (command.action === "update") {
				if (command.retentionDays !== undefined && command.retentionDays < tenant.retention_days &&
					!command.confirmRetentionReduction) {
					return corsJson(req, 409, {
						error: "retention_reduction_unconfirmed",
						current_retention_days: tenant.retention_days,
					}, rateLimitHeaders(rate));
				}
				const { data, error } = await db.rpc("update_tenant_workspace_settings", {
					p_tenant_id: tenantId,
					p_actor_user_id: userId,
					p_name: command.name ?? null,
					p_retention_days: command.retentionDays ?? null,
					p_confirm_retention_reduction: command.confirmRetentionReduction,
				});
				const retentionRefusal = error ? retentionFailure(req, error) : null;
				if (retentionRefusal) return retentionRefusal;
				if (error?.code === "22023") return corsJson(req, 400, { error: "invalid_workspace_settings" });
				if (error) return rpcFailure(req, error, "workspace_update_failed");
				if (!isRecord(data) || data.id !== tenantId || typeof data.name !== "string" ||
					!validRetentionDays(data.retention_days) || !Array.isArray(data.changed)) {
					return corsJson(req, 503, { error: "workspace_update_failed" });
				}
				return corsJson(req, 200, {
					ok: true,
					workspace: workspaceView({ ...tenant, name: data.name, retention_days: data.retention_days as number }),
					changed: data.changed,
				}, rateLimitHeaders(rate));
			}

			// Typed confirmation is checked here for a clear error and again in
			// the RPC under the tenant row lock.
			if (command.confirmName.trim() !== tenant.name) {
				return corsJson(req, 400, { error: "confirmation_mismatch" }, rateLimitHeaders(rate));
			}
			const { data, error } = await db.rpc("request_workspace_closure", {
				p_tenant_id: tenantId,
				p_actor_user_id: userId,
				p_confirm_name: command.confirmName,
			});
			if (error?.code === "22023") return corsJson(req, 400, { error: "confirmation_mismatch" });
			if (error) return rpcFailure(req, error, "workspace_closure_failed");
			if (!isRecord(data) || data.tenant_id !== tenantId || typeof data.run_id !== "string" ||
				typeof data.status !== "string") {
				return corsJson(req, 503, { error: "workspace_closure_failed" });
			}
			return corsJson(req, 200, {
				ok: true,
				closure: {
					run_id: data.run_id,
					status: data.status,
					backup_scope: data.backup_scope ?? null,
					backup_exception: data.backup_exception ?? null,
				},
			}, rateLimitHeaders(rate));
		} catch {
			return corsJson(req, 503, { error: "workspace_unavailable" });
		}
	};
}

const tenantSettings = createTenantSettingsHandler();
Deno.serve(tenantSettings);
