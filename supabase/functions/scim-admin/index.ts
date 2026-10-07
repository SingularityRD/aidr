import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { type PlanEntitlementDb, requireFeature } from "../_shared/plan-entitlements.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const MAX_TOKENS = 100;
const MAX_MAPPINGS = 500;
const DEFAULT_TOKEN_TTL_MS = 90 * 24 * 60 * 60 * 1000;
const MAX_TOKEN_TTL_MS = 365 * 24 * 60 * 60 * 1000;
const ROLES = new Set(["admin", "member", "viewer"]);
const STEP_UP_ACTIONS: ReadonlySet<string> = new Set(["create_token", "rotate_token", "set_group_mapping", "remove_group_mapping"]);

type Row = Record<string, unknown>;
type ReadTable<T extends Row> = { Row: T; Insert: never; Update: never; Relationships: [] };
type ScimAdminDatabase = {
	public: {
		Tables: {
			tenant_members: ReadTable<{ tenant_id: string; user_id: string; role: string; expires_at: string | null }>;
			tenants: ReadTable<{ id: string; status: string }>;
			scim_tokens: ReadTable<{ id: string; tenant_id: string; label: string; rotated_from: string | null; created_at: string; expires_at: string | null; revoked_at: string | null; last_used_at: string | null }>;
			scim_group_role_mappings: ReadTable<{ tenant_id: string; external_group_id: string; role: string; created_by: string; created_at: string }>;
		};
		Views: Record<string, never>;
		Functions: {
			scim_admin_create_token: { Args: { p_tenant_id: string; p_actor_user_id: string; p_token_hash: string; p_label: string; p_expires_at: string; p_rotated_from_id: string | null }; Returns: string };
			scim_admin_revoke_token: { Args: { p_tenant_id: string; p_actor_user_id: string; p_token_id: string }; Returns: boolean };
			scim_admin_set_group_role_mapping: { Args: { p_tenant_id: string; p_actor_user_id: string; p_external_group_id: string; p_role: string }; Returns: boolean };
			scim_admin_remove_group_role_mapping: { Args: { p_tenant_id: string; p_actor_user_id: string; p_external_group_id: string }; Returns: boolean };
		};
		Enums: Record<string, never>;
		CompositeTypes: Record<string, never>;
	};
};
type Db = SupabaseClient<ScimAdminDatabase>;

export interface ScimAdminDeps {
	/** Overrides the service-role client for the contract suite. */
	db?: Db;
}

type Command =
	| { action: "create_token"; tenantId: string; label: string; expiresAt: string }
	| { action: "rotate_token"; tenantId: string; tokenId: string; label: string; expiresAt: string }
	| { action: "revoke_token"; tenantId: string; tokenId: string }
	| { action: "set_group_mapping"; tenantId: string; externalGroupId: string; role: string }
	| { action: "remove_group_mapping"; tenantId: string; externalGroupId: string };

function noStore(): Record<string, string> {
	return { "Cache-Control": "no-store", Pragma: "no-cache" };
}

function exactKeys(value: Record<string, unknown>, keys: string[]): boolean {
	const actual = Object.keys(value).sort();
	const expected = [...keys].sort();
	return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function uuid(value: unknown): value is string {
	return typeof value === "string" && TENANT_ID.test(value);
}

function expiresAt(value: unknown): string | undefined {
	const now = Date.now();
	if (value === undefined) return new Date(now + DEFAULT_TOKEN_TTL_MS).toISOString();
	if (typeof value !== "string" || value.length > 40 || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/.test(value)) return undefined;
	const time = Date.parse(value);
	if (!Number.isFinite(time) || time <= now || time > now + MAX_TOKEN_TTL_MS) return undefined;
	return new Date(time).toISOString();
}

function groupId(value: unknown): string | null {
	if (typeof value !== "string" || value.length < 1 || value.length > 255 || value.trim() !== value || /[\u0000-\u001f\u007f]/.test(value)) return null;
	return value;
}

function label(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const normalized = value.trim();
	return normalized.length > 0 && normalized.length <= 120 && !/[\u0000-\u001f\u007f]/.test(normalized) ? normalized : null;
}

function parseCommand(value: unknown): Command | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const body = value as Record<string, unknown>;
	if (!uuid(body.tenant_id) || typeof body.action !== "string") return null;
	const tenantId = body.tenant_id;
	switch (body.action) {
		case "create_token": {
			if (!exactKeys(body, ["action", "tenant_id", "label", ...(Object.hasOwn(body, "expires_at") ? ["expires_at"] : [])])) return null;
			const tokenLabel = label(body.label);
			const expiry = expiresAt(body.expires_at);
			return tokenLabel && expiry !== undefined ? { action: body.action, tenantId, label: tokenLabel, expiresAt: expiry } : null;
		}
		case "rotate_token": {
			if (!exactKeys(body, ["action", "tenant_id", "token_id", "label", ...(Object.hasOwn(body, "expires_at") ? ["expires_at"] : [])])) return null;
			const tokenId = uuid(body.token_id) ? body.token_id : null;
			const tokenLabel = label(body.label);
			const expiry = expiresAt(body.expires_at);
			return tokenId && tokenLabel && expiry !== undefined ? { action: body.action, tenantId, tokenId, label: tokenLabel, expiresAt: expiry } : null;
		}
		case "revoke_token":
			return exactKeys(body, ["action", "tenant_id", "token_id"]) && uuid(body.token_id)
				? { action: body.action, tenantId, tokenId: body.token_id }
				: null;
		case "set_group_mapping":
			return exactKeys(body, ["action", "tenant_id", "external_group_id", "role"])
				&& groupId(body.external_group_id) !== null
				&& typeof body.role === "string" && ROLES.has(body.role)
				? { action: body.action, tenantId, externalGroupId: body.external_group_id as string, role: body.role }
				: null;
		case "remove_group_mapping":
			return exactKeys(body, ["action", "tenant_id", "external_group_id"])
				&& groupId(body.external_group_id) !== null
				? { action: body.action, tenantId, externalGroupId: body.external_group_id as string }
				: null;
		default:
			return null;
	}
}

function rawToken(): string {
	const bytes = crypto.getRandomValues(new Uint8Array(32));
	let binary = "";
	for (const byte of bytes) binary += String.fromCharCode(byte);
	return `aidr_scim_${btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "")}`;
}

function rpcFailure(req: Request, error: unknown): Response {
	const result = error && typeof error === "object" ? error as { code?: unknown; message?: unknown } : {};
	const code = typeof result.code === "string" ? result.code : "";
	const message = typeof result.message === "string" ? result.message : "";
	if (message === "scim_admin_owner_required") return corsJson(req, 403, { error: "owner_required" }, noStore());
	if (message === "scim_admin_rotation_parent_unavailable") return corsJson(req, 404, { error: "token_not_found_or_inactive" }, noStore());
	if (message === "scim_cannot_take_over_manual_membership") return corsJson(req, 409, { error: "mapping_conflicts_with_manual_membership" }, noStore());
	if (message === "scim_admin_invalid_token" || message === "scim_admin_invalid_mapping") return corsJson(req, 400, { error: "invalid_request" }, noStore());
	if (code === "23505") return corsJson(req, 409, { error: "scim_resource_conflict" }, noStore());
	return corsJson(req, 503, { error: "scim_management_unavailable" }, noStore());
}

function uuidResult(value: unknown): string | null {
	if (typeof value === "string" && uuid(value)) return value;
	if (value && typeof value === "object" && !Array.isArray(value)) {
		const id = (value as Record<string, unknown>).id;
		return uuid(id) ? id : null;
	}
	return null;
}

function activeOwner(value: unknown): value is Row {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as Row;
	if (row.role !== "owner") return false;
	if (row.expires_at !== null && (typeof row.expires_at !== "string" || !Number.isFinite(Date.parse(row.expires_at)))) return false;
	return membershipActive({ role: row.role, expires_at: row.expires_at as string | null });
}

function tokenCursor(url: URL): { createdAt: string; id: string } | null | undefined {
	const createdAt = url.searchParams.getAll("token_after_created_at");
	const id = url.searchParams.getAll("token_after_id");
	if (createdAt.length > 1 || id.length > 1) return undefined;
	if (createdAt.length === 0 && id.length === 0) return null;
	if (createdAt.length !== 1 || id.length !== 1 || !uuid(id[0])
		|| !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,6})?(?:Z|[+-]\d\d:\d\d)$/.test(createdAt[0])
		|| !Number.isFinite(Date.parse(createdAt[0]))) return undefined;
	return { createdAt: createdAt[0], id: id[0] };
}

function mappingCursor(url: URL): string | null | undefined {
	const values = url.searchParams.getAll("mapping_after_external_group_id");
	if (values.length === 0) return null;
	return values.length === 1 && groupId(values[0]) !== null ? values[0] : undefined;
}

/** Owner-only API for provisioning SCIM secrets and exact immutable group-role mappings. */
export function createScimAdminHandler(deps: ScimAdminDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" }, { ...noStore(), Allow: "GET, POST" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("scim-admin", config.error, (status, body) => corsJson(req, status, body, noStore()));

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" }, noStore());
		try {
			const db = deps.db ?? createClient<ScimAdminDatabase>(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" }, noStore());
			const userId = auth.user.id;
			const globalIdentity = await checkIdentityBarrier(db, token, userId);
			if (!globalIdentity.ok) return corsJson(req, globalIdentity.status, { error: globalIdentity.error }, noStore());

			let command: Command | null = null;
			let tenantId: string;
			if (req.method === "GET") {
				const rawRequested = req.headers.get("X-AIDR-Tenant-ID");
				const requested = rawRequested?.trim();
				if (!uuid(requested) || requested !== rawRequested) return corsJson(req, 400, { error: "invalid_tenant" }, noStore());
				tenantId = requested;
			} else {
				const parsed = await readBoundedJson(req, 16_384);
				if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error }, noStore());
				command = parseCommand(parsed.value);
				if (!command) return corsJson(req, 400, { error: "invalid_request" }, noStore());
				tenantId = command.tenantId;
				const rawHeaderTenant = req.headers.get("X-AIDR-Tenant-ID");
				const headerTenant = rawHeaderTenant?.trim();
				if (rawHeaderTenant && (headerTenant !== rawHeaderTenant || headerTenant !== tenantId)) return corsJson(req, 400, { error: "tenant_mismatch" }, noStore());
			}

			const tenantIdentity = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error }, noStore());
			const { data: member, error: memberError } = await db.from("tenant_members")
				.select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
			const { data: tenant, error: tenantError } = await db.from("tenants")
				.select("status").eq("id", tenantId).maybeSingle();
			if (memberError || tenantError) return corsJson(req, 503, { error: "authorization_unavailable" }, noStore());
			if (!activeOwner(member) || tenant?.status !== "active") return corsJson(req, 403, { error: "owner_required" }, noStore());
			// Issuing a provisioning credential or changing which directory groups map
			// to tenant roles is privilege-granting, so it requires a step-up (AAL2)
			// session regardless of tenant MFA policy — the same bar as OIDC admin.
			// Revocation stays available at AAL1 so a leaked token can be cut off fast.
			if (command && STEP_UP_ACTIONS.has(command.action)) {
				const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
				if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" }, noStore());
				if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" }, noStore());
			}
			const quota = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: "scim-admin",
				perSubject: 60,
				perTenant: 300,
			});
			if (!quota.ok) return corsJson(req, quota.status, { error: quota.error }, { ...noStore(), ...rateLimitHeaders(quota) });
			// Plan gate: SCIM is a Business-edition feature. Decided once the caller
			// is an authorized owner of `tenantId`, before any SCIM token or mapping
			// is read or written. Fails closed (402 / 503), never allow on error.
			const plan = await requireFeature(db as unknown as PlanEntitlementDb, tenantId, "scim");
			if (!plan.ok) return corsJson(req, plan.status, plan.body, noStore());

			if (req.method === "GET") {
				const url = new URL(req.url);
				const tokenAfter = tokenCursor(url);
				const mappingAfter = mappingCursor(url);
				if (tokenAfter === undefined || mappingAfter === undefined) return corsJson(req, 400, { error: "invalid_pagination" }, noStore());
				let tokenQuery = db.from("scim_tokens").select("id,label,rotated_from,created_at,expires_at,revoked_at,last_used_at")
					.eq("tenant_id", tenantId);
				if (tokenAfter) tokenQuery = tokenQuery.or(`created_at.lt.${tokenAfter.createdAt},and(created_at.eq.${tokenAfter.createdAt},id.gt.${tokenAfter.id})`);
				let mappingQuery = db.from("scim_group_role_mappings").select("external_group_id,role,created_by,created_at")
					.eq("tenant_id", tenantId);
				if (mappingAfter !== null) mappingQuery = mappingQuery.gt("external_group_id", mappingAfter);
				const [tokens, mappings] = await Promise.all([
					tokenQuery.order("created_at", { ascending: false }).order("id", { ascending: true }).limit(MAX_TOKENS + 1),
					mappingQuery.order("external_group_id", { ascending: true }).limit(MAX_MAPPINGS + 1),
				]);
				if (tokens.error || mappings.error)
					return corsJson(req, 503, { error: "scim_management_unavailable" }, noStore());
				const tokenRows = tokens.data ?? [];
				const mappingRows = mappings.data ?? [];
				return corsJson(req, 200, {
					ok: true,
					tokens: tokenRows.slice(0, MAX_TOKENS),
					group_role_mappings: mappingRows.slice(0, MAX_MAPPINGS),
					next_token_cursor: tokenRows.length > MAX_TOKENS ? {
						created_at: tokenRows[MAX_TOKENS - 1].created_at,
						id: tokenRows[MAX_TOKENS - 1].id,
					} : null,
					next_mapping_cursor: mappingRows.length > MAX_MAPPINGS
						? mappingRows[MAX_MAPPINGS - 1].external_group_id : null,
				}, noStore());
			}

			if (command?.action === "create_token" || command?.action === "rotate_token") {
				const rotatedFrom = command.action === "rotate_token" ? command.tokenId : null;
				const secret = rawToken();
				const hash = await sha256(secret);
				const { data, error } = await db.rpc("scim_admin_create_token", {
					p_tenant_id: tenantId, p_actor_user_id: userId, p_token_hash: hash,
					p_label: command.label, p_expires_at: command.expiresAt, p_rotated_from_id: rotatedFrom,
				});
				if (error) return rpcFailure(req, error);
				const id = uuidResult(data);
				if (!id) return corsJson(req, 503, { error: "scim_management_unavailable" }, noStore());
				return corsJson(req, 201, { ok: true, token_id: id, scim_token: secret, expires_at: command.expiresAt }, noStore());
			}

			if (command?.action === "revoke_token") {
				const { data, error } = await db.rpc("scim_admin_revoke_token", {
					p_tenant_id: tenantId, p_actor_user_id: userId, p_token_id: command.tokenId,
				});
				if (error) return rpcFailure(req, error);
				if (data !== true) return corsJson(req, 404, { error: "token_not_found_or_revoked" }, noStore());
				return corsJson(req, 200, { ok: true }, noStore());
			}

			if (command?.action === "set_group_mapping") {
				const { data, error } = await db.rpc("scim_admin_set_group_role_mapping", {
					p_tenant_id: tenantId, p_actor_user_id: userId,
					p_external_group_id: command.externalGroupId, p_role: command.role,
				});
				if (error) return rpcFailure(req, error);
				if (typeof data !== "boolean") return corsJson(req, 503, { error: "scim_management_unavailable" }, noStore());
				return corsJson(req, 200, { ok: true, changed: data }, noStore());
			}

			if (command?.action === "remove_group_mapping") {
				const { data, error } = await db.rpc("scim_admin_remove_group_role_mapping", {
					p_tenant_id: tenantId, p_actor_user_id: userId, p_external_group_id: command.externalGroupId,
				});
				if (error) return rpcFailure(req, error);
				if (data !== true) return corsJson(req, 404, { error: "group_mapping_not_found" }, noStore());
				return corsJson(req, 200, { ok: true }, noStore());
			}

			return corsJson(req, 400, { error: "invalid_request" }, noStore());
		} catch {
			return corsJson(req, 503, { error: "scim_management_unavailable" }, noStore());
		}
	};
}

Deno.serve(createScimAdminHandler());
