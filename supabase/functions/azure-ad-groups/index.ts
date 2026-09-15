import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EXTERNAL_ID_MAX = 255;
const MAX_TENANTS = 100;
const MAX_GROUPS = 500;

const VERIFIED_ROLES = new Set(["admin", "member", "viewer"]);

type Db = ReturnType<typeof createClient>;
type Row = Record<string, unknown>;

export interface AzureAdGroupsDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: Db;
}

function isUuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value);
}

function externalId(value: unknown): string | null {
	if (typeof value !== "string") return null;
	if (value.trim() !== value) return null;
	return value.length > 0 && value.length <= EXTERNAL_ID_MAX ? value : null;
}

function tenantHeader(req: Request): string | null | "invalid" {
	const value = req.headers.get("X-AIDR-Tenant-ID")?.trim();
	if (!value) return null;
	return isUuid(value) ? value : "invalid";
}

function noStore(): Record<string, string> {
	return { "Content-Type": "application/json", "Cache-Control": "no-store", Pragma: "no-cache" };
}

function unavailable(req: Request): Response {
	return corsJson(req, 503, { error: "verified_groups_unavailable" }, noStore());
}

function unauthorized(req: Request, error: string): Response {
	return corsJson(req, 401, { error }, { ...noStore(), "WWW-Authenticate": "Bearer" });
}

function exceededLimit(data: unknown, limit: number): boolean {
	return Array.isArray(data) && data.length > limit;
}

function validMembershipExpiry(row: Row): boolean {
	if (!Object.hasOwn(row, "expires_at")) return false;
	const expiresAt = row.expires_at;
	return expiresAt === null || (typeof expiresAt === "string" && Number.isFinite(Date.parse(expiresAt)));
}

function groupResponse(req: Request, userId: string, groups: Array<Record<string, unknown>>): Response {
	return corsJson(req, 200, {
		ok: true,
		user_id: userId,
		groups,
		synced_at: new Date().toISOString(),
	}, noStore());
}

/**
 * Read the server-owned SCIM directory projection for the authenticated user.
 *
 * This route is deliberately read-only and caller-scoped. It applies the shared
 * session/MFA barrier before any directory read; it does not grant a tenant-wide
 * admin capability. The SCIM bearer-token route remains the machine provisioning
 * boundary; a browser session never supplies a group, role, display name, or
 * external id to this response. Any role in the projection is display-only;
 * protected actions must authorize again from server-side membership.
 */
export function createAzureAdGroupsHandler(deps: AzureAdGroupsDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET") return corsJson(req, 405, { error: "method_not_allowed" }, { ...noStore(), Allow: "GET" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("azure-ad-groups", config.error, (status, body) => corsJson(req, status, body, noStore()));

		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return unauthorized(req, "missing_access_token");
		const requestedTenant = tenantHeader(req);
		if (requestedTenant === "invalid") return corsJson(req, 400, { error: "invalid_tenant" }, noStore());

		try {
			const db = deps.db ?? createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return unauthorized(req, "invalid_access_token");
			// Provider metadata is not an authorization input. The server-side
			// SCIM auth_user_id binding and active tenant membership scope this read.
			const userId = auth.user.id;

			// Service-role reads must repeat both the global session barrier and the
			// tenant MFA policy. A requested tenant is checked before membership
			// discovery; all-tenant mode discovers only memberships after the global
			// barrier, then checks every active tenant before touching SCIM tables.
			const globalIdentity = await checkIdentityBarrier(db, token, userId);
			if (!globalIdentity.ok) return corsJson(req, globalIdentity.status, { error: globalIdentity.error }, noStore());
			if (requestedTenant) {
				const requestedIdentity = await checkIdentityBarrier(db, token, userId, requestedTenant);
				if (!requestedIdentity.ok) return corsJson(req, requestedIdentity.status, { error: requestedIdentity.error }, noStore());
			}

			let membershipQuery = db.from("tenant_members")
				.select("tenant_id,role,expires_at")
				.eq("user_id", userId)
				.order("tenant_id", { ascending: true })
				.limit(MAX_TENANTS + 1);
			if (requestedTenant) membershipQuery = membershipQuery.eq("tenant_id", requestedTenant);
			const memberships = await membershipQuery;
			if (memberships.error || exceededLimit(memberships.data, MAX_TENANTS)) return unavailable(req);
			const candidateMemberships = (memberships.data ?? []) as Row[];
			if (candidateMemberships.some((row) => !isUuid(row.tenant_id) || typeof row.role !== "string" || row.role.length === 0 || !validMembershipExpiry(row))) return unavailable(req);
			// This is a caller-scoped read, so every active membership role may
			// inspect its own projection; returned roles never authorize actions.
			const tenantIds = [...new Set(candidateMemberships
				.filter((row) => membershipActive({ role: row.role as string, expires_at: row.expires_at as string | null }))
				.map((row) => String(row.tenant_id))
				.filter(isUuid))];
			if (tenantIds.length === 0) {
				return requestedTenant
					? corsJson(req, 403, { error: "tenant_access_denied" }, noStore())
					: groupResponse(req, userId, []);
			}

			const tenants = await db.from("tenants").select("id,status").in("id", tenantIds).order("id", { ascending: true });
			if (tenants.error) return unavailable(req);
			const tenantRows = (tenants.data ?? []) as Row[];
			const returnedTenantIds = new Set(tenantRows.map((row) => String(row.id)));
			if (
				tenantRows.length !== tenantIds.length ||
				returnedTenantIds.size !== tenantIds.length ||
				tenantIds.some((tenantId) => !returnedTenantIds.has(tenantId)) ||
				tenantRows.some((row) => !isUuid(row.id) || typeof row.status !== "string")
			)
				return unavailable(req);
			const activeTenantIds = [...new Set(tenantRows
				.filter((row) => row.status === "active")
				.map((row) => String(row.id))
				.filter((id): id is string => tenantIds.includes(id)))];
			if (activeTenantIds.length === 0) {
				return requestedTenant
					? corsJson(req, 403, { error: "tenant_inactive" }, noStore())
					: groupResponse(req, userId, []);
			}

			// A response spanning multiple tenants is only valid when every tenant
			// passes the same identity barrier. A policy or assurance read failure
			// therefore cannot degrade into a partial group list.
			for (const tenantId of activeTenantIds) {
				if (tenantId === requestedTenant) continue;
				const tenantIdentity = await checkIdentityBarrier(db, token, userId, tenantId);
				if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error }, noStore());
			}

			const usersQuery = db.from("scim_users").select("tenant_id,id").eq("auth_user_id", userId).eq("active", true).in("tenant_id", activeTenantIds).order("tenant_id", { ascending: true }).order("id", { ascending: true }).limit(MAX_GROUPS + 1);
			const users = await usersQuery;
			if (users.error || exceededLimit(users.data, MAX_GROUPS)) return unavailable(req);
			const scimUsers = (users.data ?? []) as Row[];
			if (scimUsers.some((row) => !isUuid(row.tenant_id) || !activeTenantIds.includes(String(row.tenant_id)) || !isUuid(row.id))) return unavailable(req);
			const scimUserIds = [...new Set(scimUsers.map((row) => String(row.id)))];
			if (scimUserIds.length === 0) return groupResponse(req, userId, []);

			const membershipsResult = await db.from("scim_group_memberships")
				.select("tenant_id,group_id,user_id")
				.in("tenant_id", activeTenantIds)
				.in("user_id", scimUserIds)
				.order("tenant_id", { ascending: true })
				.order("group_id", { ascending: true })
				.order("user_id", { ascending: true })
				.limit(MAX_GROUPS + 1);
			if (membershipsResult.error || exceededLimit(membershipsResult.data, MAX_GROUPS)) return unavailable(req);
			const membershipsRows = (membershipsResult.data ?? []) as Row[];
			const groupIds = [...new Set(membershipsRows.map((row) => String(row.group_id)))];
			if (
				membershipsRows.some(
					(row) =>
						!isUuid(row.tenant_id) ||
						!activeTenantIds.includes(String(row.tenant_id)) ||
						!isUuid(row.group_id) ||
						!groupIds.includes(String(row.group_id)) ||
						!isUuid(row.user_id) ||
						!scimUserIds.includes(String(row.user_id)),
					)
			)
				return unavailable(req);
			const groupKeys = new Set(membershipsRows
				.map((row) => `${String(row.tenant_id)}:${String(row.group_id)}`));
			if (groupIds.length === 0) return groupResponse(req, userId, []);

			const groupsResult = await db.from("scim_groups")
				.select("tenant_id,id,external_id,display_name")
				.in("tenant_id", activeTenantIds)
				.in("id", groupIds)
				.order("tenant_id", { ascending: true })
				.order("id", { ascending: true })
				.limit(MAX_GROUPS + 1);
			if (groupsResult.error || exceededLimit(groupsResult.data, MAX_GROUPS)) return unavailable(req);
			const groupRows = (groupsResult.data ?? []) as Row[];
			if (
				groupRows.some(
					(row) =>
						!isUuid(row.tenant_id) ||
						!activeTenantIds.includes(String(row.tenant_id)) ||
						!isUuid(row.id) ||
						!groupIds.includes(String(row.id)) ||
						typeof row.display_name !== "string" ||
						externalId(row.external_id) === null,
					)
				)
				return unavailable(req);
			const groupExternalIds = [...new Set(groupRows.map((row) => externalId(row.external_id) as string))];
			if (groupExternalIds.length === 0) return groupResponse(req, userId, []);

			const mappingsResult = await db.from("scim_group_role_mappings")
				.select("tenant_id,external_group_id,role")
				.in("tenant_id", activeTenantIds)
				.in("external_group_id", groupExternalIds)
				.order("tenant_id", { ascending: true })
				.order("external_group_id", { ascending: true })
				.limit(MAX_GROUPS + 1);
			if (mappingsResult.error || exceededLimit(mappingsResult.data, MAX_GROUPS)) return unavailable(req);
			const roles = new Map<string, string>();
			for (const row of (mappingsResult.data ?? []) as Row[]) {
				const id = externalId(row.external_group_id);
				const role = typeof row.role === "string" && VERIFIED_ROLES.has(row.role) ? row.role : null;
				const tenantId = String(row.tenant_id);
				if (!isUuid(row.tenant_id) || !activeTenantIds.includes(tenantId) || !id || !groupExternalIds.includes(id) || !role) return unavailable(req);
				roles.set(`${tenantId}:${id}`, role);
			}

			const seen = new Set<string>();
			const returnedGroupKeys = new Set<string>();
			const groups: Array<Record<string, unknown>> = [];
			for (const row of groupRows) {
				const tenantId = String(row.tenant_id);
				const groupId = String(row.id);
				const groupKey = `${tenantId}:${groupId}`;
				if (!groupKeys.has(groupKey)) continue;
				const immutableId = externalId(row.external_id);
				if (!immutableId) return unavailable(req);
				const key = `${tenantId}:${immutableId}`;
				if (seen.has(key)) return unavailable(req);
				seen.add(key);
				returnedGroupKeys.add(groupKey);
				const displayName = row.display_name as string;
				groups.push({
					id: immutableId,
					external_id: immutableId,
					display_name: displayName,
					tenant_id: tenantId,
					...(roles.has(key) ? { role: roles.get(key) } : {}),
				});
			}
			if ([...groupKeys].some((key) => !returnedGroupKeys.has(key))) return unavailable(req);
			return groupResponse(req, userId, groups);
		} catch {
			return unavailable(req);
		}
	};
}

Deno.serve(createAzureAdGroupsHandler());
