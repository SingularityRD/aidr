import { createClient } from "npm:@supabase/supabase-js@2";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { collectMemberPages } from "./member-pages.ts";
import {
	createScimHandler,
	ScimConflictError,
	type ScimCreateGroup,
	type ScimCreateUser,
	type ScimFilter,
	type ScimGroup,
	type ScimList,
	type ScimStore,
	type ScimTenant,
	type ScimUser,
} from "./scim.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

type Db = ReturnType<typeof createClient>;
type Row = Record<string, unknown>;

async function sha256(input: string): Promise<string> {
	const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function asIso(value: unknown): string {
	return typeof value === "string" ? value : new Date(0).toISOString();
}

function asUser(row: Row): ScimUser {
	return {
		id: String(row.id),
		externalId: typeof row.external_id === "string" ? row.external_id : null,
		userName: String(row.user_name),
		displayName: typeof row.display_name === "string" ? row.display_name : null,
		active: row.active === true,
		version: Number(row.version),
		createdAt: asIso(row.created_at),
		updatedAt: asIso(row.updated_at),
	};
}

function conflictFrom(error: { code?: string; message?: string } | null): never {
	const message = error?.message ?? "SCIM persistence failed";
	if (error?.code === "40001" || message.includes("scim_version_mismatch")) throw new ScimConflictError("versionMismatch", "Resource version does not match");
	if (error?.code === "23505" || message.includes("conflict")) throw new ScimConflictError("uniqueness", "Resource identity already exists with different attributes");
	throw new Error("SCIM persistence unavailable");
}

class SupabaseScimStore implements ScimStore {
	constructor(private readonly db: Db) {}

	async authenticate(token: string): Promise<ScimTenant | null> {
		if (token.length < 32 || token.length > 4096) return null;
		const result = await this.db.rpc("scim_resolve_token", { p_token_hash: await sha256(token) });
		if (result.error) throw new Error("SCIM authentication storage unavailable");
		const row = (Array.isArray(result.data) ? result.data[0] : result.data) as Row | null;
		return row?.tenant_id && row?.token_id ? { tenantId: String(row.tenant_id), tokenId: String(row.token_id) } : null;
	}

	private async usersQuery(tenantId: string, offset: number, limit: number, filter: ScimFilter | null): Promise<ScimList<ScimUser>> {
		let query = this.db.from("scim_users").select("*", { count: "exact" }).eq("tenant_id", tenantId).order("id", { ascending: true });
		if (filter?.attribute === "userName") query = query.eq("normalized_user_name", filter.value.trim().toLowerCase());
		if (filter?.attribute === "externalId") query = query.eq("external_id", filter.value);
		query = limit === 0 ? query.limit(0) : query.range(offset, offset + limit - 1);
		const result = await query;
		if (result.error) throw new Error("SCIM user list unavailable");
		return { items: ((result.data ?? []) as Row[]).map(asUser), total: result.count ?? 0 };
	}

	listUsers(tenantId: string, offset: number, limit: number, filter: ScimFilter | null): Promise<ScimList<ScimUser>> {
		return this.usersQuery(tenantId, offset, limit, filter);
	}

	async getUser(tenantId: string, id: string): Promise<ScimUser | null> {
		const result = await this.db.from("scim_users").select("*").eq("tenant_id", tenantId).eq("id", id).maybeSingle();
		if (result.error) throw new Error("SCIM user lookup unavailable");
		return result.data ? asUser(result.data as Row) : null;
	}

	private async authUserByEmail(tenantId: string, email: string): Promise<string | null> {
		const result = await this.db.rpc("scim_user_id_by_email", { p_tenant_id: tenantId, p_email: email });
		if (result.error) throw new Error("SCIM identity lookup unavailable");
		return typeof result.data === "string" && result.data ? result.data : null;
	}

	async createUser(tenantId: string, input: ScimCreateUser): Promise<{ user: ScimUser; created: boolean }> {
		const claimed = await this.db.rpc("scim_claim_user", {
			p_tenant_id: tenantId, p_external_id: input.externalId, p_user_name: input.userName,
			p_display_name: input.displayName, p_active: input.active,
		});
		if (claimed.error) conflictFrom(claimed.error);
		const claim = (Array.isArray(claimed.data) ? claimed.data[0] : claimed.data) as Row | null;
		if (!claim?.user_id) throw new Error("SCIM user claim returned no resource");
		const scimId = String(claim.user_id);
		let rowResult = await this.db.from("scim_users").select("*").eq("tenant_id", tenantId).eq("id", scimId).single();
		if (rowResult.error || !rowResult.data) throw new Error("SCIM claimed user unavailable");
		let row = rowResult.data as Row;
		if (!row.auth_user_id) {
			let authUserId = await this.authUserByEmail(tenantId, input.userName);
			if (!authUserId) {
				const created = await this.db.auth.admin.createUser({
					email: input.userName,
					email_confirm: true,
					app_metadata: { aidr_scim_provisioned: true },
					user_metadata: input.displayName ? { display_name: input.displayName } : {},
				});
				if (created.error || !created.data.user?.id) {
					authUserId = await this.authUserByEmail(input.userName);
					if (!authUserId) throw new Error("SCIM auth user creation failed");
				} else authUserId = created.data.user.id;
			}
			const bound = await this.db.rpc("scim_bind_user", { p_tenant_id: tenantId, p_scim_user_id: scimId, p_auth_user_id: authUserId });
			if (bound.error) conflictFrom(bound.error);
			rowResult = await this.db.from("scim_users").select("*").eq("tenant_id", tenantId).eq("id", scimId).single();
			if (rowResult.error || !rowResult.data) throw new Error("SCIM bound user unavailable");
			row = rowResult.data as Row;
		}
		return { user: asUser(row), created: claim.created === true };
	}

	async updateUser(tenantId: string, id: string, input: ScimCreateUser, expectedVersion: number | null): Promise<ScimUser | null> {
		const result = await this.db.rpc("scim_update_user", {
			p_tenant_id: tenantId, p_scim_user_id: id, p_display_name: input.displayName,
			p_active: input.active, p_expected_version: expectedVersion,
		});
		if (result.error) conflictFrom(result.error);
		return result.data === false ? null : await this.getUser(tenantId, id);
	}

	async deactivateUser(tenantId: string, id: string, expectedVersion: number | null): Promise<ScimUser | null> {
		const current = await this.getUser(tenantId, id);
		if (!current) return null;
		if (!current.active) {
			if (expectedVersion !== null && expectedVersion !== current.version) throw new ScimConflictError("versionMismatch", "Resource version does not match");
			return current;
		}
		return this.updateUser(tenantId, id, { externalId: current.externalId, userName: current.userName, displayName: current.displayName, active: false }, expectedVersion);
	}

	private async hydrateGroups(rows: Row[]): Promise<ScimGroup[]> {
		if (rows.length === 0) return [];
		const tenantId = String(rows[0]?.tenant_id);
		const groupIds = rows.map((row) => String(row.id));
		const memberships = await collectMemberPages<Row>(async (offset, limit) => {
			const result = await this.db.from("scim_group_memberships").select("group_id,user_id")
				.eq("tenant_id", tenantId).in("group_id", groupIds)
				.order("group_id", { ascending: true }).order("user_id", { ascending: true })
				.range(offset, offset + limit - 1);
			if (result.error) throw new Error("SCIM group membership lookup unavailable");
			return (result.data ?? []) as Row[];
		});
		const userIds = [...new Set(memberships.map((member) => String(member.user_id)))];
		const names = new Map<string, string>();
		for (let offset = 0; offset < userIds.length; offset += 200) {
			const users = await this.db.from("scim_users").select("id,user_name")
				.eq("tenant_id", tenantId).in("id", userIds.slice(offset, offset + 200));
			if (users.error) throw new Error("SCIM group member lookup unavailable");
			for (const user of (users.data ?? []) as Row[]) names.set(String(user.id), String(user.user_name));
		}
		return rows.map((row) => ({
			id: String(row.id), externalId: String(row.external_id), displayName: String(row.display_name), version: Number(row.version),
			createdAt: asIso(row.created_at), updatedAt: asIso(row.updated_at),
			members: memberships.filter((member) => member.group_id === row.id).map((member) => ({ value: String(member.user_id), ...(names.has(String(member.user_id)) ? { display: names.get(String(member.user_id)) } : {}) })),
		}));
	}

	async listGroups(tenantId: string, offset: number, limit: number, filter: ScimFilter | null): Promise<ScimList<ScimGroup>> {
		let query = this.db.from("scim_groups").select("*", { count: "exact" }).eq("tenant_id", tenantId).order("id", { ascending: true });
		if (filter?.attribute === "externalId") query = query.eq("external_id", filter.value);
		if (filter?.attribute === "displayName") query = query.eq("display_name", filter.value);
		query = limit === 0 ? query.limit(0) : query.range(offset, offset + limit - 1);
		const result = await query;
		if (result.error) throw new Error("SCIM group list unavailable");
		return { items: await this.hydrateGroups((result.data ?? []) as Row[]), total: result.count ?? 0 };
	}

	async getGroup(tenantId: string, id: string): Promise<ScimGroup | null> {
		const result = await this.db.from("scim_groups").select("*").eq("tenant_id", tenantId).eq("id", id).maybeSingle();
		if (result.error) throw new Error("SCIM group lookup unavailable");
		return result.data ? (await this.hydrateGroups([result.data as Row]))[0] ?? null : null;
	}

	async createGroup(tenantId: string, input: ScimCreateGroup): Promise<{ group: ScimGroup; created: boolean }> {
		const result = await this.db.rpc("scim_create_group", {
			p_tenant_id: tenantId, p_external_id: input.externalId, p_display_name: input.displayName, p_user_ids: input.members,
		});
		if (result.error) conflictFrom(result.error);
		const row = (Array.isArray(result.data) ? result.data[0] : result.data) as Row | null;
		if (!row?.group_id) throw new Error("SCIM group create returned no resource");
		const group = await this.getGroup(tenantId, String(row.group_id));
		if (!group) throw new Error("SCIM created group unavailable");
		return { group, created: row.created === true };
	}

	async updateGroup(tenantId: string, id: string, input: ScimCreateGroup, expectedVersion: number | null): Promise<ScimGroup | null> {
		const result = await this.db.rpc("scim_update_group", {
			p_tenant_id: tenantId, p_group_id: id, p_display_name: input.displayName,
			p_user_ids: input.members, p_expected_version: expectedVersion,
		});
		if (result.error) conflictFrom(result.error);
		return result.data === false ? null : await this.getGroup(tenantId, id);
	}

	async deleteGroup(tenantId: string, id: string, expectedVersion: number | null): Promise<boolean> {
		const result = await this.db.rpc("scim_delete_group", { p_tenant_id: tenantId, p_group_id: id, p_expected_version: expectedVersion });
		if (result.error) conflictFrom(result.error);
		return result.data === true;
	}
}

Deno.serve(async (req) => {
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (config.ok === false) return configFailure("scim", config.error, (status, body) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/scim+json", "Cache-Control": "no-store" } }));
	const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false, autoRefreshToken: false } });
	return createScimHandler(new SupabaseScimStore(db))(req);
});
