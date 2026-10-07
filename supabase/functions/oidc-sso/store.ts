// Supabase-backed OidcStore. Every method fails closed: a database error becomes
// null / false / "error" / "unavailable", never a permissive default.

import type { SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import type { MappedRole, OidcAlgorithm, OidcDiscovery } from "./oidc.ts";
import { SUPPORTED_ALGORITHMS } from "./oidc.ts";
import { type FeatureDecision, requireFeature } from "../_shared/plan-entitlements.ts";
import type {
	AuditValues,
	DomainRow,
	OidcAuthRequestRow,
	OidcPolicyRow,
	OidcProviderRow,
	OidcStore,
	RateLimitDecision,
} from "./types.ts";

// deno-lint-ignore no-explicit-any
type Db = SupabaseClient<any, "public">;
type Row = Record<string, unknown>;

const PROVIDER_COLUMNS =
	"id,tenant_id,kind,display_name,issuer,client_id,client_secret_ref,token_auth_method,allowed_algs,subject_claim,groups_claim,groups_mode,session_max_seconds,clock_skew_seconds,discovery,enabled";
const REQUEST_COLUMNS =
	"state_hash,provider_id,tenant_id,nonce_hash,code_verifier,binding_hash,redirect_uri,mode,link_user_id,expires_at";

function asDiscovery(value: unknown): OidcDiscovery | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const doc = value as Row;
	if (
		typeof doc.issuer !== "string" ||
		typeof doc.authorization_endpoint !== "string" ||
		typeof doc.token_endpoint !== "string" ||
		typeof doc.jwks_uri !== "string"
	)
		return null;
	return {
		issuer: doc.issuer,
		authorization_endpoint: doc.authorization_endpoint,
		token_endpoint: doc.token_endpoint,
		jwks_uri: doc.jwks_uri,
		...(Array.isArray(doc.id_token_signing_alg_values_supported)
			? { id_token_signing_alg_values_supported: doc.id_token_signing_alg_values_supported.filter((item): item is string => typeof item === "string") }
			: {}),
	};
}

function asProvider(row: Row): OidcProviderRow | null {
	const algs = Array.isArray(row.allowed_algs)
		? (row.allowed_algs as unknown[]).filter((alg): alg is OidcAlgorithm => SUPPORTED_ALGORITHMS.includes(alg as OidcAlgorithm))
		: [];
	if (typeof row.id !== "string" || typeof row.tenant_id !== "string" || algs.length === 0) return null;
	return {
		id: row.id,
		tenant_id: row.tenant_id,
		kind: row.kind as OidcProviderRow["kind"],
		display_name: String(row.display_name),
		issuer: String(row.issuer),
		client_id: String(row.client_id),
		client_secret_ref: typeof row.client_secret_ref === "string" ? row.client_secret_ref : null,
		token_auth_method: row.token_auth_method as OidcProviderRow["token_auth_method"],
		allowed_algs: algs,
		subject_claim: row.subject_claim === "oid" ? "oid" : "sub",
		groups_claim: typeof row.groups_claim === "string" ? row.groups_claim : null,
		groups_mode: row.groups_mode === "require_mapped" ? "require_mapped" : "ignore",
		session_max_seconds: Number(row.session_max_seconds),
		clock_skew_seconds: Number(row.clock_skew_seconds),
		discovery: asDiscovery(row.discovery),
		enabled: row.enabled === true,
	};
}

function asRequest(row: Row): OidcAuthRequestRow {
	return {
		state_hash: String(row.state_hash),
		provider_id: String(row.provider_id),
		tenant_id: String(row.tenant_id),
		nonce_hash: String(row.nonce_hash),
		code_verifier: String(row.code_verifier),
		binding_hash: String(row.binding_hash),
		redirect_uri: String(row.redirect_uri),
		mode: row.mode === "link" ? "link" : "login",
		link_user_id: typeof row.link_user_id === "string" ? row.link_user_id : null,
		expires_at: String(row.expires_at),
	};
}

export class SupabaseOidcStore implements OidcStore {
	constructor(private readonly db: Db) {}

	private async providerWhere(column: string, value: string): Promise<OidcProviderRow | null> {
		const { data, error } = await this.db.from("oidc_providers").select(PROVIDER_COLUMNS).eq(column, value).maybeSingle();
		return error || !data ? null : asProvider(data as Row);
	}

	findProviderById(id: string) {
		return this.providerWhere("id", id);
	}

	findProviderByTenant(tenantId: string) {
		return this.providerWhere("tenant_id", tenantId);
	}

	async findProviderByVerifiedDomain(domain: string): Promise<OidcProviderRow | null> {
		const { data, error } = await this.db
			.from("oidc_tenant_domains")
			.select("tenant_id")
			.eq("domain", domain)
			.not("verified_at", "is", null)
			.maybeSingle();
		if (error || !data) return null;
		return this.findProviderByTenant(String((data as Row).tenant_id));
	}

	async saveProvider(row: OidcProviderRow, actorUserId: string): Promise<boolean> {
		const { error } = await this.db.from("oidc_providers").upsert(
			{
				id: row.id,
				tenant_id: row.tenant_id,
				kind: row.kind,
				display_name: row.display_name,
				issuer: row.issuer,
				client_id: row.client_id,
				client_secret_ref: row.client_secret_ref,
				token_auth_method: row.token_auth_method,
				allowed_algs: row.allowed_algs,
				subject_claim: row.subject_claim,
				groups_claim: row.groups_claim,
				groups_mode: row.groups_mode,
				session_max_seconds: row.session_max_seconds,
				clock_skew_seconds: row.clock_skew_seconds,
				discovery: row.discovery,
				discovery_fetched_at: row.discovery ? new Date().toISOString() : null,
				enabled: row.enabled,
				created_by: actorUserId,
			},
			{ onConflict: "id" },
		);
		return !error;
	}

	async createAuthRequest(row: OidcAuthRequestRow): Promise<boolean> {
		const { error } = await this.db.from("oidc_auth_requests").insert(row);
		return !error;
	}

	async pendingAuthRequest(stateHash: string, nowIso: string): Promise<{ provider_id: string } | null | "error"> {
		// Unique-index lookup, no write: lets the callback reject unknown state before counting.
		const { data, error } = await this.db
			.from("oidc_auth_requests")
			.select("provider_id")
			.eq("state_hash", stateHash)
			.is("consumed_at", null)
			.gt("expires_at", nowIso)
			.maybeSingle();
		if (error) return "error";
		const providerId = (data as Row | null)?.provider_id;
		return typeof providerId === "string" ? { provider_id: providerId } : null;
	}

	async consumeAuthRequest(stateHash: string, nowIso: string): Promise<OidcAuthRequestRow | null> {
		// One statement: only the first presenter of an unexpired, unconsumed state gets a row.
		const { data, error } = await this.db
			.from("oidc_auth_requests")
			.update({ consumed_at: nowIso })
			.eq("state_hash", stateHash)
			.is("consumed_at", null)
			.gt("expires_at", nowIso)
			.select(REQUEST_COLUMNS)
			.maybeSingle();
		return error || !data ? null : asRequest(data as Row);
	}

	async groupMappings(tenantId: string): Promise<ReadonlyMap<string, MappedRole> | null> {
		const { data, error } = await this.db
			.from("scim_group_role_mappings")
			.select("external_group_id,role")
			.eq("tenant_id", tenantId)
			.limit(1000);
		if (error || !data) return null;
		const mappings = new Map<string, MappedRole>();
		for (const row of data as Row[]) {
			if (row.role === "admin" || row.role === "member" || row.role === "viewer")
				mappings.set(String(row.external_group_id), row.role);
		}
		return mappings;
	}

	async verifiedDomains(tenantId: string): Promise<string[] | null> {
		const { data, error } = await this.db
			.from("oidc_tenant_domains")
			.select("domain")
			.eq("tenant_id", tenantId)
			.not("verified_at", "is", null);
		return error || !data ? null : (data as Row[]).map((row) => String(row.domain));
	}

	async listDomains(tenantId: string): Promise<DomainRow[] | null> {
		const { data, error } = await this.db
			.from("oidc_tenant_domains")
			.select("tenant_id,domain,verification_token,verified_at")
			.eq("tenant_id", tenantId)
			.order("domain")
			.limit(100);
		return error || !data ? null : (data as DomainRow[]);
	}

	async addDomain(tenantId: string, domain: string, token: string, actorUserId: string): Promise<DomainRow | null> {
		const columns = "tenant_id,domain,verification_token,verified_at";
		const existing = await this.db.from("oidc_tenant_domains").select(columns).eq("tenant_id", tenantId).eq("domain", domain).maybeSingle();
		if (existing.error) return null;
		if (existing.data) return existing.data as DomainRow;
		const { data, error } = await this.db
			.from("oidc_tenant_domains")
			.insert({ tenant_id: tenantId, domain, verification_token: token, created_by: actorUserId })
			.select(columns)
			.maybeSingle();
		return error || !data ? null : (data as DomainRow);
	}

	async markDomainVerified(tenantId: string, domain: string): Promise<"verified" | "taken" | "error"> {
		const { error } = await this.db
			.from("oidc_tenant_domains")
			.update({ verified_at: new Date().toISOString() })
			.eq("tenant_id", tenantId)
			.eq("domain", domain)
			.is("verified_at", null);
		if (!error) return "verified";
		// 23505 on oidc_tenant_domains_verified_unique: another tenant already proved this domain.
		return (error as { code?: string }).code === "23505" ? "taken" : "error";
	}

	async removeDomain(tenantId: string, domain: string): Promise<boolean> {
		const { error } = await this.db.from("oidc_tenant_domains").delete().eq("tenant_id", tenantId).eq("domain", domain);
		return !error;
	}

	async findIdentity(providerId: string, subject: string) {
		const { data, error } = await this.db.from("oidc_identities").select("auth_user_id").eq("provider_id", providerId).eq("subject", subject).maybeSingle();
		return error || !data ? null : { auth_user_id: String((data as Row).auth_user_id) };
	}

	async findIdentityForUser(providerId: string, userId: string) {
		const { data, error } = await this.db.from("oidc_identities").select("subject").eq("provider_id", providerId).eq("auth_user_id", userId).maybeSingle();
		return error || !data ? null : { subject: String((data as Row).subject) };
	}

	async insertIdentity(
		row: Parameters<OidcStore["insertIdentity"]>[0],
		provider: Parameters<OidcStore["insertIdentity"]>[1],
	): Promise<"ok" | "conflict" | "error"> {
		const { error } = await this.db.rpc("oidc_insert_identity", {
			p_provider_id: row.provider_id, p_tenant_id: row.tenant_id,
			p_subject: row.subject, p_auth_user_id: row.auth_user_id, p_email_claim: row.email_claim,
			p_expected_issuer: provider.issuer, p_expected_client_id: provider.client_id,
			p_expected_subject_claim: provider.subject_claim,
		});
		if (!error) return "ok";
		return (error as { code?: string }).code === "23505" ? "conflict" : "error";
	}

	async touchIdentity(providerId: string, subject: string): Promise<void> {
		await this.db.from("oidc_identities").update({ last_login_at: new Date().toISOString() }).eq("provider_id", providerId).eq("subject", subject);
	}

	async scimSubjectCompatible(tenantId: string, userId: string, subject: string): Promise<boolean> {
		const { data, error } = await this.db.from("scim_users").select("external_id").eq("tenant_id", tenantId).eq("auth_user_id", userId).maybeSingle();
		if (error) return false;
		return !data || (data as Row).external_id === subject;
	}

	async createAuthUser(input: { providerId: string; tenantId: string; subject: string }): Promise<string | null> {
		const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(`${input.providerId}:${input.subject}`));
		const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
		// Never the IdP's email: a same-email account must not be linked. The synthetic
		// address is unroutable (.invalid) and the user has no password.
		const { data, error } = await this.db.auth.admin.createUser({
			email: `oidc-${hex.slice(0, 40)}@sso.aidr.invalid`,
			email_confirm: true,
			app_metadata: {
				// Same marker the SCIM path uses so the signup trigger creates no personal workspace.
				aidr_scim_provisioned: true,
				aidr_oidc_provider_id: input.providerId,
				aidr_oidc_tenant_id: input.tenantId,
			},
		});
		return error || !data.user?.id ? null : data.user.id;
	}

	async deleteAuthUser(userId: string): Promise<void> {
		await this.db.auth.admin.deleteUser(userId);
	}

	async generateSessionTokenHash(userId: string): Promise<string | null> {
		const { data: user, error: userError } = await this.db.auth.admin.getUserById(userId);
		const email = user?.user?.email;
		if (userError || !email) return null;
		const { data, error } = await this.db.auth.admin.generateLink({ type: "magiclink", email });
		const hash = data?.properties?.hashed_token;
		if (error || data?.user?.id !== userId || typeof hash !== "string" || !/^[0-9a-f]{64}$/i.test(hash)) return null;
		return hash;
	}

	async createLoginTicket(row: Parameters<OidcStore["createLoginTicket"]>[0]): Promise<boolean> {
		const { error } = await this.db.from("oidc_login_tickets").insert(row);
		return !error;
	}

	async recordSsoSession(ticketHash: string, userId: string, sessionId: string) {
		const { data, error } = await this.db.rpc("oidc_record_sso_session", {
			p_ticket_hash: ticketHash,
			p_user_id: userId,
			p_session_id: sessionId,
		});
		const value = data && typeof data === "object" ? (data as Row) : null;
		if (error || !value || typeof value.provider_id !== "string") return null;
		return { provider_id: value.provider_id, tenant_id: String(value.tenant_id), expires_at: String(value.expires_at) };
	}

	async bindScimIdentity(providerId: string, authUserId: string): Promise<string | null> {
		const { data, error } = await this.db.rpc("oidc_bind_scim_identity", { p_provider_id: providerId, p_auth_user_id: authUserId });
		if (error) throw new Error("scim_bind_failed");
		return typeof data === "string" ? data : null;
	}

	async memberRole(userId: string, tenantId: string): Promise<string | null> {
		const { data, error } = await this.db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
		if (error || !data) return null;
		const row = data as Row;
		if (typeof row.expires_at === "string" && Date.parse(row.expires_at) <= Date.now()) return null;
		const tenant = await this.db.from("tenants").select("status").eq("id", tenantId).maybeSingle();
		if (tenant.error || (tenant.data as Row | null)?.status !== "active") return null;
		return typeof row.role === "string" ? row.role : null;
	}

	requireSsoFeature(tenantId: string): Promise<FeatureDecision> {
		return requireFeature(this.db, tenantId, "entra_sso");
	}

	async policy(tenantId: string): Promise<OidcPolicyRow | null> {
		const { data, error } = await this.db
			.from("tenant_identity_policies")
			.select("required_oidc_provider_id,required_saml_provider_id,break_glass_enabled,require_mfa")
			.eq("tenant_id", tenantId)
			.maybeSingle();
		if (error) return null;
		const row = (data ?? {}) as Row;
		// No row means "no enforcement"; an unreadable row never does.
		return {
			required_oidc_provider_id: typeof row.required_oidc_provider_id === "string" ? row.required_oidc_provider_id : null,
			required_saml_provider_id: typeof row.required_saml_provider_id === "string" ? row.required_saml_provider_id : null,
			break_glass_enabled: row.break_glass_enabled === true,
			require_mfa: row.require_mfa === true,
		};
	}

	async setEnforcement(input: Parameters<OidcStore["setEnforcement"]>[0]) {
		const { error } = await this.db.rpc("oidc_set_enforcement", {
			p_tenant_id: input.tenantId,
			p_actor_user_id: input.actorUserId,
			p_session_id: input.sessionId,
			p_provider_id: input.providerId,
			p_reason: input.reason,
			p_change_ref: input.changeRef,
		});
		if (!error) return { ok: true as const };
		const message = (error as { message?: string }).message ?? "";
		const code = /oidc_[a-z_]+|invalid_oidc_enforcement_request/.exec(message)?.[0];
		return { ok: false as const, error: code ?? "oidc_enforcement_failed" };
	}

	async breakGlassSuspend(input: { email: string; codeHash: string; requestId: string }) {
		const { data, error } = await this.db.rpc("oidc_break_glass_suspend", {
			p_email: input.email,
			p_code_hash: input.codeHash,
			p_request_id: input.requestId,
		});
		if (error) return "error" as const;
		const value = data && typeof data === "object" ? (data as Row) : null;
		return value && typeof value.tenant_id === "string" && typeof value.user_id === "string"
			? { tenant_id: value.tenant_id, user_id: value.user_id }
			: null;
	}

	async audit(values: AuditValues): Promise<boolean> {
		const { error } = await this.db.from("admin_audit_logs").insert(values);
		return !error;
	}

	async rateLimit(key: string, windowMs: number, maximum: number): Promise<RateLimitDecision> {
		const windowStart = Math.floor(Date.now() / windowMs);
		const increment = await this.db.rpc("increment_rate_limit", { p_key: key, p_window_start: windowStart, p_delta: 1 });
		if (increment.error) return "unavailable";
		const { data, error } = await this.db.from("rate_limits").select("count").eq("key", key).eq("window_start", windowStart).maybeSingle();
		const count = (data as Row | null)?.count;
		if (error || typeof count !== "number" || !Number.isSafeInteger(count) || count < 1) return "unavailable";
		return count <= maximum ? "allowed" : "limited";
	}
}
