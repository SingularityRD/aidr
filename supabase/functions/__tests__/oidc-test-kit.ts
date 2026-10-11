// Shared fixtures for the OIDC SSO tests: real WebCrypto signing keys, a JWT
// minter, a fake IdP and an in-memory OidcStore. No mocks of the code under
// test: signatures are genuinely produced and genuinely verified.

import { requireFeature } from "../_shared/plan-entitlements.ts";
import { CLIENT_SECRET_BINDINGS_ENV, CLIENT_SECRET_ENV_PREFIX, resolveClientSecret } from "../oidc-sso/client-secrets.ts";
import { base64UrlEncode, type Jwk, type MappedRole, type OidcAlgorithm, type OidcDiscovery } from "../oidc-sso/oidc.ts";
import type {
	AuditValues,
	AuthenticatedCaller,
	AuthenticationFailure,
	DomainRow,
	OidcAuthRequestRow,
	OidcDeps,
	OidcPolicyRow,
	OidcProviderRow,
	OidcStore,
	ProviderAudit,
	RateLimitDecision,
	RefreshDiscoveryResult,
	SaveProviderResult,
} from "../oidc-sso/types.ts";

const encoder = new TextEncoder();

/** A `tenant_plan_entitlements` row for a plan that includes SSO administration. */
export function entitledPlan(tenantId: string, overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		tenant_id: tenantId,
		plan_id: "team",
		plan_source: "team_record",
		trial_active: false,
		features: ["local_detection", "dashboard", "browser_privacy_guard", "entra_sso"],
		retention_days_max: 90,
		...overrides,
	};
}

export function freePlan(tenantId: string): Record<string, unknown> {
	return entitledPlan(tenantId, { plan_id: "free", plan_source: "default", features: ["local_detection", "dashboard"], retention_days_max: 7 });
}

export interface TestKey {
	kid: string;
	alg: OidcAlgorithm;
	publicJwk: Jwk;
	privateKey: CryptoKey;
}

export async function makeKey(alg: OidcAlgorithm, kid: string, modulusLength = 2048): Promise<TestKey> {
	let pair: CryptoKeyPair;
	if (alg === "ES256") {
		pair = (await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign", "verify"])) as CryptoKeyPair;
	} else {
		pair = (await crypto.subtle.generateKey(
			{
				name: alg === "RS256" ? "RSASSA-PKCS1-v1_5" : "RSA-PSS",
				modulusLength,
				publicExponent: new Uint8Array([1, 0, 1]),
				hash: "SHA-256",
			},
			true,
			["sign", "verify"],
		)) as CryptoKeyPair;
	}
	const exported = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as Jwk;
	const publicJwk: Jwk = { kty: exported.kty, kid, use: "sig", alg };
	if (alg === "ES256") Object.assign(publicJwk, { crv: exported.crv, x: exported.x, y: exported.y });
	else Object.assign(publicJwk, { n: exported.n, e: exported.e });
	return { kid, alg, publicJwk, privateKey: pair.privateKey };
}

async function sign(alg: string, key: CryptoKey | null, input: string): Promise<string> {
	if (!key) return "";
	const data = encoder.encode(input);
	const params =
		alg === "ES256"
			? { name: "ECDSA", hash: "SHA-256" }
			: alg === "PS256"
				? { name: "RSA-PSS", saltLength: 32 }
				: { name: "RSASSA-PKCS1-v1_5" };
	return base64UrlEncode(new Uint8Array(await crypto.subtle.sign(params, key, data)));
}

export interface MintOptions {
	key: TestKey | null;
	/** Override the JOSE header (for example `alg: "none"`). */
	header?: Record<string, unknown>;
	claims: Record<string, unknown>;
	/** Sign with a different key than the header claims (tampering tests). */
	signWith?: CryptoKey | null;
	rawSignature?: string;
}

export async function mintJwt(options: MintOptions): Promise<string> {
	const header = { alg: options.key?.alg ?? "none", typ: "JWT", ...(options.key ? { kid: options.key.kid } : {}), ...options.header };
	const encodedHeader = base64UrlEncode(encoder.encode(JSON.stringify(header)));
	const encodedPayload = base64UrlEncode(encoder.encode(JSON.stringify(options.claims)));
	const signingInput = `${encodedHeader}.${encodedPayload}`;
	const signature =
		options.rawSignature ??
		(await sign(String(header.alg), options.signWith === undefined ? (options.key?.privateKey ?? null) : options.signWith, signingInput));
	return `${signingInput}.${signature}`;
}

export const NOW_MS = Date.parse("2026-10-05T12:00:00.000Z");
export const NOW_S = Math.floor(NOW_MS / 1000);

export function sha256Text(value: string): Promise<string> {
	return crypto.subtle.digest("SHA-256", encoder.encode(value)).then((digest) =>
		Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""),
	);
}

export const TENANT_A = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
export const TENANT_B = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
export const PROVIDER_A = "a1a1a1a1-a1a1-4a1a-8a1a-a1a1a1a1a1a1";
export const PROVIDER_B = "b2b2b2b2-b2b2-4b2b-8b2b-b2b2b2b2b2b2";
export const OWNER_A = "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a0a";
export const OWNER_A2 = "0a0a0a0a-0a0a-4a0a-8a0a-0a0a0a0a0a02";
export const MEMBER_A = "1a1a1a1a-1a1a-4a1a-8a1a-1a1a1a1a1a1a";
export const OWNER_B = "0b0b0b0b-0b0b-4b0b-8b0b-0b0b0b0b0b0b";
export const SESSION_1 = "5e5e5e5e-5e5e-4e5e-8e5e-5e5e5e5e5e5e";

export const ISSUER_A = "https://login.microsoftonline.com/11111111-2222-4333-8444-555555555555/v2.0";
export const ISSUER_B = "https://tenant-b.okta.com/oauth2/default";

export interface IdpFixture {
	issuer: string;
	discoveryUrl: string;
	authorizationEndpoint: string;
	tokenEndpoint: string;
	jwksUri: string;
	keys: TestKey[];
	/** What the token endpoint returns for the next exchange. */
	nextIdToken: string | null;
	requests: Array<{ url: string; method: string; body?: string; authorization?: string }>;
	discoveryOverride?: Record<string, unknown>;
	failTokenEndpoint?: boolean;
	failJwks?: boolean;
	jwksFetches: number;
}

export function makeIdp(issuer: string, keys: TestKey[], host = new URL(issuer).origin): IdpFixture {
	const path = new URL(issuer).pathname.replace(/\/$/, "");
	return {
		issuer,
		discoveryUrl: `${issuer.replace(/\/+$/, "")}/.well-known/openid-configuration`,
		authorizationEndpoint: `${host}${path}/oauth2/v2.0/authorize`,
		tokenEndpoint: `${host}${path}/oauth2/v2.0/token`,
		jwksUri: `${host}${path}/discovery/v2.0/keys`,
		keys,
		nextIdToken: null,
		requests: [],
		jwksFetches: 0,
	};
}

function idpFetch(idps: IdpFixture[]): OidcDeps["fetchJson"] {
	return async (url, init) => {
		const idp = idps.find((candidate) => [candidate.discoveryUrl, candidate.tokenEndpoint, candidate.jwksUri].includes(url));
		if (!idp) return { ok: false, error: "blocked_host" };
		const headers = (init?.headers ?? {}) as Record<string, string>;
		idp.requests.push({ url, method: init?.method ?? "GET", body: typeof init?.body === "string" ? init.body : undefined, authorization: headers.authorization });
		if (url === idp.discoveryUrl) {
			return {
				ok: true,
				json: {
					issuer: idp.issuer,
					authorization_endpoint: idp.authorizationEndpoint,
					token_endpoint: idp.tokenEndpoint,
					jwks_uri: idp.jwksUri,
					response_types_supported: ["code", "id_token"],
					code_challenge_methods_supported: ["S256", "plain"],
					id_token_signing_alg_values_supported: ["RS256", "ES256"],
					...idp.discoveryOverride,
				},
			};
		}
		if (url === idp.jwksUri) {
			idp.jwksFetches += 1;
			return idp.failJwks ? { ok: false, error: "network_error" } : { ok: true, json: { keys: idp.keys.map((key) => key.publicJwk) } };
		}
		if (idp.failTokenEndpoint || !idp.nextIdToken) return { ok: false, error: "http_status", status: 400 };
		return { ok: true, json: { access_token: "unused", token_type: "Bearer", id_token: idp.nextIdToken } };
	};
}

export function baseClaims(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		iss: ISSUER_A,
		aud: "client-a",
		sub: "subject-1",
		oid: "oid-1",
		email: "alice@a-corp.test",
		iat: NOW_S - 5,
		exp: NOW_S + 3000,
		...overrides,
	};
}

export function providerRow(overrides: Partial<OidcProviderRow> = {}): OidcProviderRow {
	return {
		id: PROVIDER_A,
		tenant_id: TENANT_A,
		kind: "entra",
		display_name: "Contoso Entra",
		issuer: ISSUER_A,
		client_id: "client-a",
		client_secret_ref: "TENANT_A",
		token_auth_method: "client_secret_basic",
		allowed_algs: ["RS256"],
		subject_claim: "sub",
		groups_claim: null,
		groups_mode: "ignore",
		session_max_seconds: 43_200,
		clock_skew_seconds: 60,
		discovery: null,
		enabled: true,
		...overrides,
	};
}

class MemoryStore implements OidcStore {
	providers = new Map<string, OidcProviderRow>();
	requests = new Map<string, OidcAuthRequestRow & { consumed_at?: string }>();
	domains: DomainRow[] = [];
	identities: Array<{ provider_id: string; subject: string; auth_user_id: string; tenant_id: string; email_claim: string | null }> = [];
	tickets = new Map<string, { provider_id: string; tenant_id: string; auth_user_id: string; expires_at: string; consumed?: boolean }>();
	sessions = new Map<string, { user_id: string; provider_id: string; tenant_id: string; expires_at: string }>();
	policies = new Map<string, OidcPolicyRow>();
	members = new Map<string, string>(); // `${tenant}:${user}` -> role
	mappings = new Map<string, Map<string, MappedRole>>();
	scimUsers: Array<{ tenant_id: string; external_id: string; auth_user_id: string | null }> = [];
	audits: AuditValues[] = [];
	authUsers = new Set<string>();
	deletedUsers: string[] = [];
	counters = new Map<string, number>();
	failAudit = false;
	failBind = false;
	enforcementCalls: Array<Parameters<OidcStore["setEnforcement"]>[0]> = [];
	enforcementResult: { ok: true } | { ok: false; error: string } = { ok: true };
	breakGlassResult: { tenant_id: string; user_id: string } | null | "error" = null;
	private userSeq = 0;
	clock: () => number = () => NOW_MS;

	async findProviderById(id: string) {
		return this.providers.get(id) ?? null;
	}
	async findProviderByTenant(tenantId: string) {
		return [...this.providers.values()].find((row) => row.tenant_id === tenantId) ?? null;
	}
	async findProviderByVerifiedDomain(domain: string) {
		const row = this.domains.find((candidate) => candidate.domain === domain && candidate.verified_at);
		return row ? this.findProviderByTenant(row.tenant_id) : null;
	}
	/**
	 * Models RPC oidc_save_provider: one transaction that re-checks the actor's
	 * live owner role at write time, upserts and audits. A failed audit insert
	 * rolls the provider write back; a non-owner writes nothing.
	 */
	async saveProvider(row: OidcProviderRow, actorUserId: string, audit: ProviderAudit): Promise<SaveProviderResult> {
		if (this.members.get(`${row.tenant_id}:${actorUserId}`) !== "owner") return "owner_required";
		const existing = this.providers.get(row.id);
		if (existing && existing.tenant_id !== row.tenant_id) return "owner_required";
		if (this.failAudit) return "error";
		this.providers.set(row.id, row);
		this.audits.push({
			actor_user_id: actorUserId,
			tenant_id: row.tenant_id,
			target_user_id: null,
			action: audit.action,
			detail: { ...audit.detail, provider_id: row.id },
		});
		return "saved";
	}
	/**
	 * Models RPC oidc_update_provider_discovery: owner re-check at write time,
	 * refusal when the issuer/algorithms changed since the read, then ONLY the
	 * discovery column of the CURRENT row changes, plus the audit row.
	 */
	async refreshProviderDiscovery(
		read: Pick<OidcProviderRow, "id" | "tenant_id" | "issuer" | "allowed_algs">,
		discovery: OidcDiscovery,
		actorUserId: string,
		auditDetail: Record<string, unknown>,
	): Promise<RefreshDiscoveryResult> {
		if (this.members.get(`${read.tenant_id}:${actorUserId}`) !== "owner") return "owner_required";
		const current = this.providers.get(read.id);
		if (!current) return "provider_changed";
		if (current.tenant_id !== read.tenant_id) return "owner_required";
		if (current.issuer !== read.issuer || current.allowed_algs.join(",") !== read.allowed_algs.join(",")) return "provider_changed";
		if (this.failAudit) return "error";
		this.providers.set(read.id, { ...current, discovery });
		this.audits.push({
			actor_user_id: actorUserId,
			tenant_id: read.tenant_id,
			target_user_id: null,
			action: "identity.oidc.discovery_refreshed",
			detail: { ...auditDetail, provider_id: read.id },
		});
		return "saved";
	}
	async createAuthRequest(row: OidcAuthRequestRow) {
		this.requests.set(row.state_hash, { ...row });
		return true;
	}
	pendingLookups = 0;
	failPendingLookup = false;
	async pendingAuthRequest(stateHash: string, nowIso: string) {
		this.pendingLookups += 1;
		if (this.failPendingLookup) return "error" as const;
		const row = this.requests.get(stateHash);
		return !row || row.consumed_at || row.expires_at <= nowIso ? null : { provider_id: row.provider_id };
	}
	async consumeAuthRequest(stateHash: string, nowIso: string) {
		const row = this.requests.get(stateHash);
		if (!row || row.consumed_at || row.expires_at <= nowIso) return null;
		row.consumed_at = nowIso;
		return { ...row };
	}
	async groupMappings(tenantId: string) {
		return this.mappings.get(tenantId) ?? new Map<string, MappedRole>();
	}
	async verifiedDomains(tenantId: string) {
		return this.domains.filter((row) => row.tenant_id === tenantId && row.verified_at).map((row) => row.domain);
	}
	async listDomains(tenantId: string) {
		return this.domains.filter((row) => row.tenant_id === tenantId);
	}
	async addDomain(tenantId: string, domain: string, token: string) {
		const existing = this.domains.find((row) => row.tenant_id === tenantId && row.domain === domain);
		if (existing) return existing;
		const row = { tenant_id: tenantId, domain, verification_token: token, verified_at: null };
		this.domains.push(row);
		return row;
	}
	async markDomainVerified(tenantId: string, domain: string) {
		if (this.domains.some((row) => row.domain === domain && row.verified_at && row.tenant_id !== tenantId)) return "taken" as const;
		const row = this.domains.find((candidate) => candidate.tenant_id === tenantId && candidate.domain === domain);
		if (row) row.verified_at = new Date(this.clock()).toISOString();
		return "verified" as const;
	}
	async removeDomain(tenantId: string, domain: string) {
		this.domains = this.domains.filter((row) => !(row.tenant_id === tenantId && row.domain === domain));
		return true;
	}
	async findIdentity(providerId: string, subject: string) {
		const row = this.identities.find((candidate) => candidate.provider_id === providerId && candidate.subject === subject);
		return row ? { auth_user_id: row.auth_user_id } : null;
	}
	async findIdentityForUser(providerId: string, userId: string) {
		const row = this.identities.find((candidate) => candidate.provider_id === providerId && candidate.auth_user_id === userId);
		return row ? { subject: row.subject } : null;
	}
	async insertIdentity(row: (typeof this.identities)[number]) {
		if (this.identities.some((candidate) => candidate.provider_id === row.provider_id && (candidate.subject === row.subject || candidate.auth_user_id === row.auth_user_id)))
			return "conflict" as const;
		this.identities.push(row);
		return "ok" as const;
	}
	async touchIdentity() {}
	async scimSubjectCompatible(tenantId: string, userId: string, subject: string) {
		const scim = this.scimUsers.find((row) => row.tenant_id === tenantId && row.auth_user_id === userId);
		return !scim || scim.external_id === subject;
	}
	async createAuthUser() {
		this.userSeq += 1;
		const id = `99999999-9999-4999-8999-${String(this.userSeq).padStart(12, "0")}`;
		this.authUsers.add(id);
		return id;
	}
	async deleteAuthUser(userId: string) {
		this.deletedUsers.push(userId);
	}
	async generateSessionTokenHash(userId: string) {
		return this.authUsers.has(userId) ? `${"c".repeat(60)}${userId.slice(-4)}` : null;
	}
	async createLoginTicket(row: { ticket_hash: string; provider_id: string; tenant_id: string; auth_user_id: string; expires_at: string }) {
		this.tickets.set(row.ticket_hash, row);
		return true;
	}
	async recordSsoSession(ticketHash: string, userId: string, sessionId: string) {
		const ticket = this.tickets.get(ticketHash);
		if (!ticket || ticket.consumed || ticket.auth_user_id !== userId || ticket.expires_at <= new Date(this.clock()).toISOString()) return null;
		ticket.consumed = true;
		const expires = new Date(this.clock() + 43_200_000).toISOString();
		this.sessions.set(sessionId, { user_id: userId, provider_id: ticket.provider_id, tenant_id: ticket.tenant_id, expires_at: expires });
		return { provider_id: ticket.provider_id, tenant_id: ticket.tenant_id, expires_at: expires };
	}
	async bindScimIdentity(providerId: string, authUserId: string) {
		if (this.failBind) throw new Error("scim_bind_failed");
		const identity = this.identities.find((row) => row.provider_id === providerId && row.auth_user_id === authUserId);
		const provider = this.providers.get(providerId);
		if (!identity || !provider || this.policies.get(provider.tenant_id)?.required_oidc_provider_id !== providerId) return null;
		const scim = this.scimUsers.find((row) => row.tenant_id === provider.tenant_id && row.external_id === identity.subject);
		if (!scim) return null;
		if (scim.auth_user_id && scim.auth_user_id !== authUserId) throw new Error("scim_oidc_identity_conflict");
		scim.auth_user_id = authUserId;
		if (!this.members.has(`${provider.tenant_id}:${authUserId}`)) this.members.set(`${provider.tenant_id}:${authUserId}`, "member");
		return provider.tenant_id;
	}
	async memberRole(userId: string, tenantId: string) {
		return this.members.get(`${tenantId}:${userId}`) ?? null;
	}
	/** `tenant_plan_entitlements` RPC answer per tenant; unset = entitled Team plan. */
	plans = new Map<string, { data: unknown; error: unknown }>();
	planRpcCalls: string[] = [];
	async requireSsoFeature(tenantId: string) {
		// Runs the real shared resolver over a fake RPC so parsing and fail-closed
		// behaviour are exercised exactly as in production.
		return requireFeature({
			rpc: async (name: string, args: Record<string, unknown>) => {
				if (name !== "tenant_plan_entitlements") throw new Error(`unexpected rpc ${name}`);
				const id = String(args.p_tenant_id);
				this.planRpcCalls.push(id);
				return this.plans.get(id) ?? { data: entitledPlan(id), error: null };
			},
		}, tenantId, "entra_sso");
	}
	async policy(tenantId: string) {
		return this.policies.get(tenantId) ?? { required_oidc_provider_id: null, required_saml_provider_id: null, break_glass_enabled: false, require_mfa: false };
	}
	async setEnforcement(input: Parameters<OidcStore["setEnforcement"]>[0]) {
		this.enforcementCalls.push(input);
		return this.enforcementResult;
	}
	async breakGlassSuspend() {
		return this.breakGlassResult;
	}
	async audit(values: AuditValues) {
		if (this.failAudit) return false;
		this.audits.push(values);
		return true;
	}
	async rateLimit(key: string, _windowMs: number, maximum: number): Promise<RateLimitDecision> {
		const count = (this.counters.get(key) ?? 0) + 1;
		this.counters.set(key, count);
		return count <= maximum ? "allowed" : "limited";
	}
	auditActions(): string[] {
		return this.audits.map((entry) => entry.action);
	}
}

export interface World {
	store: MemoryStore;
	idps: IdpFixture[];
	callers: Map<string, AuthenticatedCaller | AuthenticationFailure>;
	clock: { now: number };
	/** `ref -> secret value`, i.e. the AIDR_OIDC_CLIENT_SECRET_<ref> Edge secrets. */
	secrets: Map<string, string>;
	/** The operator's AIDR_OIDC_CLIENT_SECRET_BINDINGS document (resolved by the real resolver). */
	secretBindings: Record<string, unknown>;
	/** Every env name the secret resolver read, in order. */
	secretEnvReads: string[];
	txt: Map<string, string[]>;
	jwksInvalidated: string[];
	deps: OidcDeps;
}

export function makeWorld(options: { idps: IdpFixture[]; jwks?: OidcDeps["jwksGetKey"] }): World {
	const store = new MemoryStore();
	const callers = new Map<string, AuthenticatedCaller | AuthenticationFailure>();
	const clock = { now: NOW_MS };
	store.clock = () => clock.now;
	const secrets = new Map<string, string>([["TENANT_A", "s3cr3t-A"], ["TENANT_B", "s3cr3t-B"]]);
	const world = {
		secretBindings: {
			TENANT_A: { tenant_id: TENANT_A, issuer: ISSUER_A },
			TENANT_B: { tenant_id: TENANT_B, issuer: ISSUER_B, client_id: "client-b" },
		} as Record<string, unknown>,
		secretEnvReads: [] as string[],
	};
	const readEnv = (name: string): string | undefined => {
		world.secretEnvReads.push(name);
		if (name === CLIENT_SECRET_BINDINGS_ENV) return JSON.stringify(world.secretBindings);
		return name.startsWith(CLIENT_SECRET_ENV_PREFIX) ? secrets.get(name.slice(CLIENT_SECRET_ENV_PREFIX.length)) : undefined;
	};
	const txt = new Map<string, string[]>();
	const jwksInvalidated: string[] = [];
	let counter = 0;
	const deps: OidcDeps = {
		store,
		authenticate: async (req) => {
			const token = req.headers.get("authorization")?.replace(/^Bearer /, "") ?? "";
			return callers.get(token) ?? { ok: false, status: 401, error: "invalid_access_token" };
		},
		json: (_req, status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } }),
		dashboardBaseUrl: "https://app.aidr.test",
		now: () => clock.now,
		randomBytes: (length) => {
			counter += 1;
			const bytes = new Uint8Array(length);
			// Unpredictable-looking but deterministic per call so tests can run twice identically.
			for (let index = 0; index < length; index += 1) bytes[index] = (index * 31 + counter * 17 + 7) & 0xff;
			return bytes;
		},
		requestId: () => "req-test",
		getClientSecret: (request) => resolveClientSecret(readEnv, request),
		fetchJson: idpFetch(options.idps),
		resolveTxt: async (name) => {
			const records = txt.get(name);
			if (!records) throw new Error("NXDOMAIN");
			return records;
		},
		jwksGetKey: options.jwks ?? (async () => ({ status: "unavailable" })),
		invalidateJwks: (uri) => {
			jwksInvalidated.push(uri);
		},
	};
	return Object.assign(world, { store, idps: options.idps, callers, clock, secrets, txt, jwksInvalidated, deps });
}

export function post(body: Record<string, unknown>, token?: string): Request {
	return new Request("https://edge.test/functions/v1/oidc-sso", {
		method: "POST",
		headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
		body: JSON.stringify(body),
	});
}

export function caller(userId: string, overrides: Partial<AuthenticatedCaller> = {}): AuthenticatedCaller {
	return { ok: true, token: "t", userId, email: null, sessionId: SESSION_1, assurance: "aal2", ...overrides };
}
