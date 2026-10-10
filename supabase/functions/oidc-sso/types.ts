// Contracts between the OIDC SSO request handler and its collaborators. The
// handler is pure over these interfaces; index.ts binds them to Supabase and
// the Edge runtime, and the tests bind them to in-memory fakes.

import type { FeatureDecision } from "../_shared/plan-entitlements.ts";
import type { ClientSecretRequest } from "./client-secrets.ts";
import type { MappedRole, OidcAlgorithm, OidcDiscovery } from "./oidc.ts";

export type ProviderKind = "entra" | "okta" | "generic";
export type TokenAuthMethod = "client_secret_basic" | "client_secret_post" | "none";

export interface OidcProviderRow {
	id: string;
	tenant_id: string;
	kind: ProviderKind;
	display_name: string;
	issuer: string;
	client_id: string;
	client_secret_ref: string | null;
	token_auth_method: TokenAuthMethod;
	allowed_algs: OidcAlgorithm[];
	subject_claim: "sub" | "oid";
	groups_claim: string | null;
	groups_mode: "ignore" | "require_mapped";
	session_max_seconds: number;
	clock_skew_seconds: number;
	discovery: OidcDiscovery | null;
	enabled: boolean;
}

export interface OidcAuthRequestRow {
	state_hash: string;
	provider_id: string;
	tenant_id: string;
	nonce_hash: string;
	code_verifier: string;
	binding_hash: string;
	redirect_uri: string;
	mode: "login" | "link";
	link_user_id: string | null;
	expires_at: string;
}

export interface OidcPolicyRow {
	required_oidc_provider_id: string | null;
	required_saml_provider_id: string | null;
	break_glass_enabled: boolean;
	require_mfa: boolean;
}

export interface AuditValues {
	actor_user_id: string | null;
	tenant_id: string | null;
	target_user_id: string | null;
	action: string;
	detail: Record<string, unknown>;
}

export interface ProviderAudit {
	action: "identity.oidc.provider_updated" | "identity.oidc.discovery_refreshed";
	detail: Record<string, unknown>;
}

export type SaveProviderResult =
	| "saved"
	| "owner_required"
	| "provider_locked_by_enforcement"
	| "provider_identity_namespace_locked"
	| "error";

export interface DomainRow {
	tenant_id: string;
	domain: string;
	verification_token: string;
	verified_at: string | null;
}

export type RateLimitDecision = "allowed" | "limited" | "unavailable";

export interface OidcStore {
	findProviderById(id: string): Promise<OidcProviderRow | null>;
	findProviderByTenant(tenantId: string): Promise<OidcProviderRow | null>;
	/** Provider of the tenant that has VERIFIED this domain. */
	findProviderByVerifiedDomain(domain: string): Promise<OidcProviderRow | null>;
	/**
	 * One transaction (RPC oidc_save_provider): re-checks that the actor is still
	 * a live owner, upserts the provider and writes the audit row. Nothing is
	 * committed unless all three succeed.
	 */
	saveProvider(row: OidcProviderRow, actorUserId: string, audit: ProviderAudit): Promise<SaveProviderResult>;

	createAuthRequest(row: OidcAuthRequestRow): Promise<boolean>;
	/** Single atomic UPDATE ... WHERE consumed_at IS NULL AND expires_at > now(); null when replayed/expired/unknown. */
	consumeAuthRequest(stateHash: string, nowIso: string): Promise<OidcAuthRequestRow | null>;
	/** Read-only: the provider of an unexpired, unconsumed request; null when unknown, "error" when unreadable. */
	pendingAuthRequest(stateHash: string, nowIso: string): Promise<{ provider_id: string } | null | "error">;

	groupMappings(tenantId: string): Promise<ReadonlyMap<string, MappedRole> | null>;
	verifiedDomains(tenantId: string): Promise<string[] | null>;
	listDomains(tenantId: string): Promise<DomainRow[] | null>;
	addDomain(tenantId: string, domain: string, token: string, actorUserId: string): Promise<DomainRow | null>;
	markDomainVerified(tenantId: string, domain: string): Promise<"verified" | "taken" | "error">;
	removeDomain(tenantId: string, domain: string): Promise<boolean>;

	findIdentity(providerId: string, subject: string): Promise<{ auth_user_id: string } | null>;
	findIdentityForUser(providerId: string, userId: string): Promise<{ subject: string } | null>;
	insertIdentity(row: {
		provider_id: string;
		subject: string;
		auth_user_id: string;
		tenant_id: string;
		email_claim: string | null;
	}, provider: Pick<OidcProviderRow, "issuer" | "client_id" | "subject_claim">): Promise<"ok" | "conflict" | "error">;
	touchIdentity(providerId: string, subject: string): Promise<void>;
	/** True unless a SCIM user is already bound to this Auth user with a different external id. */
	scimSubjectCompatible(tenantId: string, userId: string, subject: string): Promise<boolean>;

	createAuthUser(input: { providerId: string; tenantId: string; subject: string }): Promise<string | null>;
	deleteAuthUser(userId: string): Promise<void>;
	/** One-time magic-link hash for a new browser session of this user. */
	generateSessionTokenHash(userId: string): Promise<string | null>;
	createLoginTicket(row: {
		ticket_hash: string;
		provider_id: string;
		tenant_id: string;
		auth_user_id: string;
		expires_at: string;
	}): Promise<boolean>;
	recordSsoSession(
		ticketHash: string,
		userId: string,
		sessionId: string,
	): Promise<{ provider_id: string; tenant_id: string; expires_at: string } | null>;

	/** Returns the tenant id, null when the user is not a provisioned SCIM subject. Throws `scim_*` conflicts. */
	bindScimIdentity(providerId: string, authUserId: string): Promise<string | null>;
	memberRole(userId: string, tenantId: string): Promise<string | null>;
	/**
	 * Fail-closed plan gate for SSO administration (`requireFeature` in
	 * _shared/plan-entitlements.ts). Never consulted by the public login actions.
	 */
	requireSsoFeature(tenantId: string): Promise<FeatureDecision>;
	policy(tenantId: string): Promise<OidcPolicyRow | null>;
	setEnforcement(input: {
		tenantId: string;
		actorUserId: string;
		sessionId: string;
		providerId: string | null;
		reason: string;
		changeRef: string;
	}): Promise<{ ok: true } | { ok: false; error: string }>;
	breakGlassSuspend(input: {
		email: string;
		codeHash: string;
		requestId: string;
	}): Promise<{ tenant_id: string; user_id: string } | null | "error">;

	audit(values: AuditValues): Promise<boolean>;
	rateLimit(key: string, windowMs: number, maximum: number): Promise<RateLimitDecision>;
}

export interface AuthenticatedCaller {
	ok: true;
	token: string;
	userId: string;
	email: string | null;
	sessionId: string;
	assurance: string | null;
}
export interface AuthenticationFailure {
	ok: false;
	status: number;
	error: string;
}

export interface OidcDeps {
	store: OidcStore;
	/** `tenantId` makes the identity barrier tenant-scoped (MFA / SSO enforcement for that tenant). */
	authenticate(req: Request, options?: { tenantId?: string }): Promise<AuthenticatedCaller | AuthenticationFailure>;
	json(req: Request, status: number, body: Record<string, unknown>): Response;
	dashboardBaseUrl: string;
	now(): number;
	randomBytes(length: number): Uint8Array;
	requestId(req: Request): string;
	/**
	 * Tenant-bound secret lookup (client-secrets.ts). Every field comes from the
	 * stored provider row; a reference alone never releases a secret.
	 */
	getClientSecret(request: ClientSecretRequest): string | null;
	/** SSRF-guarded JSON fetch (supabase/functions/_shared/safe-fetch.ts). */
	fetchJson(
		url: string,
		init?: RequestInit,
	): Promise<{ ok: true; json: unknown } | { ok: false; error: string; status?: number }>;
	/** DNS TXT lookup for domain verification. */
	resolveTxt(name: string): Promise<string[]>;
	jwksGetKey: (
		jwksUri: string,
		kid: string | undefined,
		alg: OidcAlgorithm,
	) => Promise<import("./oidc.ts").KeyLookup>;
	invalidateJwks(jwksUri: string): void;
	/** Client IP attested by the trusted ingress (HMAC proof), or null when absent/invalid. */
	clientIp?(req: Request): Promise<string | null>;
}
