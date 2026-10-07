// OIDC SSO request handler (Entra ID / Okta / generic).
//
// Public actions (no Supabase session; each is bound by single-use state, PKCE
// and a browser-held binding secret, or by a recovery code):
//   start, callback, break_glass_suspend_enforcement
// Authenticated actions (identity barrier, tenant membership):
//   bind_session                       - any session holding a fresh login ticket
//   get_config                         - tenant owner
//   put_provider, refresh_discovery,
//   add_domain, verify_domain,
//   remove_domain, set_enforcement     - tenant owner at AAL2
//
// Failure policy: authentication and authorization failures fail closed with a
// coarse reason; audit failures on a success path deny the login.

import { normalizeEmail, normalizeRecoveryCode, normalizeUuid } from "../identity-security/logic.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import {
	buildAuthorizationUrl,
	constantTimeEqual,
	discoveryUrlFor,
	emailDomain,
	isDnsDomain,
	isPkceVerifier,
	mapGroupClaims,
	normalizeIssuer,
	type OidcAlgorithm,
	pkceChallenge,
	SUPPORTED_ALGORITHMS,
	sha256Hex,
	validateDiscovery,
	verifyIdToken,
	base64UrlEncode,
} from "./oidc.ts";
import type {
	AuthenticatedCaller,
	OidcDeps,
	OidcProviderRow,
	ProviderKind,
	TokenAuthMethod,
} from "./types.ts";

const MAX_BODY_BYTES = 16 * 1024;
const AUTH_REQUEST_TTL_MS = 10 * 60_000;
const LOGIN_TICKET_TTL_MS = 2 * 60_000;
// Availability bounds, not security controls: state is 256-bit and single-use, so guessing is
// infeasible. No public action consumes a fixed deployment-wide bucket any more, because one
// caller could use it to starve sign-in or recovery for every tenant:
//  - start resolves the provider first (read-only); unknown providers/domains write nothing, and
//    a known provider is bounded by its own bucket;
//  - callback checks that the state exists and is pending (read-only) before counting, and then
//    counts against the provider the state belongs to;
//  - break-glass is bounded per email.
// A caller whose IP the trusted ingress attested (see _shared/trusted-ingress.ts) is first limited
// by its own bucket, and attested callers never share a bucket with unsigned direct callers.
const START_LIMIT_PER_MINUTE = 600;
const CALLBACK_LIMIT_PER_MINUTE = 1_200;
const CLIENT_START_LIMIT_PER_MINUTE = 60;
const CLIENT_CALLBACK_LIMIT_PER_MINUTE = 120;
const BREAK_GLASS_WINDOW_MS = 10 * 60_000;
const BREAK_GLASS_PER_EMAIL = 5;
const BREAK_GLASS_PER_CLIENT = 20;
const BREAK_GLASS_UNSIGNED_AGGREGATE = 300;
const SCOPES = ["openid", "email", "profile"] as const;
const DOMAIN_TXT_LABEL = "_aidr-sso";
const DOMAIN_TXT_PREFIX = "aidr-sso-verification=";
const ENTRA_ISSUER = /^https:\/\/login\.microsoftonline\.com\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\/v2\.0$/;

type Body = Record<string, unknown>;
type LoginFailureReason =
	| "request_invalid"
	| "binding_mismatch"
	| "provider_unavailable"
	| "token_exchange_failed"
	| "token_invalid"
	| "domain_not_verified"
	| "email_claim_missing"
	| "group_not_mapped"
	| "groups_overage"
	| "not_provisioned"
	| "identity_conflict"
	| "session_unavailable";

function isRecord(value: unknown): value is Body {
	return Boolean(value && typeof value === "object" && !Array.isArray(value));
}

function str(value: unknown, max: number): string | null {
	return typeof value === "string" && value.length > 0 && value.length <= max ? value : null;
}

const HEX64 = /^[0-9a-f]{64}$/;

export function createOidcHandler(deps: OidcDeps): (req: Request) => Promise<Response> {
	const { store } = deps;
	const redirectUri = `${deps.dashboardBaseUrl.replace(/\/+$/, "")}/auth/oidc/callback`;
	const nowIso = () => new Date(deps.now()).toISOString();
	const random = (bytes: number) => base64UrlEncode(deps.randomBytes(bytes));

	async function attestedClientIp(req: Request): Promise<string | null> {
		return deps.clientIp ? await deps.clientIp(req) : null;
	}

	/**
	 * Per-provider bound for a public action. An attested client is checked
	 * against its own bucket first, and attested and unsigned callers use
	 * separate per-provider buckets, so a direct caller cannot exhaust the budget
	 * of clients arriving through the trusted ingress.
	 */
	async function publicLimit(
		req: Request,
		scope: "oidc-start" | "oidc-callback",
		providerId: string,
		windowMs: number,
		perClient: number,
		perProvider: number,
	): Promise<"allowed" | "limited" | "unavailable"> {
		const clientIp = await attestedClientIp(req);
		if (clientIp) {
			const client = await store.rateLimit(`${scope}:v2:client:${await sha256Hex(clientIp)}`, windowMs, perClient);
			if (client !== "allowed") return client;
		}
		return store.rateLimit(`${scope}:v2:${clientIp ? "signed" : "unsigned"}:${providerId}`, windowMs, perProvider);
	}

	async function failLogin(
		req: Request,
		provider: OidcProviderRow | null,
		reason: LoginFailureReason,
		internal: string,
		status = 401,
	): Promise<Response> {
		// Best effort: a failed audit write must not turn a denial into an error.
		await store.audit({
			actor_user_id: null,
			tenant_id: provider?.tenant_id ?? null,
			target_user_id: null,
			action: "identity.oidc.login_failed",
			detail: { provider_id: provider?.id ?? null, reason: internal, request_id: deps.requestId(req) },
		});
		return deps.json(req, status, { error: "sso_login_failed", reason });
	}

	// -- start ------------------------------------------------------------------

	async function start(req: Request, body: Body): Promise<Response> {
		const bindingChallenge = typeof body.binding_challenge === "string" ? body.binding_challenge : "";
		if (!HEX64.test(bindingChallenge)) return deps.json(req, 400, { error: "invalid_request" });
		const mode = body.mode === "link" ? "link" : "login";
		const providerId = body.provider_id === undefined ? null : normalizeUuid(body.provider_id);
		const domain =
			typeof body.domain === "string"
				? body.domain.trim().toLowerCase()
				: (emailDomain(body.email) ?? null);
		if ((body.provider_id !== undefined && !providerId) || (!providerId && !domain))
			return deps.json(req, 400, { error: "invalid_request" });

		// Resolve first (read-only): an unknown provider/domain writes nothing, not
		// even a counter row, so random identifiers cannot mint counters or starve
		// other tenants' sign-in.
		const provider = providerId
			? await store.findProviderById(providerId)
			: isDnsDomain(domain)
				? await store.findProviderByVerifiedDomain(domain)
				: null;
		// One answer for unknown, disabled and un-discovered providers: no enumeration.
		if (!provider || !provider.enabled || !provider.discovery)
			return deps.json(req, 404, { error: "sso_not_available" });

		const limit = await publicLimit(req, "oidc-start", provider.id, 60_000, CLIENT_START_LIMIT_PER_MINUTE, START_LIMIT_PER_MINUTE);
		if (limit === "unavailable") return deps.json(req, 503, { error: "sso_unavailable" });
		if (limit === "limited") return deps.json(req, 429, { error: "rate_limited" });

		let linkUserId: string | null = null;
		if (mode === "link") {
			const caller = await deps.authenticate(req, { tenantId: provider.tenant_id });
			if (!caller.ok) return deps.json(req, caller.status, { error: caller.error });
			if (!(await store.memberRole(caller.userId, provider.tenant_id)))
				return deps.json(req, 403, { error: "tenant_not_authorized" });
			linkUserId = caller.userId;
		}

		const state = random(32);
		const nonce = random(32);
		const verifier = random(48);
		const created = await store.createAuthRequest({
			state_hash: await sha256Hex(state),
			provider_id: provider.id,
			tenant_id: provider.tenant_id,
			nonce_hash: await sha256Hex(nonce),
			code_verifier: verifier,
			binding_hash: bindingChallenge,
			redirect_uri: redirectUri,
			mode,
			link_user_id: linkUserId,
			expires_at: new Date(deps.now() + AUTH_REQUEST_TTL_MS).toISOString(),
		});
		if (!created) return deps.json(req, 503, { error: "sso_unavailable" });
		return deps.json(req, 200, {
			ok: true,
			authorization_url: buildAuthorizationUrl({
				authorizationEndpoint: provider.discovery.authorization_endpoint,
				clientId: provider.client_id,
				redirectUri,
				state,
				nonce,
				codeChallenge: await pkceChallenge(verifier),
				scopes: SCOPES,
			}),
			expires_in: AUTH_REQUEST_TTL_MS / 1000,
		});
	}

	// -- callback ---------------------------------------------------------------

	async function exchangeCode(
		provider: OidcProviderRow,
		code: string,
		verifier: string,
		requestRedirectUri: string,
	): Promise<{ ok: true; idToken: string } | { ok: false; reason: string }> {
		if (!provider.discovery) return { ok: false, reason: "no_discovery" };
		const form = new URLSearchParams({
			grant_type: "authorization_code",
			code,
			redirect_uri: requestRedirectUri,
			code_verifier: verifier,
		});
		const headers: Record<string, string> = {
			"content-type": "application/x-www-form-urlencoded",
			accept: "application/json",
		};
		if (provider.token_auth_method === "none") {
			form.set("client_id", provider.client_id);
		} else {
			const secret = provider.client_secret_ref ? deps.getClientSecret(provider.client_secret_ref) : null;
			if (!secret) return { ok: false, reason: "client_secret_not_configured" };
			if (provider.token_auth_method === "client_secret_post") {
				form.set("client_id", provider.client_id);
				form.set("client_secret", secret);
			} else {
				headers.authorization = `Basic ${btoa(
					`${encodeURIComponent(provider.client_id)}:${encodeURIComponent(secret)}`,
				)}`;
			}
		}
		const response = await deps.fetchJson(provider.discovery.token_endpoint, {
			method: "POST",
			headers,
			body: form.toString(),
		});
		if (!response.ok) return { ok: false, reason: `token_endpoint_${response.error}` };
		const json = response.json;
		if (!isRecord(json) || typeof json.id_token !== "string")
			return { ok: false, reason: "id_token_missing" };
		return { ok: true, idToken: json.id_token };
	}

	function algorithmsFor(provider: OidcProviderRow): OidcAlgorithm[] {
		const advertised = provider.discovery?.id_token_signing_alg_values_supported;
		return provider.allowed_algs.filter(
			(alg) => SUPPORTED_ALGORITHMS.includes(alg) && (!advertised || advertised.includes(alg)),
		);
	}

	async function callback(req: Request, body: Body): Promise<Response> {
		const code = str(body.code, 4096);
		const state = typeof body.state === "string" && /^[A-Za-z0-9_-]{32,128}$/.test(body.state) ? body.state : null;
		const bindingVerifier = isPkceVerifier(body.binding_verifier) ? body.binding_verifier : null;
		if (!code || !state || !bindingVerifier) return deps.json(req, 400, { error: "invalid_request" });

		// Cheap read-only existence check before counting: a random or replayed
		// state is rejected without consuming any bucket, so it cannot starve
		// callbacks for flows other users legitimately started.
		const stateHash = await sha256Hex(state);
		const pending = await store.pendingAuthRequest(stateHash, nowIso());
		if (pending === "error") return deps.json(req, 503, { error: "sso_unavailable" });
		if (!pending) return deps.json(req, 400, { error: "sso_login_failed", reason: "request_invalid" });
		const limit = await publicLimit(req, "oidc-callback", pending.provider_id, 60_000, CLIENT_CALLBACK_LIMIT_PER_MINUTE, CALLBACK_LIMIT_PER_MINUTE);
		if (limit === "unavailable") return deps.json(req, 503, { error: "sso_unavailable" });
		if (limit === "limited") return deps.json(req, 429, { error: "rate_limited" });

		// Single-use: the first presentation consumes the request, so a replayed
		// state (or a second tab, or an attacker) finds nothing.
		const authRequest = await store.consumeAuthRequest(stateHash, nowIso());
		if (!authRequest) return deps.json(req, 400, { error: "sso_login_failed", reason: "request_invalid" });

		const provider = await store.findProviderById(authRequest.provider_id);
		if (!provider || !provider.enabled || !provider.discovery || provider.tenant_id !== authRequest.tenant_id)
			return failLogin(req, provider, "provider_unavailable", "provider_unavailable", 503);

		// Login-CSRF defence: the browser that finishes the flow must be the one that started it.
		if (!(await constantTimeEqual(await sha256Hex(bindingVerifier), authRequest.binding_hash)))
			return failLogin(req, provider, "binding_mismatch", "binding_mismatch");

		const exchanged = await exchangeCode(provider, code, authRequest.code_verifier, authRequest.redirect_uri);
		if (!exchanged.ok) return failLogin(req, provider, "token_exchange_failed", exchanged.reason);

		const discovery = provider.discovery;
		const verified = await verifyIdToken(exchanged.idToken, {
			issuer: provider.issuer,
			clientId: provider.client_id,
			nonceHash: authRequest.nonce_hash,
			allowedAlgorithms: algorithmsFor(provider),
			nowSeconds: Math.floor(deps.now() / 1000),
			clockSkewSeconds: provider.clock_skew_seconds,
			getKey: (kid, alg) => deps.jwksGetKey(discovery.jwks_uri, kid, alg),
		});
		if (!verified.ok) return failLogin(req, provider, "token_invalid", `id_token_${verified.error}`);
		const claims = verified.claims;

		const subjectValue = claims[provider.subject_claim];
		const subject = typeof subjectValue === "string" && subjectValue.length > 0 && subjectValue.length <= 255 ? subjectValue : null;
		if (!subject) return failLogin(req, provider, "token_invalid", "subject_claim_missing");

		// Tenant-bound domain verification: the asserted email must belong to a
		// domain THIS tenant verified, so one tenant's IdP can never sign users
		// into another tenant by asserting that tenant's email addresses.
		const email = typeof claims.email === "string" ? claims.email : null;
		const domain = emailDomain(email);
		if (!email || !domain) return failLogin(req, provider, "email_claim_missing", "email_claim_missing");
		if (claims.email_verified === false) return failLogin(req, provider, "domain_not_verified", "email_not_verified");
		const domains = await store.verifiedDomains(provider.tenant_id);
		if (!domains) return failLogin(req, provider, "provider_unavailable", "domain_lookup_failed", 503);
		if (!domains.includes(domain)) return failLogin(req, provider, "domain_not_verified", "domain_not_verified");

		let claimsRole: string | null = null;
		if (provider.groups_claim) {
			const mappings = await store.groupMappings(provider.tenant_id);
			if (!mappings) return failLogin(req, provider, "provider_unavailable", "mapping_lookup_failed", 503);
			const mapped = mapGroupClaims(claims, provider.groups_claim, mappings);
			if (mapped.status === "mapped") claimsRole = mapped.role;
			if (provider.groups_mode === "require_mapped" && mapped.status !== "mapped") {
				return failLogin(
					req,
					provider,
					mapped.status === "overage" ? "groups_overage" : "group_not_mapped",
					`groups_${mapped.status}`,
					403,
				);
			}
		}

		if (authRequest.mode === "link") return link(req, provider, authRequest.link_user_id, subject, email, claimsRole);
		return login(req, provider, subject, email, claimsRole);
	}

	async function link(
		req: Request,
		provider: OidcProviderRow,
		userId: string | null,
		subject: string,
		email: string,
		claimsRole: string | null,
	): Promise<Response> {
		if (!userId) return failLogin(req, provider, "request_invalid", "link_user_missing");
		const existing = await store.findIdentity(provider.id, subject);
		const own = await store.findIdentityForUser(provider.id, userId);
		if ((existing && existing.auth_user_id !== userId) || (own && own.subject !== subject))
			return failLogin(req, provider, "identity_conflict", "link_conflict", 409);
		if (!(await store.scimSubjectCompatible(provider.tenant_id, userId, subject)))
			return failLogin(req, provider, "identity_conflict", "scim_subject_mismatch", 409);
		if (!existing) {
			const inserted = await store.insertIdentity({
				provider_id: provider.id,
				subject,
				auth_user_id: userId,
				tenant_id: provider.tenant_id,
				email_claim: email,
			}, provider);
			if (inserted !== "ok") return failLogin(req, provider, "identity_conflict", `link_${inserted}`, 409);
		}
		const logged = await store.audit({
			actor_user_id: userId,
			tenant_id: provider.tenant_id,
			target_user_id: userId,
			action: "identity.oidc.identity_linked",
			detail: { provider_id: provider.id, subject_sha256: await sha256Hex(subject), claims_role: claimsRole },
		});
		if (!logged) return deps.json(req, 503, { error: "sso_unavailable" });
		return deps.json(req, 200, { ok: true, linked: true, provider_id: provider.id });
	}

	async function resolveAuthUser(provider: OidcProviderRow, subject: string, email: string): Promise<string | null | "conflict"> {
		const existing = await store.findIdentity(provider.id, subject);
		if (existing) return existing.auth_user_id;
		const created = await store.createAuthUser({ providerId: provider.id, tenantId: provider.tenant_id, subject });
		if (!created) return null;
		const inserted = await store.insertIdentity({
			provider_id: provider.id,
			subject,
			auth_user_id: created,
			tenant_id: provider.tenant_id,
			email_claim: email,
		}, provider);
		if (inserted === "ok") return created;
		// Lost a concurrent first-login race: discard our Auth user and use the winner.
		await store.deleteAuthUser(created);
		if (inserted === "conflict") {
			const winner = await store.findIdentity(provider.id, subject);
			return winner?.auth_user_id ?? "conflict";
		}
		return null;
	}

	async function login(
		req: Request,
		provider: OidcProviderRow,
		subject: string,
		email: string,
		claimsRole: string | null,
	): Promise<Response> {
		const userId = await resolveAuthUser(provider, subject, email);
		if (userId === null) return failLogin(req, provider, "session_unavailable", "auth_user_unavailable", 503);
		if (userId === "conflict") return failLogin(req, provider, "identity_conflict", "identity_conflict", 409);

		const policy = await store.policy(provider.tenant_id);
		if (!policy) return failLogin(req, provider, "provider_unavailable", "policy_unavailable", 503);
		const enforced = policy.required_oidc_provider_id === provider.id;
		if (enforced) {
			try {
				await store.bindScimIdentity(provider.id, userId);
			} catch {
				return failLogin(req, provider, "identity_conflict", "scim_bind_conflict", 403);
			}
			// Membership comes from SCIM (and manual owners); no membership, no session.
			if (!(await store.memberRole(userId, provider.tenant_id)))
				return failLogin(req, provider, "not_provisioned", "not_provisioned", 403);
		}

		const tokenHash = await store.generateSessionTokenHash(userId);
		if (!tokenHash) return failLogin(req, provider, "session_unavailable", "session_token_unavailable", 503);
		const ticket = random(32);
		const ticketStored = await store.createLoginTicket({
			ticket_hash: await sha256Hex(ticket),
			provider_id: provider.id,
			tenant_id: provider.tenant_id,
			auth_user_id: userId,
			expires_at: new Date(deps.now() + LOGIN_TICKET_TTL_MS).toISOString(),
		});
		if (!ticketStored) return failLogin(req, provider, "session_unavailable", "ticket_unavailable", 503);
		await store.touchIdentity(provider.id, subject);
		const logged = await store.audit({
			actor_user_id: userId,
			tenant_id: provider.tenant_id,
			target_user_id: userId,
			action: "identity.oidc.login_succeeded",
			detail: {
				provider_id: provider.id,
				enforced,
				subject_sha256: await sha256Hex(subject),
				claims_role: claimsRole,
				request_id: deps.requestId(req),
			},
		});
		// A login that cannot be audited does not happen.
		if (!logged) return deps.json(req, 503, { error: "sso_unavailable" });
		return deps.json(req, 200, {
			ok: true,
			token_hash: tokenHash,
			verification_type: "magiclink",
			login_ticket: ticket,
			tenant_id: provider.tenant_id,
		});
	}

	// -- bind_session -----------------------------------------------------------

	async function bindSession(req: Request, body: Body): Promise<Response> {
		const caller = await deps.authenticate(req);
		if (!caller.ok) return deps.json(req, caller.status, { error: caller.error });
		const ticket = str(body.login_ticket, 128);
		if (!ticket || !/^[A-Za-z0-9_-]{32,128}$/.test(ticket)) return deps.json(req, 400, { error: "invalid_request" });
		const bound = await store.recordSsoSession(await sha256Hex(ticket), caller.userId, caller.sessionId);
		if (!bound) return deps.json(req, 401, { error: "invalid_or_expired_login_ticket" });
		return deps.json(req, 200, { ok: true, tenant_id: bound.tenant_id, expires_at: bound.expires_at });
	}

	// -- break glass ------------------------------------------------------------

	async function breakGlassSuspend(req: Request, body: Body): Promise<Response> {
		const email = normalizeEmail(body.email);
		const recoveryCode = normalizeRecoveryCode(body.recovery_code);
		// Malformed input never reaches the database, so it needs no counter.
		if (!email || !recoveryCode) return deps.json(req, 401, { error: "invalid_or_expired_recovery_code" });
		// An attested client is limited by its own bucket; unsigned direct callers
		// share only an unsigned aggregate, so they cannot exhaust recovery for
		// clients arriving through the ingress. Every caller is then bounded per email.
		const clientIp = await attestedClientIp(req);
		const client = clientIp
			? await store.rateLimit(`oidc-break-glass:v2:client:${await sha256Hex(clientIp)}`, BREAK_GLASS_WINDOW_MS, BREAK_GLASS_PER_CLIENT)
			: await store.rateLimit("oidc-break-glass:v2:unsigned-aggregate", BREAK_GLASS_WINDOW_MS, BREAK_GLASS_UNSIGNED_AGGREGATE);
		if (client === "unavailable") return deps.json(req, 503, { error: "recovery_unavailable" });
		if (client === "limited") return deps.json(req, 429, { error: "rate_limited" });
		const limit = await store.rateLimit(`oidc-break-glass:v2:email:${await sha256Hex(email)}`, BREAK_GLASS_WINDOW_MS, BREAK_GLASS_PER_EMAIL);
		if (limit === "unavailable") return deps.json(req, 503, { error: "recovery_unavailable" });
		if (limit === "limited") return deps.json(req, 429, { error: "rate_limited" });
		const result = await store.breakGlassSuspend({
			email,
			codeHash: await sha256Hex(recoveryCode),
			requestId: deps.requestId(req),
		});
		if (result === "error") return deps.json(req, 503, { error: "recovery_unavailable" });
		if (!result) return deps.json(req, 401, { error: "invalid_or_expired_recovery_code" });
		return deps.json(req, 200, {
			ok: true,
			enforcement_suspended: true,
			next_step: "sign_in_with_password_then_repair_provider",
		});
	}

	// -- owner administration -----------------------------------------------------

	async function ownerContext(
		req: Request,
		body: Body,
		options: { requireAal2: boolean },
	): Promise<{ caller: AuthenticatedCaller; tenantId: string } | Response> {
		const tenantId = normalizeUuid(body.tenant_id);
		if (!tenantId) return deps.json(req, 400, { error: "invalid_request" });
		const caller = await deps.authenticate(req, { tenantId });
		if (!caller.ok) return deps.json(req, caller.status, { error: caller.error });
		if ((await store.memberRole(caller.userId, tenantId)) !== "owner")
			return deps.json(req, 403, { error: "owner_required" });
		if (options.requireAal2 && caller.assurance !== "aal2") return deps.json(req, 403, { error: "mfa_required" });
		return { caller, tenantId };
	}

	async function getConfig(req: Request, body: Body): Promise<Response> {
		const context = await ownerContext(req, body, { requireAal2: false });
		if (context instanceof Response) return context;
		const [provider, domains, policy] = await Promise.all([
			store.findProviderByTenant(context.tenantId),
			store.listDomains(context.tenantId),
			store.policy(context.tenantId),
		]);
		if (!domains || !policy) return deps.json(req, 503, { error: "sso_unavailable" });
		return deps.json(req, 200, {
			ok: true,
			redirect_uri: redirectUri,
			provider: provider && {
				id: provider.id,
				kind: provider.kind,
				display_name: provider.display_name,
				issuer: provider.issuer,
				client_id: provider.client_id,
				token_auth_method: provider.token_auth_method,
				client_secret_configured: provider.client_secret_ref
					? deps.getClientSecret(provider.client_secret_ref) !== null
					: null,
				allowed_algs: provider.allowed_algs,
				subject_claim: provider.subject_claim,
				groups_claim: provider.groups_claim,
				groups_mode: provider.groups_mode,
				session_max_seconds: provider.session_max_seconds,
				enabled: provider.enabled,
				discovery_ready: provider.discovery !== null,
			},
			domains: domains.map((row) => ({
				domain: row.domain,
				verified: row.verified_at !== null,
				txt_name: `${DOMAIN_TXT_LABEL}.${row.domain}`,
				txt_value: row.verified_at ? undefined : `${DOMAIN_TXT_PREFIX}${row.verification_token}`,
			})),
			enforced: policy.required_oidc_provider_id !== null,
			saml_enforced: policy.required_saml_provider_id !== null,
			break_glass_enabled: policy.break_glass_enabled,
		});
	}

	async function fetchDiscovery(provider: OidcProviderRow): Promise<OidcProviderRow | string> {
		const response = await deps.fetchJson(discoveryUrlFor(provider.issuer), {
			method: "GET",
			headers: { accept: "application/json" },
		});
		if (!response.ok) return `discovery_${response.error}`;
		const validated = validateDiscovery(response.json, provider.issuer, provider.allowed_algs);
		if (!validated.ok) return `discovery_${validated.error}`;
		return { ...provider, discovery: validated.discovery };
	}

	function parseProviderInput(body: Body, existing: OidcProviderRow | null): OidcProviderRow | string {
		const kind = body.kind as ProviderKind;
		if (!["entra", "okta", "generic"].includes(kind)) return "invalid_kind";
		const issuer = normalizeIssuer(body.issuer);
		if (!issuer) return "invalid_issuer";
		// A multi-tenant Entra authority has no fixed issuer, so only a concrete directory GUID is accepted.
		if (kind === "entra" && !ENTRA_ISSUER.test(issuer)) return "invalid_entra_issuer";
		const clientId = str(body.client_id, 256);
		if (!clientId || /\s/.test(clientId)) return "invalid_client_id";
		const method = (body.token_auth_method ?? "client_secret_basic") as TokenAuthMethod;
		if (!["client_secret_basic", "client_secret_post", "none"].includes(method)) return "invalid_token_auth_method";
		const secretRef = body.client_secret_ref === undefined || body.client_secret_ref === null ? null : body.client_secret_ref;
		if (secretRef !== null && !(typeof secretRef === "string" && /^[A-Z0-9_]{1,40}$/.test(secretRef))) return "invalid_client_secret_ref";
		if (method !== "none" && secretRef === null) return "client_secret_ref_required";
		const algs = body.allowed_algs === undefined ? ["RS256"] : body.allowed_algs;
		if (!Array.isArray(algs) || algs.length < 1 || algs.some((alg) => !SUPPORTED_ALGORITHMS.includes(alg as OidcAlgorithm)))
			return "invalid_algorithms";
		const subjectClaim = body.subject_claim ?? (kind === "entra" ? "oid" : "sub");
		if (subjectClaim !== "sub" && subjectClaim !== "oid") return "invalid_subject_claim";
		const groupsClaim = body.groups_claim === undefined || body.groups_claim === null || body.groups_claim === "" ? null : body.groups_claim;
		if (groupsClaim !== null && !(typeof groupsClaim === "string" && /^[A-Za-z0-9_:.-]{1,64}$/.test(groupsClaim))) return "invalid_groups_claim";
		const groupsMode = body.groups_mode ?? "ignore";
		if (groupsMode !== "ignore" && groupsMode !== "require_mapped") return "invalid_groups_mode";
		if (groupsMode === "require_mapped" && groupsClaim === null) return "groups_claim_required";
		const sessionMax = body.session_max_seconds ?? 43_200;
		if (!Number.isInteger(sessionMax) || (sessionMax as number) < 900 || (sessionMax as number) > 86_400) return "invalid_session_lifetime";
		const skew = body.clock_skew_seconds ?? 60;
		if (!Number.isInteger(skew) || (skew as number) < 0 || (skew as number) > 120) return "invalid_clock_skew";
		const displayName = str(body.display_name, 64);
		if (!displayName) return "invalid_display_name";
		const identityChanged =
			!existing || existing.issuer !== issuer || existing.kind !== kind || existing.allowed_algs.join() !== (algs as string[]).join();
		return {
			id: existing?.id ?? crypto.randomUUID(),
			tenant_id: existing?.tenant_id ?? "",
			kind,
			display_name: displayName,
			issuer,
			client_id: clientId,
			client_secret_ref: secretRef as string | null,
			token_auth_method: method,
			allowed_algs: algs as OidcAlgorithm[],
			subject_claim: subjectClaim,
			groups_claim: groupsClaim as string | null,
			groups_mode: groupsMode,
			session_max_seconds: sessionMax as number,
			clock_skew_seconds: skew as number,
			// Changing the issuer/algorithms invalidates what was discovered.
			discovery: identityChanged ? null : existing.discovery,
			enabled: false,
		};
	}

	async function putProvider(req: Request, body: Body): Promise<Response> {
		const context = await ownerContext(req, body, { requireAal2: true });
		if (context instanceof Response) return context;
		const existing = await store.findProviderByTenant(context.tenantId);
		const policy = await store.policy(context.tenantId);
		if (!policy) return deps.json(req, 503, { error: "sso_unavailable" });
		if (existing && policy.required_oidc_provider_id === existing.id)
			return deps.json(req, 409, { error: "provider_locked_by_enforcement" });
		const parsed = parseProviderInput(body, existing);
		if (typeof parsed === "string") return deps.json(req, 400, { error: "invalid_provider", reason: parsed });
		let provider: OidcProviderRow = { ...parsed, tenant_id: context.tenantId };
		if (!provider.discovery) {
			const discovered = await fetchDiscovery(provider);
			if (typeof discovered === "string") return deps.json(req, 422, { error: "discovery_failed", reason: discovered });
			provider = discovered;
		}
		const wantsEnabled = body.enabled === true;
		if (wantsEnabled) {
			const secretOk =
				provider.token_auth_method === "none" ||
				(provider.client_secret_ref !== null && deps.getClientSecret(provider.client_secret_ref) !== null);
			if (!secretOk) return deps.json(req, 422, { error: "client_secret_not_configured" });
			provider = { ...provider, enabled: true };
		}
		if (!(await store.saveProvider(provider, context.caller.userId))) return deps.json(req, 503, { error: "sso_unavailable" });
		deps.invalidateJwks(provider.discovery?.jwks_uri ?? "");
		const logged = await store.audit({
			actor_user_id: context.caller.userId,
			tenant_id: context.tenantId,
			target_user_id: null,
			action: "identity.oidc.provider_updated",
			detail: { provider_id: provider.id, kind: provider.kind, issuer: provider.issuer, enabled: provider.enabled, request_id: deps.requestId(req) },
		});
		if (!logged) return deps.json(req, 503, { error: "sso_unavailable" });
		return deps.json(req, 200, { ok: true, provider_id: provider.id, enabled: provider.enabled, redirect_uri: redirectUri });
	}

	async function refreshDiscovery(req: Request, body: Body): Promise<Response> {
		const context = await ownerContext(req, body, { requireAal2: true });
		if (context instanceof Response) return context;
		const provider = await store.findProviderByTenant(context.tenantId);
		if (!provider) return deps.json(req, 404, { error: "provider_not_found" });
		const discovered = await fetchDiscovery(provider);
		if (typeof discovered === "string") return deps.json(req, 422, { error: "discovery_failed", reason: discovered });
		if (provider.discovery) deps.invalidateJwks(provider.discovery.jwks_uri);
		if (!(await store.saveProvider(discovered, context.caller.userId))) return deps.json(req, 503, { error: "sso_unavailable" });
		const logged = await store.audit({
			actor_user_id: context.caller.userId,
			tenant_id: context.tenantId,
			target_user_id: null,
			action: "identity.oidc.discovery_refreshed",
			detail: { provider_id: provider.id, jwks_changed: provider.discovery?.jwks_uri !== discovered.discovery?.jwks_uri },
		});
		if (!logged) return deps.json(req, 503, { error: "sso_unavailable" });
		return deps.json(req, 200, { ok: true });
	}

	async function addDomain(req: Request, body: Body): Promise<Response> {
		const context = await ownerContext(req, body, { requireAal2: true });
		if (context instanceof Response) return context;
		const domain = typeof body.domain === "string" ? body.domain.trim().toLowerCase() : "";
		if (!isDnsDomain(domain)) return deps.json(req, 400, { error: "invalid_domain" });
		const row = await store.addDomain(context.tenantId, domain, random(32), context.caller.userId);
		if (!row) return deps.json(req, 503, { error: "sso_unavailable" });
		await store.audit({
			actor_user_id: context.caller.userId,
			tenant_id: context.tenantId,
			target_user_id: null,
			action: "identity.oidc.domain_added",
			detail: { domain },
		});
		return deps.json(req, 200, {
			ok: true,
			domain,
			verified: row.verified_at !== null,
			txt_name: `${DOMAIN_TXT_LABEL}.${domain}`,
			txt_value: row.verified_at ? undefined : `${DOMAIN_TXT_PREFIX}${row.verification_token}`,
		});
	}

	async function verifyDomain(req: Request, body: Body): Promise<Response> {
		const context = await ownerContext(req, body, { requireAal2: true });
		if (context instanceof Response) return context;
		const domain = typeof body.domain === "string" ? body.domain.trim().toLowerCase() : "";
		const rows = await store.listDomains(context.tenantId);
		const row = rows?.find((candidate) => candidate.domain === domain);
		if (!row) return deps.json(req, 404, { error: "domain_not_found" });
		if (row.verified_at) return deps.json(req, 200, { ok: true, verified: true });
		let records: string[];
		try {
			records = await deps.resolveTxt(`${DOMAIN_TXT_LABEL}.${domain}`);
		} catch {
			return deps.json(req, 422, { error: "dns_lookup_failed" });
		}
		const expected = `${DOMAIN_TXT_PREFIX}${row.verification_token}`;
		let matched = false;
		for (const record of records) matched = (await constantTimeEqual(record.trim(), expected)) || matched;
		if (!matched) return deps.json(req, 422, { error: "verification_record_not_found" });
		const outcome = await store.markDomainVerified(context.tenantId, domain);
		if (outcome === "taken") return deps.json(req, 409, { error: "domain_verified_by_another_tenant" });
		if (outcome === "error") return deps.json(req, 503, { error: "sso_unavailable" });
		const logged = await store.audit({
			actor_user_id: context.caller.userId,
			tenant_id: context.tenantId,
			target_user_id: null,
			action: "identity.oidc.domain_verified",
			detail: { domain },
		});
		if (!logged) return deps.json(req, 503, { error: "sso_unavailable" });
		return deps.json(req, 200, { ok: true, verified: true });
	}

	async function removeDomain(req: Request, body: Body): Promise<Response> {
		const context = await ownerContext(req, body, { requireAal2: true });
		if (context instanceof Response) return context;
		const domain = typeof body.domain === "string" ? body.domain.trim().toLowerCase() : "";
		const policy = await store.policy(context.tenantId);
		const verified = await store.verifiedDomains(context.tenantId);
		if (!policy || !verified) return deps.json(req, 503, { error: "sso_unavailable" });
		if (policy.required_oidc_provider_id && verified.length === 1 && verified[0] === domain)
			return deps.json(req, 409, { error: "last_verified_domain_locked_by_enforcement" });
		if (!(await store.removeDomain(context.tenantId, domain))) return deps.json(req, 503, { error: "sso_unavailable" });
		await store.audit({
			actor_user_id: context.caller.userId,
			tenant_id: context.tenantId,
			target_user_id: null,
			action: "identity.oidc.domain_removed",
			detail: { domain },
		});
		return deps.json(req, 200, { ok: true });
	}

	async function setEnforcement(req: Request, body: Body): Promise<Response> {
		const context = await ownerContext(req, body, { requireAal2: true });
		if (context instanceof Response) return context;
		const providerId = body.provider_id === null ? null : normalizeUuid(body.provider_id);
		const reason = str(body.reason, 500);
		const changeRef = str(body.change_ref, 64);
		if ((body.provider_id !== null && !providerId) || !reason || !changeRef)
			return deps.json(req, 400, { error: "invalid_request" });
		const result = await store.setEnforcement({
			tenantId: context.tenantId,
			actorUserId: context.caller.userId,
			sessionId: context.caller.sessionId,
			providerId,
			reason,
			changeRef,
		});
		if (!result.ok) {
			const known: Record<string, number> = {
				oidc_enforcement_forbidden: 403,
				oidc_actor_session_required: 403,
				oidc_verified_owners_required: 409,
				oidc_existing_identity_conflict: 409,
				oidc_saml_enforcement_active: 409,
				oidc_provider_unavailable: 409,
				oidc_verified_domain_required: 409,
				invalid_oidc_enforcement_request: 400,
			};
			const status = known[result.error];
			return deps.json(req, status ?? 503, { error: status ? result.error : "sso_unavailable" });
		}
		return deps.json(req, 200, { ok: true, enforced: providerId !== null });
	}

	// -- dispatch -----------------------------------------------------------------

	return async function handle(req: Request): Promise<Response> {
		if (req.method !== "POST") return deps.json(req, 405, { error: "method_not_allowed" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok)
			return deps.json(req, parsed.status, {
				error: parsed.error === "request_too_large" ? parsed.error : "invalid_request",
			});
		if (!isRecord(parsed.value) || typeof parsed.value.action !== "string")
			return deps.json(req, 400, { error: "invalid_request" });
		const body = parsed.value;
		try {
			switch (body.action) {
				// public-action: start
				case "start":
					return await start(req, body);
				// public-action: callback
				case "callback":
					return await callback(req, body);
				// public-action: break_glass_suspend_enforcement
				case "break_glass_suspend_enforcement":
					return await breakGlassSuspend(req, body);
				case "bind_session":
					return await bindSession(req, body);
				case "get_config":
					return await getConfig(req, body);
				case "put_provider":
					return await putProvider(req, body);
				case "refresh_discovery":
					return await refreshDiscovery(req, body);
				case "add_domain":
					return await addDomain(req, body);
				case "verify_domain":
					return await verifyDomain(req, body);
				case "remove_domain":
					return await removeDomain(req, body);
				case "set_enforcement":
					return await setEnforcement(req, body);
				default:
					return deps.json(req, 400, { error: "invalid_action" });
			}
		} catch {
			return deps.json(req, 503, { error: "sso_unavailable" });
		}
	};
}

