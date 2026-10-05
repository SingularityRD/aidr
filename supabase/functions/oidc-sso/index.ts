// Supabase Edge Function: /oidc-sso
//
// Tenant OpenID Connect SSO (Entra ID, Okta, generic). The protocol logic lives
// in handler.ts / oidc.ts / jwks.ts (unit-tested without a runtime); this file
// binds it to Supabase and the Edge runtime.
//
// Public actions (`start`, `callback`, `break_glass_suspend_enforcement`) are
// authenticated by single-use state + PKCE + a browser-held binding secret, or
// by a recovery code. Every other action verifies the Supabase access token and
// runs the shared identity barrier (see authenticate() below).

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { getRequestId } from "../_shared/response.ts";
import { safeFetchJson } from "../_shared/safe-fetch.ts";
import { jwtIssuedAtMs, jwtSessionId } from "../identity-security/logic.ts";
import { createOidcHandler } from "./handler.ts";
import { JwksCache, parseJwks } from "./jwks.ts";
import { SupabaseOidcStore } from "./store.ts";
import type { AuthenticatedCaller, AuthenticationFailure, OidcDeps } from "./types.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "AIDR_DASHBOARD_URL"] as const;

// Warm-isolate cache: signing keys are shared by every tenant using the same IdP
// document, and rotation is handled inside JwksCache.
const jwks = new JwksCache({
	fetchKeys: async (jwksUri) => {
		const response = await safeFetchJson(jwksUri, { method: "GET", headers: { accept: "application/json" } });
		return response.ok ? parseJwks(response.json) : null;
	},
});

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("oidc-sso", config.error, (status, body) => corsJson(req, status, body));
	}
	let dashboardBaseUrl: string;
	try {
		const configured = new URL(config.values.AIDR_DASHBOARD_URL);
		const loopback = ["localhost", "127.0.0.1", "[::1]"].includes(configured.hostname);
		if ((configured.protocol !== "https:" && !(configured.protocol === "http:" && loopback)) || configured.username || configured.password) {
			throw new Error("invalid_dashboard_url");
		}
		dashboardBaseUrl = configured.origin;
	} catch {
		return corsJson(req, 500, { error: "server_misconfigured" });
	}

	const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	});

	async function authenticate(
		request: Request,
		options?: { tenantId?: string },
	): Promise<AuthenticatedCaller | AuthenticationFailure> {
		const token = getBearerToken(request.headers.get("Authorization"));
		if (!token) return { ok: false, status: 401, error: "missing_access_token" };
		const { data, error } = await db.auth.getUser(token);
		const sessionId = jwtSessionId(token);
		if (error || !data.user?.id || !sessionId || jwtIssuedAtMs(token) === null) {
			return { ok: false, status: 401, error: "invalid_access_token" };
		}
		// The shared barrier owns session revocation and tenant MFA/SSO enforcement.
		const barrier = await checkIdentityBarrier(db, token, data.user.id, options?.tenantId);
		if (!barrier.ok) return { ok: false, status: barrier.status, error: barrier.error };
		const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
		if (assuranceError || !assurance) return { ok: false, status: 503, error: "assurance_unavailable" };
		return {
			ok: true,
			token,
			userId: data.user.id,
			email: data.user.email ?? null,
			sessionId,
			assurance: assurance.currentLevel ?? null,
		};
	}

	const deps: OidcDeps = {
		store: new SupabaseOidcStore(db),
		authenticate,
		json: (request, status, body) => corsJson(request, status, body),
		dashboardBaseUrl,
		now: () => Date.now(),
		randomBytes: (length) => crypto.getRandomValues(new Uint8Array(length)),
		requestId: getRequestId,
		getClientSecret: (ref) => {
			const value = Deno.env.get(`AIDR_OIDC_CLIENT_SECRET_${ref}`);
			return value && value.trim() !== "" ? value : null;
		},
		fetchJson: async (url, init) => {
			const response = await safeFetchJson(url, init);
			return response.ok ? { ok: true, json: response.json } : { ok: false, error: response.error, status: response.status };
		},
		resolveTxt: async (name) => (await Deno.resolveDns(name, "TXT")).map((chunks) => chunks.join("")),
		jwksGetKey: (jwksUri, kid, alg) => jwks.getKey(jwksUri, kid, alg),
		invalidateJwks: (jwksUri) => jwks.invalidate(jwksUri),
	};
	return createOidcHandler(deps)(req);
});
