// AIDR pilot edge: serve the existing dashboard and proxy the existing
// Supabase API. This is not a replacement for Postgres, Auth or Edge Functions.
import { parseOidcRuntimeConfig, parseSamlRuntimeConfig } from "../saml-config.mjs";

const API_PREFIXES = ["/auth/v1", "/rest/v1", "/storage/v1", "/realtime/v1", "/functions/v1"];
const DEVICE_START = "/functions/v1/device-start";
const WAITLIST_SIGNUP = "/functions/v1/waitlist-signup";
const MAX_DEVICE_BODY = 4096;
const MAX_AUTH_BODY = 16384;
const MAX_DEVICE_RESPONSE = 16384;
const MAX_PROBE_RESPONSE = 512;
const PROBE_TIMEOUT_MS = 3000;
const READINESS_CACHE_MS = 5000;
const encoder = new TextEncoder();
const RELEASE_VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
const RELEASE_SHA = /^[a-f0-9]{40}$/;
let cachedReadiness = null;
let inFlightReadiness = null;

function jsonError(status, error, request) {
	return new Response(request?.method === "HEAD" ? null : JSON.stringify({ error }), {
		status, headers: { "cache-control": "no-store", "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
	});
}

function health(request, path, env, fetcher) {
	if (!["GET", "HEAD"].includes(request.method)) {
		return new Response(JSON.stringify({ error: "method_not_allowed" }), {
			status: 405,
			headers: { allow: "GET, HEAD", "cache-control": "no-store", "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
		});
	}
	if (path === "/readyz") return readiness(request, env, fetcher);
	if (path === "/metrics") {
		return new Response(request.method === "HEAD" ? null : JSON.stringify({ error: "metrics_not_supported" }), {
			status: 501,
			headers: { "cache-control": "no-store", "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
		});
	}
	return new Response(request.method === "HEAD" ? null : JSON.stringify({ status: "alive" }), {
		status: 200,
		headers: { "cache-control": "no-store", "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
	});
}

function version(request, url, env) {
	if (!["GET", "HEAD"].includes(request.method)) {
		return new Response(JSON.stringify({ error: "method_not_allowed" }), {
			status: 405,
			headers: { allow: "GET, HEAD", "cache-control": "no-store", "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
		});
	}
	try {
		const config = configuration(env);
		if (url.origin !== config.site) return jsonError(403, "wrong_public_origin", request);
		if (!RELEASE_VERSION.test(env.AIDR_RELEASE_VERSION ?? "") || !RELEASE_SHA.test(env.AIDR_RELEASE_SHA ?? "")) {
			return jsonError(503, "release_identity_unavailable", request);
		}
		return new Response(request.method === "HEAD" ? null : JSON.stringify({ version: env.AIDR_RELEASE_VERSION, git_sha: env.AIDR_RELEASE_SHA }), {
			status: 200,
			headers: { "cache-control": "no-store", "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
		});
	} catch {
		return jsonError(503, "service_not_configured", request);
	}
}

function configuredOrigin(value, name, provider = false) {
	const url = new URL(value);
	if (url.protocol !== "https:" || url.username || url.password || url.search || url.hash || url.pathname !== "/") {
		throw new Error(`${name} must be an HTTPS origin`);
	}
	if (provider && (url.hostname === "supabase.co" || !url.hostname.endsWith(".supabase.co"))) {
		throw new Error(`${name} must be a managed Supabase project origin`);
	}
	return url.origin;
}

function publicKey(value) {
	if (typeof value !== "string" || !value || /[\r\n]/.test(value)) throw new Error("Missing public API key");
	if (value.startsWith("sb_publishable_")) return value;
	try {
		const payload = JSON.parse(atob(value.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
		if (payload.role === "anon") return value;
	} catch { /* Reject malformed JWTs. */ }
	throw new Error("Only a Supabase anon or publishable key may be exposed");
}

function configuration(env) {
	const site = configuredOrigin(env.AIDR_PUBLIC_ORIGIN, "AIDR_PUBLIC_ORIGIN");
	const provider = configuredOrigin(env.AIDR_SUPABASE_ORIGIN, "AIDR_SUPABASE_ORIGIN", true);
	const anonKey = publicKey(env.AIDR_SUPABASE_ANON_KEY);
	const secret = env.AIDR_DEVICE_START_INGRESS_SECRET;
	if (typeof secret !== "string" || encoder.encode(secret).length < 32 || /[\r\n]/.test(secret)) {
		throw new Error("Missing device-start signing secret");
	}
	if (site === provider) throw new Error("Public and provider origins must be different");
	const signupMode = env.AIDR_SIGNUP_MODE || "closed";
	if (!["closed", "cloud"].includes(signupMode)) throw new Error("Invalid AIDR_SIGNUP_MODE");
	return { site, provider, anonKey, secret, signupMode };
}

function canonicalIp(value) {
	if (typeof value !== "string" || !value || value.length > 45 || value !== value.trim()) return null;
	if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(value)) {
		const parts = value.split(".");
		return parts.every((part) => Number(part) <= 255 && (part.length === 1 || !part.startsWith("0"))) ? value : null;
	}
	if (!/^[0-9a-fA-F:]+$/.test(value) || !value.includes(":")) return null;
	try { return new URL(`http://[${value}]/`).hostname.slice(1, -1).toLowerCase(); }
	catch { return null; }
}

async function boundedBody(request, limit = MAX_DEVICE_BODY) {
	const declared = request.headers.get("content-length");
	if (declared && (!/^(0|[1-9]\d*)$/.test(declared) || Number(declared) > limit)) return null;
	if (!request.body) return new Uint8Array();
	const reader = request.body.getReader();
	const chunks = [];
	let size = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > limit) return null;
			chunks.push(value);
		}
	} finally { reader.releaseLock(); }
	const body = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
	return body;
}

async function boundedResponse(response, limit = MAX_DEVICE_RESPONSE) {
	const declared = response.headers.get("content-length");
	if (declared && (!/^\d+$/.test(declared) || Number(declared) > limit)) return null;
	if (!response.body) return new Uint8Array();
	const reader = response.body.getReader();
	const chunks = [];
	let size = 0;
	try {
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			size += value.byteLength;
			if (size > limit) return null;
			chunks.push(value);
		}
	} finally { reader.releaseLock(); }
	const body = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.byteLength; }
	return body;
}

async function probe(url, key, fetcher, expectedStatus, expectedBody = null) {
	try {
		const response = await fetcher(url, {
			method: "GET", headers: { apikey: key, "cache-control": "no-cache" }, redirect: "manual", signal: AbortSignal.timeout(PROBE_TIMEOUT_MS),
		});
		if (response.status !== expectedStatus) { await response.body?.cancel(); return "failed"; }
		if (!expectedBody) { await response.body?.cancel(); return "reachable"; }
		if (!response.headers.get("content-type")?.toLowerCase().startsWith("application/json")) { await response.body?.cancel(); return "failed"; }
		const bytes = await boundedResponse(response, MAX_PROBE_RESPONSE);
		if (!bytes) { await response.body?.cancel(); return "failed"; }
		return JSON.stringify(JSON.parse(new TextDecoder().decode(bytes))) === JSON.stringify(expectedBody) ? "reachable" : "failed";
	} catch { return "failed"; }
}

async function readiness(request, env, fetcher) {
	let config;
	try { config = configuration(env); }
	catch { return jsonError(503, "service_not_configured", request); }
	if (new URL(request.url).origin !== config.site) return jsonError(403, "wrong_public_origin", request);
	if (!RELEASE_VERSION.test(env.AIDR_RELEASE_VERSION ?? "") || !RELEASE_SHA.test(env.AIDR_RELEASE_SHA ?? "")) {
		return jsonError(503, "release_identity_unavailable", request);
	}
	const cacheKey = `${config.site}\n${config.provider}\n${config.anonKey}\n${env.AIDR_RELEASE_SHA}`;
	let checks = cachedReadiness?.key === cacheKey && cachedReadiness.fetcher === fetcher && Date.now() >= cachedReadiness.at && Date.now() - cachedReadiness.at < READINESS_CACHE_MS
		? cachedReadiness.checks : null;
	if (!checks) {
		let pending = inFlightReadiness?.key === cacheKey && inFlightReadiness.fetcher === fetcher ? inFlightReadiness.promise : null;
		if (!pending) {
			pending = Promise.all([
				probe(`${config.provider}/auth/v1/health`, config.anonKey, fetcher, 200),
				probe(`${config.provider}/rest/v1/rpc/aidr_readiness_probe`, config.anonKey, fetcher, 200, { ok: true }),
				probe(`${config.provider}/storage/v1/status`, config.anonKey, fetcher, 200),
				probe(`${config.provider}/functions/v1/packs-manifest`, config.anonKey, fetcher, 401, { error: "missing_api_key" }),
			]);
			inFlightReadiness = { key: cacheKey, fetcher, promise: pending };
		}
		try {
			checks = await pending;
			cachedReadiness = { key: cacheKey, fetcher, checks, at: Date.now() };
		} finally {
			if (inFlightReadiness?.promise === pending) inFlightReadiness = null;
		}
	}
	const [auth, database, storage, functions] = checks;
	// These live dependencies do not attest backup, signer, queue or public TLS.
	const body = { status: "not_ready", component: "cloud-control-plane", checks: {
		auth, database, storage, functions,
		signing: "unverified", backup: "unverified", queue: "unverified", certificate: "unverified",
	} };
	return new Response(request.method === "HEAD" ? null : JSON.stringify(body), {
		status: 503,
		headers: { "cache-control": "no-store", "content-type": "application/json; charset=utf-8", "x-content-type-options": "nosniff" },
	});
}

// The signing context binds a proof to one Edge Function route, so a
// device-start proof cannot be replayed against waitlist-signup or vice versa.
async function signedHeaders(request, config, context = "device-start:v1") {
	const ip = canonicalIp(request.headers.get("cf-connecting-ip"));
	if (!ip) return null; // Never fall back to client-supplied forwarding headers.
	const timestamp = String(Math.floor(Date.now() / 1000));
	const key = await crypto.subtle.importKey("raw", encoder.encode(config.secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
	const signed = await crypto.subtle.sign("HMAC", key, encoder.encode(`${context}\n${timestamp}\n${ip}`));
	return {
		"x-aidr-client-ip": ip,
		"x-aidr-client-timestamp": timestamp,
		"x-aidr-client-signature": [...new Uint8Array(signed)].map((byte) => byte.toString(16).padStart(2, "0")).join(""),
	};
}

function forwardHeaders(request) {
	const headers = new Headers(request.headers);
	for (const name of [...headers.keys()]) {
		if (name.startsWith("x-aidr-client-") || name.startsWith("cf-") || ["host", "connection", "content-length", "transfer-encoding", "x-aidr-proxy-token", "x-forwarded-for", "x-real-ip"].includes(name)) {
			headers.delete(name);
		}
	}
	return headers;
}

async function proxy(request, config, fetcher) {
	const incoming = new URL(request.url);
	let body = request.body;
	if (config.signupMode === "closed" && request.method === "POST") {
		let authPath = incoming.pathname;
		try { authPath = decodeURIComponent(authPath); } catch { /* Leave malformed paths to the upstream router. */ }
		authPath = authPath.replace(/\/+$/, "");
		if (authPath === "/auth/v1/signup") return jsonError(403, "signup_closed", request);
		if (authPath === "/auth/v1/otp") {
			const contentType = request.headers.get("content-type") ?? "";
			if (!/^application\/json(?:\s*;|$)/i.test(contentType)) return jsonError(403, "signup_closed", request);
			const bytes = await boundedBody(request, MAX_AUTH_BODY);
			if (!bytes) return jsonError(413, "request_too_large", request);
			let payload;
			try { payload = JSON.parse(new TextDecoder().decode(bytes)); }
			catch { return jsonError(403, "signup_closed", request); }
			if (!payload || payload.create_user !== false) return jsonError(403, "signup_closed", request);
			body = bytes;
		}
	}
	const deviceStart = incoming.pathname === DEVICE_START;
	const headers = forwardHeaders(request);
	if (deviceStart) {
		if (!["POST", "OPTIONS"].includes(request.method)) return jsonError(405, "method_not_allowed");
		const bytes = await boundedBody(request);
		if (!bytes) return jsonError(413, "request_too_large");
		if (request.method === "OPTIONS" && bytes.length) return jsonError(400, "preflight_body_not_allowed");
		const signature = await signedHeaders(request, config);
		if (!signature) return jsonError(403, "trusted_edge_ip_required");
		for (const [name, value] of Object.entries(signature)) headers.set(name, value);
		headers.set("apikey", config.anonKey);
		headers.set("authorization", `Bearer ${config.anonKey}`);
		headers.set("content-type", "application/json");
		body = request.method === "POST" ? bytes : null;
	}
	if (incoming.pathname === WAITLIST_SIGNUP && request.method === "POST") {
		// The waitlist function keys its per-client quota on this proof when
		// AIDR_WAITLIST_INGRESS_SECRET matches the edge secret; without a
		// Cloudflare client IP it is forwarded unsigned and the function decides.
		const signature = await signedHeaders(request, config, "waitlist-signup:v1");
		if (signature) for (const [name, value] of Object.entries(signature)) headers.set(name, value);
	}
	const upstream = `${config.provider}${incoming.pathname}${incoming.search}`;
	let response;
	try {
		response = await fetcher(upstream, { method: request.method, headers, body: ["GET", "HEAD"].includes(request.method) ? undefined : body, redirect: "manual", duplex: "half" });
	} catch { return jsonError(502, "upstream_unavailable"); }
	if (deviceStart) {
		if (response.status >= 300 && response.status < 400) return jsonError(502, "upstream_redirect_rejected");
		let bytes;
		try { bytes = await boundedResponse(response); }
		catch { return jsonError(502, "upstream_unavailable"); }
		if (!bytes) return jsonError(502, "upstream_response_too_large");
		const safe = new Headers({ "content-type": "application/json; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" });
		const origin = request.headers.get("origin");
		if (origin === config.site && response.headers.get("access-control-allow-origin") === origin) {
			safe.set("access-control-allow-origin", origin);
			safe.set("vary", "Origin");
			for (const name of ["access-control-allow-headers", "access-control-allow-methods"]) {
				const value = response.headers.get(name);
				if (value && !/[\r\n]/.test(value)) safe.set(name, value);
			}
		}
		return new Response([204, 205, 304].includes(response.status) ? null : bytes, { status: response.status, headers: safe });
	}
	if (response.webSocket) return response; // Preserve Realtime upgrades.
	const safe = new Headers(response.headers);
	safe.set("cache-control", "no-store");
	safe.set("x-content-type-options", "nosniff");
	return new Response(response.body, { status: response.status, statusText: response.statusText, headers: safe });
}

export async function handle(request, env, fetcher = fetch) {
	const url = new URL(request.url);
	if (url.pathname === "/demo" || url.pathname === "/demo/") {
		if (!["GET", "HEAD"].includes(request.method)) return jsonError(405, "method_not_allowed");
		return new Response(null, { status: 302, headers: { location: "/login?returnTo=%2Fonboarding", "cache-control": "no-store" } });
	}
	if (url.pathname === "/version") return version(request, url, env);
	if (["/livez", "/healthz", "/readyz", "/metrics"].includes(url.pathname)) return health(request, url.pathname, env, fetcher);
	const api = API_PREFIXES.some((prefix) => url.pathname === prefix || url.pathname.startsWith(`${prefix}/`));
	if (!api && url.pathname !== "/runtime-config.js") return env.ASSETS.fetch(request);
	let config;
	try { config = configuration(env); }
	catch { return jsonError(503, "service_not_configured"); }
	if (url.origin !== config.site) return jsonError(403, "wrong_public_origin");
	if (url.pathname === "/runtime-config.js") {
		if (request.method !== "GET" && request.method !== "HEAD") return jsonError(405, "method_not_allowed");
		const authMethods = ["password", "magic-link"];
		if (env.AIDR_ENABLE_AZURE_AUTH === "true") authMethods.push("azure");
		let samlConfig;
		let oidcConfig;
		try {
			oidcConfig = parseOidcRuntimeConfig(env.AIDR_OIDC_SSO);
			samlConfig = parseSamlRuntimeConfig({
				providers: env.AIDR_SAML_PROVIDERS,
				providerId: env.AIDR_SAML_PROVIDER_ID,
				domain: env.AIDR_SAML_DOMAIN,
			});
		} catch {
			return jsonError(503, "service_not_configured");
		}
		const payload = JSON.stringify({ supabaseUrl: config.site, supabaseAnonKey: config.anonKey, authMethods, signupMode: config.signupMode, ...samlConfig, ...oidcConfig }).replace(/</g, "\\u003c");
		return new Response(request.method === "HEAD" ? null : `window.__AIDR_CONFIG__=${payload};`, {
			headers: { "content-type": "application/javascript; charset=utf-8", "cache-control": "no-store", "x-content-type-options": "nosniff" },
		});
	}
	return proxy(request, config, fetcher);
}

// Workers supplies an execution context as the third argument. Keep it out of
// handle's injected fetcher slot, which is reserved for deterministic tests.
export default { fetch: (request, env) => handle(request, env) };
