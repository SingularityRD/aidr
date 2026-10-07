#!/usr/bin/env node
// Gate: every Supabase Edge route must present an authentication guard.
//
// A route under `supabase/functions/<name>/index.ts` is *guarded* when it calls
// either shared guard:
//
//   * the identity barrier (`_shared/identity-barrier.ts`) for a Supabase
//     user session, or
//   * the API-key guard (`_shared/api-key-auth.ts`) for a hash-only tenant API
//     key.
//
// Anything else fails the gate unless it is listed in PUBLIC_ROUTE_ALLOWLIST
// with a written, one-line justification. The matrix is route level: a route
// that serves a public action *and* an authenticated action (for example a
// recovery endpoint) still has to present one of the guards for the
// authenticated path.
//
// The allowlist is deliberately small and derived from the code, not from a
// list of names: every entry below was read and has an explicit mechanism that
// is not a Supabase session or API key. A route that grows a guard while still
// being allowlisted is reported as a stale exception, so the exception list
// cannot outlive its reason.

import { existsSync, readFileSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const IDENTITY_BARRIER_MODULE = "../_shared/identity-barrier.ts";
export const IDENTITY_BARRIER_CALL = "checkIdentityBarrier(";
export const API_KEY_GUARD_MODULE = "../_shared/api-key-auth.ts";
export const API_KEY_GUARD_CALL = "authenticateTenantApiKey(";
// Same guard behind the per-endpoint unresolved-credential budget.
export const API_KEY_BUDGETED_GUARD_CALL = "authenticateTenantApiKeyBudgeted(";

/**
 * Routes with no Supabase user session and no tenant API key, by design.
 * `mechanism` names the credential the route actually verifies; `justification`
 * is the one-line reason it is not a missing guard.
 */
export const PUBLIC_ROUTE_ALLOWLIST = Object.freeze([
	{
		route: "supabase/functions/device-start/index.ts",
		rateLimited: true,
		mechanism: "signed ingress IP proof",
		justification:
			"Public device-code bootstrap: no user identity exists yet, and the caller must present an HMAC signature over the canonical client IP (AIDR_DEVICE_START_INGRESS_SECRET).",
	},
	{
		route: "supabase/functions/device-poll/index.ts",
		rateLimited: true,
		mechanism: "device code",
		justification:
			"Public device-code poll: the 256-bit device code in the request is the credential, it can only read the session it names, and each live code has a fail-closed per-minute poll budget answered with RFC 8628 slow_down.",
	},
	{
		route: "supabase/functions/enroll/index.ts",
		rateLimited: true,
		mechanism: "one-time enrollment token",
		justification:
			"Exchanges a one-time enrollment token (Bearer) for an API key; the caller has neither an account JWT nor an API key by definition.",
	},
	{
		route: "supabase/functions/waitlist-signup/index.ts",
		rateLimited: true,
		mechanism: "public intake",
		justification:
			"Public waitlist intake: it creates no account, writes no tenant data and only inserts (never overwrites) a signup; it verifies a Cloudflare Turnstile token server-side when TURNSTILE_SECRET_KEY is set, is throttled by a fail-closed deployment-wide aggregate quota plus a per-client quota keyed by a signed ingress IP proof when AIDR_WAITLIST_INGRESS_SECRET is set (never by caller-supplied proxy headers), and echoes CORS headers only for allowlisted origins.",
	},
	{
		route: "supabase/functions/scim/index.ts",
		rateLimited: true,
		mechanism: "SCIM bearer token",
		justification:
			"IdP provisioning: the Bearer token is resolved to a tenant by the hash-only `scim_resolve_token` RPC, which is neither a Supabase session nor a tenant API key.",
	},
	{
		route: "supabase/functions/paddle-webhook/index.ts",
		rateLimited: false,
		mechanism: "webhook HMAC signature",
		justification:
			"Paddle webhook: HMAC-SHA256 over `ts:rawBody` is verified against the configured secret before any billing state is read or written.",
	},
	{
		route: "supabase/functions/stripe-webhook/index.ts",
		rateLimited: false,
		mechanism: "webhook HMAC signature",
		justification:
			"Stripe webhook: the `Stripe-Signature` header is verified over the raw body before any billing state is read or written.",
	},
	{
		route: "supabase/functions/notification-dispatch/index.ts",
		// Like a signature-verified webhook: a 32+ char shared secret compared in
		// constant time is required before any work, so there is no anonymous
		// caller to rate limit. Not application rate limited (declared honestly).
		rateLimited: false,
		mechanism: "dedicated dispatcher bearer token",
		justification:
			"Scheduler-only outbox dispatcher: POST with `Authorization: Bearer <AIDR_NOTIFICATION_DISPATCH_TOKEN>` (at least 32 chars, compared in constant time) before any row is read; it has no user or tenant caller, fails closed when the token or keyring is unset, and never accepts the service-role key.",
	},
]);

export const RATE_LIMIT_MODULE = "../_shared/rate-limit.ts";
export const RATE_LIMIT_CALL = "consumeRateLimit(";
export const RATE_LIMIT_RPC = "increment_rate_limit";

/**
 * A public route enforces application-level rate limiting when it calls the
 * shared limiter or the `increment_rate_limit` RPC directly. Importing the
 * module without calling it does not count.
 */
export function hasRateLimit(source) {
	return (
		(source.includes(RATE_LIMIT_MODULE) && source.includes(RATE_LIMIT_CALL)) ||
		source.includes(RATE_LIMIT_RPC)
	);
}
/**
 * Guarded routes that ALSO serve a deliberately public action. The route-level
 * guard above is not enough for these: a guard on one action says nothing about
 * the others. Each public action must be declared here with the credential it
 * verifies, and the handler must mark exactly those switch cases with a
 * `// public-action: <name>` comment. An undeclared public case, a declared case
 * that is missing, or a handler with no authenticated case at all fails the gate.
 */
export const MIXED_ROUTE_PUBLIC_ACTIONS = Object.freeze([
	{
		route: "supabase/functions/oidc-sso/index.ts",
		handler: "supabase/functions/oidc-sso/handler.ts",
		actions: Object.freeze([
			{
				name: "start",
				mechanism: "provider-scoped rate limit; creates only a single-use PKCE/state row",
				justification:
					"Begins an authorization-code flow: it returns an IdP URL and stores a hashed single-use state, nonce and PKCE verifier; no session or tenant data is returned and unknown providers are indistinguishable.",
			},
			{
				name: "callback",
				mechanism: "single-use state + PKCE + browser binding secret + verified ID token",
				justification:
					"Finishes the flow: the state is consumed atomically, the browser must present the binding secret, and the ID token signature, issuer, audience, nonce and tenant-verified email domain are checked before any login ticket is issued.",
			},
			{
				name: "break_glass_suspend_enforcement",
				mechanism: "single-use owner recovery code",
				justification:
					"IdP-outage recovery for a tenant owner: spends one single-use, hashed recovery code under the shared identity-recovery rate limit, returns no session and audits the suspension.",
			},
		]),
	},
]);

/** Which shared guards the route source presents (an empty list is a failure). */
export function guardsForRoute(source) {
	const guards = [];
	if (source.includes(IDENTITY_BARRIER_MODULE) && source.includes(IDENTITY_BARRIER_CALL)) {
		guards.push("identity-barrier");
	}
	if (
		source.includes(API_KEY_GUARD_MODULE) &&
		(source.includes(API_KEY_GUARD_CALL) || source.includes(API_KEY_BUDGETED_GUARD_CALL))
	) {
		guards.push("api-key-auth");
	}
	return guards;
}

/**
 * Evaluate the matrix. `routes` is `[{ route, source }]`; `fileExists` resolves
 * an allowlist path so a stale exception is reported instead of trusted.
 */
export function evaluateAuthMatrix(routes, allowlist = PUBLIC_ROUTE_ALLOWLIST, options = {}) {
	const fileExists = options.fileExists ?? (() => true);
	const failures = [];
	const allowed = new Map();

	for (const entry of allowlist) {
		if (allowed.has(entry.route)) failures.push(`${entry.route}: duplicate allowlist entry`);
		allowed.set(entry.route, entry);
		if (typeof entry.justification !== "string" || entry.justification.trim().length < 40) {
			failures.push(`${entry.route}: allowlist entry needs a written one-line justification`);
		} else if (entry.justification.includes("\n")) {
			failures.push(`${entry.route}: allowlist justification must be one line`);
		}
		if (typeof entry.mechanism !== "string" || entry.mechanism.trim().length === 0) {
			failures.push(`${entry.route}: allowlist entry must name the credential mechanism it verifies`);
		}
		if (!fileExists(entry.route)) {
			failures.push(`${entry.route}: allowlisted route does not exist (stale exception)`);
		}
	}

	let guarded = 0;
	for (const { route, source } of routes) {
		const guards = guardsForRoute(source);
		if (guards.length > 0) {
			guarded += 1;
			if (allowed.has(route)) {
				failures.push(
					`${route}: allowlisted as public but presents ${guards.join(" + ")} (stale exception)`,
				);
			}
			continue;
		}
		const entry = allowed.get(route);
		if (entry && typeof entry.rateLimited !== "boolean") {
			failures.push(`${route}: allowlist entry must declare rateLimited (true, or false for a signature-verified webhook)`);
		} else if (entry?.rateLimited && !hasRateLimit(source)) {
			failures.push(`${route}: public route must enforce application-level rate limiting (consumeRateLimit or increment_rate_limit)`);
		}
		if (!allowed.has(route)) {
			failures.push(
				`${route}: no identity barrier and no API-key guard (add one, or justify the route in PUBLIC_ROUTE_ALLOWLIST)`,
			);
		}
	}

	for (const mixed of options.mixedRoutes ?? []) {
		const route = routes.find((candidate) => candidate.route === mixed.route);
		if (!route) {
			failures.push(`${mixed.route}: mixed-route declaration does not match an Edge route (stale entry)`);
			continue;
		}
		if (guardsForRoute(route.source).length === 0)
			failures.push(`${mixed.route}: declares public actions but presents no identity or API-key guard`);
		const handlerSource = options.readSource?.(mixed.handler);
		if (typeof handlerSource !== "string") {
			failures.push(`${mixed.handler}: handler for ${mixed.route} cannot be read`);
			continue;
		}
		failures.push(...evaluateMixedHandler(mixed, handlerSource));
	}

	return {
		failures,
		checked: routes.length,
		guarded,
		allowlisted: allowed.size,
		mixed: (options.mixedRoutes ?? []).length,
	};
}

/** Compare the handler's `// public-action:` markers with the declared public actions. */
export function evaluateMixedHandler(mixed, handlerSource) {
	const failures = [];
	const cases = [...handlerSource.matchAll(/(\/\/ public-action: (\w+)\s*\n\s*)?case "(\w+)":/g)];
	const publicCases = new Set();
	let authenticated = 0;
	for (const match of cases) {
		if (match[1]) {
			if (match[2] !== match[3])
				failures.push(`${mixed.handler}: public-action marker "${match[2]}" is attached to case "${match[3]}"`);
			publicCases.add(match[3]);
		} else {
			authenticated += 1;
		}
	}
	const declared = new Set(mixed.actions.map((action) => action.name));
	for (const name of publicCases)
		if (!declared.has(name))
			failures.push(`${mixed.handler}: public action "${name}" is not declared in MIXED_ROUTE_PUBLIC_ACTIONS`);
	for (const action of mixed.actions) {
		if (!publicCases.has(action.name))
			failures.push(`${mixed.handler}: declared public action "${action.name}" is not marked in the handler (stale declaration)`);
		if (action.justification.trim().length < 40 || action.justification.includes("\n"))
			failures.push(`${mixed.handler}: public action "${action.name}" needs a one-line justification`);
		if (action.mechanism.trim().length === 0)
			failures.push(`${mixed.handler}: public action "${action.name}" must name its mechanism`);
	}
	if (authenticated === 0) failures.push(`${mixed.handler}: no authenticated action; the route is entirely public`);
	if (!/\.authenticate\(/.test(handlerSource))
		failures.push(`${mixed.handler}: authenticated actions never call authenticate()`);
	return failures;
}

/** Every `supabase/functions/<name>/index.ts` route plus its source. */
export async function readRoutes(root = process.cwd()) {
	const functionsDir = path.join(root, "supabase", "functions");
	const routes = [];
	for (const entry of await readdir(functionsDir, { withFileTypes: true })) {
		if (!entry.isDirectory() || entry.name.startsWith("_") || entry.name === "__tests__") continue;
		const file = path.join(functionsDir, entry.name, "index.ts");
		if (!existsSync(file)) continue;
		routes.push({
			route: path.relative(root, file).split(path.sep).join("/"),
			source: await readFile(file, "utf8"),
		});
	}
	return routes.sort((a, b) => a.route.localeCompare(b.route));
}

async function main() {
	const root = process.cwd();
	const routes = await readRoutes(root);
	const report = evaluateAuthMatrix(routes, PUBLIC_ROUTE_ALLOWLIST, {
		fileExists: (route) => existsSync(path.join(root, route)),
		mixedRoutes: MIXED_ROUTE_PUBLIC_ACTIONS,
		readSource: (file) => readFileSync(path.join(root, file), "utf8"),
	});
	if (report.failures.length > 0) {
		console.error("Endpoint auth matrix failed:");
		for (const failure of report.failures) console.error(`- ${failure}`);
		process.exitCode = 1;
		return;
	}
	console.log(
		`Endpoint auth matrix passed (${report.checked} routes: ${report.guarded} guarded, ` +
			`${report.allowlisted} justified public, ${report.mixed} with declared public actions).`,
	);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
	await main();
}
