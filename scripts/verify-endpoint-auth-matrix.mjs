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

import { existsSync } from "node:fs";
import { readdir, readFile } from "node:fs/promises";
import path from "node:path";
import process from "node:process";
import { fileURLToPath } from "node:url";

export const IDENTITY_BARRIER_MODULE = "../_shared/identity-barrier.ts";
export const IDENTITY_BARRIER_CALL = "checkIdentityBarrier(";
export const API_KEY_GUARD_MODULE = "../_shared/api-key-auth.ts";
export const API_KEY_GUARD_CALL = "authenticateTenantApiKey(";

/**
 * Routes with no Supabase user session and no tenant API key, by design.
 * `mechanism` names the credential the route actually verifies; `justification`
 * is the one-line reason it is not a missing guard.
 */
export const PUBLIC_ROUTE_ALLOWLIST = Object.freeze([
	{
		route: "supabase/functions/device-start/index.ts",
		mechanism: "signed ingress IP proof",
		justification:
			"Public device-code bootstrap: no user identity exists yet, and the caller must present an HMAC signature over the canonical client IP (AIDR_DEVICE_START_INGRESS_SECRET).",
	},
	{
		route: "supabase/functions/device-poll/index.ts",
		mechanism: "device code",
		justification:
			"Public device-code poll: the 256-bit device code in the request is the credential, and it can only read the session it names.",
	},
	{
		route: "supabase/functions/enroll/index.ts",
		mechanism: "one-time enrollment token",
		justification:
			"Exchanges a one-time enrollment token (Bearer) for an API key; the caller has neither an account JWT nor an API key by definition.",
	},
	{
		route: "supabase/functions/waitlist-signup/index.ts",
		mechanism: "public intake",
		justification:
			"Public waitlist intake: it creates no account and writes no tenant data, is throttled by a fail-closed deployment-wide aggregate quota (not caller IP), and echoes CORS headers only for allowlisted origins.",
	},
	{
		route: "supabase/functions/scim/index.ts",
		mechanism: "SCIM bearer token",
		justification:
			"IdP provisioning: the Bearer token is resolved to a tenant by the hash-only `scim_resolve_token` RPC, which is neither a Supabase session nor a tenant API key.",
	},
	{
		route: "supabase/functions/paddle-webhook/index.ts",
		mechanism: "webhook HMAC signature",
		justification:
			"Paddle webhook: HMAC-SHA256 over `ts:rawBody` is verified against the configured secret before any billing state is read or written.",
	},
	{
		route: "supabase/functions/stripe-webhook/index.ts",
		mechanism: "webhook HMAC signature",
		justification:
			"Stripe webhook: the `Stripe-Signature` header is verified over the raw body before any billing state is read or written.",
	},
]);

/** Which shared guards the route source presents (an empty list is a failure). */
export function guardsForRoute(source) {
	const guards = [];
	if (source.includes(IDENTITY_BARRIER_MODULE) && source.includes(IDENTITY_BARRIER_CALL)) {
		guards.push("identity-barrier");
	}
	if (source.includes(API_KEY_GUARD_MODULE) && source.includes(API_KEY_GUARD_CALL)) {
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
		if (!allowed.has(route)) {
			failures.push(
				`${route}: no identity barrier and no API-key guard (add one, or justify the route in PUBLIC_ROUTE_ALLOWLIST)`,
			);
		}
	}

	return {
		failures,
		checked: routes.length,
		guarded,
		allowlisted: allowed.size,
	};
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
	});
	if (report.failures.length > 0) {
		console.error("Endpoint auth matrix failed:");
		for (const failure of report.failures) console.error(`- ${failure}`);
		process.exitCode = 1;
		return;
	}
	console.log(
		`Endpoint auth matrix passed (${report.checked} routes: ${report.guarded} guarded, ` +
			`${report.allowlisted} justified public).`,
	);
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(fileURLToPath(import.meta.url))) {
	await main();
}
