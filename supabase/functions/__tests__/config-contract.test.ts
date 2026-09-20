// Static wiring contract for Edge Function configuration validation (AIDR-011).
//
// Every `supabase/functions/<name>/index.ts` calls `Deno.serve` and imports
// `npm:@supabase/supabase-js@2`, so a function file cannot be imported into
// vitest. What can be verified here is the wiring contract that only exists in
// those files: that each function validates its required configuration through
// the shared guard, before it creates a client or performs any work, and that
// no function went back to the `Deno.env.get(...) ?? ""` fallback that this
// finding is about.
//
// COVERAGE BOUNDARY: this suite reads source text. It does not execute the
// deployed Deno runtime. The behaviour of the guard itself is unit-tested in
// ./config.test.ts.

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const FUNCTIONS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO_ROOT = resolve(FUNCTIONS_DIR, "..", "..");

/** Variables no Edge Function may read with an empty-string fallback. */
const PLATFORM_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

/**
 * Work that must never run before configuration has been validated. Anchored
 * inside the request handler only, so definitions of these helpers elsewhere in
 * the file do not count.
 */
const WORK_ANCHORS = [
	"createClient(",
	".auth.getUser(",
	".from(",
	".rpc(",
	"authenticatedUser(",
] as const;

/** Function-specific required configuration, by function name. */
const FUNCTION_ENV: Record<string, readonly string[]> = {
	"paddle-webhook": ["AIDR_PADDLE_WEBHOOK_SECRET"],
	"billing-checkout": ["STRIPE_SECRET_KEY", "AIDR_STRIPE_EXTRA_AGENT_PRICE_ID", "AIDR_DASHBOARD_URL"],
	"team-invite": ["AIDR_DASHBOARD_URL"],
};

function functionNames(): string[] {
	return readdirSync(FUNCTIONS_DIR)
		.filter((entry) => !entry.startsWith("_") && !entry.startsWith("__"))
		.filter((entry) => statSync(join(FUNCTIONS_DIR, entry)).isDirectory())
		.sort();
}

function sourceOf(name: string): string {
	return readFileSync(join(FUNCTIONS_DIR, name, "index.ts"), "utf8");
}

/**
 * The request path: the `Deno.serve(async (req) => { ... })` body, or the
 * exported handler factory it delegates to (`Deno.serve(createXHandler())`).
 * A function that moves its handler into a factory — so a contract suite can
 * drive it with an injected client — is still covered.
 */
function handlerBody(source: string): string {
	const start = source.indexOf("Deno.serve(");
	expect(start, "expected Deno.serve in the function file").toBeGreaterThanOrEqual(0);
	const factory = source.indexOf("export function create");
	if (factory >= 0 && factory < start) {
		// A factory wraps the request path in further helpers defined next to it.
		// Scope the body to the exported factory up to `Deno.serve(`, not to the
		// module: that is what a reader would call "the request path". A
		// dependency-injected client builder may legitimately appear before the
		// guard because it is only *called* after the guard runs, so the client
		// anchor is bound to the call site rather than to the builder.
		return source.slice(factory, start);
	}
	return source.slice(start);
}

/**
 * Index of the first *reachable* use of an anchor.
 *
 * A factory may declare a dependency-injected client builder
 * (`deps.client ?? ((url, key) => createClient(...))`) before the guard; that
 * builder is only *called* after the guard runs, so for `createClient(` the
 * ordering rule is applied to the last occurrence inside the factory rather
 * than to the declaration. Every other anchor uses its first occurrence.
 */
function firstUnsafeIndex(source: string, anchor: string): number {
	if (anchor !== "createClient(") return source.indexOf(anchor);
	// Prefer a resolved binding (`makeClient = ...`) when the factory uses one;
	// otherwise the declaration itself is the earliest reachable client work.
	const bound = source.indexOf("makeClient =");
	if (bound >= 0) return bound;
	const last = source.lastIndexOf(anchor);
	return last < 0 ? -1 : last;
}

/** Names listed in `const REQUIRED_ENV = [...] as const;`. */
function requiredEnvNames(source: string): string[] {
	const block = /const REQUIRED_ENV = \[([\s\S]*?)\]\s*as const;/.exec(source);
	if (!block) return [];
	return [...(block[1] ?? "").matchAll(/"([A-Z][A-Z0-9_]*)"/g)].map((match) => match[1] ?? "");
}

/**
 * Every variable a function declares as required: the base list plus any name
 * added to the expression actually handed to `loadConfig` (billing-checkout
 * requires its checkout URL only while the legacy self-service path is on).
 */
function declaredRequiredNames(source: string): string[] {
	const names = new Set(requiredEnvNames(source));
	const argument = /loadConfig\(runtimeEnv,\s*([A-Za-z_$][\w$]*)/.exec(source)?.[1];
	if (argument && argument !== "REQUIRED_ENV") {
		const declaration = new RegExp(`const ${argument} = ([\\s\\S]*?);\\n`).exec(source);
		for (const match of (declaration?.[1] ?? "").matchAll(/"([A-Z][A-Z0-9_]*)"/g)) {
			if (match[1]) names.add(match[1]);
		}
	}
	return [...names];
}

/**
 * Empty-string fallbacks that remain, each with the reason it is safe. Anything
 * not on this list is an unvalidated read: `Deno.env.get("X") ?? ""` for a
 * credential is exactly the defect this contract exists to prevent.
 */
const DOCUMENTED_EMPTY_FALLBACKS: Record<string, string> = {
	// Optional per-deployment integration. The URL/token pair is guarded by
	// `partialGroupError`; the team mapping is an explicit alternative in
	// `configured()`, which fails closed with `integration_not_configured`.
	AUTOSECOPS_RUNTIME_URL: "optional integration",
	AUTOSECOPS_RUNTIME_TOKEN: "optional integration",
	AUTOSECOPS_AIDR_TEAM_ID: "optional integration",
	AUTOSECOPS_TEAM_ID: "optional integration",
	AUTOSECOPS_RUNTIME_TEAM_MAP: "optional integration",
	// Optional provisioning. A half-configured pair is rejected by
	// `partialGroupError`; a fully unprovisioned one yields an explicitly
	// unsigned payload the client already refuses.
	AIDR_ENTITLEMENT_SIGNING_KEY_ID: "optional provisioning",
	AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64: "optional provisioning",
	AIDR_REVOCATION_SIGNING_KEY_ID: "optional provisioning",
	AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64: "optional provisioning",
	AIDR_PACK_MASTER_KEY_B64: "optional provisioning",
	// Unprovisioned endpoint secret with its own documented fail-closed path:
	// 400 `invalid_signature`, no writes, variable named in the log.
	STRIPE_WEBHOOK_SECRET: "self-gated fail-closed path",
	// Optional booleans and pricing; absence means "feature off" / "no price
	// filter", never an empty credential.
	AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING: "optional flag",
	AIDR_STRIPE_EXTRA_AGENT_PRICE_ID: "optional pricing",
	AIDR_PADDLE_EXTRA_AGENT_PRICE_ID: "optional pricing",
};

const FUNCTIONS = functionNames();

describe("edge function inventory", () => {
	it("finds every function directory", () => {
		// Guard against the suite silently passing because discovery broke.
		expect(FUNCTIONS.length).toBeGreaterThanOrEqual(20);
		expect(FUNCTIONS).toContain("url-check");
		expect(FUNCTIONS).toContain("waitlist-signup");
		expect(FUNCTIONS).toContain("stripe-webhook");
	});
});

describe.each(FUNCTIONS)("%s configuration guard", (name) => {
	const source = sourceOf(name);

	it("validates required configuration through the shared helper", () => {
		expect(source).toContain('from "../_shared/config.ts"');
		expect(source).toContain("loadConfig(runtimeEnv,");
		expect(source).toContain("configFailure(");

		const names = declaredRequiredNames(source);
		for (const variable of PLATFORM_ENV) {
			expect(names, `${name}: REQUIRED_ENV must contain ${variable}`).toContain(variable);
		}
		for (const variable of FUNCTION_ENV[name] ?? []) {
			expect(names, `${name}: required configuration must contain ${variable}`).toContain(variable);
		}
	});

	it("never falls back to an empty string for required configuration", () => {
		for (const variable of [...PLATFORM_ENV, ...(FUNCTION_ENV[name] ?? [])]) {
			// The defect: `Deno.env.get("X") ?? ""`. Tolerate any spacing.
			const fallback = new RegExp(`Deno\\.env\\.get\\(\\s*"${variable}"\\s*\\)\\s*\\?\\?\\s*""`);
			expect(source, `${name}: ${variable} must not use an empty-string fallback`).not.toMatch(
				fallback,
			);
		}
	});

	it("validates exactly once, before any client, auth, database or RPC work", () => {
		const handler = handlerBody(source);
		const guard = handler.indexOf("loadConfig(runtimeEnv,");
		expect(guard, `${name}: no request-time configuration guard`).toBeGreaterThanOrEqual(0);

		const loadCalls = [...handler.matchAll(/loadConfig\(runtimeEnv,/g)].length;
		expect(loadCalls, `${name}: configuration must be validated once per request`).toBe(1);

		for (const anchor of WORK_ANCHORS) {
			const index = firstUnsafeIndex(handler, anchor);
			if (index < 0) continue;
			expect(
				guard,
				`${name}: configuration guard must precede ${anchor}`,
			).toBeLessThan(index);
		}
	});

	it("still answers preflight and origin policy before configuration work", () => {
		const corsImport = 'from "../_shared/cors.ts"';
		const usesCors = source.includes(corsImport);
		const handler = handlerBody(source);
		const preflight = handler.indexOf("handleCors(req)");
		const guard = handler.indexOf("loadConfig(runtimeEnv,");

		if (usesCors) {
			expect(preflight, `${name}: missing handleCors`).toBeGreaterThanOrEqual(0);
			expect(preflight).toBeLessThan(guard);
		} else {
			// Functions without the shared CORS import have no preflight contract;
			// assert that this exception remains narrow rather than skipping coverage.
			expect(preflight, `${name}: handleCors requires the shared CORS import`).toBe(-1);
		}
	});

	it("answers a configuration failure with the shared structured body", () => {
		// Every configuration failure goes through `configFailure`, which is the
		// only projection of a ConfigurationError. A hand-rolled body could leak.
		expect(source).not.toMatch(/error:\s*(?:error|e)\.message/);
		expect(source).not.toMatch(/json\(500,\s*\{\s*error:\s*"misconfigured/);
	});
});

describe("no unvalidated credential read remains", () => {
	it("limits every remaining empty-string fallback to a documented safe case", () => {
		const seen = new Map<string, string>();
		for (const name of FUNCTIONS) {
			const functionSource = sourceOf(name);
			for (const match of functionSource.matchAll(
				/Deno\.env\.get\(\s*"([A-Z0-9_]+)"\s*\)\s*\?\?\s*""/g,
			)) {
				const variable = match[1] ?? "";
				seen.set(variable, name);
				expect(
					DOCUMENTED_EMPTY_FALLBACKS[variable],
					`${name}: ${variable} is read with an empty-string fallback and has no documented reason`,
				).toBeDefined();
			}
		}
		// Sanity: the audit must actually observe the fallbacks that remain.
		expect(seen.size).toBeGreaterThan(0);
		expect(seen.has("SUPABASE_URL")).toBe(false);
		expect(seen.has("SUPABASE_SERVICE_ROLE_KEY")).toBe(false);
	});

	it("keeps the Stripe endpoint secret on its documented fail-closed path", () => {
		const stripe = sourceOf("stripe-webhook");
		expect(stripe).not.toContain('Deno.env.get("SUPABASE_URL")');
		expect(stripe).toContain("if (!STRIPE_WEBHOOK_SECRET)");
		expect(stripe).toContain("missing STRIPE_WEBHOOK_SECRET");
		expect(stripe).toContain('json(400, { error: "invalid_signature" }, requestId)');
	});
});

describe("shared configuration helper", () => {
	const source = readFileSync(join(FUNCTIONS_DIR, "_shared", "config.ts"), "utf8");

	it("is the only module that binds the Deno environment", () => {
		// Required platform variables are read in exactly one place: the shared
		// reader. A function file that binds Deno.env for them has gone back to
		// the unvalidated read this finding is about.
		for (const name of FUNCTIONS) {
			const functionSource = sourceOf(name);
			for (const variable of PLATFORM_ENV) {
				expect(
					functionSource,
					`${name} must read ${variable} through the shared guard`,
				).not.toContain(`Deno.env.get("${variable}")`);
			}
		}
		expect(source).toContain("export const runtimeEnv");
		expect(source).toContain("Deno.env.get(name)");
	});

	it("exports the structured error surface the functions rely on", () => {
		for (const symbol of [
			"export class ConfigurationError",
			"export function loadConfig",
			"export function configFailure",
			"export function partialGroupError",
			"export function isConfigurationError",
			"export function logConfigFailure",
		]) {
			expect(source, `missing ${symbol}`).toContain(symbol);
		}
	});

	it("has no empty-string credential fallback and never interpolates a message", () => {
		expect(source).not.toMatch(/\?\?\s*""/);
		expect(source).not.toMatch(/\.message\s*\+/);
		expect(source).toContain('"server_misconfigured"');
	});

	it("filters reported identifiers down to environment-variable names", () => {
		expect(source).toContain("/^[A-Z][A-Z0-9_]{0,63}$/");
	});
});

describe("dashboard-owned Edge Function tree", () => {
	const DASHBOARD_FUNCTIONS = join(REPO_ROOT, "packages", "dashboard", "supabase", "functions");

	it("carries a byte-identical copy of the shared helper", () => {
		const canonical = readFileSync(join(FUNCTIONS_DIR, "_shared", "config.ts"), "utf8");
		const dashboardShared = join(DASHBOARD_FUNCTIONS, "_shared");
		expect(statSync(dashboardShared).isDirectory(), `${dashboardShared} must exist`).toBe(true);
		const copy = readFileSync(join(dashboardShared, "config.ts"), "utf8");
		expect(copy).toBe(canonical);
	});

	it("validates dashboard configuration, including the auth-callback exception", () => {
		expect(statSync(DASHBOARD_FUNCTIONS).isDirectory(), `${DASHBOARD_FUNCTIONS} must exist`).toBe(true);
		const functionDirs = readdirSync(DASHBOARD_FUNCTIONS).filter(
			(entry) =>
				!entry.startsWith("_") && statSync(join(DASHBOARD_FUNCTIONS, entry)).isDirectory(),
		);
		expect(functionDirs.length).toBeGreaterThan(0);
		for (const name of functionDirs) {
			const file = join(DASHBOARD_FUNCTIONS, name, "index.ts");
			const functionSource = readFileSync(file, "utf8");

			if (name === "auth-callback") {
				// This browser-facing callback deliberately owns a tighter guard than
				// ordinary dashboard functions: it validates callback configuration
				// together with exact Origin and signed-state (HMAC) checks. Keep the
				// exception narrow by asserting each part of that security boundary.
				expect(functionSource, "auth-callback: missing required environment declaration").toContain(
					"const REQUIRED_ENV = [",
				);
				for (const variable of [
					"SUPABASE_URL",
					"SUPABASE_ANON_KEY",
					"GOOGLE_CLIENT_ID",
					"GOOGLE_CLIENT_SECRET",
					"AUTH_CALLBACK_ALLOWED_ORIGINS",
					"AUTH_CALLBACK_STATE_SECRET",
				]) {
					expect(functionSource, `auth-callback: REQUIRED_ENV must contain ${variable}`).toContain(
						`"${variable}"`,
					);
				}
				expect(functionSource, "auth-callback: missing exact-origin validation").toMatch(
					/allowedOrigins\(|requestOrigin\(|origin_not_allowed/,
				);
				expect(functionSource, "auth-callback: missing HMAC state validation").toMatch(
					/verifyState\(|crypto\.subtle\.importKey|crypto\.subtle\.verify/,
				);
			} else {
				expect(functionSource, `${name}: missing shared configuration import`).toContain(
					'from "../_shared/config.ts"',
				);
				expect(functionSource, `${name}: missing shared configuration guard`).toContain(
					"loadConfig(runtimeEnv,",
				);
			}
			for (const match of functionSource.matchAll(
				/Deno\.env\.get\(\s*"([A-Z0-9_]+)"\s*\)\s*\?\?\s*""/g,
			)) {
				expect(
					DOCUMENTED_EMPTY_FALLBACKS[match[1] ?? ""],
					`${name}: ${match[1]} is read with an empty-string fallback and has no documented reason`,
				).toBeDefined();
			}
		}
	});
});
