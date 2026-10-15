import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
	evaluateAuthMatrix,
	MIXED_ROUTE_PUBLIC_ACTIONS,
	PUBLIC_ROUTE_ALLOWLIST,
	readRoutes,
} from "./verify-endpoint-auth-matrix.mjs";

const ROOT = path.resolve(fileURLToPath(new URL("..", import.meta.url)));

test("an unguarded route fails the gate", () => {
	const report = evaluateAuthMatrix(
		[{ route: "supabase/functions/unguarded/index.ts", source: "Deno.serve(() => new Response('ok'));" }],
		[],
		{ fileExists: () => true },
	);
	assert.equal(report.guarded, 0);
	assert.equal(report.failures.length, 1);
	assert.match(report.failures[0], /unguarded\/index\.ts: no identity barrier and no API-key guard/);

	// Importing a guard module without calling it is not a guard.
	const importedOnly = evaluateAuthMatrix(
		[
			{
				route: "supabase/functions/imported-only/index.ts",
				source: 'import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";\nDeno.serve(() => new Response());',
			},
		],
		[],
		{ fileExists: () => true },
	);
	assert.equal(importedOnly.failures.length, 1);
	assert.match(importedOnly.failures[0], /imported-only\/index\.ts: no identity barrier and no API-key guard/);
});

test("a guarded route passes with either shared guard", () => {
	const identity = [
		'import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";',
		"await checkIdentityBarrier(db, token, userId, tenantId);",
	].join("\n");
	const apiKey = [
		'import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";',
		"await authenticateTenantApiKey(db, apiKey);",
	].join("\n");
	const budgeted = [
		'import { authenticateTenantApiKeyBudgeted } from "../_shared/api-key-auth.ts";',
		'await authenticateTenantApiKeyBudgeted(db, apiKey, "ingest");',
	].join("\n");
	const report = evaluateAuthMatrix(
		[
			{ route: "supabase/functions/identity-route/index.ts", source: identity },
			{ route: "supabase/functions/api-key-route/index.ts", source: apiKey },
			{ route: "supabase/functions/budgeted-route/index.ts", source: budgeted },
		],
		[],
		{ fileExists: () => true },
	);
	assert.deepEqual(report.failures, []);
	assert.equal(report.guarded, 3);

	// An allowlist entry may not silently cover a route that already has a guard:
	// that is a stale exception, not a public route.
	const stale = evaluateAuthMatrix(
		[{ route: "supabase/functions/identity-route/index.ts", source: identity }],
		[{ route: "supabase/functions/identity-route/index.ts", mechanism: "m", justification: "x".repeat(60) }],
		{ fileExists: () => true },
	);
	assert.equal(stale.failures.length, 1);
	assert.match(stale.failures[0], /stale exception/);
});

test("every allowlist entry names a file that exists and carries a one-line justification", () => {
	for (const entry of PUBLIC_ROUTE_ALLOWLIST) {
		assert.match(entry.route, /^supabase\/functions\/[a-z0-9-]+\/index\.ts$/);
		assert.ok(existsSync(path.join(ROOT, entry.route)), `${entry.route} does not exist`);
		assert.equal(typeof entry.mechanism, "string");
		assert.ok(entry.mechanism.trim().length > 0, `${entry.route} must name its mechanism`);
		assert.ok(entry.justification.trim().length >= 40, `${entry.route} needs a real justification`);
		assert.ok(!entry.justification.includes("\n"), `${entry.route} justification must be one line`);
	}
});

test("the repository tree satisfies the matrix", async () => {
	const routes = await readRoutes(ROOT);
	assert.ok(routes.length >= 30, `expected the Edge routes to be enumerated, saw ${routes.length}`);
	const report = evaluateAuthMatrix(routes, PUBLIC_ROUTE_ALLOWLIST, {
		fileExists: (route) => existsSync(path.join(ROOT, route)),
		mixedRoutes: MIXED_ROUTE_PUBLIC_ACTIONS,
		readSource: (file) => readFileSync(path.join(ROOT, file), "utf8"),
	});
	assert.deepEqual(report.failures, []);
	assert.equal(report.checked, routes.length);
	// Every allowlisted route is genuinely unguarded, and every other route is
	// guarded: the two sets partition the tree.
	assert.equal(report.guarded + report.allowlisted, routes.length);
});

test("a public route without application rate limiting fails the gate", () => {
	const entry = {
		route: "supabase/functions/open/index.ts",
		mechanism: "device code",
		justification: "Public bootstrap route whose credential is a high-entropy code in the request body.",
		rateLimited: true,
	};
	const unlimited = evaluateAuthMatrix(
		[{ route: entry.route, source: "Deno.serve(() => new Response('ok'));" }],
		[entry],
		{ fileExists: () => true },
	);
	assert.equal(unlimited.failures.length, 1);
	assert.match(unlimited.failures[0], /must enforce application-level rate limiting/);

	// Importing the limiter without calling it is not enforcement.
	const importedOnly = evaluateAuthMatrix(
		[{ route: entry.route, source: 'import { consumeRateLimit } from "../_shared/rate-limit.ts";' }],
		[entry],
		{ fileExists: () => true },
	);
	assert.equal(importedOnly.failures.length, 1);

	const limited = evaluateAuthMatrix(
		[
			{
				route: entry.route,
				source: 'import { consumeRateLimit } from "../_shared/rate-limit.ts";\nawait consumeRateLimit(db, key, 5);',
			},
		],
		[entry],
		{ fileExists: () => true },
	);
	assert.deepEqual(limited.failures, []);

	const undeclared = evaluateAuthMatrix(
		[{ route: entry.route, source: "Deno.serve(() => new Response());" }],
		[{ ...entry, rateLimited: undefined }],
		{ fileExists: () => true },
	);
	assert.match(undeclared.failures[0], /must declare rateLimited/);
});

test("device-poll and scim are rate limited public routes in the real allowlist", () => {
	for (const route of ["device-poll", "scim"]) {
		const entry = PUBLIC_ROUTE_ALLOWLIST.find((item) => item.route === `supabase/functions/${route}/index.ts`);
		assert.equal(entry?.rateLimited, true, `${route} must declare rate limiting`);
	}
});

const MIXED = {
	route: "supabase/functions/mixed/index.ts",
	handler: "supabase/functions/mixed/handler.ts",
	actions: [
		{
			name: "login",
			mechanism: "single-use state",
			justification: "Public login start: it only stores a hashed single-use state and returns an IdP redirect URL.",
		},
	],
};
const MIXED_ROUTE = {
	route: MIXED.route,
	source: [
		'import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";',
		"await checkIdentityBarrier(db, token, userId);",
	].join("\n"),
};
const HANDLER_OK = [
	"switch (body.action) {",
	"\t// public-action: login",
	'\tcase "login": return start();',
	'\tcase "admin": return deps.authenticate(req);',
	"}",
].join("\n");

function mixedFailures(handlerSource, mixed = MIXED, route = MIXED_ROUTE) {
	return evaluateAuthMatrix([route], [], {
		fileExists: () => true,
		mixedRoutes: [mixed],
		readSource: () => handlerSource,
	}).failures;
}

test("a mixed route passes only when its public actions are declared and marked", () => {
	assert.deepEqual(mixedFailures(HANDLER_OK), []);
});

test("an undeclared public action in a mixed route fails the gate", () => {
	const failures = mixedFailures(
		HANDLER_OK.replace('\tcase "admin"', '\t// public-action: sneaky\n\tcase "sneaky": return ok();\n\tcase "admin"'),
	);
	assert.equal(failures.length, 1);
	assert.match(failures[0], /public action "sneaky" is not declared/);
});

test("a stale declaration, a mismatched marker and an all-public handler fail", () => {
	assert.match(mixedFailures(HANDLER_OK.replace("// public-action: login", "// nothing")).join("\n"), /declared public action "login" is not marked/);
	assert.match(
		mixedFailures(HANDLER_OK.replace('case "login"', 'case "other"')).join("\n"),
		/marker "login" is attached to case "other"/,
	);
	const allPublic = ["// public-action: login", 'case "login": return start();'].join("\n");
	assert.match(mixedFailures(allPublic).join("\n"), /no authenticated action/);
	assert.match(mixedFailures(HANDLER_OK.replace("deps.authenticate(req)", "ok()")).join("\n"), /never call authenticate/);
});

test("a mixed declaration needs a guarded route and a readable handler", () => {
	const unguarded = { route: MIXED.route, source: "Deno.serve(() => new Response());" };
	assert.match(mixedFailures(HANDLER_OK, MIXED, unguarded).join("\n"), /presents no identity or API-key guard/);
	const missing = evaluateAuthMatrix([MIXED_ROUTE], [], {
		fileExists: () => true,
		mixedRoutes: [MIXED],
		readSource: () => undefined,
	});
	assert.match(missing.failures.join("\n"), /cannot be read/);
	const stale = evaluateAuthMatrix([], [], { fileExists: () => true, mixedRoutes: [MIXED], readSource: () => HANDLER_OK });
	assert.match(stale.failures.join("\n"), /does not match an Edge route/);
});

// SEC-1: response-playbooks serves `trigger_automation` with a per-grant
// automation secret and no user session. The route-level guard (operator
// actions call the identity barrier) hid that public action from the gate.
test("the response-playbooks automation trigger is a declared, marked public action", () => {
	const declared = MIXED_ROUTE_PUBLIC_ACTIONS.find((entry) => entry.route === "supabase/functions/response-playbooks/index.ts");
	assert.ok(declared, "response-playbooks must be declared as a mixed route");
	assert.deepEqual(declared.actions.map((action) => action.name), ["trigger_automation"]);
	const source = readFileSync(path.join(ROOT, declared.handler), "utf8");
	const report = evaluateAuthMatrix([{ route: declared.route, source }], [], {
		fileExists: () => true,
		mixedRoutes: [declared],
		readSource: () => source,
	});
	assert.deepEqual(report.failures, []);
	// Removing the marker (an unreviewed non-session path) fails the gate.
	const unmarked = source.replace("// public-action: trigger_automation", "// automation");
	const failures = evaluateAuthMatrix([{ route: declared.route, source: unmarked }], [], {
		fileExists: () => true,
		mixedRoutes: [declared],
		readSource: () => unmarked,
	}).failures.join("\n");
	assert.match(failures, /declared public action "trigger_automation" is not marked/);
});

test("if-dispatched public actions, stray markers and undeclared marked routes fail the gate", () => {
	const ifHandler = [
		'import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";',
		"await checkIdentityBarrier(db, token, userId);",
		"// public-action: login",
		'if (request.action === "login") return start();',
		'if (request.action === "admin") return authorizeOperator(req);',
	].join("\n");
	const mixed = { ...MIXED, route: MIXED.route, handler: MIXED.route, authenticatedCall: "authorizeOperator(" };
	const route = { route: MIXED.route, source: ifHandler };
	assert.deepEqual(mixedFailures(ifHandler, mixed, route), []);
	const stray = ifHandler.replace("// public-action: login\n", "") + "\n// public-action: login\nconst x = 1;";
	assert.match(mixedFailures(stray, mixed, { route: MIXED.route, source: stray }).join("\n"), /not directly above a case\/if dispatch/);
	assert.match(mixedFailures(ifHandler.replace("authorizeOperator(req)", "ok()"), mixed, route).join("\n"), /never call authorizeOperator\(\)/);
	const undeclared = evaluateAuthMatrix([route], [], { fileExists: () => true, mixedRoutes: [], readSource: () => ifHandler });
	assert.match(undeclared.failures.join("\n"), /marks a public action but is not declared/);
});

test("the OIDC route's declared public actions match its handler", () => {
	const declared = MIXED_ROUTE_PUBLIC_ACTIONS.find((entry) => entry.route === "supabase/functions/oidc-sso/index.ts");
	assert.ok(declared, "oidc-sso must be declared as a mixed route");
	assert.deepEqual(
		declared.actions.map((action) => action.name).sort(),
		["break_glass_suspend_enforcement", "callback", "start"],
	);
});
