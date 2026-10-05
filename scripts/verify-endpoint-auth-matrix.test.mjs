import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import path from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import {
	evaluateAuthMatrix,
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
	const report = evaluateAuthMatrix(
		[
			{ route: "supabase/functions/identity-route/index.ts", source: identity },
			{ route: "supabase/functions/api-key-route/index.ts", source: apiKey },
		],
		[],
		{ fileExists: () => true },
	);
	assert.deepEqual(report.failures, []);
	assert.equal(report.guarded, 2);

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
