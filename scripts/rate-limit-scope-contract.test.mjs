// Every counter an Edge Function charges through public.increment_rate_limit
// must use a scope the RPC admits; an unlisted scope raises
// invalid_rate_limit_scope and the caller fails closed with 503 for every
// request (20261009000200 fixed api-key and version-check).
import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const migrations = join(root, "supabase", "migrations");
const functions = join(root, "supabase", "functions");

function admittedScopes() {
	const scopes = new Set();
	for (const name of readdirSync(migrations).filter((file) => file.endsWith(".sql")).sort()) {
		const sql = readFileSync(join(migrations, name), "utf8");
		if (!sql.includes("increment_rate_limit")) continue;
		for (const [, list] of sql.matchAll(/v_scope not in \(([\s\S]*?)\)/g)) {
			for (const [, scope] of list.matchAll(/'([^']+)'/g)) scopes.add(scope);
		}
		for (const [, list] of sql.matchAll(/execute replace\(v_definition, v_old, v_old \|\| '([\s\S]*?)'\);/g)) {
			for (const [, scope] of list.matchAll(/''([^']+)''/g)) scopes.add(scope);
		}
	}
	return scopes;
}

function sourceFiles(dir) {
	return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) return entry.name === "__tests__" ? [] : sourceFiles(path);
		return entry.name.endsWith(".ts") ? [path] : [];
	});
}

// String literals shaped like a rate-limit key: `<scope>:` followed by a
// version, an interpolated subject or a named bucket. Ingress HMAC contexts and
// consume_tenant_rate_limit subjects/endpoints (including the `*RateSubject`
// helpers that build them) share the shape but are not RPC scopes.
const KEY_LITERAL = /["`]([a-z][a-z_-]*):(?:v\d|\$\{|global|aggregate|verify)/g;

test("every Edge Function rate-limit scope is admitted by increment_rate_limit", () => {
	const admitted = admittedScopes();
	assert.ok(admitted.has("waitlist") && admitted.has("oidc-start"), "allowlist parser found the reviewed scopes");
	const used = new Map();
	for (const file of sourceFiles(functions)) {
		const source = readFileSync(file, "utf8");
		if (!/increment_rate_limit|consumeRateLimit|rateLimit\(|authenticateTenantApiKeyBudgeted/.test(source)) continue;
		let inSubjectHelper = false;
		for (const line of source.split(/\r?\n/)) {
			// A top-level `*RateSubject(...)` helper builds a consume_tenant_rate_limit
			// subject (e.g. `api_key:${id}`), not an increment_rate_limit scope.
			if (/^export function \w+RateSubject\(/.test(line)) inSubjectHelper = true;
			if (inSubjectHelper) {
				if (line === "}") inSubjectHelper = false;
				continue;
			}
			if (/_CONTEXT\s*=|\b(?:subject|endpoint):/.test(line)) continue;
			for (const [, scope] of line.matchAll(KEY_LITERAL)) {
				if (!used.has(scope)) used.set(scope, relative(root, file));
			}
		}
	}
	for (const scope of ["api-key", "version-check", "device_start", "device_poll", "scim", "waitlist"]) {
		assert.ok(used.has(scope), `expected the scan to find the ${scope} counter`);
	}
	const missing = [...used].filter(([scope]) => !admitted.has(scope)).map(([scope, file]) => `${scope} (${file})`);
	assert.deepEqual(missing, [], "rate-limit scopes missing from the increment_rate_limit allowlist");
});
