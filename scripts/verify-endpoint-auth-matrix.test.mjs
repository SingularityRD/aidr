/**
 * Tests for verify-endpoint-auth-matrix.mjs.
 *
 * The gate is exercised the way it runs: a temporary tree holding
 * `supabase/functions/<name>/index.ts` plus the two shared guard modules, and the real
 * command line through `node scripts/verify-endpoint-auth-matrix.mjs --repo <dir>`.
 *
 * Coverage:
 *   - an unguarded route fails the gate and the CLI exits 1;
 *   - a route that calls the identity barrier passes;
 *   - a route that calls the API-key guard passes;
 *   - a route with neither guard fails and the failure names the route and its file;
 *   - every allowlist entry names a file that exists and carries a usable reason;
 *   - a bad allowlist entry fails the gate's self-check (short reason, missing file,
 *     stale evidence marker, unknown route, invalid kind, duplicate route);
 *   - a justified exemption passes and is reported as stale once the route is guarded;
 *   - the gate exits 2 when it cannot run at all.
 */

import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { afterEach, test } from "node:test";
import {
	ALLOWLIST,
	MIN_ALLOWLIST_REASON_LENGTH,
	checkAllowlistSelfCheck,
	discoverRoutes,
	runGate,
	validAllowlistEntries,
} from "./verify-endpoint-auth-matrix.mjs";

const repoRoot = path.resolve(import.meta.dirname, "..");
const gateScript = path.join(repoRoot, "scripts", "verify-endpoint-auth-matrix.mjs");
const temporaryDirectories = [];

afterEach(async () => {
	await Promise.all(
		temporaryDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
	);
});

/** The two shared guards must exist for the gate to be able to run at all. */
const GUARD_MODULE_FILES = {
	"supabase/functions/_shared/identity-barrier.ts": "export async function checkIdentityBarrier() {}\n",
	"supabase/functions/_shared/api-key-auth.ts": "export async function authenticateTenantApiKey() {}\n",
};

const UNGUARDED = `${[
	"// Supabase Edge Function: POST /v1/rogue",
	'import { createClient } from "npm:@supabase/supabase-js@2";',
	"",
	"Deno.serve(async (req) => {",
	"\tconst db = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });",
	'\treturn new Response(JSON.stringify({ ok: true, rows: [] }), { headers: { "Content-Type": "application/json" } });',
	"});",
].join("\n")}\n`;

const IDENTITY_BARRIER_GUARDED = `${[
	"// Supabase Edge Function: POST /v1/guarded-identity",
	'import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";',
	"",
	"Deno.serve(async (req) => {",
	"\tconst identity = await checkIdentityBarrier(db, token, userId);",
	'\tif (!identity.ok) return new Response("denied", { status: identity.status });',
	'\treturn new Response("ok");',
	"});",
].join("\n")}\n`;

const API_KEY_GUARDED = `${[
	"// Supabase Edge Function: POST /v1/guarded-api-key",
	'import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";',
	"",
	"Deno.serve(async (req) => {",
	"\tconst authorization = await authenticateTenantApiKey(db, apiKey);",
	'\tif (!authorization.ok) return new Response("denied", { status: authorization.status });',
	'\treturn new Response("ok");',
	"});",
].join("\n")}\n`;

/** Write a temporary repository tree holding the shared guard modules and the given files. */
async function createFixture(files) {
	const root = await mkdtemp(path.join(os.tmpdir(), "aidr-endpoint-auth-"));
	temporaryDirectories.push(root);
	for (const [file, source] of Object.entries({ ...GUARD_MODULE_FILES, ...files })) {
		const target = path.join(root, file);
		await mkdir(path.dirname(target), { recursive: true });
		await writeFile(target, source);
	}
	return root;
}

function runCli(args) {
	return spawnSync(process.execPath, [gateScript, ...args], { encoding: "utf8" });
}

test("an unguarded route fails the gate with a non-zero exit", async () => {
	const root = await createFixture({ "supabase/functions/rogue/index.ts": UNGUARDED });

	const report = runGate({ repoRoot: root, allowlist: [] });
	assert.equal(report.ok, false);
	assert.equal(report.summary.routes, 1);
	assert.equal(report.results[0].route, "rogue");
	assert.equal(report.results[0].status, "unguarded");

	const cli = runCli(["--repo", root]);
	assert.equal(cli.status, 1, cli.stderr);
	assert.match(cli.stdout, /\[unguarded-route\]/);
	assert.match(cli.stdout, /result: FAIL/);
});

test("a route that calls the identity barrier passes", async () => {
	const root = await createFixture({ "supabase/functions/guarded-identity/index.ts": IDENTITY_BARRIER_GUARDED });

	const report = runGate({ repoRoot: root, allowlist: [] });
	assert.equal(report.ok, true, JSON.stringify(report.violations));
	assert.equal(report.results[0].status, "guarded");
	assert.deepEqual(report.results[0].guards, ["identity_barrier"]);
});

test("a route that calls the API-key guard passes", async () => {
	const root = await createFixture({ "supabase/functions/guarded-api-key/index.ts": API_KEY_GUARDED });

	const report = runGate({ repoRoot: root, allowlist: [] });
	assert.equal(report.ok, true, JSON.stringify(report.violations));
	assert.equal(report.results[0].status, "guarded");
	assert.deepEqual(report.results[0].guards, ["tenant_api_key"]);
});

test("a route with neither guard fails and the failure names the route", async () => {
	const root = await createFixture({ "supabase/functions/rogue/index.ts": UNGUARDED });

	const report = runGate({ repoRoot: root, allowlist: [] });
	const violation = report.violations.find((entry) => entry.kind === "unguarded-route");
	assert.ok(violation, "an unguarded route must produce an unguarded-route violation");
	assert.equal(violation.route, "rogue");
	assert.match(violation.message, /rogue/);
	assert.match(violation.message, /supabase\/functions\/rogue\/index\.ts/);
	assert.match(violation.message, /checkIdentityBarrier/);
	assert.match(violation.message, /authenticateTenantApiKey/);
});

test("the real repository matrix passes, in text and as JSON", () => {
	const report = runGate({});
	assert.equal(
		report.ok,
		true,
		JSON.stringify({ violations: report.violations, allowlistProblems: report.allowlistProblems }, null, 2),
	);
	assert.ok(report.summary.routes > 0);
	assert.equal(report.summary.routes, report.summary.guardedRoutes + report.summary.exemptRoutes);

	const cli = runCli(["--json"]);
	assert.equal(cli.status, 0, cli.stderr);
	const parsed = JSON.parse(cli.stdout);
	assert.equal(parsed.gate, "verify-endpoint-auth-matrix");
	assert.equal(parsed.ok, true);
});

test("every allowlist entry names a file that exists and carries a usable reason", () => {
	const { routes, problems } = discoverRoutes(repoRoot);
	assert.deepEqual(problems, []);
	assert.ok(ALLOWLIST.length > 0, "the allowlist must be explicit, not empty");
	assert.deepEqual(checkAllowlistSelfCheck(ALLOWLIST, { repoRoot, routes }), []);

	for (const entry of ALLOWLIST) {
		assert.equal(validAllowlistEntries([entry]).length, 1, `allowlist entry ${entry.route} must be valid`);
		assert.ok(
			entry.reason.trim().length >= MIN_ALLOWLIST_REASON_LENGTH,
			`allowlist entry ${entry.route} needs a written reason`,
		);
		assert.ok(entry.reason.trim().split(/\s+/).length >= 5, `allowlist entry ${entry.route} reason is a stub`);
		assert.ok(
			existsSync(path.join(repoRoot, entry.file)),
			`allowlist entry ${entry.route} names a file that does not exist: ${entry.file}`,
		);
		assert.ok(entry.evidence.length > 0, `allowlist entry ${entry.route} needs evidence markers`);
	}
});

test("a bad allowlist entry fails the gate's self-check", async () => {
	const root = await createFixture({ "supabase/functions/rogue/index.ts": UNGUARDED });
	const routes = discoverRoutes(root).routes;
	const reason = "Deliberately public fixture route used to prove the self-check rejects bad entries.";
	const usable = { route: "rogue", file: "supabase/functions/rogue/index.ts", kind: "public", reason, evidence: ["Deno.serve("] };

	const problems = checkAllowlistSelfCheck(
		[
			usable,
			{ ...usable, route: "short-reason", reason: "nope" },
			{ ...usable, route: "missing-file", file: "supabase/functions/missing/index.ts" },
			{ ...usable, route: "stale-evidence", kind: "equivalent-guard", evidence: ["checkIdentityBarrier(db, token, userId)"] },
			{ ...usable, route: "unknown-route" },
			{ ...usable, route: "bad-kind", kind: "protected" },
		],
		{ repoRoot: root, routes },
	);
	const kinds = new Set(problems.map((problem) => problem.kind));
	for (const expected of [
		"allowlist-missing-reason",
		"allowlist-missing-file",
		"allowlist-evidence-missing",
		"allowlist-unknown-route",
		"allowlist-invalid-kind",
	]) {
		assert.ok(kinds.has(expected), `expected ${expected} among ${[...kinds].join(", ") || "<none>"}`);
	}

	const duplicates = checkAllowlistSelfCheck([usable, { ...usable }], { repoRoot: root, routes });
	assert.ok(duplicates.some((problem) => problem.kind === "allowlist-duplicate-route"));

	// A malformed entry cannot exempt anything, so the route still fails the gate.
	const report = runGate({ repoRoot: root, allowlist: [{ ...usable, route: "short-reason", reason: "nope" }] });
	assert.equal(report.ok, false);
	assert.equal(report.results[0].status, "unguarded");
});

test("a justified exemption passes and is reported as stale once the route is guarded", async () => {
	const entry = {
		route: "public-intake",
		file: "supabase/functions/public-intake/index.ts",
		kind: "public",
		reason: "Fixture intake route that exists only to prove the exemption and its staleness check.",
		evidence: ["Deno.serve("],
	};

	const publicRoot = await createFixture({ "supabase/functions/public-intake/index.ts": UNGUARDED });
	const exempt = runGate({ repoRoot: publicRoot, allowlist: [entry] });
	assert.equal(exempt.ok, true, JSON.stringify(exempt.violations));
	assert.equal(exempt.results[0].status, "exempt");
	assert.equal(exempt.results[0].exemptionKind, "public");

	const guardedRoot = await createFixture({ "supabase/functions/public-intake/index.ts": IDENTITY_BARRIER_GUARDED });
	const stale = runGate({ repoRoot: guardedRoot, allowlist: [entry] });
	assert.equal(stale.ok, false);
	assert.ok(stale.violations.some((violation) => violation.kind === "stale-exemption"));
});

test("the gate exits 2 when it cannot run", async () => {
	const unknownArgument = runCli(["--nope"]);
	assert.equal(unknownArgument.status, 2);
	assert.match(unknownArgument.stderr, /unknown argument/);

	const empty = await mkdtemp(path.join(os.tmpdir(), "aidr-endpoint-auth-empty-"));
	temporaryDirectories.push(empty);
	const noTree = runCli(["--repo", empty]);
	assert.equal(noTree.status, 2);
	assert.match(noTree.stderr, /gate could not run/);

	const noGuards = await createFixture({});
	await rm(path.join(noGuards, "supabase", "functions", "_shared"), { recursive: true, force: true });
	await mkdir(path.join(noGuards, "supabase", "functions", "rogue"), { recursive: true });
	await writeFile(path.join(noGuards, "supabase", "functions", "rogue", "index.ts"), UNGUARDED);
	const missingGuardModules = runCli(["--repo", noGuards]);
	assert.equal(missingGuardModules.status, 2);
	assert.match(missingGuardModules.stderr, /shared guard module/);
});
