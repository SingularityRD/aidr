import assert from "node:assert/strict";
import { spawnSync, execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import test from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const script = join(root, "scripts/deployment-smoke.mjs");
const head = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();

test("customer enrollment smoke requires operator bootstrap, not a forged pilot approval", () => {
	const source = readFileSync(script, "utf8");
	assert.match(source, /free team cannot issue an enrollment token/);
	assert.match(source, /free team cannot issue a managed API key/);
	assert.match(source, /\/rest\/v1\/rpc\/bootstrap_customer/);
	assert.match(source, /authorize device for licensed tenant/);
	assert.equal((source.match(/provenance_verified: true/g) ?? []).length, 2,
		"both controlled URL and file smoke fixtures must explicitly carry trusted provenance");
	assert.match(source, /owner signup created one team/);
	assert.match(source, /token: bob\.token, method: "POST", body: \{ p_name: `Outsider/);
	assert.doesNotMatch(source, /token: alice\.token, method: "POST", body: \{ p_name: `Smoke/);
	assert.doesNotMatch(source, /\/rest\/v1\/pilot_applications/);
	assert.match(source, /restored membership cannot revive retired key/);
	assert.match(source, /restored member issues a fresh key/);
	assert.match(source, /state === "expired membership" \? 401 : 403/);
	assert.doesNotMatch(source, /restored membership key works again/);
	assert.match(source, /remote_policy_required: true/);
	assert.match(source, /policyDenial: typeof response\.systemMessage/);
	assert.match(source, /policy: \{ mcp: \{ inventory_paths: \[mcpInventoryPath\] \} \}/);
	assert.match(source, /"X-AIDR-Proxy-Request-ID": randomBytes\(16\)\.toString\("hex"\)/);
	assert.match(source, /private pack fixture uploaded/);
	assert.match(source, /active scoped pack grant streams private bytes/);
	assert.match(source, /previous pack grant rejects revoked key/);
	assert.match(source, /"packs-download"\]\.map/);
});

function fixture(sourceCommit = head, inventorySha = "a".repeat(64)) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-smoke-preflight-"));
	const deployment = join(dir, "deployment");
	const candidate = join(dir, "candidate");
	mkdirSync(deployment);
	mkdirSync(candidate);
	writeFileSync(join(deployment, "deployment.json"), JSON.stringify({
		development: true, supabase_url: "http://127.0.0.1:54321", source_commit: sourceCommit, source_has_changes: false,
	}));
	writeFileSync(join(candidate, "release-inventory.json"), JSON.stringify({
		schema_version: 1, artifacts: [{ staged_path: "candidate.tgz", sha256: inventorySha }],
	}));
	writeFileSync(join(candidate, "release-metadata.json"), JSON.stringify({
		schema_version: 1, git_sha: head, worktree_dirty: false, artifacts: [{ path: "candidate.tgz", sha256: "b".repeat(64) }],
	}));
	return { dir, deployment, candidate };
}

function run(f, env = process.env) {
	return spawnSync(process.execPath, [script, f.deployment, "--candidate-inventory", join(f.candidate, "release-inventory.json")], {
		cwd: root, encoding: "utf8", timeout: 10_000, env,
	});
}

test("candidate smoke refuses a deployment from another source commit before reading credentials", () => {
	const f = fixture("0".repeat(40), "b".repeat(64));
	try {
		const result = run(f);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /share one clean source commit/);
		assert.doesNotMatch(result.stdout, /checks passed/);
	} finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("candidate smoke refuses inventory and release metadata disagreement before HTTP", () => {
	const f = fixture();
	try {
		const result = run(f);
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /inventory differs from release metadata/);
		assert.doesNotMatch(result.stdout, /checks passed/);
	} finally { rmSync(f.dir, { recursive: true, force: true }); }
});

test("candidate smoke refuses a different workflow digest before reading credentials", () => {
	const f = fixture(head, "b".repeat(64));
	try {
		const result = run(f, { ...process.env, AIDR_E2E_RC_DIGEST: "0".repeat(64) });
		assert.notEqual(result.status, 0);
		assert.match(result.stderr, /Candidate digest differs from the RC workflow binding/);
		assert.doesNotMatch(result.stdout, /checks passed/);
	} finally { rmSync(f.dir, { recursive: true, force: true }); }
});
