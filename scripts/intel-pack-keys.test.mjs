// CLI checks for the intel pack publishing tool. The derivation contract and
// the publish -> entitlement -> endpoint decrypt round trip live in
// supabase/functions/__tests__/intel-pack-keys.test.ts.
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";
import { deriveTenantPackKey, packKeyScope } from "./intel-pack-keys.mjs";

const script = fileURLToPath(new URL("./intel-pack-keys.mjs", import.meta.url));
const TENANT = "0a0a0a0a-1111-4111-8111-aaaaaaaaaaaa";
const run = (args, env = {}) => spawnSync(process.execPath, [script, ...args], { encoding: "utf8", env: { ...process.env, ...env } });

function workdir(t) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-pack-keys-cli-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	return dir;
}

function plainPack(dir) {
	mkdirSync(join(dir, "lists"), { recursive: true });
	const content = "https://exfil.pack-cli.test/x\n";
	writeFileSync(join(dir, "lists", "deny.txt"), content);
	writeFileSync(join(dir, "manifest.json"), JSON.stringify({
		pack_id: "p", version: "1.0.0", issued_at: "2026-10-01T00:00:00Z", key_id: "signer",
		files: [{ kind: "url_denylist", path: "lists/deny.txt", sha256: createHash("sha256").update(content).digest("hex") }],
	}));
	return content;
}

test("new-shared-key writes an owner-only key file and refuses to overwrite it", (t) => {
	const dir = workdir(t);
	const out = join(dir, "shared.key");
	const created = run(["new-shared-key", "--label", "2026q4", "--out", out]);
	assert.equal(created.status, 0, created.stderr);
	assert.deepEqual(JSON.parse(created.stdout).key_id, "aidr-shared-pack-2026q4");
	assert.doesNotMatch(created.stdout, /=[A-Za-z0-9+/]{43}=/, "the key is never printed");
	assert.match(readFileSync(out, "utf8"), /^aidr-shared-pack-2026q4=[A-Za-z0-9+/]{43}=\n$/);
	if (process.platform !== "win32") assert.equal(statSync(out).mode & 0o777, 0o600);
	assert.notEqual(run(["new-shared-key", "--label", "2026q4", "--out", out]).status, 0);
	assert.notEqual(run(["new-shared-key", "--label", "bad label", "--out", join(dir, "x")]).status, 0);
});

test("encrypt-pack with a tenant key records the tenant key id; the master key is never printed", (t) => {
	const dir = workdir(t);
	const content = plainPack(dir);
	const master = randomBytes(32).toString("base64");
	const result = run(["encrypt-pack", "--pack", dir, "--tenant-id", TENANT], { AIDR_PACK_MASTER_KEY_B64: master });
	assert.equal(result.status, 0, result.stderr);
	assert.ok(!result.stdout.includes(master));
	const expected = deriveTenantPackKey(master, TENANT).key_id;
	assert.equal(JSON.parse(result.stdout).key_id, expected);
	const manifest = JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
	assert.equal(manifest.files[0].key_id, expected);
	assert.deepEqual(packKeyScope(expected), { kind: "tenant", tenantId: TENANT });
	assert.ok(!readFileSync(join(dir, "lists", "deny.txt"), "latin1").includes("exfil.pack-cli.test"));
	assert.equal(manifest.files[0].sha256, createHash("sha256").update(content).digest("hex"));
	assert.notEqual(run(["encrypt-pack", "--pack", dir, "--tenant-id", TENANT], { AIDR_PACK_MASTER_KEY_B64: master }).status, 0, "double encryption is refused");
});

test("encrypt-pack needs exactly one key source", (t) => {
	const dir = workdir(t);
	plainPack(dir);
	assert.notEqual(run(["encrypt-pack", "--pack", dir], { AIDR_PACK_MASTER_KEY_B64: "" }).status, 0);
	assert.notEqual(run(["encrypt-pack", "--pack", dir, "--tenant-id", TENANT], { AIDR_PACK_MASTER_KEY_B64: "" }).status, 0);
	assert.equal(packKeyScope("aidr-pack-v1"), null, "the retired one-id-for-every-tenant key is not deliverable");
});
