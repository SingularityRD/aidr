import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const script = fileURLToPath(new URL("./license-revocations-issue.mjs", import.meta.url));
const core = new URL("../packages/core/dist/intel/license-revocations.js", import.meta.url);

// DEV license key generated per run.
const signer = generateKeyPairSync("ed25519");

function setup(t) {
	const root = mkdtempSync(join(tmpdir(), "aidr-revocations-issue-"));
	t.after(() => rmSync(root, { recursive: true, force: true }));
	const keyFile = join(root, "license-signing.pem");
	writeFileSync(keyFile, signer.privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
	const registry = (status = "active") => {
		const path = join(root, `registry-${status}.json`);
		writeFileSync(path, JSON.stringify({ format: "aidr-license-public-keys-v1", schema_version: 1, keys: [{ key_id: "aidr-license-dev-1", algorithm: "ed25519", public_key_pem: signer.publicKey.export({ type: "spki", format: "pem" }).toString(), not_before: "2026-01-01T00:00:00Z", not_after: null, status, ...(status === "retired" ? { retired_at: "2026-02-01T00:00:00Z" } : {}) }] }));
		return path;
	};
	const run = (args) => spawnSync(process.execPath, [script, "--key-id", "aidr-license-dev-1", "--private-key-file", keyFile, ...args], { encoding: "utf8", env: { ...process.env, AIDR_LICENSE_SIGNING_KEY: "", AIDR_LICENSE_SIGNING_KEY_FILE: "" } });
	return { root, keyFile, registry, run };
}

test("issues a complete, sorted list that the core verifier accepts", async (t) => {
	const { root, registry, run } = setup(t);
	const ids = join(root, "ids.txt");
	writeFileSync(ids, "# revoked after non-payment\nLIC-2026-0009\nLIC-2026-0002\n");
	const out = join(root, "list.json");
	const result = run(["--sequence", "2", "--license-ids-file", ids, "--license-id", "LIC-2026-0009", "--issued-at", "2026-10-01T00:00:00Z", "--public-keys", registry(), "--out", out]);
	assert.equal(result.status, 0, result.stderr);
	assert.match(result.stdout, /list #2 \(2 revoked license\(s\)\)/);
	const document = JSON.parse(readFileSync(out, "utf8"));
	assert.deepEqual(document.payload, { issued_at: "2026-10-01T00:00:00Z", sequence: 2, license_ids: ["LIC-2026-0002", "LIC-2026-0009"] });
	const { verifyLicenseRevocations } = await import(core);
	const verified = verifyLicenseRevocations(document, { registry: JSON.parse(readFileSync(registry(), "utf8")) });
	assert.deepEqual([...verified.licenseIds], ["LIC-2026-0002", "LIC-2026-0009"]);
	// Never overwrites a delivered list.
	assert.equal(run(["--sequence", "3", "--license-id", "LIC-1", "--out", out]).status, 1);
});

test("refuses bad input, a loose key file and a key that is not active in the registry", (t) => {
	const { root, keyFile, registry, run } = setup(t);
	const out = (name) => join(root, `${name}.json`);
	for (const [name, args, pattern] of [
		["sequence", ["--sequence", "0", "--license-id", "LIC-1"], /--sequence must be a positive integer/],
		["id", ["--sequence", "1", "--license-id", "../LIC"], /invalid license id/],
		["revoked-key", ["--sequence", "1", "--license-id", "LIC-1", "--public-keys", registry("revoked")], /not an active key/],
		["retired-key", ["--sequence", "1", "--license-id", "LIC-1", "--public-keys", registry("retired")], /not an active key/],
	]) {
		const result = run([...args, "--out", out(name)]);
		assert.equal(result.status, 1, name);
		assert.match(result.stderr, pattern, name);
		assert.equal(existsSync(out(name)), false, name);
	}
	if (process.platform !== "win32") {
		chmodSync(keyFile, 0o644);
		const loose = run(["--sequence", "1", "--license-id", "LIC-1", "--out", out("loose")]);
		assert.match(loose.stderr, /owner-only/);
	}
});
