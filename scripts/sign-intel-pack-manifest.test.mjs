import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";
import { test } from "node:test";

const script = fileURLToPath(new URL("./sign-intel-pack-manifest.mjs", import.meta.url));

test("signs exact intel manifest bytes with Ed25519 and refuses to overwrite", () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-intel-sign-"));
	try {
		const manifestPath = join(directory, "manifest.json");
		const keyPath = join(directory, "publisher-key.pem");
		const signaturePath = join(directory, "manifest.sig");
		const manifestBytes = Buffer.from(`${JSON.stringify({ pack_id: "test-pack", version: "1.0.0", key_id: "publisher-1", files: [] }, null, 2)}\n`);
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		writeFileSync(manifestPath, manifestBytes);
		writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });

		const run = () => spawnSync(process.execPath, [script, "--manifest", manifestPath, "--private-key", keyPath], { encoding: "utf8" });
		const first = run();
		assert.equal(first.status, 0, first.stderr);
		const signature = Buffer.from(readFileSync(signaturePath, "utf8").trim(), "base64");
		assert.equal(verify(null, manifestBytes, publicKey, signature), true);

		const signatureBytes = readFileSync(signaturePath);
		const second = run();
		assert.equal(second.status, 1, "existing signature must not be overwritten");
		assert.deepEqual(readFileSync(signaturePath), signatureBytes);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
});
