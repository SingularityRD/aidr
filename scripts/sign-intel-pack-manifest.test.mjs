import assert from "node:assert/strict";
import { generateKeyPairSync, verify } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
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
		const manifestBytes = Buffer.from(`${JSON.stringify({ pack_id: "test-pack", version: "1.0.0", issued_at: "2026-10-01T00:00:00Z", key_id: "publisher-1", files: [] }, null, 2)}\n`);
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

test("--audience binds the signed customer audience and refuses a mismatch; issued_at is required", () => {
	const directory = mkdtempSync(join(tmpdir(), "aidr-intel-sign-audience-"));
	try {
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const keyPath = join(directory, "publisher-key.pem");
		writeFileSync(keyPath, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
		const base = { pack_id: "test-pack", version: "1.0.0", issued_at: "2026-10-01T00:00:00Z", key_id: "publisher-1", files: [] };
		const signManifest = (name, manifest, extra = []) => {
			const manifestPath = join(directory, `${name}.json`);
			writeFileSync(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
			const out = join(directory, `${name}.sig`);
			const result = spawnSync(process.execPath, [script, "--manifest", manifestPath, "--private-key", keyPath, "--out", out, ...extra], { encoding: "utf8" });
			return { ...result, manifestPath, out };
		};

		const forCustomer = { ...base, audience: { customer_ids: ["bilgem", "example-co"] } };
		const ok = signManifest("ok", forCustomer, ["--audience", "example-co,bilgem"]);
		assert.equal(ok.status, 0, ok.stderr);
		assert.match(ok.stdout, /audience bilgem,example-co/);
		// The audience is inside the signed bytes: dropping it breaks the signature.
		const signature = Buffer.from(readFileSync(ok.out, "utf8").trim(), "base64");
		assert.equal(verify(null, readFileSync(ok.manifestPath), publicKey, signature), true);
		assert.equal(verify(null, Buffer.from(`${JSON.stringify(base, null, 2)}\n`), publicKey, signature), false);

		for (const [name, manifest, audience, pattern] of [
			["other", forCustomer, "bilgem", /does not match --audience bilgem/],
			["generic-as-customer", base, "bilgem", /audience none does not match/],
			["customer-as-generic", forCustomer, "none", /does not match --audience none/],
			["malformed", { ...base, audience: { customer_ids: ["Not_Valid"] } }, undefined, /audience must be/],
			["no-issued-at", { pack_id: "p", version: "1", key_id: "k", files: [] }, undefined, /issued_at/],
		]) {
			const refused = signManifest(name, manifest, audience ? ["--audience", audience] : []);
			assert.equal(refused.status, 1, `${name} must be refused`);
			assert.match(refused.stderr, pattern);
			assert.equal(existsSync(refused.out), false, `${name} must not write a signature`);
		}
		const generic = signManifest("generic", base, ["--audience", "none"]);
		assert.equal(generic.status, 0, generic.stderr);
	} finally {
		rmSync(directory, { recursive: true, force: true });
	}
});
