import assert from "node:assert/strict";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";
import test from "node:test";
import { fileURLToPath } from "node:url";

const repository = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const verifier = path.join(repository, "scripts", "verify-release-evidence.mjs");

function createSignedEndpointPackage() {
	const temporaryRoot = mkdtempSync(path.join(tmpdir(), "aidr-verify-endpoint-package-"));
	const packageRoot = path.join(temporaryRoot, "package");
	const dist = path.join(packageRoot, "dist");
	const resources = path.join(packageRoot, "resources", "threats");
	mkdirSync(dist, { recursive: true });
	mkdirSync(resources, { recursive: true });
	writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ name: "@singularityrd/aidr-claude-code", version: "1.2.3" }));
	writeFileSync(path.join(dist, "pre-tool-use.cjs"), "module.exports = {};\n");
	writeFileSync(path.join(dist, "aidr-artifact.manifest.json"), "{}\n");
	writeFileSync(path.join(dist, "aidr-artifact.manifest.sig"), `${Buffer.alloc(64).toString("base64")}\n`);
	writeFileSync(path.join(resources, "commands.yaml"), "rules: []\n");
	const { publicKey, privateKey } = generateKeyPairSync("ed25519");
	const fingerprint = `sha256:${createHash("sha256").update(publicKey.export({ type: "spki", format: "der" })).digest("hex")}`;
	const files = [
		"package.json",
		"dist/aidr-artifact.manifest.json",
		"dist/aidr-artifact.manifest.sig",
		"dist/pre-tool-use.cjs",
		"resources/threats/commands.yaml",
	].sort().map((relative) => ({
		path: relative,
		sha256: createHash("sha256").update(readFileSync(path.join(packageRoot, ...relative.split("/")))).digest("hex"),
	}));
	const raw = `${JSON.stringify({
		schema_version: 1,
		artifact_id: "claude-code/package",
		artifact_version: "1.2.3",
		created_at: "2026-09-23T00:00:00.000Z",
		key_fingerprint: fingerprint,
		lineage: { watermark_id: "test-release", channel: "commercial" },
		files,
	}, null, 2)}\n`;
	writeFileSync(path.join(packageRoot, "aidr-artifact.manifest.json"), raw);
	writeFileSync(path.join(packageRoot, "aidr-artifact.manifest.sig"), `${sign(null, Buffer.from(raw), privateKey).toString("base64")}\n`);
	const publicKeyPath = path.join(temporaryRoot, "publisher-public.pem");
	writeFileSync(publicKeyPath, publicKey.export({ type: "spki", format: "pem" }));
	return { temporaryRoot, packageRoot, publicKeyPath, fingerprint };
}

function verify(fixture) {
	return spawnSync(process.execPath, [
		verifier,
		"--public-key", fixture.publicKeyPath,
		"--fingerprint", fixture.fingerprint,
		"--dirs", fixture.packageRoot,
	], { encoding: "utf8", env: { ...process.env, AIDR_RELEASE_MODE: "commercial" } });
}

test("release evidence verifies an exact, publisher-signed Claude package tree", () => {
	const fixture = createSignedEndpointPackage();
	try {
		const verified = verify(fixture);
		assert.equal(verified.status, 0, verified.stderr || verified.stdout);
		writeFileSync(path.join(fixture.packageRoot, "resources", "threats", "unlisted.yaml"), "extra: true\n");
		const tampered = verify(fixture);
		assert.notEqual(tampered.status, 0);
		assert.match(tampered.stderr, /unexpected file is not covered by the signed manifest/);
	} finally {
		rmSync(fixture.temporaryRoot, { recursive: true, force: true });
	}
});
