import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { appendFile, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { buildGatewayPackageFixture } from "../../scripts/library-fixture.mjs";

test("clean installed package exposes the verified gateway factory and rejects a tampered library", async () => {
	const root = await mkdtemp(join(tmpdir(), "aidr-mcp-package-"));
	try {
		const fixture = await buildGatewayPackageFixture(root);
		const consumer = join(root, "consumer.mjs");
		await writeFile(
			consumer,
			`import { createMcpGateway } from "@singularityrd/aidr-mcp-gateway";\nif (typeof createMcpGateway !== "function") throw new Error("missing factory");\nprocess.stdout.write("verified installed gateway factory\\n");\n`,
		);
		const invoke = () =>
			spawnSync(process.execPath, [consumer], {
				cwd: root,
				env: fixture.environment,
				encoding: "utf8",
				timeout: 10_000,
			});
		const clean = invoke();
		assert.equal(clean.status, 0, clean.stderr);
		assert.match(clean.stdout, /verified installed gateway factory/);
		const verifierConfig = join(fixture.home, ".singularity-aidr", "config.json");
		const trustedConfig = await readFile(verifierConfig, "utf8");
		const useVerifierKeys = (keys) =>
			writeFile(
				verifierConfig,
				JSON.stringify({
					integrity: { enabled: true, verify_on_start: true, public_keys_pem: keys },
					logging: { enabled: false },
				}),
			);
		// A signature that does not verify against the provisioned key is refused.
		await useVerifierKeys([
			generateKeyPairSync("ed25519").publicKey.export({ type: "spki", format: "pem" }).toString(),
		]);
		const untrusted = invoke();
		assert.notEqual(untrusted.status, 0);
		assert.equal(untrusted.stdout.includes("verified installed gateway factory"), false);
		// With no verifier key provisioned at all (un-enrolled/offline commercial install)
		// the library deliberately loads on verified file digests, so local enforcement
		// is never gated on enrollment (core integrity/runtime.ts).
		await useVerifierKeys([]);
		const unenrolled = invoke();
		assert.equal(unenrolled.status, 0, unenrolled.stderr);
		assert.match(unenrolled.stdout, /verified installed gateway factory/);
		await appendFile(join(fixture.dist, "aidr-mcp-library.mjs"), "\n// altered fixture\n");
		// Tampering fails closed both without and with the trusted verifier key.
		const alteredUnenrolled = invoke();
		assert.notEqual(alteredUnenrolled.status, 0);
		assert.equal(alteredUnenrolled.stdout.includes("verified installed gateway factory"), false);
		await writeFile(verifierConfig, trustedConfig);
		const altered = invoke();
		assert.notEqual(altered.status, 0);
		assert.equal(altered.stdout.includes("verified installed gateway factory"), false);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
