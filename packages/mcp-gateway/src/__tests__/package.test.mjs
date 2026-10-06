import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtemp, rm, readFile, writeFile, appendFile } from "node:fs/promises";
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
		await writeFile(
			verifierConfig,
			JSON.stringify({
				integrity: { enabled: true, verify_on_start: true, public_keys_pem: [] },
				logging: { enabled: false },
			}),
		);
		const untrusted = invoke();
		assert.notEqual(untrusted.status, 0);
		assert.equal(untrusted.stdout.includes("verified installed gateway factory"), false);
		await writeFile(verifierConfig, trustedConfig);
		await appendFile(join(fixture.dist, "aidr-mcp-library.mjs"), "\n// altered fixture\n");
		const altered = invoke();
		assert.notEqual(altered.status, 0);
		assert.equal(altered.stdout.includes("verified installed gateway factory"), false);
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
