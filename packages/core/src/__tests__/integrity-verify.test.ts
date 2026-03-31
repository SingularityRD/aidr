import { generateKeyPairSync, sign } from "node:crypto";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import { describe, expect, it } from "vitest";

import { verifyArtifactIntegrity } from "../integrity/verify.js";

function tmpDir(name: string): string {
	return path.join(process.cwd(), ".tmp-test", name);
}

describe("integrity/verifyArtifactIntegrity", () => {
	it("verifies a signed manifest (ed25519)", async () => {
		const dir = tmpDir(`integrity-${Date.now()}`);
		await mkdir(dir, { recursive: true });

		await writeFile(path.join(dir, "a.txt"), "hello", "utf8");
		const manifest = {
			schema_version: 1,
			artifact_id: "claude-code/session-start",
			artifact_version: "0.0.0",
			created_at: new Date().toISOString(),
			files: [
				{
					path: "a.txt",
					sha256: "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
				},
			],
		};
		const manifestPath = path.join(dir, "aidr-artifact.manifest.json");
		await writeFile(manifestPath, `${JSON.stringify(manifest)}\n`, "utf8");

		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const raw = await readFile(manifestPath, "utf8");
		const sig = sign(null, Buffer.from(raw, "utf8"), privateKey);
		await writeFile(path.join(dir, "aidr-artifact.manifest.sig"), sig.toString("base64"), "utf8");

		const result = await verifyArtifactIntegrity({
			artifactDir: dir,
			publicKeysPem: [publicKey.export({ type: "spki", format: "pem" }).toString()],
			verifySignatures: true,
			expectedArtifactId: "claude-code/session-start",
		});
		expect(result.status).toBe("ok");
	});

	it("rejects path traversal", async () => {
		const dir = tmpDir(`integrity-traversal-${Date.now()}`);
		await mkdir(dir, { recursive: true });

		const manifest = {
			schema_version: 1,
			artifact_id: "opencode/plugin",
			artifact_version: "0.0.0",
			created_at: new Date().toISOString(),
			files: [{ path: "../secrets.txt", sha256: "0".repeat(64) }],
		};
		await writeFile(
			path.join(dir, "aidr-artifact.manifest.json"),
			`${JSON.stringify(manifest)}\n`,
			"utf8",
		);

		const result = await verifyArtifactIntegrity({
			artifactDir: dir,
			publicKeysPem: [],
			verifySignatures: false,
			expectedArtifactId: "opencode/plugin",
		});
		expect(result.status).toBe("path_traversal");
	});
});
