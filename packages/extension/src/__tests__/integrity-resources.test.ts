import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
import { verifyArtifactIntegrity } from "@singularityrd/aidr-core";
import { expect, it } from "vitest";
import { getBundledDataDirs } from "../aidr-hook.js";

it("detects tampering in the extension's runtime-loaded rules inside the verified dist", async () => {
	const dist = resolve(__dirname, "..", "..", "dist");
	const dirs = getBundledDataDirs();
	expect(relative(dist, dirs.threatsDir).replaceAll("\\", "/")).toBe("resources/threats");
	expect(relative(dist, dirs.allowlistsDir).replaceAll("\\", "/")).toBe("resources/allowlists");
	const root = await mkdtemp(join(tmpdir(), "aidr-extension-integrity-"));
	try {
		const resourcePath = `${relative(dist, dirs.threatsDir).replaceAll("\\", "/")}/rule.yaml`;
		const resource = join(root, resourcePath);
		await mkdir(join(root, "resources", "threats"), { recursive: true });
		const content = "id: original-rule\n";
		await writeFile(resource, content);
		await writeFile(join(root, "aidr-artifact.manifest.json"), JSON.stringify({
			schema_version: 1,
			artifact_id: "extension/dist",
			artifact_version: "0.6.0",
			created_at: new Date().toISOString(),
			files: [{ path: resourcePath, sha256: createHash("sha256").update(content).digest("hex") }],
		}));
		const params = { artifactDir: root, publicKeysPem: [], verifySignatures: false, expectedArtifactId: "extension/dist" };
		expect(await verifyArtifactIntegrity(params)).toMatchObject({ status: "ok" });
		await writeFile(resource, "id: tampered-rule\n");
		expect(await verifyArtifactIntegrity(params)).toMatchObject({ status: "hash_mismatch", mismatches: [{ path: resourcePath }] });
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
