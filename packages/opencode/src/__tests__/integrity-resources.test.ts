import { createHash } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative } from "node:path";
import { verifyArtifactIntegrity } from "@singularityrd/aidr-core";
import { expect, it } from "vitest";
import { getBundledDataDirs } from "../bundled-dirs.js";

it("keeps runtime-loaded OpenCode resources inside the verified artifact and detects tampering", async () => {
	const { pluginDir, threatsDir, allowlistsDir } = getBundledDataDirs();
	const paths = [threatsDir, allowlistsDir].map((directory) => relative(pluginDir, directory));
	for (const path of paths) {
		expect(isAbsolute(path) || path.split(/[\\/]/).includes("..")).toBe(false);
	}
	const root = await mkdtemp(join(tmpdir(), "aidr-opencode-integrity-"));
	try {
		const resourcePath = join(paths[0] as string, "rule.yaml").replaceAll("\\", "/");
		const file = join(root, resourcePath);
		const original = "id: safe-rule\n";
		await mkdir(join(root, paths[0] as string), { recursive: true });
		await writeFile(file, original);
		await writeFile(
			join(root, "aidr-artifact.manifest.json"),
			JSON.stringify({
				schema_version: 1,
				artifact_id: "opencode/dist",
				artifact_version: "0.6.0",
				created_at: new Date().toISOString(),
				files: [
					{ path: resourcePath, sha256: createHash("sha256").update(original).digest("hex") },
				],
			}),
		);
		const options = {
			artifactDir: root,
			publicKeysPem: [],
			verifySignatures: false,
			expectedArtifactId: "opencode/dist",
		};
		expect(await verifyArtifactIntegrity(options)).toMatchObject({ status: "ok" });
		await writeFile(file, "id: tampered-rule\n");
		expect(await verifyArtifactIntegrity(options)).toMatchObject({
			status: "hash_mismatch",
			mismatches: [{ path: resourcePath }],
		});
	} finally {
		await rm(root, { recursive: true, force: true });
	}
});
