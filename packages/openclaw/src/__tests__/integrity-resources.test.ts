import { createHash } from "node:crypto";
import { mkdtemp, mkdir, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { verifyArtifactIntegrity } from "@singularityrd/aidr-core";
import { afterEach, describe, expect, it } from "vitest";

const roots: string[] = [];

afterEach(async () => {
	await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe("OpenClaw resource integrity", () => {
	it("detects tampering in a runtime-loaded threat resource under dist", async () => {
		const root = await mkdtemp(join(tmpdir(), "aidr-openclaw-integrity-"));
		roots.push(root);
		const relative = "resources/threats/rule.yaml";
		const file = join(root, ...relative.split("/"));
		await mkdir(join(root, "resources", "threats"), { recursive: true });
		const original = "id: safe-rule\n";
		await writeFile(file, original);
		await writeFile(
			join(root, "aidr-artifact.manifest.json"),
			`${JSON.stringify({
				schema_version: 1,
				artifact_id: "openclaw/dist",
				artifact_version: "0.6.0",
				created_at: new Date().toISOString(),
				files: [{ path: relative, sha256: createHash("sha256").update(original).digest("hex") }],
			})}\n`,
		);

		expect(
			await verifyArtifactIntegrity({
				artifactDir: root,
				publicKeysPem: [],
				verifySignatures: false,
				expectedArtifactId: "openclaw/dist",
			}),
		).toMatchObject({ status: "ok" });

		await writeFile(file, "id: tampered-rule\n");
		expect(
			await verifyArtifactIntegrity({
				artifactDir: root,
				publicKeysPem: [],
				verifySignatures: false,
				expectedArtifactId: "openclaw/dist",
			}),
		).toMatchObject({ status: "hash_mismatch", mismatches: [{ path: relative }] });
	});
});
