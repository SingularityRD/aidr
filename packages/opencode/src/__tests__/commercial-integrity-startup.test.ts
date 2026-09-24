import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";

const artifactDirs = vi.hoisted(() => ({
	core: "",
	opencode: "",
}));

vi.mock("@singularityrd/aidr-core", async (importOriginal) => {
	const actual = await importOriginal<typeof import("@singularityrd/aidr-core")>();
	return {
		...actual,
		verifyArtifactIntegrityAndLog: vi.fn(
			(params: Parameters<typeof actual.verifyArtifactIntegrityAndLog>[0]) =>
				actual.verifyArtifactIntegrityAndLog({
					...params,
					artifactDir:
						params.artifactId === "opencode/dist" ? artifactDirs.opencode : artifactDirs.core,
				}),
		),
	};
});

import { verifyArtifactIntegrityAndLog } from "@singularityrd/aidr-core";
import AidrPlugin from "../index.js";

let testRoot = "";

afterEach(async () => {
	vi.unstubAllEnvs();
	artifactDirs.core = "";
	artifactDirs.opencode = "";
	vi.mocked(verifyArtifactIntegrityAndLog).mockClear();
	if (testRoot) await rm(testRoot, { recursive: true, force: true });
	testRoot = "";
});

async function writeSignedArtifact(
	dir: string,
	artifactId: "core/dist" | "opencode/dist",
	privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"],
): Promise<void> {
	const payload = `${artifactId} payload\n`;
	await mkdir(dir, { recursive: true });
	await writeFile(join(dir, "payload.js"), payload, "utf8");
	const manifest = `${JSON.stringify({
		schema_version: 1,
		artifact_id: artifactId,
		artifact_version: "0.6.0",
		created_at: new Date().toISOString(),
		files: [
			{
				path: "payload.js",
				sha256: createHash("sha256").update(payload).digest("hex"),
			},
		],
	})}\n`;
	await writeFile(join(dir, "aidr-artifact.manifest.json"), manifest, "utf8");
	await writeFile(
		join(dir, "aidr-artifact.manifest.sig"),
		sign(null, Buffer.from(manifest), privateKey).toString("base64"),
		"utf8",
	);
}

describe("OpenCode commercial integrity startup", () => {
	it("loads after verifying finalized signed OpenCode and core artifacts", async () => {
		testRoot = await mkdtemp(join(tmpdir(), "aidr-opencode-commercial-integrity-"));
		const homeDir = join(testRoot, "home");
		const aidrDir = join(homeDir, ".singularity-aidr");
		artifactDirs.opencode = join(testRoot, "opencode-dist");
		artifactDirs.core = join(testRoot, "core-dist");
		const { privateKey, publicKey } = generateKeyPairSync("ed25519");
		const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

		await Promise.all([
			writeSignedArtifact(artifactDirs.opencode, "opencode/dist", privateKey),
			writeSignedArtifact(artifactDirs.core, "core/dist", privateKey),
			mkdir(aidrDir, { recursive: true }),
		]);
		await writeFile(
			join(aidrDir, "config.json"),
			JSON.stringify({
				mode: "local",
				control_plane: { enabled: false },
				integrity: {
					enabled: true,
					verify_on_start: true,
					public_keys_pem: [publicKeyPem],
				},
				logging: { enabled: false },
			}),
			"utf8",
		);
		vi.stubEnv("HOME", homeDir);
		vi.stubEnv("AIDR_COMMERCIAL", "1");
		vi.stubEnv("SENTRY_ENABLED", "0");

		const hooks = await AidrPlugin({
			client: { app: { log: async () => undefined } },
			project: { id: "commercial-integrity-test" },
			directory: testRoot,
			worktree: testRoot,
			$: {} as never,
		} as never);

		expect(hooks["tool.execute.before"]).toBeTypeOf("function");
		expect(
			vi.mocked(verifyArtifactIntegrityAndLog).mock.calls.map(([params]) => params.artifactId),
		).toEqual(["opencode/dist", "core/dist"]);
	});
});
