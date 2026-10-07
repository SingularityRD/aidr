/**
 * Release evidence contract across every shipped artifact.
 *
 * - The artifact id written by each package's `build:release` must be the id
 *   that the release wrapper, the manifest schema and every runtime consumer
 *   verify. A mismatch (e.g. `@singularityrd/aidr-core` vs `core/dist`) makes a
 *   commercial connector refuse to load.
 * - Every package the release bundle packs must ship its signed manifest,
 *   signature and SBOM evidence; an explicit `files` list that forgets them
 *   breaks the bundle ("packed consumer artifact is missing signed evidence").
 */
import { spawnSync } from "node:child_process";
import { generateKeyPairSync, sign } from "node:crypto";
import {
	copyFileSync,
	existsSync,
	mkdirSync,
	mkdtempSync,
	readFileSync,
	rmSync,
	writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { ArtifactManifestV1Schema } from "../integrity/schema.js";
import { verifyArtifactIntegrity } from "../integrity/verify.js";

const repoRoot = resolve(__dirname, "../../../..");
const evidenceFiles = [
	"aidr-artifact.manifest.json",
	"aidr-artifact.manifest.sig",
	"aidr-sbom.cdx.json",
	"aidr-sbom.cdx.json.sha256",
];
const temporaryRoots: string[] = [];

afterAll(() => {
	for (const root of temporaryRoots) rmSync(root, { recursive: true, force: true });
});

function tempRoot(prefix: string): string {
	const root = mkdtempSync(join(tmpdir(), prefix));
	temporaryRoots.push(root);
	return root;
}

interface ReleaseTarget {
	pkg: string;
	dir: string;
	artifactId: string;
}

function releaseTargets(): ReleaseTarget[] {
	const source = readFileSync(join(repoRoot, "scripts/release-artifact-manifests.mjs"), "utf8");
	const targets = [
		...source.matchAll(
			/\{\s*pkg:\s*"([^"]+)",\s*dir:\s*"([^"]+)",\s*artifactId:\s*"([^"]+)"\s*\}/g,
		),
	].map(([, pkg, dir, artifactId]) => ({ pkg, dir, artifactId }) as ReleaseTarget);
	expect(targets.length).toBeGreaterThanOrEqual(10);
	return targets;
}

function bundlePackageDirs(): string[] {
	const source = readFileSync(join(repoRoot, ".github/scripts/build-release-bundle.mjs"), "utf8");
	const block = source.match(/const packageDirs = \[([\s\S]*?)\];/);
	if (!block) throw new Error("packageDirs not found in build-release-bundle.mjs");
	return [...block[1].matchAll(/"([^"]+)"/g)].map((match) => match[1]);
}

/** The artifact id a package's own release build writes into dist. */
function producerArtifactId(target: ReleaseTarget): string {
	const packageDir = dirname(target.pkg);
	const pkg = JSON.parse(readFileSync(join(repoRoot, target.pkg), "utf8")) as {
		scripts?: Record<string, string>;
	};
	const script = pkg.scripts?.["build:release"] ?? "";
	const fromScript = script.match(/generate-artifact-manifest\.mjs[^&]*--artifact-id\s+(\S+)/)?.[1];
	if (fromScript) return fromScript;
	// mcp-gateway builds through its own script.
	const buildScript = join(repoRoot, packageDir, "scripts/build.mjs");
	const fromBuild = existsSync(buildScript)
		? readFileSync(buildScript, "utf8").match(/"--artifact-id",\s*"([^"]+)"/)?.[1]
		: undefined;
	if (!fromBuild)
		throw new Error(`${packageDir}: build:release does not pass an explicit --artifact-id`);
	return fromBuild;
}

/** Every artifact id a runtime consumer verifies. */
const consumerSources = [
	"packages/claude-code/src/pre-tool-use.ts",
	"packages/claude-code/src/post-tool-use.ts",
	"packages/claude-code/src/session-start.ts",
	"packages/claude-code/src/mcp-server.ts",
	"packages/codex/src/cli.ts",
	"packages/openclaw/src/index.ts",
	"packages/opencode/src/index.ts",
	"packages/extension/src/aidr-hook.ts",
	"packages/mcp-gateway/src/integrity.mjs",
	"packages/core/src/windows-response-worker.ts",
];

function consumerArtifactIds(): Array<{ source: string; id: string }> {
	const ids: Array<{ source: string; id: string }> = [];
	for (const source of consumerSources) {
		const text = readFileSync(join(repoRoot, source), "utf8");
		for (const match of text.matchAll(
			/(?:artifactId|expectedArtifactId):\s*"([^"]+)"|maybeVerifyIntegrity\("([^"]+)"\)/g,
		)) {
			ids.push({ source, id: match[1] ?? match[2] });
		}
	}
	return ids;
}

describe("release artifact ids", () => {
	const targets = releaseTargets();

	it("covers every package the release bundle packs", () => {
		const targetDirs = new Set(targets.map((target) => dirname(target.dir)));
		for (const packageDir of bundlePackageDirs())
			expect(targetDirs, packageDir).toContain(packageDir);
	});

	it.each(targets.map((target) => [target.artifactId, target] as const))(
		"%s: build:release writes the id the release wrapper and schema accept",
		(_id, target) => {
			const produced = producerArtifactId(target);
			expect(produced).toBe(target.artifactId);
			const manifest = {
				schema_version: 1,
				artifact_id: produced,
				artifact_version: "0.6.0",
				created_at: new Date().toISOString(),
				files: [{ path: "a.js", sha256: "0".repeat(64) }],
			};
			expect(ArtifactManifestV1Schema.safeParse(manifest).success).toBe(true);
		},
	);

	it("every runtime consumer verifies an id some release build produces", () => {
		const produced = new Set(targets.map(producerArtifactId));
		const consumers = consumerArtifactIds();
		expect(consumers.length).toBeGreaterThanOrEqual(consumerSources.length);
		for (const { source, id } of consumers)
			expect(produced, `${source} verifies ${id}`).toContain(id);
		// OpenCode loads the core library and must accept core's own manifest.
		expect(
			consumers.filter((entry) => entry.source.includes("opencode")).map((entry) => entry.id),
		).toEqual(["opencode/dist", "core/dist"]);
	});

	it("the manifest generator rejects ids the runtime schema would refuse", () => {
		const dir = tempRoot("aidr-artifact-id-");
		writeFileSync(join(dir, "payload.js"), "x\n");
		const result = spawnSync(
			process.execPath,
			[
				join(repoRoot, "scripts/generate-artifact-manifest.mjs"),
				"--dir",
				dir,
				"--artifact-id",
				"@singularityrd/aidr-core",
				"--version",
				"0.6.0",
			],
			{ encoding: "utf8" },
		);
		expect(result.status).toBe(2);
		expect(result.stderr).toContain("Invalid artifact id");
		expect(existsSync(join(dir, "aidr-artifact.manifest.json"))).toBe(false);
	});

	it.each(targets.map((target) => [target.artifactId, target] as const))(
		"%s: a generated, signed release manifest verifies under the consumer id",
		async (_id, target) => {
			const dir = tempRoot("aidr-artifact-e2e-");
			writeFileSync(join(dir, "payload.js"), `${target.artifactId} payload\n`);
			const generated = spawnSync(
				process.execPath,
				[
					join(repoRoot, "scripts/generate-artifact-manifest.mjs"),
					"--dir",
					dir,
					"--artifact-id",
					producerArtifactId(target),
					"--version",
					"0.6.0",
				],
				{
					encoding: "utf8",
					env: { ...process.env, AIDR_FINAL_MANIFEST: "", AIDR_WATERMARK_ID: "" },
				},
			);
			expect(generated.status, generated.stderr).toBe(0);
			const { privateKey, publicKey } = generateKeyPairSync("ed25519");
			const manifestBytes = readFileSync(join(dir, "aidr-artifact.manifest.json"));
			writeFileSync(
				join(dir, "aidr-artifact.manifest.sig"),
				sign(null, manifestBytes, privateKey).toString("base64"),
			);
			const result = await verifyArtifactIntegrity({
				artifactDir: dir,
				publicKeysPem: [publicKey.export({ type: "spki", format: "pem" }).toString()],
				verifySignatures: true,
				expectedArtifactId: target.artifactId,
			});
			expect(result.status, result.reason).toBe("ok");
		},
	);
});

describe("packed release evidence", () => {
	const packageDirs = bundlePackageDirs();

	it.each(packageDirs)(
		"%s: pnpm pack includes the signed manifest, signature and SBOM",
		(packageDir) => {
			const source = join(repoRoot, packageDir);
			const stage = tempRoot("aidr-pack-evidence-");
			// Pack a staged copy: package.json `files` (plus .npmignore) decides what
			// ships, and lifecycle scripts must not run against the real workspace.
			const pkg = JSON.parse(readFileSync(join(source, "package.json"), "utf8")) as Record<
				string,
				unknown
			>;
			// Dependencies (workspace: specifiers) do not affect the file list.
			for (const key of [
				"scripts",
				"dependencies",
				"devDependencies",
				"peerDependencies",
				"optionalDependencies",
				"bundledDependencies",
				"bundleDependencies",
			])
				delete pkg[key];
			writeFileSync(join(stage, "package.json"), JSON.stringify(pkg));
			if (existsSync(join(source, ".npmignore")))
				copyFileSync(join(source, ".npmignore"), join(stage, ".npmignore"));
			mkdirSync(join(stage, "dist"), { recursive: true });
			for (const name of evidenceFiles) writeFileSync(join(stage, "dist", name), "{}\n");
			const required = evidenceFiles.map((name) => `dist/${name}`);
			if (packageDir === "packages/claude-code") {
				for (const name of ["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig"]) {
					writeFileSync(join(stage, name), "{}\n");
					required.push(name);
				}
			}
			const result = spawnSync(
				process.platform === "win32" ? "pnpm.cmd" : "pnpm",
				["pack", "--dry-run", "--json"],
				{
					cwd: stage,
					encoding: "utf8",
					shell: process.platform === "win32",
				},
			);
			expect(result.status, result.stderr).toBe(0);
			const listing = JSON.parse(result.stdout.slice(result.stdout.indexOf("{"))) as {
				files: Array<{ path: string }>;
			};
			const packed = new Set(listing.files.map((file) => file.path.replace(/\\/g, "/")));
			for (const entry of required) expect(packed, `${packageDir} packs ${entry}`).toContain(entry);
		},
	);
});
