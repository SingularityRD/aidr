import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import {
	REQUIRED_RUNTIME_FILES,
	SIGNED_EVIDENCE_FILES,
	ensureClaudeCodeDist,
} from "../packages/claude-code/scripts/ensure-dist.mjs";
import {
	REQUIRED_RESOURCE_FILES,
	assertClaudePluginPackage,
	assertClaudePluginResourcesCanonical,
	claudePluginArchivePaths,
	claudePluginRequiredFiles,
} from "./lib/claude-plugin-package.mjs";
import { inspectReleaseArchive } from "./lib/release-archive-inspection.mjs";
import { tarDirectory } from "./lib/tar-path.mjs";
import { PASS, createTempWorkspace, runPnpm, verifyExtractedPackage } from "./verify-package-install.mjs";

function fixture() {
	const workspace = createTempWorkspace("aidr-claude-plugin-package-");
	const root = workspace.root;
	for (const directory of [".claude-plugin", "hooks", "packages/claude-code/dist", "skills/security-awareness"]) {
		mkdirSync(path.join(root, directory), { recursive: true });
	}
	writeFileSync(path.join(root, ".claude-plugin/plugin.json"), JSON.stringify({
		name: "aidr",
		mcpServers: { aidr: { command: "node", args: ["${CLAUDE_PLUGIN_ROOT}/packages/claude-code/dist/mcp-server.cjs"] } },
	}));
	writeFileSync(path.join(root, ".claude-plugin/marketplace.json"), JSON.stringify({
		name: "aidr",
		plugins: [{ name: "aidr", source: "./" }],
	}));
	writeFileSync(path.join(root, "hooks/hooks.json"), JSON.stringify({
		hooks: { PreToolUse: [{ hooks: [{ command: 'node "${CLAUDE_PLUGIN_ROOT}/packages/claude-code/dist/pre-tool-use.cjs"' }] }] },
	}));
	writeFileSync(path.join(root, "packages/claude-code/package.json"), JSON.stringify({ name: "@singularityrd/aidr-claude-code", version: "1.0.0" }));
	writeFileSync(path.join(root, "packages/claude-code/aidr-artifact.manifest.json"), "{}\n");
	writeFileSync(path.join(root, "packages/claude-code/aidr-artifact.manifest.sig"), "signature\n");
	writeFileSync(path.join(root, "skills/security-awareness/SKILL.md"), "# Security awareness\n");
	for (const name of [...REQUIRED_RUNTIME_FILES, ...SIGNED_EVIDENCE_FILES]) {
		writeFileSync(path.join(root, "packages/claude-code/dist", name), `${name}\n`);
	}
	for (const relative of REQUIRED_RESOURCE_FILES) {
		const contents = `${relative}\n`;
		mkdirSync(path.dirname(path.join(root, relative)), { recursive: true });
		writeFileSync(path.join(root, relative), contents);
		const canonicalRelative = relative.replace(/^packages\/claude-code\/resources\//u, "");
		mkdirSync(path.dirname(path.join(root, canonicalRelative)), { recursive: true });
		writeFileSync(path.join(root, canonicalRelative), contents);
	}
	return workspace;
}

test("the packaged marketplace resolves every hook, MCP and signed-evidence path", () => {
	const workspace = fixture();
	try {
		assert.deepEqual(assertClaudePluginPackage(workspace.root), { plugin: "aidr", referencedFiles: 23 });
		assert.doesNotThrow(() => assertClaudePluginResourcesCanonical(workspace.root));
	} finally {
		workspace.dispose();
	}
});

test("the marketplace package fails closed when a generated runtime is absent", () => {
	const workspace = fixture();
	try {
		rmSync(path.join(workspace.root, "packages/claude-code/dist/pre-tool-use.cjs"));
		assert.throws(() => assertClaudePluginPackage(workspace.root), /missing packages\/claude-code\/dist\/pre-tool-use\.cjs/);
	} finally {
		workspace.dispose();
	}
});

test("the marketplace package fails closed when a hook bundle behind its bootstrap is absent", () => {
	const workspace = fixture();
	try {
		rmSync(path.join(workspace.root, "packages/claude-code/dist/pre-tool-use.bundle.cjs"));
		assert.throws(() => assertClaudePluginPackage(workspace.root), /missing packages\/claude-code\/dist\/pre-tool-use\.bundle\.cjs/);
	} finally {
		workspace.dispose();
	}
});

test("the release archive extracts to a complete, hygienic marketplace root", () => {
	const workspace = fixture();
	try {
		const output = workspace.directory("output");
		const extracted = workspace.directory("extracted");
		const archive = path.join(output, "aidr-claude-plugin.tar.gz");
		const packed = spawnSync("tar", ["-czf", path.basename(archive), "-C", tarDirectory(workspace.root), ...claudePluginArchivePaths()], {
			cwd: output, // relative archive name: GNU tar on Windows parses "C:" in -f as a remote host
			encoding: "utf8",
		});
		assert.equal(packed.status, 0, packed.stderr);
		const inspection = inspectReleaseArchive(archive, { requiredEntries: claudePluginRequiredFiles() });
		assert.equal(inspection.entries.has("packages/claude-code/dist/mcp-server.cjs"), true);
		const unpacked = spawnSync("tar", ["-xzf", path.basename(archive), "-C", tarDirectory(extracted)], { cwd: output, encoding: "utf8" });
		assert.equal(unpacked.status, 0, unpacked.stderr);
		assert.deepEqual(assertClaudePluginPackage(extracted), { plugin: "aidr", referencedFiles: 23 });
	} finally {
		workspace.dispose();
	}
});

test("Claude npm packs verify unsigned output and retain mandatory signed package-root evidence", async () => {
	const { name, version, license, type, files, bin } = JSON.parse(readFileSync(
		fileURLToPath(new URL("../packages/claude-code/package.json", import.meta.url)), "utf8",
	));
	for (const signed of [false, true]) {
		const workspace = fixture();
		try {
			const packageRoot = path.join(workspace.root, "packages/claude-code");
			// Use the real publication contract without lifecycle scripts or dependencies:
			// this exercises pnpm's whitelist without rebuilding shared workspace output.
			writeFileSync(path.join(packageRoot, "package.json"), JSON.stringify({ name, version, license, type, files, bin }));
			for (const document of ["README.md", "LICENSE", "CHANGELOG.md"]) writeFileSync(path.join(packageRoot, document), document);
			for (const directory of ["src", "scratch"]) {
				mkdirSync(path.join(packageRoot, directory));
				writeFileSync(path.join(packageRoot, directory, "aidr-artifact.manifest.json"), "excluded fixture manifest");
			}
			writeFileSync(path.join(packageRoot, "aidr-artifact.manifest.json.bak"), "excluded backup manifest");
			for (const relative of REQUIRED_RESOURCE_FILES) {
				const runtimeResource = path.join(packageRoot, "dist", relative.replace(/^packages\/claude-code\//u, ""));
				mkdirSync(path.dirname(runtimeResource), { recursive: true });
				writeFileSync(runtimeResource, readFileSync(path.join(workspace.root, relative)));
			}
			if (!signed) {
				for (const evidence of ["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig"]) rmSync(path.join(packageRoot, evidence));
				for (const evidence of SIGNED_EVIDENCE_FILES.filter((entry) => entry !== "aidr-artifact.manifest.json")) rmSync(path.join(packageRoot, "dist", evidence));
			}
			const output = workspace.directory("npm-output");
			const packed = runPnpm(["pack", "--pack-destination", output], { cwd: packageRoot, env: process.env, timeout: 30_000 });
			assert.equal(packed.status, 0, packed.stderr || packed.error?.message);
			const archives = readdirSync(output).filter((entry) => entry.endsWith(".tgz"));
			assert.equal(archives.length, 1);
			const archive = path.join(output, archives[0]);
			const rootEvidence = ["package/aidr-artifact.manifest.json", "package/aidr-artifact.manifest.sig"];
			const inspected = inspectReleaseArchive(archive, {
				requiredEntries: ["package/dist/aidr-artifact.manifest.json", "package/dist/resources/threats/commands.yaml", ...(signed ? rootEvidence : [])],
			});
			for (const evidence of rootEvidence) assert.equal(inspected.entries.has(evidence), signed);
			for (const directory of ["src", "scratch"]) assert.equal(inspected.entries.has(`package/${directory}/aidr-artifact.manifest.json`), false);
			assert.equal(inspected.entries.has("package/aidr-artifact.manifest.json.bak"), false);
			if (!signed) {
				assert.throws(() => inspectReleaseArchive(archive, { requiredEntries: rootEvidence }), /missing signed evidence/);
				assert.throws(() => assertClaudePluginPackage(workspace.root), /missing packages\/claude-code\/dist\/aidr-sbom.cdx.json/);
			}
			const extracted = workspace.directory("npm-extracted");
			const unpacked = spawnSync("tar", ["-xzf", path.basename(archive), "-C", tarDirectory(extracted)], { cwd: output, encoding: "utf8" });
			assert.equal(unpacked.status, 0, unpacked.stderr);
			const extractedPackage = path.join(extracted, "package");
			const verified = await verifyExtractedPackage({ packageDir: extractedPackage, strictFiles: true });
			assert.equal(verified.status, PASS, JSON.stringify(verified.failures));
			if (signed) {
				for (const evidence of rootEvidence) {
					assert.deepEqual(readFileSync(path.join(extracted, evidence)), readFileSync(path.join(packageRoot, path.basename(evidence))));
				}
				assert.doesNotThrow(() => assertClaudePluginPackage(workspace.root));
				rmSync(path.join(packageRoot, "aidr-artifact.manifest.sig"));
				assert.throws(() => assertClaudePluginPackage(workspace.root), /missing packages\/claude-code\/aidr-artifact.manifest.sig/);
			}
		} finally {
			workspace.dispose();
		}
	}
});

test("a fresh runner cannot treat restored signed dist as a complete plugin without generated resources", () => {
	const workspace = fixture();
	try {
		rmSync(path.join(workspace.root, "packages/claude-code/resources"), { recursive: true, force: true });
		assert.deepEqual(
			ensureClaudeCodeDist({
				root: path.join(workspace.root, "packages/claude-code"),
				repoRoot: workspace.root,
				coreReady: () => {
					throw new Error("signed dist must remain a no-op");
				},
				run: () => {
					throw new Error("signed dist must not be rebuilt");
				},
			}),
			{ built: false, signed: true },
		);
		assert.throws(
			() => assertClaudePluginPackage(workspace.root),
			/missing packages\/claude-code\/resources\/allowlists\/trusted-installer-domains\.yaml/,
		);
	} finally {
		workspace.dispose();
	}
});
