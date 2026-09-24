import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

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
import { createTempWorkspace } from "./verify-package-install.mjs";

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
		assert.deepEqual(assertClaudePluginPackage(workspace.root), { plugin: "aidr", referencedFiles: 19 });
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

test("the release archive extracts to a complete, hygienic marketplace root", () => {
	const workspace = fixture();
	try {
		const output = workspace.directory("output");
		const extracted = workspace.directory("extracted");
		const archive = path.join(output, "aidr-claude-plugin.tar.gz");
		const packed = spawnSync("tar", ["-czf", archive, "-C", workspace.root, ...claudePluginArchivePaths()], {
			encoding: "utf8",
		});
		assert.equal(packed.status, 0, packed.stderr);
		const inspection = inspectReleaseArchive(archive, { requiredEntries: claudePluginRequiredFiles() });
		assert.equal(inspection.entries.has("packages/claude-code/dist/mcp-server.cjs"), true);
		const unpacked = spawnSync("tar", ["-xzf", archive, "-C", extracted], { encoding: "utf8" });
		assert.equal(unpacked.status, 0, unpacked.stderr);
		assert.deepEqual(assertClaudePluginPackage(extracted), { plugin: "aidr", referencedFiles: 19 });
	} finally {
		workspace.dispose();
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
