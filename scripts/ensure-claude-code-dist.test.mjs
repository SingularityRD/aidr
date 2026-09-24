import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import test from "node:test";

import {
	REQUIRED_RUNTIME_FILES,
	SIGNED_EVIDENCE_FILES,
	ensureClaudeCodeDist,
	inspectClaudeCodeDist,
	resolveSourceDateEpoch,
} from "../packages/claude-code/scripts/ensure-dist.mjs";
import { createTempWorkspace } from "./verify-package-install.mjs";

function fixture(name) {
	const workspace = createTempWorkspace(`aidr-claude-dist-${name}-`);
	const packageRoot = workspace.directory("packages/claude-code");
	const dist = workspace.directory("packages/claude-code/dist");
	return { workspace, packageRoot, dist };
}

function writeReleaseDist(dist, { signed = false } = {}) {
	for (const name of REQUIRED_RUNTIME_FILES) writeFileSync(path.join(dist, name), 'console.log("release");\n', "utf8");
	writeFileSync(path.join(dist, "aidr-artifact.manifest.json"), "{}\n", "utf8");
	if (signed) {
		for (const name of SIGNED_EVIDENCE_FILES.filter((entry) => entry !== "aidr-artifact.manifest.json")) {
			writeFileSync(path.join(dist, name), `${name}\n`, "utf8");
		}
	}
}

function digestDirectory(directory) {
	const rows = [];
	for (const name of SIGNED_EVIDENCE_FILES) {
		rows.push(`${name}:${createHash("sha256").update(readFileSync(path.join(directory, name))).digest("hex")}`);
	}
	return rows.join("\n");
}

test("a complete signed dist is preserved byte-for-byte", () => {
	const f = fixture("signed");
	try {
		writeReleaseDist(f.dist, { signed: true });
		const before = digestDirectory(f.dist);
		const result = ensureClaudeCodeDist({
			root: f.packageRoot,
			repoRoot: f.workspace.root,
			coreReady: () => {
				throw new Error("signed dist must not inspect or rebuild core");
			},
			run: () => {
				throw new Error("signed dist must not run a build");
			},
		});
		assert.deepEqual(result, { built: false, signed: true });
		assert.equal(digestDirectory(f.dist), before);
	} finally {
		f.workspace.dispose();
	}
});

test("a partial signed evidence set fails closed instead of rebuilding", () => {
	const f = fixture("partial-signed");
	try {
		writeReleaseDist(f.dist, { signed: true });
		writeFileSync(path.join(f.dist, "bundle.js.map"), "{}\n", "utf8");
		assert.throws(() => inspectClaudeCodeDist(f.packageRoot), /refusing to rebuild signed evidence/);
	} finally {
		f.workspace.dispose();
	}
});

test("missing or development output triggers one deterministic release build", () => {
	const f = fixture("build");
	try {
		writeFileSync(path.join(f.dist, "pre-tool-use.cjs"), "//# sourceMappingURL=pre-tool-use.cjs.map\n", "utf8");
		writeFileSync(path.join(f.dist, "pre-tool-use.cjs.map"), "{}\n", "utf8");
		const calls = [];
		const result = ensureClaudeCodeDist({
			root: f.packageRoot,
			repoRoot: f.workspace.root,
			env: {},
			coreReady: () => true,
			readGitEpoch: () => "1700000000\n",
			run: (args, options) => {
				calls.push({ args, options });
				rmSync(f.dist, { recursive: true, force: true });
				mkdirSync(f.dist, { recursive: true });
				writeReleaseDist(f.dist);
			},
		});
		assert.deepEqual(result, { built: true, signed: false });
		assert.equal(calls.length, 1);
		assert.deepEqual(calls[0].args, ["run", "build:release"]);
		assert.equal(calls[0].options.env.AIDR_DETERMINISTIC_MANIFEST, "1");
		assert.equal(calls[0].options.env.SOURCE_DATE_EPOCH, "1700000000");
	} finally {
		f.workspace.dispose();
	}
});

test("SOURCE_DATE_EPOCH is validated and otherwise comes from the source commit", () => {
	assert.equal(resolveSourceDateEpoch({ env: { SOURCE_DATE_EPOCH: "123" } }), "123");
	assert.equal(resolveSourceDateEpoch({ env: {}, readGitEpoch: () => "456\n" }), "456");
	assert.throws(() => resolveSourceDateEpoch({ env: { SOURCE_DATE_EPOCH: "now" }, readGitEpoch: () => "invalid" }), /deterministic SOURCE_DATE_EPOCH/);
});
