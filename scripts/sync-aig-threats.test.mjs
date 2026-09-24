import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";
import { pinnedSourceTreeDigest, readPinnedYamlFiles, readWorktreeYamlFiles } from "./lib/aig-source-tree.mjs";
import {
	GENERATED_FILES,
	compilationEnvironment,
	parseSourceMode,
	validateSourceManifest,
} from "./sync-aig-threats.mjs";

function git(root, args) {
	return execFileSync("git", ["-C", root, ...args], { encoding: "utf8" }).trim();
}

test("normal sync is pinned; worktree sync requires an explicit valid mode", () => {
	assert.equal(parseSourceMode([]), "pinned");
	assert.equal(parseSourceMode(["--source-mode=worktree"]), "worktree");
	assert.throws(() => parseSourceMode(["--source-mode=other"]), /pinned, worktree/);
	assert.throws(
		() => parseSourceMode(["--source-mode=pinned", "--source-mode=worktree"]),
		/exactly one/,
	);
	assert.deepEqual(GENERATED_FILES, [
		"aig-cve-index.json",
		"aig-fingerprints.json",
		"aig-mcp-categories.json",
		"aig-data-manifest.json",
	]);
});

test("compile child environment never inherits private signing material", () => {
	const environment = compilationEnvironment({
		AIG_SIGNING_PRIVATE_KEY: "private-pem",
		AIG_SIGNING_PRIVATE_KEY_PATH: "private.pem",
		AIG_SIGNING_KEY_ID: "private-context",
		AIG_SIGNING_PUBLIC_KEY: "public-pem",
		KEEP_ME: "yes",
	});
	assert.deepEqual(environment, { AIG_SIGNING_PUBLIC_KEY: "public-pem", KEEP_ME: "yes" });
});

test("pinned and explicit worktree manifests are validated against their exact source bytes", async (t) => {
	const root = await mkdtemp(path.join(tmpdir(), "aidr-aig-sync-"));
	t.after(() => rm(root, { recursive: true, force: true }));
	git(root, ["init", "--quiet"]);
	git(root, ["config", "user.email", "test@example.invalid"]);
	git(root, ["config", "user.name", "AIG Sync Test"]);
	git(root, ["config", "core.autocrlf", "false"]);
	const yaml = path.join(root, "data", "vuln_en", "Demo", "CVE-TEST.yaml");
	await Promise.all([
		mkdir(path.dirname(yaml), { recursive: true }),
		mkdir(path.join(root, "data", "vuln"), { recursive: true }),
		mkdir(path.join(root, "data", "fingerprints"), { recursive: true }),
	]);
	await writeFile(yaml, "info:\n  cve: CVE-TEST\n", "utf8");
	git(root, ["add", "."]);
	git(root, ["commit", "--quiet", "-m", "fixture"]);

	const commit = git(root, ["rev-parse", "HEAD"]);
	const pinnedDigest = pinnedSourceTreeDigest(readPinnedYamlFiles({ aigRoot: root, cwd: root, ref: commit }));
	const pinnedManifest = { source: { commit, tree_sha256: pinnedDigest } };
	assert.deepEqual(validateSourceManifest(pinnedManifest, { sourceMode: "pinned", aigRoot: root, cwd: root }), {
		commit,
		treeSha256: pinnedDigest,
		fileCount: 1,
	});

	// Model a Windows checkout: Git's canonical blob remains LF while the
	// deliberate worktree source contains CRLF bytes.
	await writeFile(yaml, (await readFile(yaml, "utf8")).replaceAll("\n", "\r\n"), "utf8");
	const worktreeDigest = pinnedSourceTreeDigest(readWorktreeYamlFiles({ aigRoot: root }));
	assert.notEqual(worktreeDigest, pinnedDigest);
	assert.throws(
		() => validateSourceManifest(pinnedManifest, { sourceMode: "worktree", aigRoot: root, cwd: root }),
		/source tree mismatch/,
	);
	assert.doesNotThrow(() => validateSourceManifest(
		{ source: { commit, tree_sha256: worktreeDigest } },
		{ sourceMode: "worktree", aigRoot: root, cwd: root },
	));
	assert.throws(
		() => validateSourceManifest(
			{ source: { commit, tree_sha256: worktreeDigest } },
			{ sourceMode: "pinned", aigRoot: root, cwd: root },
		),
		/source tree mismatch/,
	);
});
