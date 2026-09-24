import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash, generateKeyPairSync } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import test from "node:test";

import {
	assertPackageReleaseEvidence,
	cycloneDxHashFromSri,
	resolveGitTreeSha256,
} from "./lib/release-evidence-digests.mjs";
import { finalizeReleaseBundle } from "./lib/finalize-release-bundle.mjs";
import { loadReleaseBundle } from "./release-signing-lib.mjs";

test("source digest is SHA-256-bound to the committed Git tree", () => {
	const repo = mkdtempSync(path.join(tmpdir(), "aidr-source-digest-"));
	const git = (args) =>
		execFileSync("git", args, {
			cwd: repo,
			env: {
				...process.env,
				GIT_AUTHOR_NAME: "AIDR Test",
				GIT_AUTHOR_EMAIL: "test@invalid.example",
				GIT_COMMITTER_NAME: "AIDR Test",
				GIT_COMMITTER_EMAIL: "test@invalid.example",
			},
			stdio: "pipe",
		});
	git(["init", "--quiet"]);
	writeFileSync(path.join(repo, "input.txt"), "one\n");
	git(["add", "input.txt"]);
	git(["commit", "--quiet", "-m", "one"]);
	const first = resolveGitTreeSha256(repo);
	assert.match(first, /^sha256:[0-9a-f]{64}$/);

	writeFileSync(path.join(repo, "input.txt"), "uncommitted\n");
	assert.equal(resolveGitTreeSha256(repo), first, "worktree bytes must not masquerade as committed source");
	git(["add", "input.txt"]);
	git(["commit", "--quiet", "-m", "two"]);
	assert.notEqual(resolveGitTreeSha256(repo), first);
});

test("npm SRI hashes are emitted as schema-valid CycloneDX hex", () => {
	const bytes = Buffer.alloc(64, 0xab);
	assert.deepEqual(cycloneDxHashFromSri(`sha512-${bytes.toString("base64")}`), {
		alg: "SHA-512",
		content: bytes.toString("hex"),
	});
	assert.equal(cycloneDxHashFromSri("sha512-not+canonical"), undefined);
	assert.equal(cycloneDxHashFromSri(`sha256-${bytes.toString("base64")}`), undefined);
});

test("commercial artifact manifests reject legacy SHA-1 provenance", () => {
	const artifact = mkdtempSync(path.join(tmpdir(), "aidr-sha1-provenance-"));
	writeFileSync(path.join(artifact, "payload.js"), "export {}\n");
	const result = spawnSync(
		process.execPath,
		[
			path.resolve("scripts/generate-artifact-manifest.mjs"),
			"--dir",
			artifact,
			"--id",
			"test/artifact",
			"--version",
			"1.0.0",
			"--rc-version",
			"1.0.0",
			"--git-sha",
			"a".repeat(40),
			"--source-digest",
			`sha1:${"a".repeat(40)}`,
			"--data-digest",
			`sha256:${"b".repeat(64)}`,
			"--package-digest",
			`sha256:${"c".repeat(64)}`,
			"--lockfile-digest",
			`sha256:${"d".repeat(64)}`,
			"--sbom-digest",
			`sha256:${"e".repeat(64)}`,
			"--key-id",
			"test-key",
			"--key-fingerprint",
			`sha256:${"f".repeat(64)}`,
			"--watermark-id",
			"test-watermark",
			"--channel",
			"commercial",
		],
		{
			cwd: path.resolve("."),
			env: { ...process.env, AIDR_FINAL_MANIFEST: "1", AIDR_DETERMINISTIC_MANIFEST: "1", SOURCE_DATE_EPOCH: "0" },
			encoding: "utf8",
		},
	);
	assert.notEqual(result.status, 0);
	assert.match(result.stderr, /source_digest must be sha256:<64 hex>/);
});

test("release assembly rejects any package without both signed evidence files", () => {
	const repo = mkdtempSync(path.join(tmpdir(), "aidr-release-evidence-"));
	for (const packageDir of ["packages/one", "packages/two"]) {
		mkdirSync(path.join(repo, packageDir, "dist"), { recursive: true });
		writeFileSync(path.join(repo, packageDir, "dist", "aidr-artifact.manifest.json"), "{}\n");
	}
	writeFileSync(path.join(repo, "packages/one/dist/aidr-artifact.manifest.sig"), "signed\n");
	assert.throws(
		() => assertPackageReleaseEvidence(repo, ["packages/one", "packages/two"]),
		/packages[\\/]two[\\/]dist[\\/]aidr-artifact\.manifest\.sig/,
	);
	writeFileSync(path.join(repo, "packages/two/dist/aidr-artifact.manifest.sig"), "signed\n");
	assert.doesNotThrow(() => assertPackageReleaseEvidence(repo, ["packages/one", "packages/two"]));
});

test("release verifier rejects a file added after the manifest was signed", () => {
	const root = mkdtempSync(path.join(tmpdir(), "aidr-exact-artifact-"));
	const artifact = path.join(root, "artifact");
	mkdirSync(artifact);
	writeFileSync(path.join(artifact, "payload.js"), "export const value = 1;\n");
	const sbom = `${JSON.stringify({
		bomFormat: "CycloneDX",
		specVersion: "1.5",
		version: 1,
		components: [{ type: "application", "bom-ref": "urn:test", name: "test", version: "1.0.0" }],
		dependencies: [],
	}, null, 2)}\n`;
	writeFileSync(path.join(artifact, "aidr-sbom.cdx.json"), sbom);
	writeFileSync(
		path.join(artifact, "aidr-sbom.cdx.json.sha256"),
		`${createHash("sha256").update(sbom).digest("hex")}  aidr-sbom.cdx.json\n`,
	);
	const keys = generateKeyPairSync("ed25519");
	const privatePath = path.join(root, "private.pem");
	const publicPath = path.join(root, "public.pem");
	writeFileSync(privatePath, keys.privateKey.export({ type: "pkcs8", format: "pem" }));
	writeFileSync(publicPath, keys.publicKey.export({ type: "spki", format: "pem" }));
	const fingerprint = `sha256:${createHash("sha256")
		.update(keys.publicKey.export({ type: "spki", format: "der" }))
		.digest("hex")}`;
	const env = {
		...process.env,
		AIDR_FINAL_MANIFEST: "1",
		AIDR_DETERMINISTIC_MANIFEST: "1",
		AIDR_RELEASE_MODE: "commercial",
		AIDR_SIGNING_KEY_ID: "test-key",
		AIDR_SIGNING_PUBLIC_KEY_FINGERPRINT: fingerprint,
		AIDR_SIGNING_PUBLIC_KEY_PEM_PATH: publicPath,
		SOURCE_DATE_EPOCH: "0",
	};
	const run = (script, args) =>
		spawnSync(process.execPath, [path.resolve(script), ...args], {
			cwd: path.resolve("."),
			env,
			encoding: "utf8",
		});
	const digest = `sha256:${"a".repeat(64)}`;
	const generated = run("scripts/generate-artifact-manifest.mjs", [
		"--dir",
		artifact,
		"--id",
		"test/artifact",
		"--version",
		"1.0.0",
		"--rc-version",
		"1.0.0",
		"--git-sha",
		"a".repeat(40),
		"--source-digest",
		digest,
		"--data-digest",
		digest,
		"--package-digest",
		digest,
		"--lockfile-digest",
		digest,
		"--sbom-digest",
		`sha256:${createHash("sha256").update(sbom).digest("hex")}`,
		"--key-id",
		"test-key",
		"--key-fingerprint",
		fingerprint,
		"--watermark-id",
		"test-watermark",
		"--channel",
		"commercial",
	]);
	assert.equal(generated.status, 0, generated.stderr);
	const signed = run("scripts/sign-artifact-manifest.mjs", ["--dir", artifact, "--key", privatePath]);
	assert.equal(signed.status, 0, signed.stderr);
	const valid = run("scripts/verify-release-evidence.mjs", ["--dirs", artifact]);
	assert.equal(valid.status, 0, valid.stderr);

	writeFileSync(path.join(artifact, "unsigned-extra.txt"), "not signed\n");
	const invalid = run("scripts/verify-release-evidence.mjs", ["--dirs", artifact]);
	assert.notEqual(invalid.status, 0);
	assert.match(invalid.stderr, /unexpected file is not covered by the signed manifest: unsigned-extra\.txt/);
});

test("bundle finalization binds VSIX and excludes every control file", async () => {
	const output = mkdtempSync(path.join(tmpdir(), "aidr-finalize-bundle-"));
	writeFileSync(
		path.join(output, "release-metadata.json"),
		`${JSON.stringify({
			schema_version: 1,
			release_tag: "v1.0.0-rc.0",
			release_version: "1.0.0",
			git_sha: "a".repeat(40),
			source_date_epoch: 0,
			worktree_dirty: false,
			artifacts: [{ path: "stale.tgz", size: 1, sha256: "0".repeat(64) }],
		})}\n`,
	);
	writeFileSync(path.join(output, "release-inventory.json"), '{"schema_version":1,"artifacts":[]}\n');
	writeFileSync(path.join(output, "package.tgz"), "package");
	writeFileSync(path.join(output, "aidr-vscode.vsix"), "vsix");
	for (const control of [
		"aidr-release.manifest.json",
		"aidr-release.manifest.sig",
		"aidr-artifact.manifest.json",
		"aidr-artifact.manifest.sig",
	]) {
		writeFileSync(path.join(output, control), "control");
	}

	const artifacts = await finalizeReleaseBundle(output);
	assert.deepEqual(
		artifacts.map((entry) => entry.path),
		["aidr-vscode.vsix", "package.tgz"],
	);
	const metadata = JSON.parse(readFileSync(path.join(output, "release-metadata.json"), "utf8"));
	const inventory = JSON.parse(readFileSync(path.join(output, "release-inventory.json"), "utf8"));
	assert.deepEqual(metadata.artifacts, artifacts);
	assert.deepEqual(
		inventory.artifacts.map((entry) => entry.staged_path),
		artifacts.map((entry) => entry.path),
	);
	for (const control of [
		"aidr-release.manifest.json",
		"aidr-release.manifest.sig",
		"aidr-artifact.manifest.json",
		"aidr-artifact.manifest.sig",
	]) {
		rmSync(path.join(output, control));
	}
	const canonical = await loadReleaseBundle(output);
	assert.deepEqual(canonical.artifacts, artifacts);
});

test("bundle finalization rejects nested paths that collide with control files", async () => {
	const output = mkdtempSync(path.join(tmpdir(), "aidr-finalize-control-collision-"));
	writeFileSync(
		path.join(output, "release-metadata.json"),
		`${JSON.stringify({
			schema_version: 1,
			release_tag: "v1.0.0-rc.0",
			release_version: "1.0.0",
			git_sha: "a".repeat(40),
			source_date_epoch: 0,
			worktree_dirty: false,
			artifacts: [],
		})}\n`,
	);
	writeFileSync(path.join(output, "release-inventory.json"), '{"schema_version":1,"artifacts":[]}\n');
	writeFileSync(path.join(output, "package.tgz"), "package");
	mkdirSync(path.join(output, "nested"));
	writeFileSync(path.join(output, "nested", "release-metadata.json"), "artifact");
	await assert.rejects(finalizeReleaseBundle(output), /artifact path collides with a control file: nested\/release-metadata\.json/);
});
