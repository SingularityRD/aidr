/**
 * Tests for scripts/stage-verified-artifact-roots.mjs: the promote job's
 * claim-gate artifact roots come only from inventory-bound, signature-verified
 * archives, and unsafe archive contents are refused before anything is written.
 *
 *   node --test scripts/stage-verified-artifact-roots.test.mjs
 */

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";
import { stageVerifiedArtifactRoots } from "./stage-verified-artifact-roots.mjs";
import { REGISTRY_FILE } from "./verify-commercial-gate-receipts.mjs";

const hash = (bytes) => createHash("sha256").update(bytes).digest("hex");
const MANIFEST = { "aidr-artifact.manifest.json": "{}\n", "aidr-artifact.manifest.sig": "fixture-signature\n" };

/** Minimal ustar writer so tests can express entries real tools refuse to create. */
function tarHeader(name, { type = "0", size = 0, mode = 0o644, linkname = "" } = {}) {
	const header = Buffer.alloc(512);
	header.write(name, 0, 100, "utf8");
	header.write(`${mode.toString(8).padStart(7, "0")}\0`, 100, "ascii");
	header.write("0000000\0", 108, "ascii");
	header.write("0000000\0", 116, "ascii");
	header.write(`${size.toString(8).padStart(11, "0")}\0`, 124, "ascii");
	header.write("00000000000\0", 136, "ascii");
	header.write("        ", 148, "ascii");
	header.write(type, 156, "ascii");
	header.write(linkname, 157, 100, "utf8");
	header.write("ustar\0", 257, "ascii");
	header.write("00", 263, "ascii");
	const sum = header.reduce((total, byte) => total + byte, 0);
	header.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, "ascii");
	return header;
}

function tgz(entries) {
	const blocks = [];
	for (const entry of entries) {
		const data = Buffer.from(entry.data ?? "");
		blocks.push(tarHeader(entry.name, { type: entry.type, size: entry.type && entry.type !== "0" ? 0 : data.length, mode: entry.mode, linkname: entry.linkname }));
		if (!entry.type || entry.type === "0") blocks.push(data, Buffer.alloc((512 - (data.length % 512)) % 512));
	}
	blocks.push(Buffer.alloc(1024));
	return gzipSync(Buffer.concat(blocks));
}

const files = (prefix, contents) => Object.entries(contents).map(([name, data]) => ({ name: `${prefix}${name}`, data, mode: name.endsWith(".sh") ? 0o755 : 0o644 }));

/**
 * A trusted checkout (registry + package.json) and a release bundle with one
 * npm tarball and one plain dist archive, bound by a release inventory.
 */
function fixture(t, { coreEntries, privacyEntries } = {}) {
	const dir = mkdtempSync(join(tmpdir(), "aidr-stage-roots-"));
	t.after(() => rmSync(dir, { recursive: true, force: true }));
	const root = join(dir, "trusted");
	const bundle = join(dir, "release-output");
	mkdirSync(dirname(join(root, REGISTRY_FILE)), { recursive: true });
	writeFileSync(join(root, REGISTRY_FILE), JSON.stringify({ artifactRoots: ["packages/core/dist", "packages/privacy/dist"] }));
	for (const [name, packageName] of [["core", "@singularityrd/aidr-core"], ["privacy", "@singularityrd/aidr-privacy"]]) {
		mkdirSync(join(root, "packages", name), { recursive: true });
		writeFileSync(join(root, "packages", name, "package.json"), JSON.stringify({ name: packageName }));
	}
	mkdirSync(bundle);
	const archives = {
		"singularityrd-aidr-core-1.0.0.tgz": tgz(
			coreEntries ?? [
				{ name: "package/package.json", data: JSON.stringify({ name: "@singularityrd/aidr-core", version: "1.0.0" }) },
				...files("package/dist/", { "index.js": "export const core = 1;\n", "bin/run.sh": "#!/bin/sh\n", ...MANIFEST }),
				{ name: "package/README.md", data: "not part of dist\n" },
			],
		),
		"aidr-privacy-dist-0.6.0.tar.gz": tgz(
			privacyEntries ?? [
				{ name: "packages/privacy/dist/", type: "5", mode: 0o755 },
				...files("packages/privacy/dist/", { "engine.js": "export const privacy = 1;\n", ...MANIFEST }),
				{ name: "packages/privacy/package.json", data: "{}" },
			],
		),
		"aidr-sbom.cdx.json": Buffer.from("{}"),
	};
	for (const [name, bytes] of Object.entries(archives)) writeFileSync(join(bundle, name), bytes);
	const inventory = Buffer.from(
		`${JSON.stringify({ schema_version: 1, artifacts: Object.entries(archives).map(([name, bytes]) => ({ source_path: `release-output/${name}`, staged_path: name, kind: "release-artifact", sha256: hash(bytes) })) })}\n`,
	);
	writeFileSync(join(bundle, "release-inventory.json"), inventory);
	return { dir, root, bundle, candidateDigest: hash(inventory) };
}

const listTree = (base, prefix = "") =>
	readdirSync(join(base, prefix), { withFileTypes: true }).flatMap((entry) => {
		const relative = prefix ? `${prefix}/${entry.name}` : entry.name;
		return entry.isDirectory() ? listTree(base, relative) : [relative];
	});

test("stages each artifact root from its verified archive, regular files only", async (t) => {
	const { root, bundle, candidateDigest } = fixture(t);
	const staged = await stageVerifiedArtifactRoots({ root, bundle, candidateDigest });
	assert.deepEqual(staged, [
		{ root: "packages/core/dist", archive: "singularityrd-aidr-core-1.0.0.tgz", files: 4 },
		{ root: "packages/privacy/dist", archive: "aidr-privacy-dist-0.6.0.tar.gz", files: 3 },
	]);
	assert.deepEqual(listTree(join(root, "packages/core/dist")).sort(), ["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig", "bin/run.sh", "index.js"]);
	assert.equal(readFileSync(join(root, "packages/core/dist/index.js"), "utf8"), "export const core = 1;\n");
	assert.ok((statSync(join(root, "packages/core/dist/bin/run.sh")).mode & 0o111) !== 0, "the executable bit survives");
	assert.ok((statSync(join(root, "packages/core/dist/index.js")).mode & 0o111) === 0);
	assert.deepEqual(listTree(join(root, "packages/privacy/dist")).sort(), ["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig", "engine.js"]);
	assert.equal(existsSync(join(root, "packages/core/README.md")), false, "nothing outside package/dist is written");
});

test("an archive that differs from the signed inventory, or a different candidate, is refused", async (t) => {
	{
		const { root, bundle, candidateDigest } = fixture(t);
		writeFileSync(join(bundle, "singularityrd-aidr-core-1.0.0.tgz"), tgz([{ name: "package/package.json", data: JSON.stringify({ name: "@singularityrd/aidr-core" }) }, ...files("package/dist/", { "index.js": "swapped\n", ...MANIFEST })]));
		await assert.rejects(stageVerifiedArtifactRoots({ root, bundle, candidateDigest }), /does not match its signed inventory digest/u);
		assert.equal(existsSync(join(root, "packages/core/dist")), false);
	}
	{
		const { root, bundle } = fixture(t);
		await assert.rejects(stageVerifiedArtifactRoots({ root, bundle, candidateDigest: "e".repeat(64) }), /is not the verified candidate/u);
		await assert.rejects(stageVerifiedArtifactRoots({ root, bundle, candidateDigest: "not-a-digest" }), /--candidate-digest must be/u);
	}
});

test("links, traversal, absolute paths and duplicates inside an archive are refused before anything is written", async (t) => {
	const base = [{ name: "package/package.json", data: JSON.stringify({ name: "@singularityrd/aidr-core" }) }, ...files("package/dist/", MANIFEST)];
	for (const [label, entry, pattern] of [
		["symlink", { name: "package/dist/link.js", type: "2", linkname: "/etc/passwd" }, /not a regular file or directory/u],
		["hard link", { name: "package/dist/hard.js", type: "1", linkname: "package/package.json" }, /not a regular file or directory/u],
		["parent traversal", { name: "package/dist/../../../escape.js", data: "x" }, /not canonical/u],
		["absolute path", { name: "/tmp/escape.js", data: "x" }, /absolute or non-portable/u],
		["duplicate", { name: "package/dist/aidr-artifact.manifest.json", data: "{}" }, /duplicate entry path/u],
	]) {
		const { root, bundle, candidateDigest } = fixture(t, { coreEntries: [...base, entry] });
		await assert.rejects(stageVerifiedArtifactRoots({ root, bundle, candidateDigest }), pattern, label);
		assert.equal(existsSync(join(root, "packages/core/dist")), false, `${label}: nothing staged`);
	}
});

test("a root with no shipped archive, or without its signed manifest, is refused", async (t) => {
	{
		const { root, bundle, candidateDigest } = fixture(t, { coreEntries: [{ name: "package/package.json", data: JSON.stringify({ name: "@singularityrd/aidr-other" }) }, ...files("package/dist/", MANIFEST)] });
		await assert.rejects(stageVerifiedArtifactRoots({ root, bundle, candidateDigest }), /ships no archive for packages\/core\/dist/u);
	}
	{
		const { root, bundle, candidateDigest } = fixture(t, { coreEntries: [{ name: "package/package.json", data: JSON.stringify({ name: "@singularityrd/aidr-core" }) }, ...files("package/dist/", { "index.js": "x\n" })] });
		await assert.rejects(stageVerifiedArtifactRoots({ root, bundle, candidateDigest }), /missing signed evidence package\/dist\/aidr-artifact\.manifest\.json/u);
	}
});

test("staging never writes through a link planted in the trusted checkout", async (t) => {
	{
		const { dir, root, bundle, candidateDigest } = fixture(t);
		const outside = join(dir, "outside");
		mkdirSync(outside);
		writeFileSync(join(outside, "keep.txt"), "keep");
		symlinkSync(outside, join(root, "packages/core/dist"));
		await stageVerifiedArtifactRoots({ root, bundle, candidateDigest });
		assert.ok(lstatSync(join(root, "packages/core/dist")).isDirectory(), "the planted link is replaced by a real directory");
		assert.deepEqual(readdirSync(outside), ["keep.txt"], "the link target is untouched");
	}
	{
		const { dir, root, bundle, candidateDigest } = fixture(t);
		const outside = join(dir, "outside-package");
		mkdirSync(outside);
		rmSync(join(root, "packages/privacy"), { recursive: true });
		symlinkSync(outside, join(root, "packages/privacy"));
		await assert.rejects(stageVerifiedArtifactRoots({ root, bundle, candidateDigest }), /packages\/privacy is not a real directory inside the trusted checkout/u);
		assert.deepEqual(readdirSync(outside), []);
	}
});
