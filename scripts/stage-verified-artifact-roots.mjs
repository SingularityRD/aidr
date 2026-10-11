#!/usr/bin/env node

/**
 * Stage the claim gate's artifact roots from a signature-verified RC bundle.
 *
 * The production GO gate runs `claim-check --mode=gate` inside the immutable
 * trusted verifier checkout, and that gate scans `registry.artifactRoots`
 * (packages/<name>/dist). Those directories used to be produced by building
 * the RC tag inside the production job, which executed release-candidate code
 * next to production credentials before the GO decision. This script replaces
 * that build: it only READS the bundle the promote job has already verified
 * (attestations, run identity, signatures, anti-rollback) and extracts each
 * root's files from the archive that actually ships them. No release-candidate
 * code runs and no external `tar` extracts anything.
 *
 *   - Every archive used must be listed in the bundle's release-inventory.json,
 *     whose SHA-256 must equal --candidate-digest, and its bytes must match the
 *     inventory digest.
 *   - packages/<name>/dist comes from `aidr-<name>-dist-<version>.tar.gz`
 *     (entries under packages/<name>/dist/) when the bundle ships one, otherwise
 *     from the single npm tarball whose package/package.json names the package
 *     declared by the trusted checkout's packages/<name>/package.json (entries
 *     under package/dist/).
 *   - Each archive is first validated by the shared tar boundary validator
 *     (regular files and directories only; no links, devices, absolute or `..`
 *     paths, duplicates or unsupported PAX fields) and by the release archive
 *     inspection (forbidden entries, source-map directives, signed manifest
 *     present). Files are then written by this script with exclusive creates
 *     under a destination whose real path is checked to be inside --root.
 *
 * Usage:
 *   node scripts/stage-verified-artifact-roots.mjs --root .trusted-release-verifier \
 *     --bundle release-output --candidate-digest <sha256>
 */

import { createHash } from "node:crypto";
import { lstatSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { gunzipSync } from "node:zlib";
import { createTarBoundaryValidator } from "./archive-boundary.mjs";
import { inspectReleaseArchive } from "./lib/release-archive-inspection.mjs";
import { REGISTRY_FILE } from "./verify-commercial-gate-receipts.mjs";

const SHA256 = /^[0-9a-f]{64}$/u;
const ROOT_PATTERN = /^packages\/([a-z0-9-]+)\/dist$/u;
const BLOCK = 512;
const TOP_LEVEL_NAME = /^[A-Za-z0-9][A-Za-z0-9._@+-]*$/u;
const SIGNED_EVIDENCE = ["aidr-artifact.manifest.json", "aidr-artifact.manifest.sig"];
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

function fail(message) {
	throw new Error(`stage-verified-artifact-roots: ${message}`);
}

function inside(child, parent) {
	const value = relative(parent, child);
	return value === "" || (value !== ".." && !value.startsWith(`..${sep}`) && !isAbsolute(value));
}

/** Validate an uncompressed tar with the shared recovery-archive boundary validator. */
async function assertTarBoundary(tar, label) {
	await new Promise((resolvePromise, rejectPromise) => {
		const validator = createTarBoundaryValidator();
		validator.on("error", (error) => rejectPromise(new Error(`${label}: ${error.message}`)));
		validator.on("finish", resolvePromise);
		validator.end(tar);
	});
}

function field(header, start, length) {
	const bytes = header.subarray(start, start + length);
	const end = bytes.indexOf(0);
	return (end < 0 ? bytes : bytes.subarray(0, end)).toString("utf8");
}

/**
 * Regular-file entries of a tar that already passed assertTarBoundary. The
 * parser still refuses anything but files, directories and long-name metadata
 * so it never depends on the validator alone.
 */
export function tarFiles(tar) {
	const files = new Map();
	let offset = 0;
	let longPath;
	while (offset + BLOCK <= tar.length) {
		const header = tar.subarray(offset, offset + BLOCK);
		offset += BLOCK;
		if (header.every((byte) => byte === 0)) break;
		const type = String.fromCharCode(header[156] || 0x30);
		const size = Number.parseInt(field(header, 124, 12).trim() || "0", 8);
		if (!Number.isSafeInteger(size) || size < 0 || offset + size > tar.length) fail("tar entry size is invalid");
		const data = tar.subarray(offset, offset + size);
		offset += Math.ceil(size / BLOCK) * BLOCK;
		if (type === "L") {
			longPath = data.subarray(0, data.indexOf(0) < 0 ? data.length : data.indexOf(0)).toString("utf8");
			continue;
		}
		if (type === "x") {
			for (const record of data.toString("utf8").split("\n")) {
				const match = /^\d+ path=(.*)$/u.exec(record);
				if (match) longPath = match[1];
			}
			continue;
		}
		const prefix = field(header, 345, 155);
		const name = field(header, 0, 100);
		let path = longPath ?? (prefix ? `${prefix}/${name}` : name);
		longPath = undefined;
		while (path.startsWith("./")) path = path.slice(2);
		if (type === "5") continue;
		if (type !== "0") fail(`tar entry ${JSON.stringify(path)} is not a regular file`);
		if (path.startsWith("/") || path.includes("\\") || path.split("/").some((part) => part === "" || part === "." || part === "..")) fail(`tar entry path is not canonical: ${JSON.stringify(path)}`);
		if (files.has(path)) fail(`duplicate tar entry ${path}`);
		const mode = Number.parseInt(field(header, 100, 8).trim() || "644", 8);
		files.set(path, { data, executable: (mode & 0o111) !== 0 });
	}
	return files;
}

function readInventory(bundle, candidateDigest) {
	const inventoryPath = join(bundle, "release-inventory.json");
	const info = lstatSync(inventoryPath, { throwIfNoEntry: false });
	if (!info?.isFile()) fail(`${inventoryPath} is missing or not a regular file`);
	const bytes = readFileSync(inventoryPath);
	if (sha256(bytes) !== candidateDigest) fail("release-inventory.json is not the verified candidate (digest mismatch)");
	const inventory = JSON.parse(bytes.toString("utf8"));
	const digests = new Map();
	for (const artifact of inventory?.artifacts ?? []) {
		const name = artifact?.staged_path;
		if (typeof name !== "string" || name === "" || !SHA256.test(artifact?.sha256 ?? "")) fail("release inventory has a malformed artifact row");
		if (digests.has(name)) fail(`release inventory lists ${name} twice`);
		// Only top-level archives can be claim-gate sources; nested rows are ignored.
		if (TOP_LEVEL_NAME.test(name)) digests.set(name, artifact.sha256);
	}
	return digests;
}

/** Load, digest-check and validate one inventory-listed archive. */
async function loadArchive(bundle, name, expectedSha256) {
	const path = join(bundle, name);
	const info = lstatSync(path, { throwIfNoEntry: false });
	if (!info?.isFile()) fail(`${name} is listed in the inventory but is not a regular file in the bundle`);
	const bytes = readFileSync(path);
	if (sha256(bytes) !== expectedSha256) fail(`${name} does not match its signed inventory digest`);
	let tar;
	try {
		tar = gunzipSync(bytes);
	} catch {
		fail(`${name} is not a gzip archive`);
	}
	await assertTarBoundary(tar, name);
	return { name, path, files: tarFiles(tar) };
}

function writeRoot(rootDir, artifactRoot, files, prefix) {
	const realRoot = realpathSync(rootDir);
	const packageDir = join(rootDir, dirname(artifactRoot));
	const packageInfo = lstatSync(packageDir, { throwIfNoEntry: false });
	if (!packageInfo?.isDirectory() || !inside(realpathSync(packageDir), realRoot)) fail(`${dirname(artifactRoot)} is not a real directory inside the trusted checkout`);
	const destination = join(rootDir, artifactRoot);
	rmSync(destination, { recursive: true, force: true });
	mkdirSync(destination, { mode: 0o755 });
	const realDestination = realpathSync(destination);
	let written = 0;
	for (const [path, entry] of [...files].sort(([left], [right]) => (left < right ? -1 : 1))) {
		if (!path.startsWith(prefix)) continue;
		const relativePath = path.slice(prefix.length);
		if (relativePath === "") continue;
		const target = resolve(realDestination, relativePath);
		if (!inside(target, realDestination)) fail(`${path} escapes ${artifactRoot}`);
		mkdirSync(dirname(target), { recursive: true, mode: 0o755 });
		if (!inside(realpathSync(dirname(target)), realDestination)) fail(`${path} escapes ${artifactRoot}`);
		writeFileSync(target, entry.data, { flag: "wx", mode: entry.executable ? 0o755 : 0o644 });
		written += 1;
	}
	if (written === 0) fail(`no files for ${artifactRoot} under ${prefix}`);
	return written;
}

export async function stageVerifiedArtifactRoots({ root, bundle, candidateDigest, inspect = inspectReleaseArchive }) {
	if (!SHA256.test(candidateDigest ?? "")) fail("--candidate-digest must be a lowercase SHA-256 digest");
	const registry = JSON.parse(readFileSync(join(root, REGISTRY_FILE), "utf8"));
	const artifactRoots = registry?.artifactRoots;
	if (!Array.isArray(artifactRoots) || artifactRoots.length === 0) fail("the trusted registry names no artifact roots");
	const inventory = readInventory(bundle, candidateDigest);

	// npm tarballs are identified by the package name they declare.
	const npmByName = new Map();
	for (const [name, digest] of inventory) {
		if (!name.endsWith(".tgz")) continue;
		const archive = await loadArchive(bundle, name, digest);
		const manifest = archive.files.get("package/package.json");
		if (!manifest) fail(`${name} has no package/package.json`);
		const packageName = JSON.parse(manifest.data.toString("utf8"))?.name;
		if (typeof packageName !== "string") fail(`${name} declares no package name`);
		if (npmByName.has(packageName)) fail(`two npm tarballs declare ${packageName}`);
		npmByName.set(packageName, archive);
	}

	const staged = [];
	for (const artifactRoot of artifactRoots) {
		const match = ROOT_PATTERN.exec(artifactRoot ?? "");
		if (!match) fail(`unexpected artifact root ${JSON.stringify(artifactRoot)}`);
		const packageName = match[1];
		const plain = [...inventory.keys()].filter((name) => name.startsWith(`aidr-${packageName}-dist-`) && name.endsWith(".tar.gz"));
		if (plain.length > 1) fail(`more than one ${packageName} dist archive in the bundle`);
		let archive;
		let prefix;
		if (plain.length === 1) {
			archive = await loadArchive(bundle, plain[0], inventory.get(plain[0]));
			prefix = `${artifactRoot}/`;
		} else {
			const declared = JSON.parse(readFileSync(join(root, "packages", packageName, "package.json"), "utf8"))?.name;
			archive = npmByName.get(declared);
			if (!archive) fail(`the verified bundle ships no archive for ${artifactRoot} (${declared})`);
			prefix = "package/dist/";
		}
		inspect(archive.path, { requiredEntries: SIGNED_EVIDENCE.map((file) => `${prefix}${file}`) });
		const files = writeRoot(root, artifactRoot, archive.files, prefix);
		staged.push({ root: artifactRoot, archive: archive.name, files });
	}
	return staged;
}

export function parseArgs(argv) {
	const options = { root: null, bundle: null, candidateDigest: null };
	const valued = { "--root": "root", "--bundle": "bundle", "--candidate-digest": "candidateDigest" };
	for (let index = 0; index < argv.length; index += 1) {
		const key = valued[argv[index]];
		if (!key || !argv[index + 1]) throw new Error(`unknown or incomplete option: ${argv[index]}`);
		options[key] = argv[++index];
	}
	for (const [flag, key] of Object.entries(valued)) if (!options[key]) throw new Error(`${flag} is required`);
	return { ...options, root: resolve(options.root), bundle: resolve(options.bundle) };
}

const invokedDirectly = process.argv[1] !== undefined && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (invokedDirectly) {
	try {
		const staged = await stageVerifiedArtifactRoots(parseArgs(process.argv.slice(2)));
		for (const row of staged) console.log(`${row.root}: ${row.files} file(s) from ${row.archive}`);
	} catch (problem) {
		console.error(problem instanceof Error ? problem.message : String(problem));
		process.exitCode = 1;
	}
}
