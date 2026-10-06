#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
	closeSync, constants, existsSync, fstatSync, lstatSync, mkdirSync, openSync,
	readSync, readdirSync, renameSync, unlinkSync, writeFileSync,
} from "node:fs";
import { dirname, isAbsolute, join, relative, resolve, sep } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";

export const WINDOWS_FLEET_SCRIPTS = Object.freeze([
	"Common.ps1", "Install-Aidr.ps1", "Install-AidrResponseWorker.ps1",
	"Invoke-AidrRemediation.ps1", "Invoke-AidrResponseAction.ps1", "New-AidrFleetManifest.ps1",
	"Rollback-Aidr.ps1", "Test-AidrDetection.ps1", "Test-AidrFleetScriptSignatures.ps1",
	"Uninstall-Aidr.ps1", "Uninstall-AidrResponseWorker.ps1", "Update-Aidr.ps1",
]);
const NATIVE_SCRIPTS = ["Common.ps1", "Invoke-AidrResponseAction.ps1"];
const INPUT_PATHS = Object.freeze([
	...WINDOWS_FLEET_SCRIPTS.map((name) => `fleet/${name}`),
	...NATIVE_SCRIPTS.map((name) => `claude/native/${name}`),
].sort());
const MAX_SCRIPT_BYTES = 1024 * 1024;
const MAX_METADATA_BYTES = 64 * 1024;
const MANIFEST_NAME = "input-manifest.json";
const RECEIPT_NAME = "authenticode-receipt.json";
const EVIDENCE_MANIFEST = ".release-evidence/windows-authenticode-input-manifest.json";
const EVIDENCE_RECEIPT = ".release-evidence/windows-authenticode-receipt.json";
const EVIDENCE_FLEET = ".release-evidence/windows-fleet";
const SHA256 = /^[a-f0-9]{64}$/;
const GIT_SHA = /^[a-f0-9]{40}$/;
const SIGNATURE_BEGIN = "# SIG # Begin signature block";
const SIGNATURE_END = "# SIG # End signature block";

function sha256(bytes) { return createHash("sha256").update(bytes).digest("hex"); }
function record(value) { return value !== null && typeof value === "object" && !Array.isArray(value); }
function requireValue(condition, message) { if (!condition) throw new Error(message); }
function exactKeys(value, keys) {
	return record(value) && Object.keys(value).length === keys.length && keys.every((key) => Object.hasOwn(value, key));
}
function thumbprint(value) {
	requireValue(typeof value === "string" && /^[a-fA-F0-9]{40}$/.test(value), "A pinned 40-hex Authenticode thumbprint is required");
	return value.toUpperCase();
}
function timestampServer(value) {
	requireValue(typeof value === "string" && value.trim() === value && value.length <= 2048, "A protected HTTPS timestamp server is required");
	const url = new URL(value);
	requireValue(url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash,
		"A protected HTTPS timestamp server is required");
	return value;
}
function isoTimestamp(value) {
	if (typeof value !== "string" || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,7})?(?:Z|\+00:00)$/.test(value)) return false;
	const parsed = Date.parse(value);
	return Number.isFinite(parsed) && new Date(parsed).toISOString().slice(0, 19) === value.slice(0, 19);
}
function inside(root, path) {
	const rel = relative(root, path);
	requireValue(rel !== ".." && !rel.startsWith(`..${sep}`) && !isAbsolute(rel), "Path escapes its expected root");
}
function safeDirectories(path, allowMissing = false) {
	const paths = [];
	for (let next = resolve(path); ; next = dirname(next)) {
		paths.push(next);
		if (dirname(next) === next) break;
	}
	for (const item of paths.reverse()) {
		let info;
		try { info = lstatSync(item); } catch (error) {
			if (allowMissing && error.code === "ENOENT") continue;
			throw error;
		}
		requireValue(info.isDirectory() && !info.isSymbolicLink(), `Unsafe directory: ${item}`);
	}
}
function sameFile(info, expected) {
	return info.isFile() && !info.isSymbolicLink() && info.nlink === 1 && info.ino === expected.ino && info.dev === expected.dev;
}
function regularBytes(root, name, maxBytes = MAX_SCRIPT_BYTES) {
	const path = resolve(root, name);
	inside(root, path);
	safeDirectories(dirname(path));
	const before = lstatSync(path);
	requireValue(sameFile(before, before) && before.size > 0 && before.size <= maxBytes, `Unsafe or oversized regular file: ${name}`);
	const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
	try {
		const opened = fstatSync(fd);
		requireValue(sameFile(opened, before), `File changed during validation: ${name}`);
		const bytes = Buffer.alloc(maxBytes + 1);
		let count = 0;
		while (count < bytes.length) {
			const read = readSync(fd, bytes, count, bytes.length - count, count);
			if (read === 0) break;
			count += read;
		}
		requireValue(count > 0 && count <= maxBytes && count === opened.size && sameFile(lstatSync(path), opened),
			`File changed or exceeded its limit: ${name}`);
		return bytes.subarray(0, count);
	} finally { closeSync(fd); }
}
function inventory(root, allowedDirectories) {
	safeDirectories(root);
	const files = [];
	function walk(directory, prefix = "") {
		for (const name of readdirSync(directory)) {
			const path = join(directory, name);
			const info = lstatSync(path);
			requireValue(!info.isSymbolicLink(), `Linked input is forbidden: ${path}`);
			const rel = prefix ? `${prefix}/${name}` : name;
			if (info.isDirectory()) {
				requireValue(allowedDirectories === undefined || allowedDirectories.includes(rel), `Unexpected input directory: ${rel}`);
				walk(path, rel);
			}
			else {
				requireValue(info.isFile() && info.nlink === 1, `Non-regular or hardlinked input: ${path}`);
				files.push(rel);
			}
		}
	}
	walk(root);
	return files.sort();
}
function samePaths(actual, expected, label) {
	requireValue(actual.length === expected.length && [...actual].sort().every((name, i) => name === [...expected].sort()[i]),
		`${label} must contain exactly the reviewed file set`);
}
function sourceFleet(repoRoot) {
	const root = join(repoRoot, "deploy/fleet/windows");
	samePaths(inventory(root).filter((name) => /\.ps1$/i.test(name)), WINDOWS_FLEET_SCRIPTS, "Windows source scripts");
	return new Map(WINDOWS_FLEET_SCRIPTS.map((name) => [name, regularBytes(root, name)]));
}
function gitHead(repoRoot, expected, clean = false) {
	const actual = execFileSync("git", ["-C", repoRoot, "rev-parse", "HEAD"], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
	requireValue(GIT_SHA.test(actual) && actual === expected, "Signing input git SHA does not match the reviewed checkout");
	if (clean) {
		const dirty = execFileSync("git", ["-C", repoRoot, "status", "--porcelain", "--untracked-files=no"],
			{ encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
		requireValue(!dirty, "Signing inputs require clean tracked source files");
	}
	return actual;
}
function inputEntries(manifest) {
	requireValue(exactKeys(manifest, ["schema_version", "purpose", "git_sha", "unsigned_release_sha256", "files"]) &&
		manifest.schema_version === 1 && manifest.purpose === "aidr.windows-authenticode.inputs" &&
		GIT_SHA.test(manifest.git_sha) && SHA256.test(manifest.unsigned_release_sha256), "Invalid Authenticode input manifest");
	requireValue(Array.isArray(manifest.files), "Input manifest files are required");
	samePaths(manifest.files.map((item) => item?.path), INPUT_PATHS, "Input manifest");
	const entries = new Map();
	for (const item of manifest.files) {
		requireValue(exactKeys(item, ["path", "before_sha256"]) && SHA256.test(item.before_sha256) && !entries.has(item.path),
			"Invalid or duplicate input manifest entry");
		entries.set(item.path, item);
	}
	return entries;
}
function receiptEntries(receipt, expectedThumbprint, expectedTimestampServer) {
	requireValue(exactKeys(receipt, ["schema_version", "purpose", "signer_thumbprint", "timestamp_server", "verified_at",
		"input_manifest_sha256", "verified", "files"]) && receipt.schema_version === 1 &&
		receipt.purpose === "aidr.windows-authenticode" && receipt.verified === true &&
		SHA256.test(receipt.input_manifest_sha256) && isoTimestamp(receipt.verified_at), "Invalid verified Authenticode receipt");
	requireValue(receipt.signer_thumbprint === thumbprint(receipt.signer_thumbprint) &&
		thumbprint(receipt.signer_thumbprint) === thumbprint(expectedThumbprint), "Authenticode signer pin mismatch");
	timestampServer(receipt.timestamp_server);
	if (expectedTimestampServer !== undefined)
		requireValue(receipt.timestamp_server === timestampServer(expectedTimestampServer), "Authenticode timestamp server pin mismatch");
	requireValue(Array.isArray(receipt.files), "Authenticode receipt files are required");
	samePaths(receipt.files.map((item) => item?.path), INPUT_PATHS, "Authenticode receipt");
	const entries = new Map();
	for (const item of receipt.files) {
		requireValue(exactKeys(item, ["path", "before_sha256", "sha256", "size"]) && SHA256.test(item.before_sha256) &&
			SHA256.test(item.sha256) && item.sha256 !== item.before_sha256 && Number.isSafeInteger(item.size) &&
			item.size > 0 && item.size <= MAX_SCRIPT_BYTES && !entries.has(item.path), "Invalid or duplicate signed file receipt");
		entries.set(item.path, item);
	}
	return entries;
}
function metadata(bytes, label) {
	try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
	catch { throw new Error(`Invalid JSON in ${label}`); }
}
function validateProof(repoRoot, manifestBytes, receiptBytes, options) {
	requireValue(SHA256.test(options.receiptSha256), "An independent Windows receipt SHA-256 is required");
	requireValue(sha256(receiptBytes) === options.receiptSha256, "Authenticode receipt digest pin mismatch");
	const manifest = metadata(manifestBytes, MANIFEST_NAME);
	const input = inputEntries(manifest);
	gitHead(repoRoot, options.gitSha ?? manifest.git_sha, options.cleanSource === true);
	requireValue(manifest.git_sha === (options.gitSha ?? manifest.git_sha) &&
		manifest.unsigned_release_sha256 === (options.unsignedReleaseSha256 ?? manifest.unsigned_release_sha256),
		"Authenticode input candidate pin mismatch");
	const receipt = metadata(receiptBytes, RECEIPT_NAME);
	const signed = receiptEntries(receipt, options.thumbprint, options.timestampServer);
	requireValue(sha256(manifestBytes) === receipt.input_manifest_sha256, "Authenticode input manifest digest mismatch");
	const source = sourceFleet(repoRoot);
	for (const name of INPUT_PATHS) {
		const original = source.get(name.slice(name.lastIndexOf("/") + 1));
		requireValue(input.get(name).before_sha256 === sha256(original) &&
			signed.get(name).before_sha256 === input.get(name).before_sha256, `Reviewed source preimage mismatch: ${name}`);
	}
	return { manifest, receipt, signed };
}
function signedBytes(root, name, entry) {
	const bytes = regularBytes(root, name);
	requireValue(bytes.length === entry.size && sha256(bytes) === entry.sha256, `Signed input digest or size mismatch: ${name}`);
	const text = bytes.toString("utf8");
	requireValue(text.indexOf(SIGNATURE_BEGIN) >= 0 && text.indexOf(SIGNATURE_END) > text.indexOf(SIGNATURE_BEGIN),
		`Unsigned script cannot be consumed: ${name}`);
	return bytes;
}
function present(path) {
	try { lstatSync(path); return true; } catch (error) {
		if (error.code === "ENOENT") return false;
		throw error;
	}
}
function targetPreflight(repoRoot, names) {
	for (const name of names) {
		const target = resolve(repoRoot, name);
		inside(repoRoot, target);
		safeDirectories(dirname(target), true);
		if (present(target)) regularBytes(repoRoot, name, name.endsWith(".json") ? MAX_METADATA_BYTES : MAX_SCRIPT_BYTES);
	}
}
function atomicWrite(repoRoot, name, bytes) {
	const target = resolve(repoRoot, name);
	inside(repoRoot, target);
	safeDirectories(dirname(target), true);
	mkdirSync(dirname(target), { recursive: true });
	const temporary = `${target}.${randomUUID()}.tmp`;
	try { writeFileSync(temporary, bytes, { flag: "wx", mode: 0o600 }); renameSync(temporary, target); }
	finally { if (existsSync(temporary)) unlinkSync(temporary); }
}

export function prepareWindowsAuthenticodeInputs(options) {
	const repoRoot = resolve(options.repoRoot ?? process.cwd());
	const stage = resolve(options.stage);
	requireValue(GIT_SHA.test(options.gitSha) && SHA256.test(options.unsignedReleaseSha256), "Independent git SHA and unsigned release SHA-256 are required");
	gitHead(repoRoot, options.gitSha, true);
	safeDirectories(repoRoot);
	safeDirectories(dirname(stage));
	requireValue(!present(stage), "Authenticode signing stage must be new");
	const source = sourceFleet(repoRoot);
	const native = join(repoRoot, "packages/claude-code/dist/native");
	samePaths(inventory(native).filter((name) => /\.ps1$/i.test(name)), NATIVE_SCRIPTS, "Unsigned native scripts");
	for (const name of NATIVE_SCRIPTS)
		requireValue(regularBytes(native, name).equals(source.get(name)), `Unsigned native preimage differs from reviewed fleet source: ${name}`);
	const files = INPUT_PATHS.map((path) => {
		const bytes = source.get(path.slice(path.lastIndexOf("/") + 1));
		requireValue(!bytes.includes(Buffer.from(SIGNATURE_BEGIN)), "Signing source scripts must be unsigned reviewed preimages");
		return { path, before_sha256: sha256(bytes) };
	});
	const manifest = { schema_version: 1, purpose: "aidr.windows-authenticode.inputs", git_sha: options.gitSha,
		unsigned_release_sha256: options.unsignedReleaseSha256, files };
	const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
	mkdirSync(stage);
	for (const file of files) atomicWrite(stage, file.path, source.get(file.path.slice(file.path.lastIndexOf("/") + 1)));
	atomicWrite(stage, MANIFEST_NAME, manifestBytes);
	return { stage, files: files.length, git_sha: manifest.git_sha, input_manifest_sha256: sha256(manifestBytes) };
}

export function validateWindowsAuthenticodeStage(options) {
	const repoRoot = resolve(options.repoRoot ?? process.cwd());
	const stage = resolve(options.stage);
	requireValue(GIT_SHA.test(options.gitSha) && SHA256.test(options.unsignedReleaseSha256), "Independent git SHA and unsigned release SHA-256 are required");
	timestampServer(options.timestampServer);
	samePaths(inventory(stage, ["fleet", "claude", "claude/native"]), [...INPUT_PATHS, MANIFEST_NAME, RECEIPT_NAME], "Signed stage");
	const manifestBytes = regularBytes(stage, MANIFEST_NAME, MAX_METADATA_BYTES);
	const receiptBytes = regularBytes(stage, RECEIPT_NAME, MAX_METADATA_BYTES);
	const proof = validateProof(repoRoot, manifestBytes, receiptBytes, { ...options, cleanSource: true });
	const files = new Map(INPUT_PATHS.map((name) => [name, signedBytes(stage, name, proof.signed.get(name))]));
	return { ...proof, repoRoot, stage, files, manifestBytes, receiptBytes };
}

export function consumeWindowsAuthenticodeInputs(options) {
	const validated = validateWindowsAuthenticodeStage(options);
	const { repoRoot, files } = validated;
	const targets = INPUT_PATHS.map((name) => name.startsWith("fleet/")
		? `${EVIDENCE_FLEET}/${name.slice(6)}` : `packages/claude-code/dist/native/${name.slice("claude/native/".length)}`);
	if (present(join(repoRoot, EVIDENCE_FLEET))) samePaths(inventory(join(repoRoot, EVIDENCE_FLEET), []), WINDOWS_FLEET_SCRIPTS, "Consumed signed fleet");
	samePaths(inventory(join(repoRoot, "packages/claude-code/dist/native")).filter((name) => /\.ps1$/i.test(name)),
		NATIVE_SCRIPTS, "Native destination scripts");
	targetPreflight(repoRoot, [...targets, EVIDENCE_MANIFEST, EVIDENCE_RECEIPT]);
	for (let i = 0; i < INPUT_PATHS.length; i++) atomicWrite(repoRoot, targets[i], files.get(INPUT_PATHS[i]));
	atomicWrite(repoRoot, EVIDENCE_MANIFEST, validated.manifestBytes);
	atomicWrite(repoRoot, EVIDENCE_RECEIPT, validated.receiptBytes);
	return { verified: true, files: INPUT_PATHS.length, receipt_sha256: options.receiptSha256,
		fleet_root: join(repoRoot, EVIDENCE_FLEET), native_root: join(repoRoot, "packages/claude-code/dist/native"),
		input_manifest: join(repoRoot, EVIDENCE_MANIFEST), receipt: join(repoRoot, EVIDENCE_RECEIPT) };
}

/** Packaging must use this returned directory; unsigned repository fleet files are never a fallback. */
export function validateSignedWindowsFleet(repoRoot, expectedReceiptSHA, expectedThumbprint, expectedTimestampServer) {
	repoRoot = resolve(repoRoot);
	const manifestBytes = regularBytes(repoRoot, EVIDENCE_MANIFEST, MAX_METADATA_BYTES);
	const receiptBytes = regularBytes(repoRoot, EVIDENCE_RECEIPT, MAX_METADATA_BYTES);
	const proof = validateProof(repoRoot, manifestBytes, receiptBytes, { receiptSha256: expectedReceiptSHA,
		thumbprint: expectedThumbprint, timestampServer: expectedTimestampServer });
	const fleet = join(repoRoot, EVIDENCE_FLEET);
	samePaths(inventory(fleet, []), WINDOWS_FLEET_SCRIPTS, "Consumed signed fleet");
	const native = join(repoRoot, "packages/claude-code/dist/native");
	samePaths(inventory(native).filter((name) => /\.ps1$/i.test(name)), NATIVE_SCRIPTS, "Consumed signed native scripts");
	for (const name of INPUT_PATHS) signedBytes(repoRoot, name.startsWith("fleet/")
		? `${EVIDENCE_FLEET}/${name.slice(6)}` : `packages/claude-code/dist/native/${name.slice("claude/native/".length)}`, proof.signed.get(name));
	return fleet;
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
	const { values, positionals } = parseArgs({ allowPositionals: true, options: Object.fromEntries([
		"stage", "git-sha", "unsigned-release-sha256", "receipt-sha256", "thumbprint", "timestamp-server", "repo-root",
	].map((name) => [name, { type: "string" }])) });
	requireValue(positionals.length === 1 && ["prepare", "consume", "check"].includes(positionals[0]) && values.stage,
		"Use prepare|consume|check --stage with independent release pins");
	const options = { stage: values.stage, repoRoot: values["repo-root"], gitSha: values["git-sha"],
		unsignedReleaseSha256: values["unsigned-release-sha256"], receiptSha256: values["receipt-sha256"],
		thumbprint: values.thumbprint, timestampServer: values["timestamp-server"] };
	const result = positionals[0] === "prepare" ? prepareWindowsAuthenticodeInputs(options)
		: positionals[0] === "consume" ? consumeWindowsAuthenticodeInputs(options)
			: { verified: true, files: validateWindowsAuthenticodeStage(options).files.size, receipt_sha256: options.receiptSha256 };
	process.stdout.write(`${JSON.stringify(result)}\n`);
}
