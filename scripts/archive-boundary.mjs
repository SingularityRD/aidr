import { createHash } from "node:crypto";
import {
	chmodSync,
	closeSync,
	constants as fsConstants,
	fstatSync,
	lstatSync,
	mkdirSync,
	openSync,
	readdirSync,
	readFileSync,
	realpathSync,
	writeFileSync,
} from "node:fs";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { Writable } from "node:stream";

const BLOCK_SIZE = 512;
export const REVIEWED_RUNTIME_ARCHIVE_ENTRIES = Object.freeze([
	".env",
	".env.functions",
	".env.ingress",
	".env.readiness",
	"agent-config.json",
	"auth-templates",
	"backup",
	"compose.yml",
	"dashboard",
	"deployment.json",
	"ingress",
	"maintenance",
	"migrations",
	"volumes",
]);
const ALLOWED_RUNTIME_ENTRIES = new Set([...REVIEWED_RUNTIME_ARCHIVE_ENTRIES, "health"]);
const REQUIRED_RUNTIME_ENTRIES = [...REVIEWED_RUNTIME_ARCHIVE_ENTRIES, "health"];
// Receipts the operator tools write into an installation root during normal
// operation: scripts/deployment-smoke.mjs (smoke-evidence*.json),
// scripts/deployment-doctor.mjs (doctor-evidence.json) and
// scripts/deployment-maintenance.mjs (maintenance-evidence.json). Like health/,
// they are not runtime configuration: they stay outside the runtime digest and
// are not copied into a recovery. Without this, the first doctor run after
// installation made every later cold backup refuse the installation.
const SMOKE_EVIDENCE_ENTRY = /^(?:smoke-evidence(?:-[a-f0-9]{64})?|doctor-evidence|maintenance-evidence)\.json$/;
// Private state of scripts/deployment-upgrade.mjs (state, receipts, rollback
// plan, the previous release's components). Compose never reads it.
const UPGRADE_STATE_ENTRY = ".aidr-upgrade";
// The endpoint machine policy deployment-prepare.mjs writes for the MSI / Linux
// packages / GPO: a deliverable derived from agent-config.json (address, public
// signing key, offline choice). Compose never reads it and installations
// prepared before it existed have none, so it is neither required nor archived.
const ENDPOINT_POLICY_ENTRY = "endpoint-policy";
const isRuntimeOutput = (name) => name === "health" || name === UPGRADE_STATE_ENTRY || name === ENDPOINT_POLICY_ENTRY || SMOKE_EVIDENCE_ENTRY.test(name);
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function fail(message) {
	throw new Error(`Unsafe recovery archive: ${message}`);
}

function fieldText(header, start, length, label) {
	const field = header.subarray(start, start + length);
	const end = field.indexOf(0);
	try {
		return textDecoder.decode(end < 0 ? field : field.subarray(0, end));
	} catch {
		fail(`${label} is not valid UTF-8`);
	}
}

function octal(header, start, length, label) {
	const raw = fieldText(header, start, length, label).trim();
	if (!/^[0-7]+$/.test(raw)) fail(`${label} is not canonical octal`);
	const value = Number.parseInt(raw, 8);
	if (!Number.isSafeInteger(value) || value < 0) fail(`${label} is outside the safe integer range`);
	return value;
}

function checksum(header) {
	const expected = octal(header, 148, 8, "header checksum");
	let actual = 0;
	for (let index = 0; index < header.length; index += 1) {
		actual += index >= 148 && index < 156 ? 0x20 : header[index];
	}
	if (actual !== expected) fail("header checksum mismatch");
}

function archivePath(header, type, extendedPath) {
	let raw = extendedPath;
	if (raw === undefined) {
		const name = fieldText(header, 0, 100, "entry name");
		const prefix = fieldText(header, 345, 155, "entry prefix");
		raw = prefix ? `${prefix}/${name}` : name;
	}
	while (raw.startsWith("./")) raw = raw.slice(2);
	if (raw.includes(":") || raw.startsWith("/") || raw.includes("\\") || /[\u0000-\u001f\u007f]/.test(raw)) {
		fail(`entry path is absolute or non-portable: ${JSON.stringify(raw)}`);
	}
	if (type === "directory") raw = raw.replace(/\/+$/, "");
	if ((raw === "" || raw === ".") && type === "directory") return null;
	const parts = raw.split("/");
	if (parts.length === 0 || parts.some((part) => part === "" || part === "." || part === "..")) {
		fail(`entry path is not canonical: ${JSON.stringify(raw)}`);
	}
	return parts.join("/");
}

function extendedPath(type, bytes) {
	if (type === "L") {
		if (bytes.at(-1) !== 0 || bytes.subarray(0, -1).includes(0)) fail("invalid GNU long-name metadata");
		try { return textDecoder.decode(bytes.subarray(0, -1)); } catch { fail("long entry name is not valid UTF-8"); }
	}
	let path;
	const keys = new Set();
	for (let offset = 0; offset < bytes.length;) {
		const space = bytes.indexOf(0x20, offset);
		const lengthText = space < 0 ? "" : bytes.subarray(offset, space).toString("ascii");
		if (!/^[1-9][0-9]*$/.test(lengthText)) fail("invalid PAX record length");
		const length = Number(lengthText);
		const end = offset + length;
		if (!Number.isSafeInteger(length) || end > bytes.length || end <= space + 1 || bytes[end - 1] !== 0x0a) fail("invalid PAX record boundary");
		let record;
		try { record = textDecoder.decode(bytes.subarray(space + 1, end - 1)); } catch { fail("PAX metadata is not valid UTF-8"); }
		const separator = record.indexOf("=");
		const key = record.slice(0, separator);
		if (separator < 1 || keys.has(key)) fail("invalid or duplicate PAX field");
		keys.add(key);
		// Only a per-entry path and metadata that cannot change extraction layout.
		if (key === "path") path = record.slice(separator + 1);
		else if (!["mtime", "atime", "ctime", "uid", "gid", "uname", "gname"].includes(key)) fail(`unsupported PAX field: ${key}`);
		offset = end;
	}
	return path;
}

function isZeroBlock(block) {
	return block.every((byte) => byte === 0);
}

class TarBoundaryValidator extends Writable {
	#buffer = Buffer.alloc(0);
	#remaining = 0;
	#padding = 0;
	#zeroBlocks = 0;
	#ended = false;
	#entries = new Map();
	#parentPaths = new Set();
	#extension = null;
	#extendedPath;
	#pendingExtension = false;

	_write(chunk, _encoding, done) {
		try {
			this.#buffer = Buffer.concat([this.#buffer, chunk]);
			this.#consume();
			done();
		} catch (error) {
			done(error);
		}
	}

	#consumeBytes(count) {
		const used = Math.min(count, this.#buffer.length);
		this.#buffer = this.#buffer.subarray(used);
		return count - used;
	}

	#consume() {
		while (this.#buffer.length > 0) {
			if (this.#remaining > 0) {
				if (this.#extension) this.#extension.chunks.push(this.#buffer.subarray(0, Math.min(this.#remaining, this.#buffer.length)));
				this.#remaining = this.#consumeBytes(this.#remaining);
				if (this.#remaining > 0) return;
				if (this.#extension) {
					this.#extendedPath = extendedPath(this.#extension.type, Buffer.concat(this.#extension.chunks));
					this.#extension = null;
					this.#pendingExtension = true;
				}
				continue;
			}
			if (this.#padding > 0) {
				this.#padding = this.#consumeBytes(this.#padding);
				if (this.#padding > 0) return;
				continue;
			}
			if (this.#buffer.length < BLOCK_SIZE) return;
			const header = this.#buffer.subarray(0, BLOCK_SIZE);
			this.#buffer = this.#buffer.subarray(BLOCK_SIZE);
			if (isZeroBlock(header)) {
				if (this.#pendingExtension) fail("long-name metadata has no following entry");
				this.#zeroBlocks += 1;
				if (this.#zeroBlocks >= 2) this.#ended = true;
				continue;
			}
			if (this.#zeroBlocks > 0 || this.#ended) fail("non-zero content follows the end marker");
			checksum(header);
			const typeFlag = String.fromCharCode(header[156] || 0x30);
			const size = octal(header, 124, 12, "entry size");
			if (typeFlag === "L" || typeFlag === "x") {
				if (this.#pendingExtension || size < 1 || size > 1024 * 1024 || fieldText(header, 157, 100, "link target") !== "") fail("invalid long-name metadata entry");
				this.#extension = { type: typeFlag, chunks: [] };
				this.#remaining = size;
				this.#padding = (BLOCK_SIZE - (size % BLOCK_SIZE)) % BLOCK_SIZE;
				continue;
			}
			const type = typeFlag === "0" ? "file" : typeFlag === "5" ? "directory" : null;
			if (!type) fail(`entry type ${JSON.stringify(typeFlag)} is not a regular file or directory`);
			if (fieldText(header, 157, 100, "link target") !== "") fail("regular entry carries a link target");
			if (type === "directory" && size !== 0) fail("directory entry has a payload");
			const path = archivePath(header, type, this.#extendedPath);
			this.#extendedPath = undefined;
			this.#pendingExtension = false;
			if (path !== null) {
				if (this.#entries.has(path)) fail(`duplicate entry path: ${path}`);
				const segments = path.split("/");
				for (let index = 1; index < segments.length; index += 1) {
					const parent = segments.slice(0, index).join("/");
					if (this.#entries.get(parent) === "file") fail(`entry descends from a regular file: ${path}`);
					this.#parentPaths.add(parent);
				}
				if (type === "file" && this.#parentPaths.has(path)) {
					fail(`regular file replaces an existing directory path: ${path}`);
				}
				this.#entries.set(path, type);
			}
			this.#remaining = size;
			this.#padding = (BLOCK_SIZE - (size % BLOCK_SIZE)) % BLOCK_SIZE;
		}
	}

	_final(done) {
		try {
			this.#consume();
			if (this.#remaining !== 0 || this.#padding !== 0 || this.#buffer.length !== 0) fail("archive is truncated");
			if (!this.#ended) fail("archive has no complete end marker");
			done();
		} catch (error) {
			done(error);
		}
	}
}

export function createTarBoundaryValidator() {
	return new TarBoundaryValidator();
}

function inside(child, parent) {
	const value = relative(parent, child);
	return value === "" || (!value.startsWith(`..${sep}`) && value !== ".." && !isAbsolute(value));
}

function samePath(left, right) {
	return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right;
}

function validateRegularTree(source, root = source) {
	const real = realpathSync(source);
	if (!inside(real, realpathSync(root))) throw new Error(`Reviewed recovery runtime escapes through a linked ancestor: ${source}`);
	const info = lstatSync(source);
	if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile()) || (info.isFile() && info.nlink !== 1)) {
		throw new Error(`Reviewed recovery runtime contains a link or special entry: ${source}`);
	}
	if (process.platform !== "win32" && (info.mode & 0o022) !== 0) {
		throw new Error(`Reviewed recovery runtime contains a group/world-writable entry: ${source}`);
	}
	if (info.isDirectory()) {
		for (const name of readdirSync(source).sort()) validateRegularTree(join(source, name), root);
	}
}

function readRegularFileNoFollow(source) {
	const before = lstatSync(source);
	if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1) {
		throw new Error(`Reviewed recovery runtime contains a link or special entry: ${source}`);
	}
	const descriptor = openSync(source, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
	try {
		const opened = fstatSync(descriptor);
		if (!opened.isFile() || opened.nlink !== 1 || opened.dev !== before.dev || opened.ino !== before.ino) {
			throw new Error(`Reviewed recovery runtime changed while being copied: ${source}`);
		}
		const bytes = readFileSync(descriptor);
		const after = fstatSync(descriptor);
		if (after.size !== bytes.byteLength || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs) {
			throw new Error(`Reviewed recovery runtime changed while being copied: ${source}`);
		}
		return { bytes, info: opened };
	} finally {
		closeSync(descriptor);
	}
}

function copyRegularTree(source, destination, expectedFiles, prefix) {
	const info = lstatSync(source);
	if (info.isSymbolicLink() || (!info.isDirectory() && !info.isFile()) || (info.isFile() && info.nlink !== 1)) {
		throw new Error(`Reviewed recovery runtime contains a link or special entry: ${source}`);
	}
	if (info.isDirectory()) {
		mkdirSync(destination, { recursive: true, mode: process.platform === "win32" ? 0o700 : info.mode & 0o777 });
		if (process.platform !== "win32") chmodSync(destination, info.mode & 0o777);
		for (const name of readdirSync(source).sort()) {
			copyRegularTree(join(source, name), join(destination, name), expectedFiles, `${prefix}/${name}`);
		}
		return;
	}
	const expected = expectedFiles.get(prefix);
	if (!expected) throw new Error(`Reviewed recovery runtime gained an undeclared file while being copied: ${prefix}`);
	const { bytes, info: opened } = readRegularFileNoFollow(source);
	if (createHash("sha256").update(bytes).digest("hex") !== expected.sha256) {
		throw new Error(`Reviewed recovery runtime changed while being copied: ${prefix}`);
	}
	mkdirSync(resolve(destination, ".."), { recursive: true, mode: 0o700 });
	writeFileSync(destination, bytes, { flag: "wx", mode: process.platform === "win32" ? 0o600 : opened.mode & 0o777 });
	if (process.platform !== "win32") chmodSync(destination, opened.mode & 0o777);
}

function sha256File(path) {
	return createHash("sha256").update(readFileSync(path)).digest("hex");
}

function safeManifestPath(value, pattern) {
	return typeof value === "string" && pattern.test(value) && !value.includes("\\") && !value.split("/").some((part) => part === "" || part === "." || part === "..");
}

function regularInventory(root, prefix) {
	const rows = [];
	function visit(directory, relativePrefix) {
		for (const name of readdirSync(directory).sort()) {
			const absolute = join(directory, name);
			const relativePath = relativePrefix ? `${relativePrefix}/${name}` : name;
			const info = lstatSync(absolute);
			if (info.isDirectory()) visit(absolute, relativePath);
			else rows.push({ path: `${prefix}/${relativePath}`, sha256: sha256File(absolute) });
		}
	}
	visit(root, "");
	return rows;
}

function runtimeInventory(root) {
	const rows = [];
	function visit(directory, relativePrefix) {
		for (const name of readdirSync(directory).sort()) {
			if (relativePrefix === "" && isRuntimeOutput(name)) continue;
			const absolute = join(directory, name);
			const relativePath = relativePrefix ? `${relativePrefix}/${name}` : name;
			const info = lstatSync(absolute);
			if (info.isDirectory()) visit(absolute, relativePath);
			else rows.push({ path: relativePath, sha256: sha256File(absolute) });
		}
	}
	visit(root, "");
	return rows;
}

function verifyDeclaredInventory(source, deployment) {
	if (!Array.isArray(deployment.migrations) || !Array.isArray(deployment.artifacts)) {
		throw new Error("Reviewed recovery runtime manifest has no migration or artifact inventory");
	}
	const migrations = deployment.migrations.map((entry) => {
		if (!entry || !safeManifestPath(entry.name, /^\d{14}_[a-z0-9_]+\.sql$/) || !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "")) {
			throw new Error("Reviewed recovery runtime has an invalid migration inventory entry");
		}
		return { name: entry.name, sha256: entry.sha256 };
	});
	const actualMigrations = readdirSync(join(source, "migrations")).sort().map((name) => {
		if (!safeManifestPath(name, /^\d{14}_[a-z0-9_]+\.sql$/)) throw new Error("Reviewed recovery runtime has an undeclared migration path");
		return { name, sha256: sha256File(join(source, "migrations", name)) };
	});
	if (new Set(migrations.map((entry) => entry.name)).size !== migrations.length || JSON.stringify(migrations) !== JSON.stringify(actualMigrations)) {
		throw new Error("Reviewed recovery runtime migration inventory differs from deployment.json");
	}

	const artifactPattern = /^(?:auth-templates|backup|dashboard|ingress|maintenance|volumes\/functions)\/[A-Za-z0-9._/-]+$/;
	const artifacts = deployment.artifacts.map((entry) => {
		if (!entry || !safeManifestPath(entry.path, artifactPattern) || !/^[a-f0-9]{64}$/.test(entry.sha256 ?? "")) {
			throw new Error("Reviewed recovery runtime has an invalid artifact inventory entry");
		}
		return { path: entry.path, sha256: entry.sha256 };
	}).sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
	if (new Set(artifacts.map((entry) => entry.path)).size !== artifacts.length) throw new Error("Reviewed recovery runtime artifact inventory contains duplicates");
	const actualArtifacts = [
		...regularInventory(join(source, "auth-templates"), "auth-templates"),
		...regularInventory(join(source, "backup"), "backup"),
		...regularInventory(join(source, "dashboard"), "dashboard"),
		...regularInventory(join(source, "ingress"), "ingress"),
		...regularInventory(join(source, "maintenance"), "maintenance"),
		...regularInventory(join(source, "volumes", "functions"), "volumes/functions"),
	].sort((left, right) => left.path < right.path ? -1 : left.path > right.path ? 1 : 0);
	if (JSON.stringify(artifacts) !== JSON.stringify(actualArtifacts)) {
		throw new Error("Reviewed recovery runtime artifact inventory differs from deployment.json");
	}
}

export function inspectReviewedRuntime(sourcePath, { sourceCommit }) {
	const source = resolve(sourcePath);
	const rootInfo = lstatSync(source);
	if (!rootInfo.isDirectory() || rootInfo.isSymbolicLink()) throw new Error("Reviewed recovery runtime must be a real directory");
	if (!samePath(realpathSync(source), source)) throw new Error("Reviewed recovery runtime path contains a symbolic-link ancestor");
	if (!/^[a-f0-9]{40,64}$/.test(sourceCommit ?? "")) throw new Error("Backup has no valid source commit for reviewed runtime binding");
	const names = readdirSync(source).sort();
	for (const name of REQUIRED_RUNTIME_ENTRIES) {
		if (!names.includes(name)) throw new Error(`Reviewed recovery runtime is missing ${name}`);
	}
	const unexpected = names.filter((name) => !ALLOWED_RUNTIME_ENTRIES.has(name) && !isRuntimeOutput(name));
	if (unexpected.length > 0) throw new Error(`Reviewed recovery runtime contains unexpected root entries: ${unexpected.join(", ")}`);
	for (const name of names) {
		if (SMOKE_EVIDENCE_ENTRY.test(name)) {
			const evidence = lstatSync(join(source, name));
			if (!evidence.isFile() || evidence.isSymbolicLink()) throw new Error(`Reviewed recovery runtime ${name} is not a regular file`);
		} else if (name === UPGRADE_STATE_ENTRY) {
			const state = lstatSync(join(source, name));
			if (!state.isDirectory() || state.isSymbolicLink()) throw new Error(`Reviewed recovery runtime ${name} is not a real directory`);
		} else if (name !== "health") validateRegularTree(join(source, name), source);
	}
	let deployment;
	const deploymentBytes = readFileSync(join(source, "deployment.json"));
	try {
		deployment = JSON.parse(deploymentBytes.toString("utf8"));
	} catch {
		throw new Error("Reviewed recovery runtime has an invalid deployment manifest");
	}
	if (
		deployment.schema_version !== 1 || deployment.mode !== "self-hosted" || deployment.source_has_changes !== false ||
		deployment.source_commit !== sourceCommit
	) {
		throw new Error("Reviewed recovery runtime is dirty, incompatible, or not bound to the backup source commit");
	}
	verifyDeclaredInventory(source, deployment);
	const files = runtimeInventory(source);
	return {
		source,
		deployment,
		files,
		runtime_tree_sha256: createHash("sha256").update(JSON.stringify(files)).digest("hex"),
		runtime_deployment_sha256: createHash("sha256").update(deploymentBytes).digest("hex"),
		source_commit: sourceCommit,
	};
}

export function inspectAuthenticatedInstallation(sourcePath, { sourceCommit, expectedTreeSha256, reviewedDeployment }) {
	if (!/^[a-f0-9]{64}$/.test(expectedTreeSha256 ?? "")) throw new Error("Backup has no authenticated installation runtime digest");
	const installed = inspectReviewedRuntime(sourcePath, { sourceCommit });
	if (installed.runtime_tree_sha256 !== expectedTreeSha256) throw new Error("Authenticated installation configuration differs from the backup manifest");
	for (const field of ["mode", "development", "upstream_sha"]) {
		if (installed.deployment[field] !== reviewedDeployment[field]) throw new Error(`Authenticated installation ${field} differs from the reviewed runtime`);
	}
	for (const field of ["migrations", "artifacts"]) {
		if (JSON.stringify(installed.deployment[field]) !== JSON.stringify(reviewedDeployment[field])) {
			throw new Error(`Authenticated installation ${field} differ from the reviewed runtime`);
		}
	}
	return installed;
}

export function copyReviewedRuntime(sourcePath, destinationPath, { sourceCommit }) {
	const source = resolve(sourcePath);
	const destination = resolve(destinationPath);
	if (inside(destination, source) || inside(source, destination)) throw new Error("Reviewed recovery runtime and output must be separate directories");
	const inspected = inspectReviewedRuntime(source, { sourceCommit });
	const expectedFiles = new Map(inspected.files.map((entry) => [entry.path, entry]));
	const names = readdirSync(source).sort();
	for (const name of names) {
		if (SMOKE_EVIDENCE_ENTRY.test(name) || name === UPGRADE_STATE_ENTRY) continue;
		if (name === "health") {
			const health = lstatSync(join(source, name));
			if (!health.isDirectory() || health.isSymbolicLink()) throw new Error("Reviewed recovery runtime health path is not a real directory");
			mkdirSync(join(destination, name), { recursive: true, mode: 0o755 });
			continue;
		}
		copyRegularTree(join(source, name), join(destination, name), expectedFiles, name);
	}
	const copied = inspectReviewedRuntime(destination, { sourceCommit });
	if (copied.runtime_tree_sha256 !== inspected.runtime_tree_sha256) {
		throw new Error("Reviewed recovery runtime changed while being copied");
	}
	return inspected;
}
