#!/usr/bin/env node
// Offsite transport for authenticated AIDR backups. A backup only becomes
// visible after every object has been copied and COMMITTED.json is published.
// Recovery keys are read locally and are never uploaded to the target.
import { createHash, randomBytes } from "node:crypto";
import {
	constants as fsConstants,
	createReadStream,
	existsSync,
} from "node:fs";
import {
	access,
	chmod,
	lstat,
	mkdir,
	mkdtemp,
	opendir,
	open,
	readFile,
	realpath,
	rename,
	rm,
	rmdir,
	stat,
	writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { spawn } from "node:child_process";

const REQUIRED_FILES = [
	"backup.json",
	"database.tar.gz.enc",
	"storage.tar.gz.enc",
	"installation.tar.gz.enc",
];
const COMMIT_FILE = "COMMITTED.json";
const BACKUP_ID = /^[a-f0-9]{64}$/;
const SOURCE_COMMIT = /^[a-f0-9]{40,64}$/;
const MAX_COMMAND_OUTPUT = 4 * 1024 * 1024;
const RETRIES = 4;
const ABANDONED_TEMP_AGE_MS = 24 * 60 * 60 * 1000;
const SPOOL_BACKUP = /^\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[a-f0-9]{10}$/;
const FILESYSTEM_STAGING = /^\.staging-[a-f0-9]{64}-[a-f0-9]{12}$/;
const TEMP_OWNER = "AIDR temporary backup v1\n";
const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));

function sleep(milliseconds) {
	return new Promise((done) => setTimeout(done, milliseconds));
}

function within(child, parent) {
	const normalize = (value) => process.platform === "win32" ? value.toLowerCase() : value;
	const normalizedChild = normalize(child);
	const normalizedParent = normalize(parent);
	const prefix = normalizedParent.endsWith(sep) ? normalizedParent : `${normalizedParent}${sep}`;
	return normalizedChild === normalizedParent || normalizedChild.startsWith(prefix);
}

function assertSeparate(child, parent, message) {
	if (within(child, parent) || within(parent, child)) throw new Error(message);
}

async function sha256(path) {
	const hash = createHash("sha256");
	for await (const chunk of createReadStream(path)) hash.update(chunk);
	return hash.digest("hex");
}

async function regularFile(path) {
	const info = await lstat(path);
	if (!info.isFile() || info.isSymbolicLink()) throw new Error(`Expected a regular backup file: ${basename(path)}`);
	return info;
}

async function canonicalExisting(path, label) {
	const resolved = resolve(path);
	const real = await realpath(resolved);
	if (!within(resolved, real) || !within(real, resolved)) throw new Error(`${label} path contains a symbolic-link ancestor`);
	return real;
}

async function canonicalNew(path, label) {
	const resolved = resolve(path);
	const parent = await canonicalExisting(dirname(resolved), `${label} parent`);
	const candidate = join(parent, basename(resolved));
	if (!within(candidate, parent) || candidate === parent) throw new Error(`${label} escaped its parent`);
	return candidate;
}

export async function assertPrivateRecoveryKey(path, { source = false } = {}) {
	const info = await lstat(path);
	if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error("Recovery key must be a regular non-linked file");
	if (process.platform !== "win32") {
		const credentialRoot = process.env.CREDENTIALS_DIRECTORY ? resolve(process.env.CREDENTIALS_DIRECTORY) : null;
		const credentialCopy = !source && credentialRoot && within(path, credentialRoot);
		const expectedMode = credentialCopy ? 0o400 : 0o600;
		const expectedUid = source ? 0 : (typeof process.geteuid === "function" ? process.geteuid() : info.uid);
		if ((info.mode & 0o777) !== expectedMode || info.uid !== expectedUid) {
			throw new Error(`Recovery key must be owned by ${source ? "root" : "the service account"} with mode ${expectedMode.toString(8)}`);
		}
	}
}

function parseDate(value, field) {
	if (typeof value !== "string" || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/.test(value)) {
		throw new Error(`Invalid ${field}`);
	}
	const timestamp = Date.parse(value);
	if (!Number.isFinite(timestamp)) throw new Error(`Invalid ${field}`);
	return timestamp;
}

function readBackupPayload(text) {
	let envelope;
	try {
		envelope = JSON.parse(text);
	} catch {
		throw new Error("Invalid backup manifest JSON");
	}
	if (!envelope || typeof envelope.payload !== "string" || typeof envelope.hmac_sha256 !== "string") {
		throw new Error("Invalid authenticated backup envelope");
	}
	let payload;
	try {
		payload = JSON.parse(envelope.payload);
	} catch {
		throw new Error("Invalid authenticated backup payload");
	}
	if (payload.schema_version !== 1 || payload.type !== "aidr-cold-volumes") {
		throw new Error("Unsupported backup payload");
	}
	const started = parseDate(payload.started_at, "backup started_at");
	const completed = parseDate(payload.completed_at, "backup completed_at");
	if (started > completed) throw new Error("Backup recovery point is later than archive completion");
	return payload;
}

async function sourceInventory(backup) {
	const root = resolve(backup);
	const backupJson = join(root, "backup.json");
	const payload = readBackupPayload(await readFile(backupJson, "utf8"));
	const objects = [];
	for (const name of REQUIRED_FILES) {
		const path = join(root, name);
		const info = await regularFile(path);
		objects.push({ name, bytes: info.size, sha256: await sha256(path) });
	}
	return {
		root,
		backupId: objects.find((entry) => entry.name === "backup.json").sha256,
		completedAt: payload.completed_at,
		objects,
	};
}

function safePrefix(prefix) {
	return (
		typeof prefix === "string" &&
		prefix.length >= 3 &&
		prefix.length <= 500 &&
		/^[A-Za-z0-9][A-Za-z0-9._/-]*[A-Za-z0-9]$/.test(prefix) &&
		!prefix.includes("..") &&
		!prefix.includes("//")
	);
}

export function parseTarget(value) {
	if (typeof value !== "string" || value.trim() !== value || value.length === 0) throw new Error("A backup target is required");
	if (value.startsWith("s3://")) {
		const match = value.match(/^s3:\/\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\/(.+)$/);
		if (!match || !safePrefix(match[2])) {
			throw new Error("S3 target must include a valid bucket and a non-root scoped prefix");
		}
		return { kind: "s3", bucket: match[1], prefix: match[2].replace(/\/$/, ""), display: `s3://${match[1]}/${match[2].replace(/\/$/, "")}` };
	}
	let path = value;
	if (value.startsWith("file://")) {
		let url;
		try {
			url = new URL(value);
		} catch {
			throw new Error("Invalid file target URL");
		}
		if (url.hostname && url.hostname !== "localhost") throw new Error("Remote file URL hosts are not supported");
		path = decodeURIComponent(url.pathname);
		if (process.platform === "win32" && /^\/[A-Za-z]:\//.test(path)) path = path.slice(1);
	}
	if (!isAbsolute(path)) throw new Error("Filesystem target must be an absolute path");
	const root = resolve(path);
	if (root === resolve(root, sep)) throw new Error("Filesystem target cannot be a volume root");
	return { kind: "filesystem", root, display: root };
}

function parseFilesystemMountIdentity(value) {
	if (typeof value !== "string" || value.length === 0 || value.trim() !== value) {
		throw new Error("Filesystem targets require AIDR_BACKUP_FILESYSTEM_MOUNT_IDENTITY as UUID=<uuid> or SOURCE=<source>");
	}
	const match = value.match(/^(UUID|SOURCE)=(.+)$/);
	if (!match || match[2].length > 500 || /[\r\n\0]/.test(match[2])) {
		throw new Error("Filesystem mount identity must be UUID=<uuid> or SOURCE=<source>");
	}
	return { kind: match[1].toLowerCase(), value: match[2] };
}

async function findmnt(path) {
	if (process.platform !== "linux") throw new Error("Filesystem offsite targets require Linux findmnt mount verification");
	const output = await run("findmnt", ["--json", "--target", path, "--output", "TARGET,UUID,SOURCE,FSTYPE"]);
	let document;
	try { document = JSON.parse(output); } catch { throw new Error("findmnt returned invalid mount metadata"); }
	if (!Array.isArray(document.filesystems) || document.filesystems.length !== 1) {
		throw new Error("findmnt did not identify exactly one filesystem mount");
	}
	const mount = document.filesystems[0];
	return {
		target: mount.target,
		uuid: mount.uuid ?? "",
		source: mount.source ?? "",
		fstype: mount.fstype ?? "",
	};
}

export async function verifyFilesystemMountIdentity(root, configuredIdentity, probe = findmnt) {
	const expected = parseFilesystemMountIdentity(configuredIdentity);
	const [targetMount, hostRootMount] = await Promise.all([probe(root), probe(sep)]);
	if (!targetMount || typeof targetMount.target !== "string" || !isAbsolute(targetMount.target)) {
		throw new Error("findmnt did not return an absolute target mountpoint");
	}
	const mountpoint = resolve(targetMount.target);
	if (!within(resolve(root), mountpoint)) throw new Error("Filesystem target is not on the reported mountpoint");
	if (mountpoint === resolve(mountpoint, sep)) throw new Error("Filesystem target must not use the host root filesystem as offsite storage");
	const actual = targetMount[expected.kind];
	if (typeof actual !== "string" || actual.length === 0 || (expected.kind === "uuid" ? actual.toLowerCase() !== expected.value.toLowerCase() : actual !== expected.value)) {
		throw new Error(`Filesystem mount ${expected.kind.toUpperCase()} does not match the configured offsite identity`);
	}
	if (!hostRootMount || typeof hostRootMount.source !== "string" || typeof hostRootMount.uuid !== "string" || (!hostRootMount.source && !hostRootMount.uuid)) {
		throw new Error("findmnt could not verify the host root filesystem identity");
	}
	const sharesRootUuid = Boolean(targetMount.uuid && hostRootMount.uuid) && targetMount.uuid.toLowerCase() === hostRootMount.uuid.toLowerCase();
	const sharesRootSource = Boolean(targetMount.source && hostRootMount.source) && targetMount.source === hostRootMount.source;
	if (sharesRootUuid || sharesRootSource) throw new Error("Filesystem offsite target shares the host root filesystem failure domain");
}

function validateKeyReference(value) {
	if (typeof value !== "string" || !/^[a-z][a-z0-9+.-]*:(?:\/\/)?[A-Za-z0-9][A-Za-z0-9._~:/-]{1,500}$/.test(value)) {
		throw new Error("--key-reference must identify the separately held recovery key without containing the key");
	}
	if (/^[a-f0-9]{64}$/i.test(value) || /(?:secret|password|private)[=:]/i.test(value)) {
		throw new Error("--key-reference appears to contain key material");
	}
	return value;
}

function retentionPolicy(days, mode, now = Date.now()) {
	const value = Number(days);
	if (!Number.isInteger(value) || value < 1 || value > 36500) throw new Error("--retention-days must be an integer from 1 to 36500");
	const normalizedMode = mode ? String(mode).toUpperCase() : "METADATA_ONLY";
	if (!["METADATA_ONLY", "GOVERNANCE", "COMPLIANCE"].includes(normalizedMode)) throw new Error("Object lock mode must be GOVERNANCE or COMPLIANCE");
	return {
		days: value,
		mode: normalizedMode,
		retain_until: new Date(now + value * 86400 * 1000).toISOString(),
		native_lock_requested: normalizedMode !== "METADATA_ONLY",
	};
}

async function run(exe, args, options = {}) {
	let lastError;
	const attempts = options.retries ?? 1;
	for (let attempt = 1; attempt <= attempts; attempt += 1) {
		try {
			return await new Promise((done, fail) => {
				const child = spawn(exe, args, {
					cwd: options.cwd,
					env: options.env ?? process.env,
					stdio: ["ignore", "pipe", "pipe"],
					windowsHide: true,
				});
				let stdout = "";
				let stderrBytes = 0;
				child.stdout.setEncoding("utf8");
				child.stdout.on("data", (chunk) => {
					stdout += chunk;
					if (Buffer.byteLength(stdout) > MAX_COMMAND_OUTPUT) child.kill();
				});
				child.stderr.on("data", (chunk) => {
					stderrBytes += chunk.length;
					if (stderrBytes > MAX_COMMAND_OUTPUT) child.kill();
				});
				child.once("error", fail);
				child.once("close", (code) => {
					if (code === 0 && Buffer.byteLength(stdout) <= MAX_COMMAND_OUTPUT) done(stdout.trim());
					else fail(new Error(`${basename(exe)} operation failed (exit ${code ?? "unknown"}); no provider output was printed`));
				});
			});
		} catch (error) {
			lastError = error;
			if (attempt < attempts) await sleep(250 * 2 ** (attempt - 1));
		}
	}
	throw lastError;
}

async function verifyEncryptedBackup(backup, keyFile) {
	await run(process.execPath, [join(SCRIPT_DIR, "deployment-backup.mjs"), "verify", "--backup", backup, "--key-file", keyFile]);
}

async function atomicJson(path, value, mode = 0o600) {
	await mkdir(dirname(path), { recursive: true, mode: 0o700 });
	const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
	try {
		const handle = await open(temporary, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
		try {
			await handle.writeFile(`${JSON.stringify(value, null, 2)}\n`);
			await handle.sync();
		} finally {
			await handle.close();
		}
		await chmod(temporary, mode);
		await rename(temporary, path);
		await syncDirectory(dirname(path));
	} catch (error) {
		await rm(temporary, { force: true });
		throw error;
	}
}

async function syncDirectory(path) {
	try {
		const directory = await open(path, "r");
		try { await directory.sync(); } finally { await directory.close(); }
	} catch (error) {
		// Windows does not expose directory fsync. File fsync and atomic rename are
		// still used; Unix platforms must successfully persist the directory entry.
		if (process.platform !== "win32") throw error;
	}
}

function validateCommit(commit, expectedId) {
	if (
		!commit ||
		commit.schema_version !== 1 ||
		commit.type !== "aidr-offsite-backup" ||
		commit.backup_id !== expectedId ||
		!BACKUP_ID.test(commit.backup_id) ||
		!Array.isArray(commit.objects) ||
		commit.objects.length !== REQUIRED_FILES.length ||
		new Set(commit.objects.map((entry) => entry.name)).size !== REQUIRED_FILES.length ||
		!REQUIRED_FILES.every((name) => commit.objects.some((entry) => entry.name === name))
	) throw new Error("Invalid or incomplete offsite commit marker");
	parseDate(commit.completed_at, "commit completed_at");
	parseDate(commit.published_at, "commit published_at");
	if (
		!commit.retention ||
		!Number.isInteger(commit.retention.days) ||
		commit.retention.days < 1 ||
		commit.retention.days > 36500 ||
		!["METADATA_ONLY", "GOVERNANCE", "COMPLIANCE"].includes(commit.retention.mode) ||
		typeof commit.retention.native_lock_requested !== "boolean"
	) throw new Error("Invalid offsite retention metadata");
	parseDate(commit.retention.retain_until, "commit retention deadline");
	for (const entry of commit.objects) {
		if (!REQUIRED_FILES.includes(entry.name) || !Number.isSafeInteger(entry.bytes) || entry.bytes < 1 || !BACKUP_ID.test(entry.sha256)) {
			throw new Error("Invalid offsite object inventory");
		}
	}
	return commit;
}

function makeCommit(inventory, target, keyReference, retention) {
	return {
		schema_version: 1,
		type: "aidr-offsite-backup",
		backup_id: inventory.backupId,
		completed_at: inventory.completedAt,
		published_at: new Date().toISOString(),
		target_kind: target.kind,
		key_reference: keyReference,
		retention,
		objects: inventory.objects,
	};
}

async function copyAndSync(source, destination, expected) {
	const sourceHandle = await open(source, fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0));
	let destinationHandle;
	try {
		const opened = await sourceHandle.stat();
		if (!opened.isFile() || opened.nlink !== 1 || opened.size !== expected.bytes) throw new Error("Filesystem copy verification failed: source changed");
		destinationHandle = await open(destination, fsConstants.O_CREAT | fsConstants.O_EXCL | fsConstants.O_WRONLY, 0o600);
		const buffer = Buffer.allocUnsafe(1024 * 1024);
		let position = 0;
		while (position < opened.size) {
			const { bytesRead } = await sourceHandle.read(buffer, 0, Math.min(buffer.length, opened.size - position), position);
			if (bytesRead === 0) throw new Error("Filesystem copy verification failed: source truncated");
			let written = 0;
			while (written < bytesRead) {
				const result = await destinationHandle.write(buffer, written, bytesRead - written, position + written);
				if (result.bytesWritten === 0) throw new Error("Filesystem copy verification failed: destination write stalled");
				written += result.bytesWritten;
			}
			position += bytesRead;
		}
		await destinationHandle.sync();
		const current = await lstat(source);
		if (!current.isFile() || current.isSymbolicLink() || current.nlink !== 1 || current.dev !== opened.dev || current.ino !== opened.ino || current.size !== opened.size || current.mtimeMs !== opened.mtimeMs) {
			throw new Error("Filesystem copy verification failed: source changed during copy");
		}
	} catch (error) {
		await rm(destination, { force: true });
		throw error;
	} finally {
		await destinationHandle?.close();
		await sourceHandle.close();
	}
	await chmod(destination, 0o600);
	const info = await stat(destination);
	if (info.size !== expected.bytes || await sha256(destination) !== expected.sha256) {
		await rm(destination, { force: true });
		throw new Error("Filesystem copy verification failed");
	}
}

async function checkedDirectory(path, create = false) {
	if (create) await mkdir(path, { recursive: true, mode: 0o700 });
	const info = await lstat(path);
	if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Filesystem target contains a symbolic link or is not a directory");
	await canonicalExisting(path, "Filesystem directory");
}

async function cleanupOldDirectories(root, pattern, now = Date.now(), preserveCompleted = false) {
	if (!existsSync(root)) return 0;
	await checkedDirectory(root);
	let removed = 0;
	const directory = await opendir(root);
	for await (const entry of directory) {
		if (!entry.isDirectory() || !pattern.test(entry.name)) continue;
		const path = join(root, entry.name);
		const info = await lstat(path);
		if (!info.isDirectory() || info.isSymbolicLink() || info.mtimeMs > now - ABANDONED_TEMP_AGE_MS) continue;
		if (preserveCompleted && existsSync(join(path, "backup.json"))) continue;
		const marker = `${path}.aidr-owned`;
		let markerInfo;
		try { markerInfo = await lstat(marker); } catch (error) { if (error.code === "ENOENT") continue; throw error; }
		if (!markerInfo.isFile() || markerInfo.isSymbolicLink() || markerInfo.nlink !== 1 || markerInfo.mtimeMs > now - ABANDONED_TEMP_AGE_MS || await readFile(marker, "utf8") !== TEMP_OWNER) continue;
		await rm(path, { recursive: true });
		await rm(marker);
		removed += 1;
	}
	return removed;
}

export async function cleanupAbandonedSpool(root, now = Date.now()) {
	return cleanupOldDirectories(resolve(root), SPOOL_BACKUP, now, true);
}

async function readFilesystemCommit(target, backupId) {
	await checkedDirectory(target.root);
	await checkedDirectory(join(target.root, backupId));
	const path = join(target.root, backupId, COMMIT_FILE);
	const info = await lstat(path);
	if (!info.isFile() || info.isSymbolicLink()) throw new Error("Offsite commit marker must be a regular file");
	return validateCommit(JSON.parse(await readFile(path, "utf8")), backupId);
}

async function uploadFilesystem(target, inventory, commit, guard = async () => {}) {
	await guard();
	await checkedDirectory(target.root);
	await cleanupOldDirectories(target.root, FILESYSTEM_STAGING);
	const final = join(target.root, inventory.backupId);
	if (existsSync(final)) {
		const existing = await readFilesystemCommit(target, inventory.backupId);
		if (JSON.stringify(existing.objects) !== JSON.stringify(inventory.objects) || existing.key_reference !== commit.key_reference) {
			throw new Error("Existing offsite backup does not match this source and key reference");
		}
		if (existing.retention.mode !== commit.retention.mode || existing.retention.days !== commit.retention.days) {
			throw new Error("Existing offsite backup retention differs from the requested policy");
		}
		return existing;
	}
	const staging = join(target.root, `.staging-${inventory.backupId}-${randomBytes(6).toString("hex")}`);
	await mkdir(staging, { mode: 0o700 });
	const owner = `${staging}.aidr-owned`;
	let ownerCreated = false;
	try {
		await writeFile(owner, TEMP_OWNER, { mode: 0o600, flag: "wx" });
		ownerCreated = true;
		for (const entry of inventory.objects) await copyAndSync(join(inventory.root, entry.name), join(staging, entry.name), entry);
		await guard();
		await atomicJson(join(staging, COMMIT_FILE), commit);
		await syncDirectory(staging);
		await rename(staging, final);
		await syncDirectory(target.root);
	} catch (error) {
		await rm(staging, { recursive: true, force: true });
		throw error;
	} finally {
		if (ownerCreated) await rm(owner, { force: true });
	}
	return commit;
}

function s3BaseArgs(options) {
	const args = [];
	if (options.endpoint) args.push("--endpoint-url", options.endpoint);
	if (options.region) args.push("--region", options.region);
	args.push("--no-cli-pager");
	return args;
}

function s3Key(target, ...parts) {
	return [target.prefix, ...parts].join("/");
}

function lockArgs(retention) {
	return retention.native_lock_requested
		? ["--object-lock-mode", retention.mode, "--object-lock-retain-until-date", retention.retain_until]
		: [];
}

async function aws(options, command, args, retries = RETRIES) {
	const text = await run(options.awsCli, [...options.awsCliArguments, ...s3BaseArgs(options), "s3api", command, ...args, "--output", "json"], { retries });
	if (!text) return {};
	try { return JSON.parse(text); } catch { throw new Error("S3 client returned invalid JSON"); }
}

async function awsS3(options, args, retries = RETRIES) {
	await run(options.awsCli, [...options.awsCliArguments, ...s3BaseArgs(options), "s3", ...args, "--only-show-errors"], { retries });
}

function s3Metadata(backupId, sha, bytes, keyReference, retention) {
	const keyRefHash = createHash("sha256").update(keyReference).digest("hex");
	return `aidr-backup-id=${backupId},sha256=${sha},bytes=${bytes},key-reference-sha256=${keyRefHash},retention-days=${retention.days},retain-until=${retention.retain_until}`;
}

async function s3Head(target, key, expected, options) {
	const head = await aws(options, "head-object", ["--bucket", target.bucket, "--key", key]);
	if (Number(head.ContentLength) !== expected.bytes || head.Metadata?.sha256 !== expected.sha256 || head.Metadata?.["aidr-backup-id"] !== expected.backupId) {
		throw new Error("S3 object metadata verification failed");
	}
	return head;
}

async function verifyS3Retention(target, key, retention, options) {
	if (!retention.native_lock_requested) return;
	const received = await aws(options, "get-object-retention", ["--bucket", target.bucket, "--key", key]);
	const deadline = received.Retention?.RetainUntilDate;
	const receivedUntil = typeof deadline === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/.test(deadline)
		? Date.parse(deadline) : NaN;
	if (received.Retention?.Mode !== retention.mode || !Number.isFinite(receivedUntil) || receivedUntil < Date.parse(retention.retain_until)) {
		throw new Error("S3 Object Lock retention verification failed");
	}
}

async function s3PutAndHead(target, key, source, expected, options, retention, finalObject = false) {
	if (finalObject) {
		await aws(options, "put-object", [
			"--bucket", target.bucket,
			"--key", key,
			"--body", source,
			"--metadata", s3Metadata(expected.backupId, expected.sha256, expected.bytes, options.keyReference, retention),
			...lockArgs(retention),
		]);
	} else {
		// High-level cp performs multipart upload for archives above PutObject's
		// size ceiling. Final visibility is still controlled by COMMITTED.json.
		await awsS3(options, [
			"cp", source, `s3://${target.bucket}/${key}`,
			"--metadata", s3Metadata(expected.backupId, expected.sha256, expected.bytes, options.keyReference, retention),
		]);
	}
	await s3Head(target, key, expected, options);
	if (finalObject) await verifyS3Retention(target, key, retention, options);
}

async function s3CopyAndHead(target, sourceKey, destinationKey, expected, options, retention) {
	await awsS3(options, [
		"cp",
		`s3://${target.bucket}/${sourceKey}`,
		`s3://${target.bucket}/${destinationKey}`,
		"--copy-props", "metadata-directive",
	]);
	await s3Head(target, destinationKey, expected, options);
	if (retention.native_lock_requested) {
		await aws(options, "put-object-retention", [
			"--bucket", target.bucket,
			"--key", destinationKey,
			"--retention", `Mode=${retention.mode},RetainUntilDate=${retention.retain_until}`,
		]);
		await verifyS3Retention(target, destinationKey, retention, options);
	}
}

async function s3Download(target, key, destination, options) {
	await aws(options, "get-object", ["--bucket", target.bucket, "--key", key, destination]);
}

async function readS3Commit(target, backupId, options, destinationDirectory) {
	const path = join(destinationDirectory, COMMIT_FILE);
	await s3Download(target, s3Key(target, backupId, COMMIT_FILE), path, options);
	return validateCommit(JSON.parse(await readFile(path, "utf8")), backupId);
}

async function uploadS3(target, inventory, commit, options) {
	// Abandoned S3 staging requires operator-reviewed cleanup; no automatic deletion.
	const markerKey = s3Key(target, inventory.backupId, COMMIT_FILE);
	const matchingKeys = await listS3Keys(target, options, markerKey);
	if (!matchingKeys.includes(markerKey)) {
		return uploadNewS3(target, inventory, commit, options);
	}
	const existingDirectory = await mkdtemp(join(tmpdir(), "aidr-offsite-existing-"));
	try {
		const existing = await readS3Commit(target, inventory.backupId, options, existingDirectory);
		if (JSON.stringify(existing.objects) !== JSON.stringify(inventory.objects) || existing.key_reference !== commit.key_reference) {
			throw new Error("Existing offsite backup does not match this source and key reference");
		}
		if (existing.retention.mode !== commit.retention.mode || existing.retention.days !== commit.retention.days) {
			throw new Error("Existing offsite backup retention differs from the requested policy");
		}
		return existing;
	} finally {
		await rm(existingDirectory, { recursive: true, force: true });
	}
}

async function uploadNewS3(target, inventory, commit, options) {
	const attempt = randomBytes(8).toString("hex");
	const temporaryKeys = [];
	const expectedByName = Object.fromEntries(inventory.objects.map((entry) => [entry.name, { ...entry, backupId: inventory.backupId }]));
	const commitDirectory = await mkdtemp(join(tmpdir(), "aidr-offsite-commit-"));
	try {
		for (const entry of inventory.objects) {
			const key = s3Key(target, ".staging", inventory.backupId, attempt, entry.name);
			temporaryKeys.push(key);
			await s3PutAndHead(target, key, join(inventory.root, entry.name), expectedByName[entry.name], options, commit.retention);
		}
		for (const entry of inventory.objects) {
			await s3CopyAndHead(
				target,
				s3Key(target, ".staging", inventory.backupId, attempt, entry.name),
				s3Key(target, inventory.backupId, entry.name),
				expectedByName[entry.name],
				options,
				commit.retention,
			);
		}
		const commitPath = join(commitDirectory, COMMIT_FILE);
		await writeFile(commitPath, `${JSON.stringify(commit, null, 2)}\n`, { mode: 0o600, flag: "wx" });
		const commitExpected = {
			backupId: inventory.backupId,
			bytes: (await stat(commitPath)).size,
			sha256: await sha256(commitPath),
		};
		const temporaryCommit = s3Key(target, ".staging", inventory.backupId, attempt, COMMIT_FILE);
		temporaryKeys.push(temporaryCommit);
		await s3PutAndHead(target, temporaryCommit, commitPath, commitExpected, options, commit.retention);
		// The small marker uses a single PutObject carrying Object Lock settings,
		// so it cannot become visible as committed before its lock is applied.
		await s3PutAndHead(target, s3Key(target, inventory.backupId, COMMIT_FILE), commitPath, commitExpected, options, commit.retention, true);
	} finally {
		await rm(commitDirectory, { recursive: true, force: true });
		for (const key of temporaryKeys) {
			try { await aws(options, "delete-object", ["--bucket", target.bucket, "--key", key], 1); } catch { /* stale staging data is never a committed backup */ }
		}
	}
	return commit;
}

async function downloadFilesystem(target, backupId, output) {
	await checkedDirectory(target.root);
	const commit = await readFilesystemCommit(target, backupId);
	await mkdir(output, { mode: 0o700 });
	for (const entry of commit.objects) {
		await copyAndSync(join(target.root, backupId, entry.name), join(output, entry.name), entry);
	}
	return commit;
}

async function downloadS3(target, backupId, output, options) {
	await mkdir(output, { mode: 0o700 });
	const commit = await readS3Commit(target, backupId, options, output);
	for (const entry of commit.objects) {
		const path = join(output, entry.name);
		await s3Download(target, s3Key(target, backupId, entry.name), path, options);
		const info = await regularFile(path);
		if (info.size !== entry.bytes || await sha256(path) !== entry.sha256) throw new Error("Downloaded S3 object digest verification failed");
	}
	return commit;
}

async function downloadTarget(target, backupId, output, options) {
	if (!BACKUP_ID.test(backupId)) throw new Error("--backup-id must be the 64 character backup manifest digest");
	if (existsSync(output)) throw new Error("Download output must not already exist");
	return target.kind === "filesystem"
		? downloadFilesystem(target, backupId, output)
		: downloadS3(target, backupId, output, options);
}

async function downloadLatest(target, output, keyFile, expectedSourceCommit, maxAgeMinutes, options, guard = async () => {}) {
	if (!SOURCE_COMMIT.test(expectedSourceCommit ?? "")) throw new Error("--expected-source-commit must be 40 to 64 lowercase hexadecimal characters");
	const maxAge = Number(maxAgeMinutes);
	if (!Number.isSafeInteger(maxAge) || maxAge < 1) throw new Error("--max-age-minutes must be a positive integer");
	if (existsSync(output)) throw new Error("Download output must not already exist");
	const commits = (target.kind === "filesystem" ? await listFilesystemCommits(target) : await listS3Commits(target, options))
		.sort((left, right) => parseDate(right.completed_at, "commit completed_at") - parseDate(left.completed_at, "commit completed_at"));
	const failures = [];
	for (const commit of commits) {
		const completionAge = (Date.now() - parseDate(commit.completed_at, "commit completed_at")) / 60000;
		if (completionAge < 0 || completionAge > maxAge) continue;
		const candidate = `${output}.candidate-${randomBytes(6).toString("hex")}`;
		try {
			await downloadTarget(target, commit.backup_id, candidate, options);
			await verifyEncryptedBackup(candidate, keyFile);
			const payload = await assertAuthenticatedCompletion(candidate, commit);
			if (payload.source_commit !== expectedSourceCommit) throw new Error("Authenticated backup source commit differs from the reviewed candidate");
			const age = (Date.now() - parseDate(payload.started_at, "backup started_at")) / 60000;
			if (age < 0 || age > maxAge) throw new Error("Authenticated recovery point exceeds the required maximum age");
			await guard();
			if (existsSync(output)) throw new Error("Download output must not already exist");
			await rename(candidate, output);
			await syncDirectory(dirname(output));
			return { commit, payload };
		} catch (error) {
			failures.push(`${commit.backup_id}: ${error.message}`);
			await rm(candidate, { recursive: true, force: true });
		}
	}
	throw new Error(`No eligible authenticated backup matched the reviewed candidate${failures.length ? ` (${failures.join("; ")})` : ""}`);
}

async function writeHealth(path, payload) {
	if (!path) return;
	if (parseDate(payload.completed_at, "backup completed_at") > Date.now()) throw new Error("Future-dated backup cannot publish readiness");
	await atomicJson(resolve(path), {
		schema_version: 2,
		status: "ok",
		recovery_point_at: payload.started_at,
		completed_at: payload.completed_at,
		verified_at: new Date().toISOString(),
	}, 0o644);
}

async function writeHealthStatus(path, status, completedAt = new Date().toISOString()) {
	if (!path) return;
	if (!isAbsolute(path)) throw new Error("--health-file must be an absolute path");
	await atomicJson(resolve(path), {
		schema_version: 1,
		status,
		completed_at: completedAt,
		verified_at: new Date().toISOString(),
	}, 0o644);
}

async function verifyRemote(target, backupId, keyFile, healthFile, options, guard = async () => {}) {
	const temporary = await mkdtemp(join(tmpdir(), "aidr-offsite-verify-"));
	const output = join(temporary, "backup");
	try {
		const commit = await downloadTarget(target, backupId, output, options);
		await verifyEncryptedBackup(output, keyFile);
		const payload = await assertAuthenticatedCompletion(output, commit);
		if (target.kind === "s3" && commit.retention.native_lock_requested) {
			for (const name of [...REQUIRED_FILES, COMMIT_FILE]) {
				await verifyS3Retention(target, s3Key(target, backupId, name), commit.retention, options);
			}
		}
		await guard();
		await writeHealth(healthFile, payload);
		return commit;
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
}

async function assertAuthenticatedCompletion(backup, commit) {
	// The commit marker lives on the backup target and is not authenticated by
	// the recovery key. Never use its timestamp for RPO health if it differs
	// from the authenticated manifest inside backup.json.
	const payload = readBackupPayload(await readFile(join(backup, "backup.json"), "utf8"));
	if (payload.completed_at !== commit.completed_at) {
		throw new Error("Offsite commit completion time does not match the authenticated backup manifest");
	}
	return payload;
}

async function listFilesystemCommits(target) {
	if (!existsSync(target.root)) return [];
	await checkedDirectory(target.root);
	const commits = [];
	const directory = await opendir(target.root);
	for await (const entry of directory) {
		if (!entry.isDirectory() || !BACKUP_ID.test(entry.name)) continue;
		try { commits.push(await readFilesystemCommit(target, entry.name)); } catch { /* partial or foreign data is out of scope */ }
	}
	return commits;
}

async function listS3Objects(target, options, prefix) {
	const objects = [];
	let token;
	do {
		const page = await aws(options, "list-objects-v2", [
			"--bucket", target.bucket,
			"--prefix", prefix,
			"--max-keys", "1000",
			...(token ? ["--continuation-token", token] : []),
		]);
		for (const object of page.Contents ?? []) {
			if (typeof object.Key !== "string" || !object.Key.startsWith(prefix)) throw new Error("S3 listing escaped the requested prefix");
			objects.push({ key: object.Key, lastModified: typeof object.LastModified === "string" ? Date.parse(object.LastModified) : null });
		}
		token = page.IsTruncated === true ? page.NextContinuationToken : undefined;
		if (page.IsTruncated === true && typeof token !== "string") throw new Error("S3 listing omitted its continuation token");
	} while (token);
	return objects;
}

async function listS3Keys(target, options, prefix) {
	return (await listS3Objects(target, options, prefix)).map((object) => object.key);
}

async function listS3Versions(target, options, prefix) {
	const versions = [];
	let keyMarker;
	let versionMarker;
	do {
		const page = await aws(options, "list-object-versions", [
			"--bucket", target.bucket,
			"--prefix", prefix,
			"--max-keys", "1000",
			...(keyMarker ? ["--key-marker", keyMarker] : []),
			...(versionMarker ? ["--version-id-marker", versionMarker] : []),
		]);
		for (const [items, deleteMarker] of [[page.Versions ?? [], false], [page.DeleteMarkers ?? [], true]]) {
			for (const item of items) {
				if (typeof item.Key !== "string" || !item.Key.startsWith(prefix) || typeof item.VersionId !== "string" || item.VersionId.length === 0) {
					throw new Error("S3 version listing escaped the requested prefix or omitted a version ID");
				}
				versions.push({ key: item.Key, versionId: item.VersionId, deleteMarker, lastModified: Date.parse(item.LastModified) });
			}
		}
		keyMarker = page.IsTruncated === true ? page.NextKeyMarker : undefined;
		versionMarker = page.IsTruncated === true ? page.NextVersionIdMarker : undefined;
		if (page.IsTruncated === true && (typeof keyMarker !== "string" || typeof versionMarker !== "string")) {
			throw new Error("S3 version listing omitted continuation markers");
		}
	} while (keyMarker);
	return versions;
}

async function s3VersionDisposition(target, version, options, now = Date.now()) {
	if (version.deleteMarker) return { eligible: true, reason: "delete-marker" };
	const head = await aws(options, "head-object", [
		"--bucket", target.bucket,
		"--key", version.key,
		"--version-id", version.versionId,
	]);
	if (head.ObjectLockLegalHoldStatus === "ON") return { eligible: false, reason: "legal-hold" };
	if (head.ObjectLockLegalHoldStatus && head.ObjectLockLegalHoldStatus !== "OFF") throw new Error("S3 returned an invalid legal-hold status");
	const retainUntil = head.ObjectLockRetainUntilDate ? Date.parse(head.ObjectLockRetainUntilDate) : null;
	if (head.ObjectLockRetainUntilDate && !Number.isFinite(retainUntil)) throw new Error("S3 returned an invalid Object Lock deadline");
	if (Number.isFinite(retainUntil) && retainUntil > now) return { eligible: false, reason: "object-lock" };
	return { eligible: true, reason: "expired-or-unlocked" };
}

async function deleteS3Version(target, version, options) {
	await aws(options, "delete-object", [
		"--bucket", target.bucket,
		"--key", version.key,
		"--version-id", version.versionId,
	]);
}

async function listS3Commits(target, options) {
	const prefix = `${target.prefix}/`;
	const keys = await listS3Keys(target, options, prefix);
	const marker = new RegExp(`^${target.prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}\/([a-f0-9]{64})\/${COMMIT_FILE}$`);
	const temporary = await mkdtemp(join(tmpdir(), "aidr-offsite-list-"));
	try {
		const commits = [];
		for (const key of keys) {
			const match = key.match(marker);
			if (!match) continue;
			const directory = join(temporary, match[1]);
			await mkdir(directory);
			commits.push(await readS3Commit(target, match[1], options, directory));
		}
		return commits;
	} finally {
		await rm(temporary, { recursive: true, force: true });
	}
}

async function prune(target, days, apply, options, guard = async () => {}, now = Date.now()) {
	const retention = retentionPolicy(days, "METADATA_ONLY", now);
	const cutoff = now - retention.days * 86400 * 1000;
	const commits = target.kind === "filesystem" ? await listFilesystemCommits(target) : await listS3Commits(target, options);
	const expired = commits.filter((commit) =>
		parseDate(commit.completed_at, "commit completed_at") < cutoff &&
		parseDate(commit.retention.retain_until, "commit retention deadline") <= now,
	);
	const fullyRemoved = [];
	const retained = [];
	let versionsDeleted = 0;
	for (const commit of expired) {
		if (!apply) continue;
		if (target.kind === "filesystem") {
			await guard();
			const candidate = resolve(target.root, commit.backup_id);
			if (!within(candidate, target.root) || candidate === target.root || basename(candidate) !== commit.backup_id) throw new Error("Filesystem prune scope validation failed");
			const info = await lstat(candidate);
			if (!info.isDirectory() || info.isSymbolicLink()) throw new Error("Filesystem prune target is not a regular backup directory");
			const names = [...commit.objects.map((entry) => entry.name), COMMIT_FILE];
			const expected = new Set(names);
			let found = 0;
			for await (const entry of await opendir(candidate)) {
				if (!expected.has(entry.name) || !entry.isFile() || entry.isSymbolicLink()) {
					throw new Error("Filesystem prune refused an unlisted or non-regular backup entry");
				}
				found += 1;
			}
			if (found !== expected.size) throw new Error("Filesystem prune refused an incomplete backup directory");
			for (const name of names) {
				const entry = await lstat(join(candidate, name));
				if (!entry.isFile() || entry.isSymbolicLink() || entry.nlink !== 1) throw new Error("Filesystem prune refused a linked or non-regular backup entry");
			}
			for (const name of names) {
				await guard();
				await rm(join(candidate, name));
			}
			await guard();
			await rmdir(candidate);
			fullyRemoved.push(commit.backup_id);
		} else {
			const prefix = s3Key(target, commit.backup_id, "");
			const markerKey = s3Key(target, commit.backup_id, COMMIT_FILE);
			const versions = await listS3Versions(target, options, prefix);
			const committedKeys = new Set([...commit.objects.map((entry) => s3Key(target, commit.backup_id, entry.name)), markerKey]);
			if (versions.some((version) => !committedKeys.has(version.key))) {
				throw new Error("S3 prune refused an unlisted object version under the backup prefix");
			}
			if (!versions.some((version) => version.key === markerKey && !version.deleteMarker)) {
				throw new Error("S3 prune refused a backup without a versioned commit marker");
			}
			const dispositions = [];
			for (const version of versions) dispositions.push([version, await s3VersionDisposition(target, version, options, now)]);
			const protectedVersions = dispositions.filter(([, disposition]) => !disposition.eligible);
			if (protectedVersions.length > 0) {
				retained.push({ backup_id: commit.backup_id, reasons: [...new Set(protectedVersions.map(([, item]) => item.reason))] });
				continue;
			}
			// Keep the commit marker visible until payload absence is verified, so
			// a silent or partial provider failure remains discoverable next run.
			for (const [version] of dispositions.filter(([version]) => version.key !== markerKey)) {
				await deleteS3Version(target, version, options);
				versionsDeleted += 1;
			}
			if ((await listS3Versions(target, options, prefix)).some((version) => version.key !== markerKey)) {
				throw new Error("S3 prune could not verify removal of every object version");
			}
			for (const [version] of dispositions.filter(([version]) => version.key === markerKey)) {
				await deleteS3Version(target, version, options);
				versionsDeleted += 1;
			}
			if ((await listS3Versions(target, options, prefix)).length > 0) {
				throw new Error("S3 prune could not verify removal of every object version");
			}
			fullyRemoved.push(commit.backup_id);
		}
	}
	return {
		apply,
		retention_days: retention.days,
		candidates: expired.map((commit) => commit.backup_id),
		fully_removed: fullyRemoved,
		retained,
		versions_deleted: versionsDeleted,
		tombstoned: [],
	};
}

function optionsFrom(argv, env) {
	const parsed = parseArgs({
		args: argv,
		allowPositionals: true,
		strict: true,
		options: {
			backup: { type: "string" },
			"backup-id": { type: "string" },
			deployment: { type: "string" },
			spool: { type: "string" },
			output: { type: "string" },
			target: { type: "string" },
			"filesystem-mount-identity": { type: "string" },
			"key-file": { type: "string" },
			"key-source-file": { type: "string" },
			"key-reference": { type: "string" },
			"health-file": { type: "string" },
			"retention-days": { type: "string" },
			"object-lock-mode": { type: "string" },
			"s3-endpoint": { type: "string" },
			"s3-region": { type: "string" },
			"aws-cli": { type: "string" },
			"aws-cli-argument": { type: "string", multiple: true },
			"expected-source-commit": { type: "string" },
			"max-age-minutes": { type: "string" },
			apply: { type: "boolean", default: false },
			"apply-retention": { type: "boolean", default: false },
		},
	});
	return {
		action: parsed.positionals[0],
		backup: parsed.values.backup,
		backupId: parsed.values["backup-id"],
		deployment: parsed.values.deployment ?? env.AIDR_DEPLOYMENT_DIR,
		spool: parsed.values.spool ?? env.AIDR_BACKUP_SPOOL,
		output: parsed.values.output,
		targetValue: parsed.values.target ?? env.AIDR_BACKUP_TARGET,
		filesystemMountIdentity: parsed.values["filesystem-mount-identity"] ?? env.AIDR_BACKUP_FILESYSTEM_MOUNT_IDENTITY,
		keyFile: parsed.values["key-file"] ?? env.AIDR_BACKUP_KEY_FILE,
		keySourceFile: parsed.values["key-source-file"],
		keyReference: parsed.values["key-reference"] ?? env.AIDR_BACKUP_KEY_REFERENCE,
		healthFile: parsed.values["health-file"] ?? env.AIDR_BACKUP_HEALTH_FILE,
		retentionDays: parsed.values["retention-days"] ?? env.AIDR_BACKUP_RETENTION_DAYS,
		objectLockMode: parsed.values["object-lock-mode"] ?? env.AIDR_BACKUP_S3_OBJECT_LOCK_MODE,
		endpoint: parsed.values["s3-endpoint"] ?? env.AIDR_BACKUP_S3_ENDPOINT,
		region: parsed.values["s3-region"] ?? env.AIDR_BACKUP_S3_REGION,
		awsCli: parsed.values["aws-cli"] ?? env.AIDR_AWS_CLI ?? "aws",
		awsCliArguments: parsed.values["aws-cli-argument"] ?? [],
		expectedSourceCommit: parsed.values["expected-source-commit"],
		maxAgeMinutes: parsed.values["max-age-minutes"],
		apply: parsed.values.apply,
		// Retention deletion must be an explicit command-line choice. An
		// environment file must not silently turn a scheduled cycle into deletion.
		applyRetention: parsed.values["apply-retention"],
	};
}

export async function runOffsite(argv, env = process.env, dependencies = {}) {
	const options = optionsFrom(argv, env);
	if (!["upload", "verify", "download", "download-latest", "prune", "cycle"].includes(options.action)) {
		throw new Error("Use upload|verify|download|download-latest|prune|cycle with --target, --key-file and the action-specific paths");
	}
	const reportsHealth = Boolean(options.healthFile) && ["upload", "verify", "download", "download-latest", "cycle"].includes(options.action);
	const attemptStartedAt = new Date().toISOString();
	if (reportsHealth) {
		if (!isAbsolute(options.healthFile)) throw new Error("--health-file must be an absolute path");
		try { await writeHealthStatus(options.healthFile, "running", attemptStartedAt); }
		catch (error) {
			try { await rm(resolve(options.healthFile), { force: true }); } catch { /* absence is safely not ready */ }
			throw error;
		}
	}
	try {
	const target = parseTarget(options.targetValue);
	if (target.kind === "filesystem") {
		if (!existsSync(target.root)) throw new Error("Filesystem target must already exist before the backup job starts");
		await checkedDirectory(target.root);
		target.root = await canonicalExisting(target.root, "Filesystem target");
		await verifyFilesystemMountIdentity(target.root, options.filesystemMountIdentity, dependencies.findmnt ?? findmnt);
	}
	const guardTargetMount = () => target.kind === "filesystem"
		? verifyFilesystemMountIdentity(target.root, options.filesystemMountIdentity, dependencies.findmnt ?? findmnt)
		: Promise.resolve();
	if (target.kind === "s3") {
		if (options.endpoint) {
			let endpoint;
			try { endpoint = new URL(options.endpoint); } catch { throw new Error("Invalid S3 endpoint URL"); }
			if (endpoint.protocol !== "https:" || endpoint.username || endpoint.password || endpoint.search || endpoint.hash) {
				throw new Error("S3 endpoint must use HTTPS and must not contain credentials, a query, or a fragment");
			}
		}
		if (options.region && !/^[A-Za-z0-9][A-Za-z0-9-]{0,62}$/.test(options.region)) throw new Error("Invalid S3 region");
	} else if (options.objectLockMode) {
		throw new Error("Native Object Lock mode is only available for S3-compatible targets");
	}
	let keyFile = options.keyFile ? resolve(options.keyFile) : null;
	if (!["prune"].includes(options.action)) {
		if (!keyFile) throw new Error("--key-file is required to authenticate backups after transfer");
		keyFile = await canonicalExisting(keyFile, "Recovery key");
		await access(keyFile, fsConstants.R_OK);
		await assertPrivateRecoveryKey(keyFile);
		if (options.keySourceFile) {
			const keySource = await canonicalExisting(options.keySourceFile, "Recovery key source");
			await assertPrivateRecoveryKey(keySource, { source: true });
		}
	}
	const s3Options = { ...options, keyReference: options.keyReference ? validateKeyReference(options.keyReference) : null };
	if (["upload", "cycle"].includes(options.action)) {
		if (!s3Options.keyReference) throw new Error("--key-reference is required and must refer to the recovery key held outside the backup target");
		const retention = retentionPolicy(options.retentionDays, options.objectLockMode);
		let backup = options.backup ? resolve(options.backup) : null;
		let cycleBackup = null;
		let cycleBackupIdentity = null;
		let cycleBackupVerified = false;
		try {
			if (options.action === "cycle") {
				if (!options.deployment || !options.spool) throw new Error("cycle requires --deployment and --spool");
				const deployment = await canonicalExisting(options.deployment, "Deployment");
				await mkdir(resolve(options.spool), { recursive: true, mode: 0o700 });
				const spool = await canonicalExisting(options.spool, "Backup spool");
				if (target.kind === "filesystem") assertSeparate(spool, target.root, "The local spool and offsite filesystem target must be separate");
				assertSeparate(keyFile, deployment, "Keep the recovery key outside the deployment");
				assertSeparate(keyFile, spool, "Keep the recovery key outside the local backup spool");
				await cleanupAbandonedSpool(spool);
				backup = join(spool, `${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(5).toString("hex")}`);
				cycleBackup = backup;
				await writeFile(`${backup}.aidr-owned`, TEMP_OWNER, { mode: 0o600, flag: "wx" });
				await run(process.execPath, [join(SCRIPT_DIR, "deployment-backup.mjs"), "backup", "--deployment", deployment, "--output", backup, "--key-file", keyFile, "--recovery-journal", join(spool, "recovery-journal.json"), "--maintenance"]);
				cycleBackupIdentity = await lstat(backup);
				if (!cycleBackupIdentity.isDirectory() || cycleBackupIdentity.isSymbolicLink()) throw new Error("Local backup output is not the completed snapshot directory");
			}
			if (!backup) throw new Error("upload requires --backup");
			backup = await canonicalExisting(backup, "Source backup");
			if (target.kind === "filesystem") {
				assertSeparate(backup, target.root, "Source backup and offsite filesystem target must be separate");
				assertSeparate(keyFile, target.root, "Recovery key must be held outside the offsite target");
			}
			await verifyEncryptedBackup(backup, keyFile);
			const inventory = await sourceInventory(backup);
			const commit = makeCommit(inventory, target, s3Options.keyReference, retention);
			await guardTargetMount();
			const published = target.kind === "filesystem"
				? await uploadFilesystem(target, inventory, commit, guardTargetMount)
				: await uploadS3(target, inventory, commit, s3Options);
			await guardTargetMount();
			await verifyRemote(target, inventory.backupId, keyFile, options.healthFile, s3Options, guardTargetMount);
			cycleBackupVerified = true;
			if (options.action === "cycle") await prune(target, retention.days, options.applyRetention, s3Options, guardTargetMount);
			console.log(JSON.stringify({ status: "ok", backup_id: inventory.backupId, completed_at: published.completed_at, target_kind: target.kind, verified: true }));
			return;
		} finally {
			if (cycleBackup && cycleBackupVerified) {
				const current = await lstat(cycleBackup);
				if (!current.isDirectory() || current.isSymbolicLink() || current.dev !== cycleBackupIdentity.dev || current.ino !== cycleBackupIdentity.ino) {
					throw new Error("Local backup output changed identity and was retained");
				}
				await rm(cycleBackup, { recursive: true, force: true });
				await rm(`${cycleBackup}.aidr-owned`, { force: true });
			} else if (cycleBackup && !existsSync(cycleBackup)) await rm(`${cycleBackup}.aidr-owned`, { force: true });
		}
	}
	if (options.action === "verify") {
		await guardTargetMount();
		const commit = await verifyRemote(target, options.backupId, keyFile, options.healthFile, s3Options, guardTargetMount);
		console.log(JSON.stringify({ status: "ok", backup_id: commit.backup_id, completed_at: commit.completed_at, verified: true }));
		return;
	}
	if (options.action === "download") {
		await guardTargetMount();
		if (!options.output) throw new Error("download requires a new --output directory");
		const output = await canonicalNew(options.output, "Download output");
		if (within(keyFile, output)) throw new Error("Recovery key must be held outside the downloaded backup");
		if (existsSync(output)) throw new Error("Download output must not already exist");
		const staging = `${output}.candidate-${randomBytes(6).toString("hex")}`;
		try {
			const commit = await downloadTarget(target, options.backupId, staging, s3Options);
			await verifyEncryptedBackup(staging, keyFile);
			const payload = await assertAuthenticatedCompletion(staging, commit);
			await guardTargetMount();
			if (existsSync(output)) throw new Error("Download output must not already exist");
			await rename(staging, output);
			await syncDirectory(dirname(output));
			await writeHealth(options.healthFile, payload);
			console.log(JSON.stringify({ status: "ok", backup_id: commit.backup_id, output, verified: true }));
			return;
		} finally {
			await rm(staging, { recursive: true, force: true });
		}
	}
	if (options.action === "download-latest") {
		await guardTargetMount();
		if (!options.output) throw new Error("download-latest requires a new --output directory");
		const output = await canonicalNew(options.output, "Download output");
		if (within(keyFile, output)) throw new Error("Recovery key must be held outside the downloaded backup");
		const { commit, payload } = await downloadLatest(target, output, keyFile, options.expectedSourceCommit, options.maxAgeMinutes, s3Options, guardTargetMount);
		await writeHealth(options.healthFile, payload);
		console.log(JSON.stringify({ status: "ok", backup_id: commit.backup_id, output, verified: true }));
		return;
	}
	const result = await prune(target, options.retentionDays, options.apply, s3Options, guardTargetMount);
	console.log(JSON.stringify(result));
	} catch (error) {
		if (reportsHealth) {
			try { await writeHealthStatus(options.healthFile, "failed", attemptStartedAt); }
			catch {
				try { await rm(resolve(options.healthFile), { force: true }); } catch { /* absence is safely not ready */ }
			}
		}
		throw error;
	}
}

async function main() {
	await runOffsite(process.argv.slice(2), process.env);
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) main().catch((error) => {
	console.error(`AIDR offsite backup failed: ${error.message}`);
	process.exitCode = 1;
});
