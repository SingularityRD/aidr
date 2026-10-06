#!/usr/bin/env node
// Recover a committed offsite backup into a new Compose project and read the
// restored database and object volume. Source services are never addressed.
import { createHash, randomBytes } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { lstat, mkdir, readFile, readdir, realpath, rm, stat, writeFile } from "node:fs/promises";
import { hostname, platform, arch } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { inspectReviewedRuntime } from "./archive-boundary.mjs";
import { assertPrivateRecoveryKey, parseTarget } from "./deployment-backup-offsite.mjs";
import { buildNodeHelperImage } from "./lib/node-helper-image.mjs";
import {
	RELEASE_MANIFEST_NAME,
	RELEASE_SIGNATURE_NAME,
	loadReleaseBundle,
	loadSignerPolicy,
	readJsonFile,
	sha256 as releaseSha256,
	validateReleaseManifest,
	verifyManifestSignature,
} from "./release-signing-lib.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const BACKUP_ID = /^[a-f0-9]{64}$/;
const SOURCE_COMMIT = /^[a-f0-9]{40,64}$/;
const PROJECT = /^aidr-recovery-[a-f0-9]{16}$/;
const MAX_OUTPUT = 4 * 1024 * 1024;
let activeChild = null;
let requestedSignal = null;

function within(path, parent) {
	const normalize = (value) => process.platform === "win32" ? value.toLowerCase() : value;
	return normalize(path) === normalize(parent) || normalize(path).startsWith(`${normalize(parent)}${sep}`);
}

function samePath(left, right) {
	return within(left, right) && within(right, left);
}

function assertSeparate(first, second, message) {
	if (within(first, second) || within(second, first)) throw new Error(message);
}

async function command(executable, args, timeoutMs = 600000, env = process.env) {
	return new Promise((done, fail) => {
		const child = spawn(executable, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true, env });
		activeChild = child;
		let stdout = "";
		let outputBytes = 0;
		let timedOut = false;
		const timer = setTimeout(() => { timedOut = true; child.kill(); }, timeoutMs);
		child.stdout.setEncoding("utf8");
		child.stdout.on("data", (chunk) => {
			outputBytes += Buffer.byteLength(chunk);
			if (outputBytes > MAX_OUTPUT) child.kill();
			else stdout += chunk;
		});
		child.stderr.on("data", (chunk) => {
			outputBytes += chunk.length;
			if (outputBytes > MAX_OUTPUT) child.kill();
		});
		child.once("error", (error) => { clearTimeout(timer); fail(new Error(`${basename(executable)} could not start: ${error.code ?? "unknown"}`)); });
		child.once("close", (code) => {
			if (activeChild === child) activeChild = null;
			clearTimeout(timer);
			if (code === 0 && !timedOut && outputBytes <= MAX_OUTPUT) done(stdout.trim());
			else fail(new Error(`${basename(executable)} operation failed (${timedOut ? "timeout" : `exit ${code ?? "unknown"}`}); service output and credentials suppressed`));
		});
	});
}

// Resolve Windows system tools by absolute path: an MSYS/POSIX-shell PATH ahead of
// System32 supplies a coreutils `whoami.exe` that rejects `/user` (and could be
// a planted binary), so never rely on PATH order for ACL-bearing operations.
function windowsSystemTool(...segments) {
	const root = process.env.SystemRoot || process.env.windir || "C:\Windows";
	return join(root, "System32", ...segments);
}

async function protectWindowsPath(path, directory, apply) {
	const identity = await command(windowsSystemTool("whoami.exe"), ["/user", "/fo", "csv", "/nh"], 30000);
	const sid = identity.match(/S-1-\d+(?:-\d+)+/)?.[0];
	if (!sid) throw new Error("Could not resolve the current user SID");
	if (apply) {
		await command(windowsSystemTool("icacls.exe"), [path, "/inheritance:r", "/grant:r", directory ? `*${sid}:(OI)(CI)F` : `*${sid}:F`], 30000);
	}
	await command(windowsSystemTool("icacls.exe"), [path, "/verify"], 30000);
	// .NET provides structured SIDs without PowerShell module autoload, which can
	// be unavailable on locked-down recovery hosts.
	const inspect = `
$ErrorActionPreference = 'Stop'
$acl = [System.IO.${directory ? "Directory" : "File"}]::GetAccessControl($env:AIDR_RESTORE_ACL_PATH)
$rules = @($acl.GetAccessRules($true, $true, [System.Security.Principal.SecurityIdentifier]) | ForEach-Object {
  [pscustomobject]@{
    sid = $_.IdentityReference.Value
    type = $_.AccessControlType.ToString()
    inherited = $_.IsInherited
    rights = $_.FileSystemRights.ToString()
    inheritance = $_.InheritanceFlags.ToString()
  }
})
[pscustomobject]@{ protected = $acl.AreAccessRulesProtected; rules = $rules } | ConvertTo-Json -Compress -Depth 4
`;
	const output = await command(windowsSystemTool("WindowsPowerShell", "v1.0", "powershell.exe"), ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(inspect, "utf16le").toString("base64")], 30000, { ...process.env, AIDR_RESTORE_ACL_PATH: path });
	const acl = JSON.parse(output);
	if (!acl || typeof acl !== "object") throw new Error(`ACL inspection returned no structured result (${output.slice(0, 80)})`);
	const rules = Array.isArray(acl.rules) ? acl.rules : acl.rules ? [acl.rules] : [];
	const failures = [
		["inheritance", acl.protected === true],
		["single principal", rules.length === 1],
		["current user", rules[0]?.sid === sid],
		["allow", rules[0]?.type === "Allow"],
		["explicit", rules[0]?.inherited === false],
		["full control", rules[0]?.rights?.includes("FullControl")],
		["child inheritance", directory
			? rules[0]?.inheritance?.includes("ContainerInherit") && rules[0]?.inheritance?.includes("ObjectInherit")
			: rules[0]?.inheritance === "None"],
	].filter(([, passed]) => !passed).map(([name]) => name);
	if (failures.length > 0) throw new Error(`ACL is not current-user-only (${failures.join(", ")})`);
	return "windows-current-user-only";
}

export async function hardenWorkDirectory(workDir) {
	if (process.platform !== "win32") {
		const info = await stat(workDir);
		if (!info.isDirectory() || (info.mode & 0o077) !== 0) throw new Error("Restore work directory permits group or world access");
		return "posix-owner-only";
	}
	return protectWindowsPath(workDir, true, true);
}

export async function hardenRecoveryKeyFile(keyFile) {
	const info = await lstat(keyFile);
	if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error("Recovery key must be a regular non-linked file");
	if (process.platform !== "win32") return "posix-mode-checked-by-key-validator";
	return protectWindowsPath(keyFile, false, true);
}

export async function assertRecoveryKeyFileAcl(keyFile) {
	const info = await lstat(keyFile);
	if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error("Recovery key must be a regular non-linked file");
	if (process.platform !== "win32") return "posix-mode-checked-by-key-validator";
	return protectWindowsPath(keyFile, false, false);
}

function composeArgs(recovered, project) {
	return ["compose", "--project-directory", recovered, "-f", join(recovered, "compose.yml"), "--project-name", project];
}

async function mountedVolume(recovered, project, service, destination) {
	const ids = (await command("docker", [...composeArgs(recovered, project), "ps", "--all", "--quiet", service])).split(/\r?\n/).filter(Boolean);
	if (ids.length !== 1 || !/^[a-f0-9]{12,64}$/.test(ids[0])) throw new Error(`Expected exactly one recovered ${service} container`);
	const inspected = JSON.parse(await command("docker", ["inspect", ids[0]]));
	const container = inspected[0];
	if (!container || container.Config?.Labels?.["com.docker.compose.project"] !== project) throw new Error("Recovered container is outside the independent project");
	if (Object.keys(container.HostConfig?.PortBindings ?? {}).length > 0) throw new Error("Recovered service publishes a host port; isolated drill refused");
	const mount = container.Mounts?.find((entry) => entry.Destination === destination);
	if (mount?.Type !== "volume" || typeof mount.Name !== "string" || !mount.Name.startsWith(`${project}_`)) throw new Error(`Recovered ${service} volume is outside the independent project`);
	const volume = JSON.parse(await command("docker", ["volume", "inspect", mount.Name]))[0];
	if (volume?.Labels?.["com.docker.compose.project"] !== project) throw new Error("Recovered volume lacks the independent project label");
	return { containerId: ids[0], volumeName: mount.Name };
}

async function waitForDatabase(containerId) {
	const deadline = Date.now() + 120000;
	while (Date.now() < deadline) {
		try {
			await command("docker", ["exec", containerId, "pg_isready", "-U", "postgres"], 15000);
			return;
		} catch {
			await new Promise((done) => setTimeout(done, 2000));
		}
	}
	throw new Error("Recovered database did not become ready within 120 seconds");
}

async function readDatabase(containerId) {
	const sql = `SELECT json_build_object(
		'migrations', (SELECT count(*) FROM public.aidr_schema_migrations),
		'tenants', (SELECT count(*) FROM public.tenants),
		'policies', (SELECT count(*) FROM public.tenant_runtime_policies),
		'audit_rows', (SELECT count(*) FROM public.audit_logs),
		'storage_objects', (SELECT count(*) FROM storage.objects),
		'database_bytes', pg_database_size(current_database())
	)::text`;
	const result = JSON.parse(await command("docker", ["exec", containerId, "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1", "-tA", "-c", sql], 60000));
	for (const key of ["migrations", "tenants", "policies", "audit_rows", "storage_objects", "database_bytes"]) {
		if (!Number.isSafeInteger(result[key]) || result[key] < 0) throw new Error("Recovered database returned invalid aggregate evidence");
	}
	if (result.migrations === 0 || result.database_bytes === 0) throw new Error("Recovered database has no installed AIDR schema");
	return result;
}

async function readStorage(volumeName) {
	const helperImage = buildNodeHelperImage();
	const shell = "set -eu; cd /data; test -z \"$(find . -type l -print -quit)\"; find . -type f -exec sha256sum {} + | sort | sha256sum; find . -type f | wc -l";
	const output = await command("docker", ["run", "--rm", "--pull", "never", "--network", "none", "--mount", `type=volume,src=${volumeName},dst=/data,readonly`, helperImage, "sh", "-c", shell], 120000);
	const lines = output.split(/\r?\n/).map((line) => line.trim());
	const fingerprint = lines[0]?.match(/^([a-f0-9]{64})\s+-$/)?.[1];
	const count = Number(lines[1]);
	if (!fingerprint || !Number.isSafeInteger(count) || count < 0) throw new Error("Restored storage inventory could not be read");
	return { files: count, sha256_inventory: fingerprint };
}

export async function validateLocation(workDir, keyFile, target, runtimeDir) {
	if (!isAbsolute(workDir) || !isAbsolute(keyFile) || (runtimeDir && !isAbsolute(runtimeDir))) {
		throw new Error("Work directory, recovery key and reviewed runtime must be absolute paths");
	}
	const work = resolve(workDir);
	if (existsSync(work)) throw new Error("Restore drill requires a new, unused work directory");
	const parent = await realpath(dirname(work));
	if (!samePath(parent, resolve(dirname(work)))) throw new Error("Restore work directory parent contains a symbolic link");
	const key = await realpath(keyFile);
	if (!samePath(key, resolve(keyFile))) throw new Error("Recovery key path contains a symbolic link");
	assertSeparate(resolve(parent, basename(work)), key, "Keep the recovery key outside the drill workspace");
	if (runtimeDir) {
		const runtime = await realpath(runtimeDir);
		if (!samePath(runtime, resolve(runtimeDir))) throw new Error("Reviewed runtime path contains a symbolic link");
		assertSeparate(resolve(parent, basename(work)), runtime, "Keep the drill workspace separate from the reviewed runtime");
		assertSeparate(key, runtime, "Keep recovery-key custody separate from the reviewed runtime");
	}
	if (target.kind === "filesystem") {
		const remote = await realpath(target.root);
		if (!samePath(remote, resolve(target.root))) throw new Error("Backup target path contains a symbolic link");
		assertSeparate(resolve(parent, basename(work)), remote, "Keep the drill workspace separate from the backup target");
		assertSeparate(key, remote, "Keep the recovery key separate from the backup target");
	}
	return join(parent, basename(work));
}

export async function loadCandidateBinding(runtimeDir, inventoryFile, policyFile) {
	if (![runtimeDir, inventoryFile, policyFile].every((value) => typeof value === "string" && isAbsolute(value))) throw new Error("Reviewed runtime, candidate inventory and signer policy must be absolute paths");
	const runtime = await realpath(runtimeDir);
	const inventoryPath = await realpath(inventoryFile);
	const policyPath = await realpath(policyFile);
	if (!samePath(runtime, resolve(runtimeDir)) || !samePath(inventoryPath, resolve(inventoryFile)) || !samePath(policyPath, resolve(policyFile))) {
		throw new Error("Reviewed runtime, candidate inventory and signer policy must not use symbolic-link ancestors");
	}
	if (basename(inventoryPath) !== "release-inventory.json") throw new Error("Candidate inventory must be named release-inventory.json");
	const bundle = await loadReleaseBundle(dirname(inventoryPath), { allowSignedControlFiles: true });
	const policy = await loadSignerPolicy(policyPath, bundle.bundle);
	const manifestRecord = await readJsonFile(join(bundle.bundle, RELEASE_MANIFEST_NAME), "release manifest");
	const signatureRecord = await readJsonFile(join(bundle.bundle, RELEASE_SIGNATURE_NAME), "release signature");
	const validated = validateReleaseManifest(manifestRecord.value, bundle, policy);
	verifyManifestSignature(manifestRecord.raw, signatureRecord.value, validated);
	if (!SOURCE_COMMIT.test(bundle.metadata.git_sha ?? "")) throw new Error("Signed candidate has no valid source commit");
	const runtimeBinding = inspectReviewedRuntime(runtime, { sourceCommit: bundle.metadata.git_sha });
	return {
		runtime,
		source_commit: runtimeBinding.source_commit,
		candidate_digest: releaseSha256(bundle.inventoryRaw),
		candidate_inventory: inventoryPath,
		candidate_metadata_sha256: releaseSha256(bundle.metadataRaw),
		candidate_manifest_sha256: releaseSha256(manifestRecord.raw),
		candidate_signer_key_id: validated.keyId,
		candidate_signer_fingerprint_sha256: validated.fingerprint,
		runtime_deployment_sha256: runtimeBinding.runtime_deployment_sha256,
		runtime_tree_sha256: runtimeBinding.runtime_tree_sha256,
	};
}

function positiveInteger(value, flag) {
	const parsed = Number(value);
	if (!Number.isSafeInteger(parsed) || parsed < 1) throw new Error(`${flag} must be a positive integer`);
	return parsed;
}

export function parseRecoveryTargets(rpoMinutes, rtoSeconds) {
	return {
		rpoTargetMinutes: positiveInteger(rpoMinutes, "--rpo-target-minutes"),
		rtoTargetSeconds: positiveInteger(rtoSeconds, "--rto-target-seconds"),
	};
}

export function conservativeBackupAgeMinutes(manifest, now = Date.now()) {
	const iso = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{3})?Z$/;
	if (!iso.test(manifest?.started_at) || !iso.test(manifest?.completed_at)) throw new Error("Backup recovery point timestamps are invalid");
	const started = Date.parse(manifest.started_at);
	const completed = Date.parse(manifest.completed_at);
	if (!Number.isFinite(started) || !Number.isFinite(completed) || started > completed || completed > now) {
		throw new Error("Backup recovery point timestamps are invalid or future-dated");
	}
	// started_at precedes source shutdown, so it conservatively bounds data age.
	return (now - started) / 60000;
}

const RESTORE_RUN = /^restore-\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}-\d{3}Z-[a-f0-9]{10}$/;

async function cleanupRecoveredRun(runDirectory) {
	const marker = join(runDirectory, ".recovery-project");
	let project;
	try {
		const markerInfo = await lstat(marker);
		if (!markerInfo.isFile() || markerInfo.isSymbolicLink()) throw new Error(`Invalid recovery project marker in ${runDirectory}`);
		project = (await readFile(marker, "utf8")).trim();
	} catch (error) {
		if (error.code !== "ENOENT") throw error;
		throw new Error(`Missing recovery project marker in ${runDirectory}`);
	}
	if (project && !PROJECT.test(project)) throw new Error(`Invalid recovery project marker in ${runDirectory}`);
	const recovered = join(runDirectory, "recovered");
	if (existsSync(recovered)) {
		const info = await lstat(recovered);
		if (!info.isDirectory() || info.isSymbolicLink() || !project) throw new Error(`Unsafe recovered directory in ${runDirectory}`);
	}
	if (project && existsSync(join(recovered, "compose.yml"))) {
		await command("docker", [...composeArgs(recovered, project), "down", "--volumes", "--remove-orphans"], 600000);
	}
	const downloaded = join(runDirectory, "downloaded");
	if (existsSync(downloaded)) {
		const info = await lstat(downloaded);
		if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`Unsafe downloaded directory in ${runDirectory}`);
	}
	await rm(downloaded, { recursive: true, force: true });
	await rm(recovered, { recursive: true, force: true });
	await rm(marker, { force: true });
}

export async function cleanupRestoreWorkRoot(workRoot, retentionDays, now = Date.now()) {
	const days = positiveInteger(retentionDays, "--evidence-retention-days");
	const root = await realpath(workRoot);
	if (!samePath(root, resolve(workRoot))) throw new Error("Restore work root path contains a symbolic link");
	const cutoff = now - days * 86400 * 1000;
	let sanitized = 0;
	let expired = 0;
	for (const entry of await readdir(root, { withFileTypes: true })) {
		if (!RESTORE_RUN.test(entry.name)) continue;
		const runDirectory = join(root, entry.name);
		const info = await lstat(runDirectory);
		if (!info.isDirectory() || info.isSymbolicLink()) throw new Error(`Restore run path is not a real directory: ${entry.name}`);
		if (!existsSync(join(runDirectory, ".recovery-project"))) continue;
		await cleanupRecoveredRun(runDirectory);
		sanitized += 1;
		if (info.mtimeMs <= cutoff) {
			await rm(runDirectory, { recursive: true });
			expired += 1;
		}
	}
	return { sanitized, expired, retention_days: days };
}

async function main() {
	const started = Date.now();
	const { values } = parseArgs({ options: {
		target: { type: "string" }, "backup-id": { type: "string" }, "key-file": { type: "string" }, "key-source-file": { type: "string" }, "work-dir": { type: "string" }, "work-root": { type: "string" },
		runtime: { type: "string" }, "candidate-inventory": { type: "string" }, "candidate-policy": { type: "string" }, "expected-source-commit": { type: "string" },
		"rpo-target-minutes": { type: "string" }, "rto-target-seconds": { type: "string" }, "evidence-retention-days": { type: "string" }, "cleanup-only": { type: "boolean", default: false },
		"s3-endpoint": { type: "string" }, "s3-region": { type: "string" }, "aws-cli": { type: "string" }, "aws-cli-argument": { type: "string", multiple: true },
	} });
	if (values["cleanup-only"]) {
		if (!values["work-root"] || !values["evidence-retention-days"]) throw new Error("Cleanup requires --work-root and --evidence-retention-days");
		await hardenWorkDirectory(await realpath(values["work-root"]));
		console.log(JSON.stringify(await cleanupRestoreWorkRoot(values["work-root"], values["evidence-retention-days"])));
		return;
	}
	if ((values["backup-id"] && !BACKUP_ID.test(values["backup-id"])) || !values.target || !values["key-file"] || !values.runtime || !values["candidate-inventory"] || !values["candidate-policy"] || (!values["work-dir"] && !values["work-root"]) || (values["work-dir"] && values["work-root"]) || (values["work-root"] && !values["evidence-retention-days"])) {
		throw new Error("Use --target, optional --backup-id, --key-file, --runtime, --candidate-inventory, --candidate-policy and exactly one of --work-dir or --work-root");
	}
	const target = parseTarget(values.target);
	const keyFile = await realpath(values["key-file"]);
	await assertPrivateRecoveryKey(keyFile);
	await assertRecoveryKeyFileAcl(keyFile);
	if (values["key-source-file"]) await assertPrivateRecoveryKey(await realpath(values["key-source-file"]), { source: true });
	const binding = await loadCandidateBinding(values.runtime, values["candidate-inventory"], values["candidate-policy"]);
	if (values["expected-source-commit"] && values["expected-source-commit"] !== binding.source_commit) throw new Error("Expected source commit differs from the candidate and reviewed runtime");
	const { rpoTargetMinutes, rtoTargetSeconds } = parseRecoveryTargets(values["rpo-target-minutes"], values["rto-target-seconds"]);
	let requestedWorkDir = values["work-dir"];
	if (values["work-root"]) {
		if (!isAbsolute(values["work-root"])) throw new Error("--work-root must be an absolute path");
		const workRoot = await realpath(values["work-root"]);
		await hardenWorkDirectory(workRoot);
		await cleanupRestoreWorkRoot(workRoot, values["evidence-retention-days"]);
		requestedWorkDir = join(workRoot, `restore-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomBytes(5).toString("hex")}`);
	}
	const workDir = await validateLocation(requestedWorkDir, keyFile, target, binding.runtime);
	await mkdir(workDir, { mode: 0o700 });
	const workDirectoryProtection = await hardenWorkDirectory(workDir);
	const evidencePath = join(workDir, "restore-drill-evidence.json");
	const evidence = {
		schema_version: 2, passed: false, started_at: new Date(started).toISOString(), target_kind: target.kind,
		backup_id: values["backup-id"] ?? null, host_identity_sha256: createHash("sha256").update(hostname()).digest("hex"),
		host_platform: platform(), host_architecture: arch(), work_directory_protection: workDirectoryProtection,
		source_commit: binding.source_commit, candidate_digest: binding.candidate_digest,
		candidate_inventory: binding.candidate_inventory, candidate_metadata_sha256: binding.candidate_metadata_sha256,
		candidate_manifest_sha256: binding.candidate_manifest_sha256, candidate_signer_key_id: binding.candidate_signer_key_id,
		candidate_signer_fingerprint_sha256: binding.candidate_signer_fingerprint_sha256,
		reviewed_runtime: binding.runtime, runtime_deployment_sha256: binding.runtime_deployment_sha256, runtime_tree_sha256: binding.runtime_tree_sha256,
		recovery_objectives: {
			rpo: { target_minutes: rpoTargetMinutes, result_minutes: null, passed: false, status: "NOT_RUN", measurement: "authenticated backup start (before source shutdown) to restored data verification" },
			rto: { target_seconds: rtoTargetSeconds, result_seconds: null, passed: false, status: "NOT_RUN", measurement: "drill process start through restored database and object-volume validation; traffic cutover excluded" },
		},
		scope: "Candidate-bound isolated technical restore and database/object read on this host. RPO/RTO results cover the stated measurements, not customer cutover or independent-host acceptance.",
	};
	let recovered;
	const project = `aidr-recovery-${randomBytes(8).toString("hex")}`;
	await writeFile(join(workDir, ".recovery-project"), `${project}\n`, { mode: 0o600, flag: "wx" });
	let failure = null;
	let cleaningUp = false;
	const interrupt = (signal) => {
		requestedSignal ??= signal;
		if (!cleaningUp) activeChild?.kill(signal);
	};
	const onInterrupt = () => interrupt("SIGINT");
	const onTerminate = () => interrupt("SIGTERM");
	process.on("SIGINT", onInterrupt);
	process.on("SIGTERM", onTerminate);
	try {
		const downloaded = join(workDir, "downloaded");
		const offsiteArgs = values["backup-id"]
			? ["download", "--target", values.target, "--backup-id", values["backup-id"], "--key-file", keyFile, "--output", downloaded]
			: ["download-latest", "--target", values.target, "--key-file", keyFile, "--output", downloaded, "--expected-source-commit", binding.source_commit, "--max-age-minutes", String(rpoTargetMinutes)];
		const s3Endpoint = values["s3-endpoint"] ?? process.env.AIDR_BACKUP_S3_ENDPOINT;
		const s3Region = values["s3-region"] ?? process.env.AIDR_BACKUP_S3_REGION;
		const awsCli = values["aws-cli"] ?? process.env.AIDR_AWS_CLI;
		if (s3Endpoint) offsiteArgs.push("--s3-endpoint", s3Endpoint);
		if (s3Region) offsiteArgs.push("--s3-region", s3Region);
		if (awsCli) offsiteArgs.push("--aws-cli", awsCli);
		for (const argument of values["aws-cli-argument"] ?? []) offsiteArgs.push("--aws-cli-argument", argument);
		const downloadResult = JSON.parse(await command(process.execPath, [join(SCRIPT_DIR, "deployment-backup-offsite.mjs"), ...offsiteArgs]));
		evidence.backup_id = downloadResult.backup_id;
		const envelope = JSON.parse(await readFile(join(downloaded, "backup.json"), "utf8"));
		const manifest = JSON.parse(envelope.payload);
		const ageMinutes = conservativeBackupAgeMinutes(manifest);
		evidence.backup_recovery_point_at = manifest.started_at;
		evidence.backup_completed_at = manifest.completed_at;
		evidence.recovery_objectives.rpo.result_minutes = Math.ceil(ageMinutes * 100) / 100;
		evidence.recovery_objectives.rpo.passed = ageMinutes <= rpoTargetMinutes;
		evidence.recovery_objectives.rpo.status = "PRECHECK";
		if (!evidence.recovery_objectives.rpo.passed) throw new Error("Backup exceeds the required RPO target");
		if (manifest.source_commit !== binding.source_commit) throw new Error("Backup source commit differs from the candidate and reviewed runtime");
		evidence.backup_age_minutes_at_drill = evidence.recovery_objectives.rpo.result_minutes;
		evidence.source_commit_verified = true;
		evidence.candidate_bound = true;
		recovered = join(workDir, "recovered");
		await command(process.execPath, [join(SCRIPT_DIR, "deployment-backup.mjs"), "recover", "--backup", downloaded, "--output", recovered, "--key-file", keyFile, "--runtime", binding.runtime, "--project", project]);
		const receipt = JSON.parse(await readFile(join(recovered, "recovery-receipt.json"), "utf8"));
		if (receipt.project_name !== project || !PROJECT.test(project) || receipt.services_started !== false || receipt.backup_manifest_sha256 !== evidence.backup_id
			|| receipt.reviewed_runtime_deployment_sha256 !== binding.runtime_deployment_sha256 || receipt.reviewed_runtime_tree_sha256 !== binding.runtime_tree_sha256
			|| receipt.installation_runtime_tree_sha256 !== manifest.installation_runtime_sha256 || receipt.source_commit !== binding.source_commit) {
			throw new Error("Recovery receipt is not bound to this backup, reviewed runtime, source commit and a new stopped project");
		}
		evidence.installation_runtime_deployment_sha256 = receipt.installation_runtime_deployment_sha256;
		evidence.installation_runtime_tree_sha256 = receipt.installation_runtime_tree_sha256;
		const db = await mountedVolume(recovered, project, "db", "/var/lib/postgresql/data");
		const storage = await mountedVolume(recovered, project, "storage", "/var/lib/storage");
		if (db.volumeName === storage.volumeName) throw new Error("Database and object volumes must be distinct");
		await command("docker", [...composeArgs(recovered, project), "start", "db"], 180000);
		await waitForDatabase(db.containerId);
		const database = await readDatabase(db.containerId);
		const objects = await readStorage(storage.volumeName);
		if (database.storage_objects > 0 && objects.files === 0) throw new Error("Database references storage objects but restored object volume is empty");
		evidence.database = database;
		evidence.object_volume = objects;
		evidence.recovered_project = project;
		evidence.recovered_volumes = { database: db.volumeName, storage: storage.volumeName };
		const verifiedAgeMinutes = conservativeBackupAgeMinutes(manifest);
		evidence.recovery_objectives.rpo.result_minutes = Math.ceil(verifiedAgeMinutes * 100) / 100;
		evidence.backup_age_minutes_at_drill = evidence.recovery_objectives.rpo.result_minutes;
		evidence.recovery_objectives.rpo.passed = verifiedAgeMinutes <= rpoTargetMinutes;
		evidence.recovery_objectives.rpo.status = "MEASURED";
		if (!evidence.recovery_objectives.rpo.passed) throw new Error("Verified restore exceeds the required RPO target");
		evidence.technical_restore_seconds = Math.ceil((Date.now() - started) / 1000);
		evidence.recovery_objectives.rto.result_seconds = evidence.technical_restore_seconds;
		evidence.recovery_objectives.rto.passed = evidence.technical_restore_seconds <= rtoTargetSeconds;
		evidence.recovery_objectives.rto.status = "MEASURED";
		if (!evidence.recovery_objectives.rto.passed) throw new Error("Technical restore exceeds the required RTO target");
		evidence.verified_at = new Date().toISOString();
		evidence.passed = true;
	} catch (error) {
		evidence.failure = error.message;
		failure = error;
	} finally {
		cleaningUp = true;
		try {
			await cleanupRecoveredRun(workDir);
			evidence.sensitive_material_removed = true;
		} catch (error) {
			evidence.passed = false;
			evidence.sensitive_material_removed = false;
			evidence.cleanup_failure = error.message;
			failure ??= new Error("Recovered project, volumes or plaintext material could not be removed");
		}
		evidence.finished_at = new Date().toISOString();
		try { await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600, flag: "wx" }); }
		finally {
			process.removeListener("SIGINT", onInterrupt);
			process.removeListener("SIGTERM", onTerminate);
		}
	}
	if (requestedSignal) {
		console.error(`AIDR restore drill interrupted by ${requestedSignal}; cleanup completed before exit.`);
		process.exitCode = requestedSignal === "SIGINT" ? 130 : 143;
		return;
	}
	if (failure || !evidence.passed) throw failure ?? new Error(evidence.failure);
	console.log(JSON.stringify({ passed: true, evidence_file: evidencePath, backup_id: evidence.backup_id, technical_restore_seconds: evidence.technical_restore_seconds }));
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) main().catch((error) => {
	console.error(`AIDR restore drill failed: ${error.message}`);
	process.exitCode = 1;
});
