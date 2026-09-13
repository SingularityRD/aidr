#!/usr/bin/env node
// Recover a committed offsite backup into a new Compose project and read the
// restored database and object volume. Source services are never addressed.
import { createHash } from "node:crypto";
import { spawn } from "node:child_process";
import { existsSync } from "node:fs";
import { mkdir, readFile, realpath, stat, writeFile } from "node:fs/promises";
import { hostname, platform, arch } from "node:os";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import { parseTarget } from "./deployment-backup-offsite.mjs";

const SCRIPT_DIR = dirname(fileURLToPath(import.meta.url));
const BACKUP_ID = /^[a-f0-9]{64}$/;
const PROJECT = /^aidr-recovery-[a-f0-9]{16}$/;
const MAX_OUTPUT = 4 * 1024 * 1024;

function within(path, parent) {
	return path === parent || path.startsWith(`${parent}${sep}`);
}

function assertSeparate(first, second, message) {
	if (within(first, second) || within(second, first)) throw new Error(message);
}

async function command(executable, args, timeoutMs = 600000, env = process.env) {
	return new Promise((done, fail) => {
		const child = spawn(executable, args, { stdio: ["ignore", "pipe", "pipe"], windowsHide: true, env });
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
			clearTimeout(timer);
			if (code === 0 && !timedOut && outputBytes <= MAX_OUTPUT) done(stdout.trim());
			else fail(new Error(`${basename(executable)} operation failed (${timedOut ? "timeout" : `exit ${code ?? "unknown"}`}); service output and credentials suppressed`));
		});
	});
}

export async function hardenWorkDirectory(workDir) {
	if (process.platform !== "win32") {
		const info = await stat(workDir);
		if (!info.isDirectory() || (info.mode & 0o077) !== 0) throw new Error("Restore work directory permits group or world access");
		return "posix-owner-only";
	}
	const identity = await command("whoami.exe", ["/user", "/fo", "csv", "/nh"], 30000);
	const sid = identity.match(/S-1-\d+(?:-\d+)+/)?.[0];
	if (!sid) throw new Error("Could not resolve the recovery operator SID");
	await command("icacls.exe", [workDir, "/inheritance:r", "/grant:r", `*${sid}:(OI)(CI)F`], 30000);
	await command("icacls.exe", [workDir, "/verify"], 30000);
	// .NET provides structured SIDs without PowerShell module autoload, which can
	// be unavailable on locked-down recovery hosts.
	const inspect = `
$ErrorActionPreference = 'Stop'
$acl = [System.IO.Directory]::GetAccessControl($env:AIDR_RESTORE_ACL_PATH)
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
	const output = await command("powershell.exe", ["-NoProfile", "-NonInteractive", "-EncodedCommand", Buffer.from(inspect, "utf16le").toString("base64")], 30000, { ...process.env, AIDR_RESTORE_ACL_PATH: workDir });
	const acl = JSON.parse(output);
	if (!acl || typeof acl !== "object") throw new Error(`Restore ACL inspection returned no structured result (${output.slice(0, 80)})`);
	const rules = Array.isArray(acl.rules) ? acl.rules : acl.rules ? [acl.rules] : [];
	const failures = [
		["inheritance", acl.protected === true],
		["single principal", rules.length === 1],
		["current user", rules[0]?.sid === sid],
		["allow", rules[0]?.type === "Allow"],
		["explicit", rules[0]?.inherited === false],
		["full control", rules[0]?.rights?.includes("FullControl")],
		["child inheritance", rules[0]?.inheritance?.includes("ContainerInherit") && rules[0]?.inheritance?.includes("ObjectInherit")],
	].filter(([, passed]) => !passed).map(([name]) => name);
	if (failures.length > 0) throw new Error(`Restore work directory ACL is not current-user-only (${failures.join(", ")})`);
	return "windows-current-user-only";
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
	const shell = "set -eu; cd /data; test -z \"$(find . -type l -print -quit)\"; find . -type f -exec sha256sum {} + | sort | sha256sum; find . -type f | wc -l";
	const output = await command("docker", ["run", "--rm", "--pull", "never", "--network", "none", "--mount", `type=volume,src=${volumeName},dst=/data,readonly`, "node:24.12.0-alpine3.23", "sh", "-c", shell], 120000);
	const lines = output.split(/\r?\n/).map((line) => line.trim());
	const fingerprint = lines[0]?.match(/^([a-f0-9]{64})\s+-$/)?.[1];
	const count = Number(lines[1]);
	if (!fingerprint || !Number.isSafeInteger(count) || count < 0) throw new Error("Restored storage inventory could not be read");
	return { files: count, sha256_inventory: fingerprint };
}

export async function validateLocation(workDir, keyFile, target) {
	if (!isAbsolute(workDir) || !isAbsolute(keyFile)) throw new Error("Work directory and recovery key must be absolute paths");
	const work = resolve(workDir);
	if (existsSync(work)) throw new Error("Restore drill requires a new, unused work directory");
	const parent = await realpath(dirname(work));
	const key = await realpath(keyFile);
	assertSeparate(resolve(parent, basename(work)), key, "Keep the recovery key outside the drill workspace");
	if (target.kind === "filesystem") {
		const remote = await realpath(target.root);
		assertSeparate(resolve(parent, basename(work)), remote, "Keep the drill workspace separate from the backup target");
		assertSeparate(key, remote, "Keep the recovery key separate from the backup target");
	}
	return work;
}

async function main() {
	const { values } = parseArgs({ options: {
		target: { type: "string" }, "backup-id": { type: "string" }, "key-file": { type: "string" }, "work-dir": { type: "string" },
		"expected-source-commit": { type: "string" }, "max-backup-age-minutes": { type: "string" },
		"s3-endpoint": { type: "string" }, "s3-region": { type: "string" }, "aws-cli": { type: "string" }, "aws-cli-argument": { type: "string", multiple: true },
	} });
	if (!BACKUP_ID.test(values["backup-id"] ?? "") || !values.target || !values["key-file"] || !values["work-dir"]) {
		throw new Error("Use --target, --backup-id, --key-file and a new absolute --work-dir");
	}
	const target = parseTarget(values.target);
	const keyFile = resolve(values["key-file"]);
	const workDir = await validateLocation(values["work-dir"], keyFile, target);
	const maxAge = values["max-backup-age-minutes"] === undefined ? null : Number(values["max-backup-age-minutes"]);
	if (maxAge !== null && (!Number.isSafeInteger(maxAge) || maxAge < 1)) throw new Error("--max-backup-age-minutes must be a positive integer");
	const started = Date.now();
	await mkdir(workDir, { mode: 0o700 });
	const workDirectoryProtection = await hardenWorkDirectory(workDir);
	const evidencePath = join(workDir, "restore-drill-evidence.json");
	const evidence = {
		schema_version: 1, passed: false, started_at: new Date(started).toISOString(), target_kind: target.kind,
		backup_id: values["backup-id"], host_identity_sha256: createHash("sha256").update(hostname()).digest("hex"),
		host_platform: platform(), host_architecture: arch(), work_directory_protection: workDirectoryProtection,
		scope: "Isolated technical restore and database/object read on this host. Not customer cutover, independent-host acceptance, or an RPO/RTO guarantee.",
	};
	let recovered;
	let project;
	let databaseMayBeRunning = false;
	try {
		const downloaded = join(workDir, "downloaded");
		const offsiteArgs = ["download", "--target", values.target, "--backup-id", values["backup-id"], "--key-file", keyFile, "--output", downloaded];
		if (values["s3-endpoint"]) offsiteArgs.push("--s3-endpoint", values["s3-endpoint"]);
		if (values["s3-region"]) offsiteArgs.push("--s3-region", values["s3-region"]);
		if (values["aws-cli"]) offsiteArgs.push("--aws-cli", values["aws-cli"]);
		for (const argument of values["aws-cli-argument"] ?? []) offsiteArgs.push("--aws-cli-argument", argument);
		await command(process.execPath, [join(SCRIPT_DIR, "deployment-backup-offsite.mjs"), ...offsiteArgs]);
		const envelope = JSON.parse(await readFile(join(downloaded, "backup.json"), "utf8"));
		const manifest = JSON.parse(envelope.payload);
		const ageMinutes = (Date.now() - Date.parse(manifest.completed_at)) / 60000;
		if (!Number.isFinite(ageMinutes) || ageMinutes < 0) throw new Error("Future-dated or invalid backup cannot pass the drill");
		if (maxAge !== null && ageMinutes > maxAge) throw new Error("Backup exceeds the required freshness window");
		if (values["expected-source-commit"] && manifest.source_commit !== values["expected-source-commit"]) throw new Error("Backup source commit differs from the expected release candidate");
		evidence.backup_completed_at = manifest.completed_at;
		evidence.backup_age_minutes_at_drill = Math.round(ageMinutes * 100) / 100;
		evidence.source_commit = manifest.source_commit ?? null;
		evidence.candidate_bound = Boolean(values["expected-source-commit"]);
		recovered = join(workDir, "recovered");
		await command(process.execPath, [join(SCRIPT_DIR, "deployment-backup.mjs"), "recover", "--backup", downloaded, "--output", recovered, "--key-file", keyFile]);
		const receipt = JSON.parse(await readFile(join(recovered, "recovery-receipt.json"), "utf8"));
		project = receipt.project_name;
		if (!PROJECT.test(project) || receipt.services_started !== false || receipt.backup_manifest_sha256 !== values["backup-id"]) {
			throw new Error("Recovery receipt is not bound to this backup and a new stopped project");
		}
		const db = await mountedVolume(recovered, project, "db", "/var/lib/postgresql/data");
		const storage = await mountedVolume(recovered, project, "storage", "/var/lib/storage");
		if (db.volumeName === storage.volumeName) throw new Error("Database and object volumes must be distinct");
		databaseMayBeRunning = true;
		await command("docker", [...composeArgs(recovered, project), "start", "db"], 180000);
		await waitForDatabase(db.containerId);
		const database = await readDatabase(db.containerId);
		const objects = await readStorage(storage.volumeName);
		if (database.storage_objects > 0 && objects.files === 0) throw new Error("Database references storage objects but restored object volume is empty");
		evidence.database = database;
		evidence.object_volume = objects;
		evidence.recovered_project = project;
		evidence.recovered_volumes = { database: db.volumeName, storage: storage.volumeName };
		evidence.technical_restore_seconds = Math.round((Date.now() - started) / 1000);
		evidence.verified_at = new Date().toISOString();
		evidence.passed = true;
	} catch (error) {
		evidence.failure = error.message;
		throw error;
	} finally {
		if (databaseMayBeRunning && recovered && project) {
			try { await command("docker", [...composeArgs(recovered, project), "stop", "db"], 180000); }
			catch { evidence.passed = false; evidence.failure = "Recovered database could not be stopped; inspect the isolated project"; }
		}
		evidence.finished_at = new Date().toISOString();
		await writeFile(evidencePath, `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600, flag: "wx" });
	}
	if (!evidence.passed) throw new Error(evidence.failure);
	console.log(JSON.stringify({ passed: true, evidence_file: evidencePath, backup_id: evidence.backup_id, technical_restore_seconds: evidence.technical_restore_seconds }));
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) main().catch((error) => {
	console.error(`AIDR restore drill failed: ${error.message}`);
	process.exitCode = 1;
});
