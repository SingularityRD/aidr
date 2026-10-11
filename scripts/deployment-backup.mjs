#!/usr/bin/env node
// Cold, encrypted volume backup. Recovery always creates a new project and new
// volumes. No command in this tool overwrites or deletes an existing database.
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import { closeSync, createReadStream, createWriteStream, existsSync, fsyncSync, linkSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, unlinkSync, writeFileSync } from "node:fs";
import { basename, dirname, isAbsolute, join, resolve, sep } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { parseArgs } from "node:util";
import { createGunzip } from "node:zlib";
import { systemTar, tarDirectory } from "./lib/tar-path.mjs";
import { REVIEWED_RUNTIME_ARCHIVE_ENTRIES, copyReviewedRuntime, createTarBoundaryValidator, inspectAuthenticatedInstallation, inspectReviewedRuntime } from "./archive-boundary.mjs";
import { assertRecoveryKeyFileAcl, hardenRecoveryKeyFile, hardenWorkDirectory } from "./deployment-restore-drill.mjs";
import { buildNodeHelperImage } from "./lib/node-helper-image.mjs";

const SOURCE_COMMIT = /^[a-f0-9]{40,64}$/;
const RECOVERY_PROJECT = /^aidr-recovery-[a-f0-9]{16}$/;
const { values, positionals } = parseArgs({ allowPositionals: true, options: { deployment: { type: "string", default: ".aidr-deploy" }, output: { type: "string" }, backup: { type: "string" }, "key-file": { type: "string" }, "recovery-journal": { type: "string" }, runtime: { type: "string" }, project: { type: "string" }, maintenance: { type: "boolean", default: false } } });
const action = positionals[0];
if (!["keygen", "backup", "verify", "recover", "recover-services"].includes(action) || (action !== "recover-services" && !values["key-file"])) throw new Error("Use keygen|backup|verify|recover with --key-file, or recover-services with --deployment and --recovery-journal");
const keyPath = values["key-file"] ? resolve(values["key-file"]) : null;
if (action === "keygen") {
  mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 });
  if (process.platform === "win32") {
    writeFileSync(keyPath, "", { mode: 0o600, flag: "wx" });
    try {
      await hardenRecoveryKeyFile(keyPath);
      writeFileSync(keyPath, randomBytes(32).toString("hex") + "\n", { mode: 0o600, flag: "w" });
    } catch (error) {
      rmSync(keyPath, { force: true });
      throw error;
    }
  } else writeFileSync(keyPath, randomBytes(32).toString("hex") + "\n", { mode: 0o600, flag: "wx" });
  console.log("Created a private recovery key. Store it separately from the installation and backup; losing it makes recovery impossible.");
  process.exit(0);
}
function samePath(left, right) {
	return process.platform === "win32" ? left.toLowerCase() === right.toLowerCase() : left === right;
}
function canonicalExisting(path, label) {
	const resolved = resolve(path);
	const real = realpathSync(resolved);
	if (!samePath(resolved, real)) throw new Error(`${label} path contains a symbolic-link ancestor`);
	return real;
}
function canonicalNew(path, label) {
	const resolved = resolve(path);
	const parent = realpathSync(dirname(resolved));
	if (!samePath(parent, dirname(resolved))) throw new Error(`${label} parent contains a symbolic link`);
	return join(parent, basename(resolved));
}
function syncDirectory(path) {
	if (process.platform === "win32") return;
	const descriptor = openSync(path, "r");
	try { fsyncSync(descriptor); } finally { closeSync(descriptor); }
}
function journalPathForWrite(path) {
	if (!path || !isAbsolute(path)) throw new Error("Backup requires an absolute --recovery-journal path outside the installation");
	const target = canonicalNew(path, "Recovery journal");
	const parent = lstatSync(dirname(target));
	if (!parent.isDirectory() || parent.isSymbolicLink() || (process.platform !== "win32" && ((parent.mode & 0o022) !== 0 || parent.uid !== process.geteuid()))) {
		throw new Error("Recovery journal directory must be a private directory owned by the backup operator");
	}
	return target;
}
function assertPrivateJournal(path) {
	const info = lstatSync(path);
	if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error("Recovery journal must be a regular, unlinked file");
	if (process.platform !== "win32" && ((info.mode & 0o777) !== 0o600 || info.uid !== process.geteuid())) {
		throw new Error("Recovery journal must be owned by the backup operator with mode 0600");
	}
	return info;
}
function writeRecoveryJournal(path, journal) {
	if (existsSync(path)) throw new Error("An interrupted backup journal exists; run recover-services before another backup");
	const temporary = `${path}.${process.pid}.${randomBytes(6).toString("hex")}.tmp`;
	let descriptor;
	try {
		descriptor = openSync(temporary, "wx", 0o600);
		writeFileSync(descriptor, `${JSON.stringify(journal)}\n`);
		fsyncSync(descriptor);
		closeSync(descriptor);
		descriptor = undefined;
		linkSync(temporary, path);
		unlinkSync(temporary);
		syncDirectory(dirname(path));
		return assertPrivateJournal(path);
	} catch (error) {
		if (descriptor !== undefined) closeSync(descriptor);
		try { unlinkSync(temporary); } catch { /* no temporary file was published */ }
		throw error;
	}
}
function clearRecoveryJournal(path, expected) {
	const current = assertPrivateJournal(path);
	if (current.dev !== expected.dev || current.ino !== expected.ino) throw new Error("Recovery journal changed identity; it was retained");
	unlinkSync(path);
	syncDirectory(dirname(path));
}
function assertPrivateRecoveryKey(path) {
	const info = lstatSync(path);
	if (!info.isFile() || info.isSymbolicLink() || info.nlink !== 1) throw new Error("Recovery key must be a regular non-linked file");
	if (process.platform !== "win32") {
		const credentialRoot = process.env.CREDENTIALS_DIRECTORY ? resolve(process.env.CREDENTIALS_DIRECTORY) : null;
		const credentialCopy = credentialRoot && (path === credentialRoot || path.startsWith(`${credentialRoot}${sep}`));
		const expectedMode = credentialCopy ? 0o400 : 0o600;
		if ((info.mode & 0o777) !== expectedMode || (typeof process.geteuid === "function" && info.uid !== process.geteuid())) {
			throw new Error(`Recovery key must be owned by the service account with mode ${expectedMode.toString(8)}`);
		}
	}
}
let rawKey = null;
if (action !== "recover-services") {
	canonicalExisting(keyPath, "Recovery key");
	await assertRecoveryKeyFileAcl(keyPath);
	assertPrivateRecoveryKey(keyPath);
	const keyText = readFileSync(keyPath, "utf8").trim();
	if (!/^[a-f0-9]{64}$/i.test(keyText)) throw new Error("Recovery key must contain 32 random bytes encoded as hex");
	rawKey = Buffer.from(keyText, "hex");
}
const encKey = rawKey && Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "encryption", 32));
const macKey = rawKey && Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "manifest", 32));
// The Supabase image's pgsodium_getkey.sh reads (and, when absent, silently
// generates) this file on the db-config volume. Every Vault secret and
// pgsodium-encrypted value in the database is useless without it, so the cold
// backup seals it under a dedicated subkey of the same recovery key and records
// it in the HMAC-authenticated manifest. It is never written to host disk.
const PGSODIUM_CONFIG_DIR = "/etc/postgresql-custom";
const PGSODIUM_KEY_NAME = "pgsodium_root.key";
const PGSODIUM_KEY_AAD = Buffer.from(`aidr-backup-v1/${PGSODIUM_KEY_NAME}`);
const PGSODIUM_KEY_FORMAT = /^[0-9a-fA-F]{64}\n?$/;
const VAULT_KEY_MISSING = "VAULT_KEY_MISSING";
const vaultKey = rawKey && Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "pgsodium-root-key", 32));
let helperImage;
const output = values.output ? canonicalNew(values.output, "Output") : null;
let ownedBackupOutput;
function backupOutputIsOwned() {
  if (!ownedBackupOutput || !existsSync(output)) return false;
  const current = lstatSync(output);
  return current.isDirectory() && !current.isSymbolicLink() && current.dev === ownedBackupOutput.dev && current.ino === ownedBackupOutput.ino;
}
function assertOwnedBackupOutput() {
  if (!backupOutputIsOwned()) throw new Error("Backup output changed identity during the snapshot");
}
const dir = action === "backup" ? canonicalExisting(values.deployment, "Deployment") : null;
const within = (child, parent) => child === parent || child.startsWith(parent + sep);
function command(exe, args) {
  const run = spawnSync(exe, args, { encoding: "utf8", timeout: 180000, maxBuffer: 16 * 1024 * 1024 });
  if (run.status !== 0) throw new Error(`${exe} ${args[0]} failed (exit ${run.status}); inspect the service locally. No environment or credentials printed.`);
  return run.stdout.trim();
}
const composeArgs = (directory, project) => ["compose", "--project-directory", directory, "-f", join(directory, "compose.yml"), ...(project ? ["--project-name", project] : [])];
function validComposeProject(value) {
	return typeof value === "string" && /^[a-z0-9][a-z0-9_-]*$/.test(value);
}
function validComposeServices(value) {
	return Array.isArray(value) && value.length > 0 && value.every((service) => typeof service === "string" && /^[A-Za-z0-9][A-Za-z0-9_.-]*$/.test(service)) && new Set(value).size === value.length;
}
function recoverInterruptedServices(deploymentPath, journalArgument) {
	if (!journalArgument || !isAbsolute(journalArgument)) throw new Error("recover-services requires an absolute --recovery-journal path");
	const journalPath = canonicalExisting(journalArgument, "Recovery journal");
	const journalIdentity = assertPrivateJournal(journalPath);
	const deployment = canonicalExisting(deploymentPath, "Deployment");
	if (within(journalPath, deployment) || within(deployment, journalPath)) throw new Error("Recovery journal and deployment must be separate");
	const journal = JSON.parse(readFileSync(journalPath, "utf8"));
	const expectedKeys = ["created_at", "deployment_dir", "project_name", "runtime_deployment_sha256", "runtime_tree_sha256", "schema_version", "services", "source_commit"];
	if (!journal || Object.keys(journal).sort().join(",") !== expectedKeys.join(",") || journal.schema_version !== 1 || journal.deployment_dir !== deployment) {
		throw new Error("Recovery journal is invalid or belongs to another deployment");
	}
	if (!validComposeProject(journal.project_name) || !SOURCE_COMMIT.test(journal.source_commit ?? "") || !validComposeServices(journal.services) || !journal.services.includes("db")
		|| !/^[a-f0-9]{64}$/.test(journal.runtime_deployment_sha256 ?? "") || !/^[a-f0-9]{64}$/.test(journal.runtime_tree_sha256 ?? "")
		|| !Number.isFinite(Date.parse(journal.created_at)) || new Date(journal.created_at).toISOString() !== journal.created_at) {
		throw new Error("Recovery journal contains invalid deployment or service identity");
	}
	const binding = inspectReviewedRuntime(deployment, { sourceCommit: journal.source_commit });
	if (binding.deployment.project_name !== journal.project_name || binding.runtime_deployment_sha256 !== journal.runtime_deployment_sha256 || binding.runtime_tree_sha256 !== journal.runtime_tree_sha256) {
		throw new Error("Recovery journal does not match the current deployment; no Compose service was started");
	}
	const args = composeArgs(deployment, journal.project_name);
	const configured = new Set(command("docker", [...args, "config", "--services"]).split(/\r?\n/).filter(Boolean));
	if (journal.services.some((service) => !configured.has(service))) throw new Error("Recovery journal names a service outside the bound Compose project");
	command("docker", [...args, "start", ...journal.services]);
	const running = new Set(command("docker", [...args, "ps", "--services", "--status", "running"]).split(/\r?\n/).filter(Boolean));
	const missing = journal.services.filter((service) => !running.has(service));
	if (missing.length > 0) throw new Error(`Recovery could not confirm originally running services: ${missing.join(", ")}; journal retained`);
	clearRecoveryJournal(journalPath, journalIdentity);
	return { recovered_services: journal.services };
}
function assertUnusedRecoveryProject(project) {
  for (const resource of ["ps", "volume", "network"]) {
    const args = resource === "ps" ? ["ps", "--all", "--quiet"] : [resource, "ls", "--quiet"];
    if (command("docker", [...args, "--filter", `label=com.docker.compose.project=${project}`])) throw new Error(`Recovery project ${project} already owns Docker resources`);
  }
  for (const name of ["aidr-db", "aidr-storage", "db-config"]) {
    const result = spawnSync("docker", ["volume", "inspect", `${project}_${name}`], { encoding: "utf8", timeout: 180000, maxBuffer: 1024 * 1024 });
    if (result.status === 0) throw new Error(`Recovery volume ${project}_${name} already exists`);
    if (result.status !== 1) throw new Error("Could not verify that recovery volume names are unused");
  }
}
function inspectMount(directory, service, destination, project) {
  const id = command("docker", [...composeArgs(directory, project), "ps", "--all", "--quiet", service]);
  if (!id || id.includes("\n")) throw new Error(`Expected one ${service} container`);
  const mount = JSON.parse(command("docker", ["inspect", id]))[0].Mounts.find((entry) => entry.Destination === destination);
  if (mount?.Type !== "volume" || !/^[a-zA-Z0-9_.-]+$/.test(mount.Name)) throw new Error(`Expected a named ${service} volume`);
  return mount.Name;
}
if (action === "recover-services") {
	console.log(JSON.stringify(recoverInterruptedServices(values.deployment, values["recovery-journal"])));
	process.exit(0);
}
async function digest(path) {
  const hash = createHash("sha256"); for await (const chunk of createReadStream(path)) hash.update(chunk); return hash.digest("hex");
}
function child(exe, args, signal) {
	const proc = spawn(exe, args, { stdio: ["pipe", "pipe", "pipe"], ...(signal ? { signal } : {}) });
  // Never echo raw child output: archives and service logs can contain secrets.
  proc.stderr.resume();
  const finished = new Promise((done, fail) => { proc.on("error", fail); proc.on("close", (code) => code === 0 ? done() : fail(new Error(`${exe} archive operation failed (exit ${code})`))); });
  return { proc, finished };
}
async function encrypt(exe, args, name, signal) {
  assertOwnedBackupOutput();
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encKey, iv); cipher.setAAD(Buffer.from(name));
  const path = join(output, name);
	const { proc, finished } = child(exe, args, signal); proc.stdin.end();
  try {
	await Promise.all([
		pipeline(proc.stdout, cipher, createWriteStream(path, { flags: "wx", mode: 0o600 })),
		pipeline(proc.stdout, createGunzip(), createTarBoundaryValidator()),
		finished,
	]);
  }
  catch (error) { proc.kill(); throw error; }
  return { name, iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), sha256: await digest(path) };
}
async function decryptTo(entry, backup, exe, args) {
  const decipher = createDecipheriv("aes-256-gcm", encKey, Buffer.from(entry.iv, "hex"));
  decipher.setAAD(Buffer.from(entry.name)); decipher.setAuthTag(Buffer.from(entry.tag, "hex"));
  const { proc, finished } = child(exe, args); proc.stdout.resume();
  try { await Promise.all([pipeline(createReadStream(join(backup, entry.name)), decipher, proc.stdin), finished]); }
  catch (error) { proc.kill(); throw error; }
}
function sha256Hex(bytes) {
	return createHash("sha256").update(bytes).digest("hex");
}
function validPgsodiumRootKey(bytes) {
	return Buffer.isBuffer(bytes) && bytes.length <= 65 && PGSODIUM_KEY_FORMAT.test(bytes.toString("latin1"));
}
// Reads the key from the stopped source's db-config volume through the
// network-isolated helper. Exit 66 means the file was never generated.
function readPgsodiumRootKey(volume) {
	const key = `/config/${PGSODIUM_KEY_NAME}`;
	const run = spawnSync("docker", ["run", "--rm", "--network", "none", "--mount", `type=volume,src=${volume},dst=/config,readonly`, helperImage, "sh", "-c", `if [ -L ${key} ]; then exit 65; fi; if [ ! -e ${key} ]; then exit 66; fi; [ -f ${key} ] || exit 65; head -c 4096 ${key}`], { timeout: 180000, maxBuffer: 8192 });
	if (run.status === 66) return null;
	if (run.status !== 0) throw new Error(`Could not read ${PGSODIUM_KEY_NAME} from the db-config volume; snapshot rejected`);
	if (!validPgsodiumRootKey(run.stdout)) throw new Error(`${PGSODIUM_KEY_NAME} on the db-config volume is not a 32-byte hex key; snapshot rejected`);
	return run.stdout;
}
function sealPgsodiumRootKey(bytes) {
	const path = `${PGSODIUM_CONFIG_DIR}/${PGSODIUM_KEY_NAME}`;
	if (!bytes) return { status: "absent_at_source", path };
	const iv = randomBytes(12);
	const cipher = createCipheriv("aes-256-gcm", vaultKey, iv); cipher.setAAD(PGSODIUM_KEY_AAD);
	const ciphertext = Buffer.concat([cipher.update(bytes), cipher.final()]);
	return { status: "captured", path, bytes: bytes.length, sha256: sha256Hex(bytes), iv: iv.toString("hex"), tag: cipher.getAuthTag().toString("hex"), ciphertext: ciphertext.toString("hex") };
}
// Returns the authenticated key bytes, null when the source never had a key,
// or VAULT_KEY_MISSING for a backup made before the key was captured.
function openPgsodiumRootKey(record) {
	if (record === undefined) return VAULT_KEY_MISSING;
	const path = `${PGSODIUM_CONFIG_DIR}/${PGSODIUM_KEY_NAME}`;
	const keys = Object.keys(record ?? {}).sort().join(",");
	if (record?.status === "absent_at_source" && keys === "path,status" && record.path === path) return null;
	if (record?.status !== "captured" || keys !== "bytes,ciphertext,iv,path,sha256,status,tag" || record.path !== path
		|| !/^[a-f0-9]{24}$/.test(record.iv) || !/^[a-f0-9]{32}$/.test(record.tag) || !/^[a-f0-9]{64}$/.test(record.sha256)
		|| !/^(?:[a-f0-9]{2}){64,65}$/.test(record.ciphertext) || record.ciphertext.length !== record.bytes * 2) {
		throw new Error("Unsupported pgsodium/Vault root key record in the backup manifest");
	}
	let bytes;
	try {
		const decipher = createDecipheriv("aes-256-gcm", vaultKey, Buffer.from(record.iv, "hex"));
		decipher.setAAD(PGSODIUM_KEY_AAD); decipher.setAuthTag(Buffer.from(record.tag, "hex"));
		bytes = Buffer.concat([decipher.update(Buffer.from(record.ciphertext, "hex")), decipher.final()]);
	} catch {
		throw new Error("pgsodium/Vault root key authentication failed: wrong key or modified backup");
	}
	if (!validPgsodiumRootKey(bytes) || sha256Hex(bytes) !== record.sha256) throw new Error("pgsodium/Vault root key integrity check failed");
	return bytes;
}
// Writes the key into the recovered project's db-config volume after Compose
// created it (Docker has already copied the image's default configuration in),
// owned by the restored PGDATA owner with mode 0600, and never over an existing file.
function restorePgsodiumRootKey(configVolume, dataVolume, bytes) {
	const key = `/config/${PGSODIUM_KEY_NAME}`;
	const temporary = `/config/.${PGSODIUM_KEY_NAME}.aidr-restore`;
	const shell = `set -euC; for p in ${key} ${temporary}; do if [ -e "$p" ] || [ -L "$p" ]; then exit 74; fi; done; owner=$(stat -c %u:%g /pgdata/PG_VERSION); case "$owner" in 0:*|*:0) exit 75;; esac; umask 077; cat > ${temporary}; chown "$owner" ${temporary}; chmod 0600 ${temporary}; mv ${temporary} ${key}; [ "$(stat -c %u:%g:%a ${key})" = "$owner:600" ] || exit 76; sha256sum ${key}`;
	const run = spawnSync("docker", ["run", "--rm", "-i", "--network", "none", "--mount", `type=volume,src=${configVolume},dst=/config`, "--mount", `type=volume,src=${dataVolume},dst=/pgdata,readonly`, helperImage, "sh", "-c", shell], { input: bytes, encoding: "utf8", timeout: 180000, maxBuffer: 8192 });
	if (run.status !== 0) throw new Error(`Could not restore ${PGSODIUM_KEY_NAME} into the recovered db-config volume (exit ${run.status})`);
	if (run.stdout.trim().split(/\s+/)[0] !== sha256Hex(bytes)) throw new Error(`Restored ${PGSODIUM_KEY_NAME} does not match the authenticated backup`);
}
async function validateEncryptedTar(entry, backup) {
  const decipher = createDecipheriv("aes-256-gcm", encKey, Buffer.from(entry.iv, "hex"));
  decipher.setAAD(Buffer.from(entry.name)); decipher.setAuthTag(Buffer.from(entry.tag, "hex"));
  await pipeline(createReadStream(join(backup, entry.name)), decipher, createGunzip(), createTarBoundaryValidator());
}

if (action === "backup") {
  if (!output || existsSync(output)) throw new Error("Provide a new --output directory; backups are never overwritten");
  if (!values["recovery-journal"]) throw new Error("Backup requires --recovery-journal so a boot can restart only services that were running before an interruption");
  if (!values.maintenance) throw new Error("Cold backup stops this AIDR deployment during the snapshot. Specify --maintenance in your scheduled maintenance window.");
  if (within(keyPath, dir) || within(keyPath, output) || within(output, dir)) throw new Error("Keep the backup and recovery key outside the installation, and keep the key outside the backup");
	const recoveryJournal = journalPathForWrite(values["recovery-journal"]);
	if (within(recoveryJournal, dir) || within(dir, recoveryJournal) || within(recoveryJournal, output) || within(output, recoveryJournal) || within(keyPath, recoveryJournal) || within(recoveryJournal, keyPath)) {
		throw new Error("Keep the recovery journal separate from the installation, backup output and recovery key");
	}
	const deployment = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
	if (deployment.mode !== "self-hosted") throw new Error("Hosted cloud databases require the provider's backup and recovery workflow");
	if (!SOURCE_COMMIT.test(deployment.source_commit ?? "") || deployment.source_has_changes !== false) throw new Error("Backup requires a clean deployment with a 40-64 character source commit");
	if (!validComposeProject(deployment.project_name)) throw new Error("Backup deployment has no valid Compose project name");
	const installationBinding = inspectReviewedRuntime(dir, { sourceCommit: deployment.source_commit });
  helperImage = buildNodeHelperImage();
  command(systemTar(), ["--version"]);
	const project = deployment.project_name;
	const dbVolume = inspectMount(dir, "db", "/var/lib/postgresql/data", project);
	const storageVolume = inspectMount(dir, "storage", "/var/lib/storage", project);
	const configVolume = inspectMount(dir, "db", PGSODIUM_CONFIG_DIR, project);
	const running = command("docker", [...composeArgs(dir, project), "ps", "--services", "--status", "running"]).split(/\r?\n/).filter(Boolean);
	if (!running.includes("db")) throw new Error("The source database must be running and healthy before backup");
	if (!validComposeServices(running)) throw new Error("Compose returned an invalid running-service list");
	command("docker", [...composeArgs(dir, project), "exec", "-T", "db", "pg_isready", "-U", "postgres"]);
	mkdirSync(output, { mode: 0o700 });
	ownedBackupOutput = lstatSync(output);
	const started = new Date().toISOString(); const entries = [];
	const abort = new AbortController();
	let interrupted = null;
	let failure = null;
	let completed = false;
	let journalIdentity;
	const interrupt = (signal) => {
		if (interrupted) return;
		interrupted = signal;
		abort.abort();
	};
	const onInterrupt = () => interrupt("SIGINT");
	const onTerminate = () => interrupt("SIGTERM");
	const checkInterrupted = () => {
		if (interrupted) throw new Error(`Backup interrupted by ${interrupted}`);
	};
	process.on("SIGINT", onInterrupt);
	process.on("SIGTERM", onTerminate);
	console.log("Stopping only this AIDR project's running services for a consistent database and object snapshot.");
	try {
		journalIdentity = writeRecoveryJournal(recoveryJournal, {
			schema_version: 1,
			deployment_dir: dir,
			project_name: project,
			source_commit: deployment.source_commit,
			runtime_deployment_sha256: installationBinding.runtime_deployment_sha256,
			runtime_tree_sha256: installationBinding.runtime_tree_sha256,
			services: [...running].sort(),
			created_at: started,
		});
		command("docker", [...composeArgs(dir, project), "stop", "--timeout", "60", ...running]);
		checkInterrupted();
		const remaining = command("docker", [...composeArgs(dir, project), "ps", "--services", "--status", "running"]);
		if (remaining) throw new Error("Some services are still running; consistent backup aborted");
    // Confirm PostgreSQL completed a clean shutdown; a killed database is not
    // accepted as a successful cold snapshot.
		const control = command("docker", ["run", "--rm", "--network", "none", "--user", "root", "--mount", `type=volume,src=${dbVolume},dst=/data,readonly`, "--entrypoint", "pg_controldata", JSON.parse(command("docker", ["inspect", command("docker", [...composeArgs(dir, project), "ps", "--all", "--quiet", "db"]) ]))[0].Config.Image, "/data"]);
		if (!/Database cluster state:\s+shut down\s*$/m.test(control)) throw new Error("Database did not shut down cleanly; snapshot rejected");
		checkInterrupted();
		const pgsodiumRootKey = sealPgsodiumRootKey(readPgsodiumRootKey(configVolume));
		for (const [name, volume] of [["database.tar.gz.enc", dbVolume], ["storage.tar.gz.enc", storageVolume]]) {
			checkInterrupted();
			entries.push(await encrypt("docker", ["run", "--rm", "--network", "none", "--mount", `type=volume,src=${volume},dst=/data,readonly`, helperImage, "tar", "-C", "/data", "-czf", "-", "."], name, abort.signal));
		}
		checkInterrupted();
		entries.push(await encrypt(systemTar(), ["-C", tarDirectory(dir), "-czf", "-", ...REVIEWED_RUNTIME_ARCHIVE_ENTRIES], "installation.tar.gz.enc", abort.signal));
		checkInterrupted();
		const payload = JSON.stringify({ schema_version: 1, type: "aidr-cold-volumes", started_at: started, completed_at: new Date().toISOString(), source_project: deployment.project_name ?? "legacy", source_commit: deployment.source_commit, installation_runtime_sha256: installationBinding.runtime_tree_sha256, architecture: command("docker", ["info", "--format", "{{.Architecture}}"]), helper_image: helperImage, entries, pgsodium_root_key: pgsodiumRootKey });
		assertOwnedBackupOutput();
		writeFileSync(join(output, "backup.json"), JSON.stringify({ payload, hmac_sha256: createHmac("sha256", macKey).update(payload).digest("hex") }, null, 2), { mode: 0o600, flag: "wx" });
		completed = true;
	} catch (error) {
		failure = error;
	} finally {
		const restartFailures = [];
		// Only the invocation that owns the journal may resume the snapshot's
		// services. A concurrent backup must not start them while another archives.
		for (const service of journalIdentity ? running : []) {
			try { command("docker", [...composeArgs(dir, project), "start", service]); }
			catch { restartFailures.push(service); }
		}
		if (journalIdentity && restartFailures.length === 0) {
			try {
				const active = new Set(command("docker", [...composeArgs(dir, project), "ps", "--services", "--status", "running"]).split(/\r?\n/).filter(Boolean));
				restartFailures.push(...running.filter((service) => !active.has(service)));
			} catch { restartFailures.push("running-state verification"); }
		}
		if (restartFailures.length === 0 && journalIdentity) {
			try { clearRecoveryJournal(recoveryJournal, journalIdentity); }
			catch { restartFailures.push("recovery journal cleanup"); }
		}
		process.removeListener("SIGINT", onInterrupt);
		process.removeListener("SIGTERM", onTerminate);
		if (!completed) {
			if (!backupOutputIsOwned()) failure = new Error(`${failure?.message ?? "Backup failed"}; backup output changed identity and was not removed`);
			else {
				try { rmSync(output, { recursive: true, force: true }); }
				catch { failure = new Error(`${failure?.message ?? "Backup failed"}; partial backup cleanup failed`); }
			}
		}
		if (restartFailures.length > 0) {
			failure = new Error(`${failure?.message ?? "Backup completed"}; could not restart originally running services: ${restartFailures.join(", ")}`);
		} else if (journalIdentity) {
			console.log("Previously running source services restarted. Verify health before ending the maintenance window.");
		}
	}
	if (interrupted) {
		console.error(`AIDR backup interrupted by ${interrupted}; ${failure?.message ?? "inspect cleanup and restarted services"}.`);
		process.exit(interrupted === "SIGINT" ? 130 : 143);
	}
	if (failure) throw failure;
	console.log("Encrypted backup completed. Database, object storage, configuration and the pgsodium/Vault root key are authenticated; no plaintext archive written.");
	process.exit(0);
}

if (!values.backup) throw new Error("--backup directory required");
const backup = canonicalExisting(values.backup, "Backup");
if (within(keyPath, backup)) throw new Error("Keep the recovery key outside the backup directory");
const envelope = JSON.parse(readFileSync(join(backup, "backup.json"), "utf8"));
const expectedMac = createHmac("sha256", macKey).update(envelope.payload).digest();
const actualMac = Buffer.from(envelope.hmac_sha256 ?? "", "hex");
if (actualMac.length !== expectedMac.length || !timingSafeEqual(actualMac, expectedMac)) throw new Error("Backup manifest authentication failed: wrong key or modified backup");
const manifest = JSON.parse(envelope.payload);
const expectedNames = ["database.tar.gz.enc", "storage.tar.gz.enc", "installation.tar.gz.enc"];
if (manifest.schema_version !== 1 || manifest.type !== "aidr-cold-volumes" || !SOURCE_COMMIT.test(manifest.source_commit ?? "") || !/^[a-f0-9]{64}$/.test(manifest.installation_runtime_sha256 ?? "") || !Array.isArray(manifest.entries) || manifest.entries.length !== 3 || !expectedNames.every((name) => manifest.entries.filter((entry) => entry.name === name).length === 1)) throw new Error("Unsupported backup manifest, source commit or installation binding");
for (const entry of manifest.entries) {
  if (!/^[a-f0-9]{24}$/.test(entry.iv) || !/^[a-f0-9]{32}$/.test(entry.tag) || await digest(join(backup, entry.name)) !== entry.sha256) throw new Error("Backup file integrity check failed");
  // Authenticate and structurally validate every archive before creating
  // recovery containers, volumes or plaintext files.
  await validateEncryptedTar(entry, backup);
}
const pgsodiumRootKey = openPgsodiumRootKey(manifest.pgsodium_root_key);
const vaultRootKeyStatus = pgsodiumRootKey === VAULT_KEY_MISSING ? VAULT_KEY_MISSING : pgsodiumRootKey ? "captured" : "absent_at_source";
function warnVaultKeyMissing(consequence) {
	console.error(`${VAULT_KEY_MISSING}: this backup predates pgsodium/Vault root key capture. ${consequence} Supabase Vault secrets and pgsodium-encrypted values cannot be decrypted unless the source ${PGSODIUM_KEY_NAME} held in separate custody is written to the recovered db-config volume (deploy/backup/README.md). AIDR's own schema does not use Vault.`);
}
if (action === "verify") {
	if (pgsodiumRootKey === VAULT_KEY_MISSING) warnVaultKeyMissing("Its data archives verified.");
	console.log(`Backup manifest, ciphertext hashes, encryption tags and archive boundaries verified. pgsodium/Vault root key: ${vaultRootKeyStatus === "captured" ? `captured and authenticated (sha256 ${manifest.pgsodium_root_key.sha256})` : vaultRootKeyStatus}.`);
	process.exit(0);
}
if (!output || existsSync(output) || within(keyPath, output) || within(output, backup)) throw new Error("Recovery requires a new separate --output directory; existing installations and backups cannot be overwritten");
if (!values.runtime) throw new Error("Recovery requires --runtime with a reviewed clean deployment bound to the backup source commit");
const runtime = canonicalExisting(values.runtime, "Reviewed runtime");
if (within(keyPath, runtime) || within(runtime, backup) || within(backup, runtime)) throw new Error("Keep the reviewed runtime separate from recovery-key custody and the backup directory");
if (manifest.architecture !== command("docker", ["info", "--format", "{{.Architecture}}"] )) throw new Error("Physical database recovery requires the same architecture and database image");
const reviewedBinding = inspectReviewedRuntime(runtime, { sourceCommit: manifest.source_commit });
helperImage = buildNodeHelperImage();
const project = values.project ?? `aidr-recovery-${randomBytes(8).toString("hex")}`;
if (!RECOVERY_PROJECT.test(project)) throw new Error("Recovery project name is invalid");
assertUnusedRecoveryProject(project);
let ownedOutput;
let dockerCreateStarted = false;
try {
  mkdirSync(output, { mode: 0o700 });
  ownedOutput = lstatSync(output);
  const installationStaging = mkdtempSync(join(dirname(output), ".aidr-installation-"));
  let installationBinding;
  try {
	await hardenWorkDirectory(installationStaging);
	await decryptTo(manifest.entries.find((entry) => entry.name === "installation.tar.gz.enc"), backup, systemTar(), ["-C", tarDirectory(installationStaging), "-xzf", "-"]);
	mkdirSync(join(installationStaging, "health"), { recursive: true, mode: 0o755 });
	installationBinding = inspectAuthenticatedInstallation(installationStaging, {
		sourceCommit: manifest.source_commit,
		expectedTreeSha256: manifest.installation_runtime_sha256,
		reviewedDeployment: reviewedBinding.deployment,
	});
	copyReviewedRuntime(installationStaging, output, { sourceCommit: manifest.source_commit });
  } finally {
	rmSync(installationStaging, { recursive: true, force: true });
  }
  await hardenWorkDirectory(output);
  // COMPOSE_PROJECT_NAME takes precedence over the reviewed compose.name.
  writeFileSync(join(output, ".env"), readFileSync(join(output, ".env"), "utf8").replace(/^COMPOSE_PROJECT_NAME=.*\r?\n/gm, "") + `\nCOMPOSE_PROJECT_NAME=${project}\n`, { mode: 0o600 });
  dockerCreateStarted = true;
  command("docker", [...composeArgs(output, project), "create", "--build", "db", "storage"]);
  const restoredVolumes = {};
  for (const [name, service, destination] of [["database.tar.gz.enc", "db", "/var/lib/postgresql/data"], ["storage.tar.gz.enc", "storage", "/var/lib/storage"]]) {
	const volume = inspectMount(output, service, destination, project);
	restoredVolumes[service] = volume;
	await decryptTo(manifest.entries.find((entry) => entry.name === name), backup, "docker", ["run", "--rm", "-i", "--network", "none", "--mount", `type=volume,src=${volume},dst=/data`, helperImage, "sh", "-c", 'test -z "$(ls -A /data)" || exit 74; tar -C /data -xzf -']);
  }
  // Before the database first starts: otherwise pgsodium_getkey.sh would
  // generate a fresh random key and every restored Vault secret would fail
  // with "invalid ciphertext".
  if (Buffer.isBuffer(pgsodiumRootKey)) restorePgsodiumRootKey(inspectMount(output, "db", PGSODIUM_CONFIG_DIR, project), restoredVolumes.db, pgsodiumRootKey);
  const vaultRootKey = vaultRootKeyStatus === "captured" ? "restored" : vaultRootKeyStatus;
  const restoredManifest = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
  restoredManifest.project_name = project;
  writeFileSync(join(output, "deployment.json"), JSON.stringify(restoredManifest, null, 2), { mode: 0o600 });
  writeFileSync(join(output, "recovery-receipt.json"), JSON.stringify({ completed_at: new Date().toISOString(), project_name: project, backup_completed_at: manifest.completed_at, backup_manifest_sha256: await digest(join(backup, "backup.json")), reviewed_runtime_deployment_sha256: reviewedBinding.runtime_deployment_sha256, reviewed_runtime_tree_sha256: reviewedBinding.runtime_tree_sha256, installation_runtime_deployment_sha256: installationBinding.runtime_deployment_sha256, installation_runtime_tree_sha256: installationBinding.runtime_tree_sha256, source_commit: reviewedBinding.source_commit, vault_root_key: vaultRootKey, ...(vaultRootKey === "restored" ? { vault_root_key_sha256: manifest.pgsodium_root_key.sha256 } : {}), services_started: false, scope: "New volumes and their exact authenticated installation configuration recovered against reviewed code inventories. Start and validate in an isolated environment before traffic cutover." }, null, 2), { mode: 0o600 });
  if (vaultRootKey === VAULT_KEY_MISSING) warnVaultKeyMissing(`Recovery completed without it; the recovery receipt records vault_root_key: ${VAULT_KEY_MISSING}.`);
  console.log(`Recovered exact authenticated installation configuration into an independent project with new volumes. pgsodium/Vault root key: ${vaultRootKey}. Services remain stopped; perform health, login, policy and storage acceptance before traffic cutover.`);
} catch (error) {
  const failures = [];
  const current = ownedOutput && existsSync(output) ? lstatSync(output) : null;
  const stillOwned = current?.isDirectory() && !current.isSymbolicLink() && current.dev === ownedOutput.dev && current.ino === ownedOutput.ino;
  if (dockerCreateStarted && stillOwned) {
    try { command("docker", [...composeArgs(output, project), "down", "--volumes", "--remove-orphans"]); }
    catch { failures.push(`Docker project ${project} may retain recovery volumes`); }
  }
  if (stillOwned) {
    try { rmSync(output, { recursive: true }); }
    catch { failures.push(`Plaintext recovery directory ${output} could not be removed`); }
  } else if (ownedOutput) failures.push(`Recovery directory ${output} changed identity; it was not removed`);
  if (failures.length) throw new Error(`${error.message}; cleanup incomplete: ${failures.join("; ")}`);
  throw error;
}
