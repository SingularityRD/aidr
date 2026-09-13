#!/usr/bin/env node
// Cold, encrypted volume backup. Recovery always creates a new project and new
// volumes. No command in this tool overwrites or deletes an existing database.
import { createCipheriv, createDecipheriv, createHash, createHmac, hkdfSync, randomBytes, timingSafeEqual } from "node:crypto";
import { createReadStream, createWriteStream, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve, sep } from "node:path";
import { spawn, spawnSync } from "node:child_process";
import { pipeline } from "node:stream/promises";
import { parseArgs } from "node:util";
import { hardenWorkDirectory } from "./deployment-restore-drill.mjs";

const { values, positionals } = parseArgs({ allowPositionals: true, options: { deployment: { type: "string", default: ".aidr-deploy" }, output: { type: "string" }, backup: { type: "string" }, "key-file": { type: "string" }, maintenance: { type: "boolean", default: false } } });
const action = positionals[0];
if (!["keygen", "backup", "verify", "recover"].includes(action) || !values["key-file"]) throw new Error("Use keygen|backup|verify|recover --key-file <private file>; backup/recover also require --output");
const keyPath = resolve(values["key-file"]);
if (action === "keygen") {
  mkdirSync(dirname(keyPath), { recursive: true, mode: 0o700 });
  writeFileSync(keyPath, randomBytes(32).toString("hex") + "\n", { mode: 0o600, flag: "wx" });
  console.log("Created a private recovery key. Store it separately from the installation and backup; losing it makes recovery impossible.");
  process.exit(0);
}
const keyText = readFileSync(keyPath, "utf8").trim();
if (!/^[a-f0-9]{64}$/i.test(keyText)) throw new Error("Recovery key must contain 32 random bytes encoded as hex");
const rawKey = Buffer.from(keyText, "hex");
const encKey = Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "encryption", 32));
const macKey = Buffer.from(hkdfSync("sha256", rawKey, "aidr-backup-v1", "manifest", 32));
const helperImage = "node:24.12.0-alpine3.23";
const output = values.output ? resolve(values.output) : null;
const dir = resolve(values.deployment);
const within = (child, parent) => child === parent || child.startsWith(parent + sep);
function command(exe, args) {
  const run = spawnSync(exe, args, { encoding: "utf8", timeout: 180000, maxBuffer: 16 * 1024 * 1024 });
  if (run.status !== 0) throw new Error(`${exe} ${args[0]} failed (exit ${run.status}); inspect the service locally. No environment or credentials printed.`);
  return run.stdout.trim();
}
const composeArgs = (directory, project) => ["compose", "--project-directory", directory, "-f", join(directory, "compose.yml"), ...(project ? ["--project-name", project] : [])];
function inspectMount(directory, service, destination, project) {
  const id = command("docker", [...composeArgs(directory, project), "ps", "--all", "--quiet", service]);
  if (!id || id.includes("\n")) throw new Error(`Expected one ${service} container`);
  const mount = JSON.parse(command("docker", ["inspect", id]))[0].Mounts.find((entry) => entry.Destination === destination);
  if (mount?.Type !== "volume" || !/^[a-zA-Z0-9_.-]+$/.test(mount.Name)) throw new Error(`Expected a named ${service} volume`);
  return mount.Name;
}
async function digest(path) {
  const hash = createHash("sha256"); for await (const chunk of createReadStream(path)) hash.update(chunk); return hash.digest("hex");
}
function child(exe, args) {
  const proc = spawn(exe, args, { stdio: ["pipe", "pipe", "pipe"] });
  // Never echo raw child output: archives and service logs can contain secrets.
  proc.stderr.resume();
  const finished = new Promise((done, fail) => { proc.on("error", fail); proc.on("close", (code) => code === 0 ? done() : fail(new Error(`${exe} archive operation failed (exit ${code})`))); });
  return { proc, finished };
}
async function encrypt(exe, args, name) {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", encKey, iv); cipher.setAAD(Buffer.from(name));
  const path = join(output, name);
  const { proc, finished } = child(exe, args); proc.stdin.end();
  try { await Promise.all([pipeline(proc.stdout, cipher, createWriteStream(path, { flags: "wx", mode: 0o600 })), finished]); }
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

if (action === "backup") {
  if (!output || existsSync(output)) throw new Error("Provide a new --output directory; backups are never overwritten");
  if (!values.maintenance) throw new Error("Cold backup stops this AIDR deployment during the snapshot. Specify --maintenance in your scheduled maintenance window.");
  if (within(keyPath, dir) || within(keyPath, output) || within(output, dir)) throw new Error("Keep the backup and recovery key outside the installation, and keep the key outside the backup");
  const deployment = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
  if (deployment.mode !== "self-hosted") throw new Error("Hosted cloud databases require the provider's backup and recovery workflow");
  command("docker", ["image", "inspect", helperImage]);
  command("tar", ["--version"]);
  const dbVolume = inspectMount(dir, "db", "/var/lib/postgresql/data");
  const storageVolume = inspectMount(dir, "storage", "/var/lib/storage");
  const running = command("docker", [...composeArgs(dir), "ps", "--services", "--status", "running"]).split(/\r?\n/).filter(Boolean);
  if (!running.includes("db")) throw new Error("The source database must be running and healthy before backup");
  command("docker", [...composeArgs(dir), "exec", "-T", "db", "pg_isready", "-U", "postgres"]);
  mkdirSync(output, { mode: 0o700 });
  const started = new Date().toISOString(); const entries = [];
  console.log("Stopping only this AIDR project's running services for a consistent database and object snapshot.");
  try {
    command("docker", [...composeArgs(dir), "stop", "--timeout", "60", ...running]);
    const remaining = command("docker", [...composeArgs(dir), "ps", "--services", "--status", "running"]);
    if (remaining) throw new Error("Some services are still running; consistent backup aborted");
    // Confirm PostgreSQL completed a clean shutdown; a killed database is not
    // accepted as a successful cold snapshot.
    const control = command("docker", ["run", "--rm", "--network", "none", "--user", "root", "--mount", `type=volume,src=${dbVolume},dst=/data,readonly`, "--entrypoint", "pg_controldata", JSON.parse(command("docker", ["inspect", command("docker", [...composeArgs(dir), "ps", "--all", "--quiet", "db"]) ]))[0].Config.Image, "/data"]);
    if (!/Database cluster state:\s+shut down\s*$/m.test(control)) throw new Error("Database did not shut down cleanly; snapshot rejected");
    for (const [name, volume] of [["database.tar.gz.enc", dbVolume], ["storage.tar.gz.enc", storageVolume]]) {
      entries.push(await encrypt("docker", ["run", "--rm", "--network", "none", "--mount", `type=volume,src=${volume},dst=/data,readonly`, helperImage, "tar", "-C", "/data", "-czf", "-", "."], name));
    }
    entries.push(await encrypt("tar", ["-C", dir, "-czf", "-", ".env", ".env.functions", "compose.yml", "deployment.json", "agent-config.json", "dashboard", "migrations", "volumes"], "installation.tar.gz.enc"));
    const payload = JSON.stringify({ schema_version: 1, type: "aidr-cold-volumes", started_at: started, completed_at: new Date().toISOString(), source_project: deployment.project_name ?? "legacy", source_commit: deployment.source_commit, architecture: command("docker", ["info", "--format", "{{.Architecture}}"]), helper_image: helperImage, entries });
    writeFileSync(join(output, "backup.json"), JSON.stringify({ payload, hmac_sha256: createHmac("sha256", macKey).update(payload).digest("hex") }, null, 2), { mode: 0o600, flag: "wx" });
    console.log("Encrypted backup completed. Database, object storage and configuration are authenticated; no plaintext archive written.");
  } finally {
    command("docker", [...composeArgs(dir), "start", ...running]);
    console.log("Previously running source services restarted. Verify health before ending the maintenance window.");
  }
  process.exit(0);
}

if (!values.backup) throw new Error("--backup directory required");
const backup = resolve(values.backup);
if (within(keyPath, backup)) throw new Error("Keep the recovery key outside the backup directory");
const envelope = JSON.parse(readFileSync(join(backup, "backup.json"), "utf8"));
const expectedMac = createHmac("sha256", macKey).update(envelope.payload).digest();
const actualMac = Buffer.from(envelope.hmac_sha256 ?? "", "hex");
if (actualMac.length !== expectedMac.length || !timingSafeEqual(actualMac, expectedMac)) throw new Error("Backup manifest authentication failed: wrong key or modified backup");
const manifest = JSON.parse(envelope.payload);
const expectedNames = ["database.tar.gz.enc", "storage.tar.gz.enc", "installation.tar.gz.enc"];
if (manifest.schema_version !== 1 || manifest.type !== "aidr-cold-volumes" || manifest.entries.length !== 3 || !expectedNames.every((name) => manifest.entries.filter((entry) => entry.name === name).length === 1)) throw new Error("Unsupported backup manifest");
for (const entry of manifest.entries) {
  if (!/^[a-f0-9]{24}$/.test(entry.iv) || !/^[a-f0-9]{32}$/.test(entry.tag) || await digest(join(backup, entry.name)) !== entry.sha256) throw new Error("Backup file integrity check failed");
  // Authenticate every GCM stream before creating recovery containers or files.
  const decipher = createDecipheriv("aes-256-gcm", encKey, Buffer.from(entry.iv, "hex"));
  decipher.setAAD(Buffer.from(entry.name)); decipher.setAuthTag(Buffer.from(entry.tag, "hex"));
  for await (const chunk of createReadStream(join(backup, entry.name))) decipher.update(chunk);
  decipher.final();
}
if (action === "verify") { console.log("Backup manifest, ciphertext hashes and all authenticated encryption tags verified."); process.exit(0); }
if (!output || existsSync(output) || within(keyPath, output) || within(output, backup)) throw new Error("Recovery requires a new separate --output directory; existing installations and backups cannot be overwritten");
if (manifest.architecture !== command("docker", ["info", "--format", "{{.Architecture}}"] )) throw new Error("Physical database recovery requires the same architecture and database image");
mkdirSync(output, { mode: 0o700 });
await hardenWorkDirectory(output);
await decryptTo(manifest.entries.find((entry) => entry.name === "installation.tar.gz.enc"), backup, "tar", ["-C", output, "-xzf", "-"]);
const project = `aidr-recovery-${randomBytes(8).toString("hex")}`;
// Persist the independent namespace in .env as well as passing it explicitly.
// COMPOSE_PROJECT_NAME takes precedence over the archived compose.name.
writeFileSync(join(output, ".env"), readFileSync(join(output, ".env"), "utf8").replace(/^COMPOSE_PROJECT_NAME=.*\r?\n/gm, "") + `\nCOMPOSE_PROJECT_NAME=${project}\n`, { mode: 0o600 });
command("docker", [...composeArgs(output, project), "create", "--build", "db", "storage"]);
for (const [name, service, destination] of [["database.tar.gz.enc", "db", "/var/lib/postgresql/data"], ["storage.tar.gz.enc", "storage", "/var/lib/storage"]]) {
  const volume = inspectMount(output, service, destination, project);
  await decryptTo(manifest.entries.find((entry) => entry.name === name), backup, "docker", ["run", "--rm", "-i", "--network", "none", "--mount", `type=volume,src=${volume},dst=/data`, helperImage, "sh", "-c", 'test -z "$(ls -A /data)" || exit 74; tar -C /data -xzf -']);
}
const restoredManifest = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
restoredManifest.project_name = project;
writeFileSync(join(output, "deployment.json"), JSON.stringify(restoredManifest, null, 2), { mode: 0o600 });
writeFileSync(join(output, "recovery-receipt.json"), JSON.stringify({ completed_at: new Date().toISOString(), project_name: project, backup_completed_at: manifest.completed_at, backup_manifest_sha256: await digest(join(backup, "backup.json")), services_started: false, scope: "New volumes recovered. Start and validate in an isolated environment before traffic cutover." }, null, 2), { mode: 0o600 });
console.log("Recovered into an independent project with new volumes. Services remain stopped; perform health, login, policy and storage acceptance before traffic cutover.");
