#!/usr/bin/env node
// Controlled self-hosted upgrade orchestration. Database rollback is deliberately
// a restore into a new project; this tool never attempts destructive down-migrations.
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import {
	closeSync,
	copyFileSync,
	existsSync,
	mkdirSync,
	openSync,
	readFileSync,
	readdirSync,
	renameSync,
	rmSync,
	statSync,
	unlinkSync,
	writeFileSync,
} from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";
import {
	compatibleInstalledHashes,
	isAuditedLegacyMigration,
	migrationHashesMatch,
} from "./lib/migration-hash-compat.mjs";
import {
	forbiddenMigrationControls,
	MIGRATION_FILENAME_PATTERN,
	migrationOrderError,
} from "./lib/migration-contract.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const { values, positionals } = parseArgs({
	allowPositionals: true,
	options: {
		current: { type: "string" },
		target: { type: "string" },
		backup: { type: "string" },
		"key-file": { type: "string" },
		contract: { type: "string" },
		"recovery-output": { type: "string" },
		"recovery-runtime": { type: "string" },
		"max-backup-age-hours": { type: "string", default: "24" },
		maintenance: { type: "boolean", default: false },
	},
});
const action = positionals[0];
if (!["check", "preflight", "apply", "resume", "rollback-plan", "recover"].includes(action)) {
	throw new Error("Use check with --current, --target and --contract, or preflight|apply|resume|rollback-plan|recover with --current, --target, --backup, --key-file and --contract; recover also requires --recovery-runtime");
}
// `check` is the read-only compatibility gate run before a backup exists: it
// needs no backup, takes no lock and writes nothing.
for (const name of action === "check" ? ["current", "target", "contract"] : ["current", "target", "backup", "key-file", "contract"]) {
	if (!values[name]) throw new Error(`--${name} is required`);
}
if (["apply", "resume", "recover"].includes(action) && !values.maintenance) {
	throw new Error(`${action} requires --maintenance after the approved maintenance window has started`);
}
if (action === "recover" && !values["recovery-runtime"]) {
	throw new Error("recover requires --recovery-runtime with a reviewed clean deployment matching the backup source commit");
}

const current = resolve(values.current);
const target = resolve(values.target);
const backup = values.backup ? resolve(values.backup) : null;
const keyFile = values["key-file"] ? resolve(values["key-file"]) : null;
const contractPath = resolve(values.contract);
const stateDir = join(current, ".aidr-upgrade");
const statePath = join(stateDir, "state.json");
const planPath = join(stateDir, "rollback-plan.json");
const lockPath = join(stateDir, "operation.lock");
const recoveryOutput = resolve(values["recovery-output"] ?? join(dirname(current), `${current.split(sep).at(-1)}-recovery`));
const recoveryRuntime = values["recovery-runtime"] ? resolve(values["recovery-runtime"]) : null;
const maxBackupAgeHours = Number(values["max-backup-age-hours"]);
if (!Number.isFinite(maxBackupAgeHours) || maxBackupAgeHours <= 0 || maxBackupAgeHours > 168) {
	throw new Error("--max-backup-age-hours must be greater than zero and no more than 168");
}
if (current === target || target.startsWith(`${current}${sep}`) || current.startsWith(`${target}${sep}`)) {
	throw new Error("Current and target installations must be separate, non-nested directories");
}
if ([current, target, backup].filter(Boolean).some((path) => recoveryOutput === path || recoveryOutput.startsWith(`${path}${sep}`))) {
	throw new Error("Recovery output must be outside the current, target and backup directories");
}
if (recoveryRuntime && [current, target, backup, recoveryOutput].some((path) => recoveryRuntime === path || recoveryRuntime.startsWith(`${path}${sep}`) || path.startsWith(`${recoveryRuntime}${sep}`))) {
	throw new Error("Reviewed recovery runtime must be separate from current, target, backup and recovery output directories");
}

const digestBuffer = (value) => createHash("sha256").update(value).digest("hex");
const digestFile = (path) => digestBuffer(readFileSync(path));
const json = (path) => JSON.parse(readFileSync(path, "utf8"));
const safeRelative = (path) =>
	typeof path === "string" &&
	path.length > 0 &&
	!path.includes("\\") &&
	!path.startsWith("/") &&
	!path.split("/").includes("..") &&
	!path.split("/").includes("");
const quote = (value) => `'${String(value).replaceAll("'", "''")}'`;
let writeSequence = 0;
let pendingSignal = null;
const signalExitCodes = { SIGINT: 130, SIGTERM: 143 };
const maxChildOutputBytes = 16 * 1024 * 1024;
// Children run in their own process group so a terminal Ctrl+C reaches only this
// orchestrator. It decides which step may be cut short: read-only or
// rollback-only children are stopped, while state-changing children (writer
// stop/start, the atomic migration, recovery) finish so their outcome is known.
const isolateChildren = process.platform !== "win32";
const interruptibleChildren = new Set();

function killChild(child) {
	try {
		if (isolateChildren) process.kill(-child.pid, "SIGTERM");
		else child.kill("SIGTERM");
	} catch {
		// The child already exited.
	}
}

for (const signal of ["SIGINT", "SIGTERM"]) {
	process.on(signal, () => {
		if (pendingSignal) return;
		pendingSignal = signal;
		process.exitCode = signalExitCodes[signal];
		process.stderr.write(`Received ${signal}; stopping at the next safe point and restoring the recorded service state.\n`);
		for (const child of interruptibleChildren) killChild(child);
	});
}

function interruptedError() {
	const error = new Error(`Upgrade interrupted by ${pendingSignal}`);
	error.signal = pendingSignal;
	return error;
}

function throwIfInterrupted() {
	if (pendingSignal) throw interruptedError();
}

function writeJson(path, value) {
	mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
	const temporary = `${path}.${process.pid}.${writeSequence++}.tmp`;
	try {
		writeFileSync(temporary, `${JSON.stringify(value, null, 2)}\n`, { mode: 0o600, flag: "wx" });
		renameSync(temporary, path);
	} catch (error) {
		try { rmSync(temporary, { force: true }); } catch { /* original write error remains */ }
		throw error;
	}
}

function copyPath(source, destination) {
	const stat = statSync(source);
	if (stat.isDirectory()) {
		mkdirSync(destination, { recursive: true, mode: 0o700 });
		for (const name of readdirSync(source)) copyPath(join(source, name), join(destination, name));
	} else if (stat.isFile()) {
		mkdirSync(dirname(destination), { recursive: true, mode: 0o700 });
		copyFileSync(source, destination);
	} else {
		throw new Error(`Upgrade source contains an unsupported file type: ${source}`);
	}
}

function inventoryFiles(directory, prefix) {
	const files = [];
	if (!existsSync(directory)) return files;
	function visit(path, relativePrefix) {
		for (const name of readdirSync(path).sort()) {
			const child = join(path, name);
			const childRelative = relativePrefix ? `${relativePrefix}/${name}` : name;
			const stat = statSync(child);
			if (stat.isDirectory()) visit(child, childRelative);
			else if (stat.isFile()) files.push(`${prefix}/${childRelative}`);
			else throw new Error(`Deployment inventory contains an unsupported file type: ${child}`);
		}
	}
	visit(directory, "");
	return files;
}

// Runs a child asynchronously so SIGINT/SIGTERM handlers run while it is in
// flight. `interruptible` children are stopped on a signal and reject with an
// interruption error; all others run to completion and the caller checks for a
// pending signal at the next phase boundary.
function command(executable, args, options = {}) {
	const label = options.label ?? `${executable} ${args[0]}`;
	if (options.interruptible && pendingSignal) return Promise.reject(interruptedError());
	return new Promise((resolveCommand, rejectCommand) => {
		const child = spawn(executable, args, { stdio: ["pipe", "pipe", "ignore"], detached: isolateChildren });
		let stdout = "";
		let stdoutBytes = 0;
		let failure = null;
		let settled = false;
		const timer = setTimeout(() => {
			failure ??= "timed out";
			killChild(child);
		}, options.timeout ?? 180_000);
		const settle = (outcome) => {
			if (settled) return;
			settled = true;
			clearTimeout(timer);
			interruptibleChildren.delete(child);
			outcome();
		};
		if (options.interruptible) interruptibleChildren.add(child);
		child.stdout.setEncoding("utf8");
		child.stdout.on("data", (chunk) => {
			stdoutBytes += Buffer.byteLength(chunk);
			if (stdoutBytes > maxChildOutputBytes) {
				failure ??= "exceeded the output limit";
				killChild(child);
			} else {
				stdout += chunk;
			}
		});
		// The child may exit before consuming its input; its exit status decides.
		child.stdin.on("error", () => {});
		child.stdin.end(options.input ?? "");
		child.on("error", () => settle(() => rejectCommand(new Error(`${label} could not be started; credentials and child output were withheld`))));
		child.on("close", (code, signal) => settle(() => {
			if (options.interruptible && pendingSignal) rejectCommand(interruptedError());
			else if (code !== 0 || failure) rejectCommand(new Error(`${label} failed (${failure ?? `exit ${code ?? signal}`}); credentials and child output were withheld`));
			else resolveCommand(stdout.trim());
		}));
	});
}

function docker(args, options = {}) {
	const testDriver = process.env.AIDR_UPGRADE_TEST_DOCKER_DRIVER;
	if (testDriver) {
		if (process.env.NODE_ENV !== "test") throw new Error("The Docker test driver is only available with NODE_ENV=test");
		return command(process.execPath, [resolve(testDriver), ...args], options);
	}
	return command("docker", args, options);
}

function validateManifest(directory, label) {
	const path = join(directory, "deployment.json");
	const raw = readFileSync(path);
	const manifest = JSON.parse(raw.toString("utf8"));
	if (manifest.schema_version !== 1 || manifest.mode !== "self-hosted") {
		throw new Error(`${label} must be a schema v1 self-hosted deployment`);
	}
	if (!/^[a-z][a-z0-9_-]{0,62}$/.test(manifest.project_name ?? "")) throw new Error(`${label} has an invalid Compose project name`);
	if (!Array.isArray(manifest.migrations) || !Array.isArray(manifest.artifacts)) {
		throw new Error(`${label} manifest must include migration and artifact inventories`);
	}
	const orderError = migrationOrderError(manifest.migrations);
	if (orderError) throw new Error(`${label} ${orderError}`);
	if (manifest.migrations.length === 0 || manifest.artifacts.length === 0 || !/^[a-f0-9]{40}$/.test(manifest.source_commit ?? "")) {
		throw new Error(`${label} must identify a commit and non-empty migration/artifact inventories`);
	}
	const seenMigrations = new Set();
	for (const entry of manifest.migrations) {
		if (!entry || !MIGRATION_FILENAME_PATTERN.test(entry.name) || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
			throw new Error(`${label} has an invalid migration inventory entry`);
		}
		if (seenMigrations.has(entry.name)) throw new Error(`${label} repeats migration ${entry.name}`);
		seenMigrations.add(entry.name);
		const migrationPath = join(directory, "migrations", entry.name);
		if (!existsSync(migrationPath) || digestFile(migrationPath) !== entry.sha256) {
			throw new Error(`${label} migration changed after preparation: ${entry.name}`);
		}
		const migrationSql = readFileSync(migrationPath, "utf8");
		const forbidden = forbiddenMigrationControls(migrationSql);
		const auditedLegacy = directory === current && isAuditedLegacyMigration(entry.name, entry.sha256, migrationSql);
		if (forbidden.length && !auditedLegacy) throw new Error(`${label} ${entry.name}:${forbidden[0].line}: forbidden ${forbidden[0].control}`);
	}
	const seenArtifacts = new Set();
	for (const entry of manifest.artifacts) {
		if (!entry || !safeRelative(entry.path) || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
			throw new Error(`${label} has an invalid artifact inventory entry`);
		}
		if (seenArtifacts.has(entry.path)) throw new Error(`${label} repeats artifact ${entry.path}`);
		seenArtifacts.add(entry.path);
		const artifactPath = join(directory, ...entry.path.split("/"));
		if (!existsSync(artifactPath) || digestFile(artifactPath) !== entry.sha256) {
			throw new Error(`${label} artifact changed after preparation: ${entry.path}`);
		}
	}
	const actualArtifacts = [
		...inventoryFiles(join(directory, "dashboard"), "dashboard"),
		...inventoryFiles(join(directory, "ingress"), "ingress"),
		...inventoryFiles(join(directory, "backup"), "backup"),
		...inventoryFiles(join(directory, "maintenance"), "maintenance"),
		...inventoryFiles(join(directory, "auth-templates"), "auth-templates"),
		...inventoryFiles(join(directory, "volumes", "functions"), "volumes/functions"),
	].sort();
	const declaredArtifacts = [...seenArtifacts].sort();
	if (actualArtifacts.length !== declaredArtifacts.length || actualArtifacts.some((path, index) => path !== declaredArtifacts[index])) {
		throw new Error(`${label} contains missing or untracked application artifacts`);
	}
	const actualMigrations = readdirSync(join(directory, "migrations")).sort();
	const declaredMigrations = [...seenMigrations].sort();
	if (actualMigrations.length !== declaredMigrations.length || actualMigrations.some((name, index) => name !== declaredMigrations[index])) {
		throw new Error(`${label} contains missing or untracked migration files`);
	}
	return { manifest, raw, sha256: digestBuffer(raw) };
}

function migrationSetHash(migrations) {
	return digestBuffer(migrations.map((entry) => `${entry.name}\0${entry.sha256}\n`).join(""));
}

function envNames(path) {
	return new Set(
		readFileSync(path, "utf8")
			.split(/\r?\n/)
			.filter((line) => /^[A-Z][A-Z0-9_]*=/.test(line))
			.map((line) => line.slice(0, line.indexOf("="))),
	);
}

function validateSigningContinuity(configPath) {
	const required = [
		"AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64", // gitleaks:allow: environment variable name only, not a credential
		"AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64",
	];
	const values = new Map();
	for (const line of readFileSync(join(current, ".env.functions"), "utf8").split(/\r?\n/)) {
		const separator = line.indexOf("=");
		if (separator < 0) continue;
		const name = line.slice(0, separator);
		if (!required.includes(name)) continue;
		if (values.has(name)) throw new Error("Current signing credential is duplicated");
		values.set(name, line.slice(separator + 1));
	}
	try {
		const trusted = json(configPath)?.licensing?.public_keys_pem;
		if (!Array.isArray(trusted) || trusted.length === 0) throw new Error("missing public keys");
		const publicHashes = new Set(trusted.map((pem) => {
			const key = createPublicKey(pem);
			if (key.asymmetricKeyType !== "ed25519") throw new Error("invalid public key type");
			return digestBuffer(key.export({ type: "spki", format: "der" }));
		}));
		for (const name of required) {
			const raw = values.get(name);
			if (typeof raw !== "string" || !/^[A-Za-z0-9+/]+={0,2}$/.test(raw) || raw.length % 4 !== 0) throw new Error("invalid private key encoding");
			const bytes = Buffer.from(raw, "base64");
			if (bytes.toString("base64") !== raw) throw new Error("invalid private key encoding");
			const key = createPrivateKey({ key: bytes, type: "pkcs8", format: "der" });
			if (key.asymmetricKeyType !== "ed25519" || !publicHashes.has(digestBuffer(createPublicKey(key).export({ type: "spki", format: "der" })))) {
				throw new Error("signing key mismatch");
			}
		}
	} catch {
		throw new Error("Current entitlement/revocation signing keys do not match the approved agent configuration");
	}
}

function validateContract(contract, currentInfo, targetInfo) {
	const requiredBooleans = [
		"current_app_compatible_with_current_schema",
		"target_app_compatible_with_target_schema",
		"target_schema_accepts_existing_data",
		"migrations_transactional",
	];
	if (
		contract.schema_version !== 1 ||
		contract.current_manifest_sha256 !== currentInfo.sha256 ||
		contract.target_manifest_sha256 !== targetInfo.sha256 ||
		contract.current_migration_set_sha256 !== migrationSetHash(currentInfo.manifest.migrations) ||
		contract.target_migration_set_sha256 !== migrationSetHash(targetInfo.manifest.migrations)
	) {
		throw new Error("Compatibility contract is not bound to the exact current and target manifests/schema sets");
	}
	if (requiredBooleans.some((name) => contract[name] !== true)) {
		throw new Error("Compatibility contract must explicitly approve current app/schema, target app/schema, existing data and transactional migrations");
	}
	if (typeof contract.approved_by !== "string" || contract.approved_by.trim().length < 3 || !Number.isFinite(Date.parse(contract.approved_at))) {
		throw new Error("Compatibility contract requires an approval identity and timestamp");
	}
	if (!Array.isArray(contract.acceptance_evidence) || contract.acceptance_evidence.length === 0) {
		throw new Error("Compatibility contract requires at least one hashed acceptance evidence file");
	}
	for (const item of contract.acceptance_evidence) {
		if (!item || !safeRelative(item.path) || !/^[a-f0-9]{64}$/.test(item.sha256)) {
			throw new Error("Compatibility contract contains invalid acceptance evidence");
		}
		const evidencePath = resolve(dirname(contractPath), ...item.path.split("/"));
		if (relative(dirname(contractPath), evidencePath).startsWith("..") || !existsSync(evidencePath) || digestFile(evidencePath) !== item.sha256) {
			throw new Error(`Compatibility evidence is missing or changed: ${item.path}`);
		}
	}
	for (const [field, file] of [["required_env_keys", ".env"], ["required_function_env_keys", ".env.functions"], ["required_ingress_env_keys", ".env.ingress"]]) {
		if (!Array.isArray(contract[field]) || contract[field].some((name) => !/^[A-Z][A-Z0-9_]*$/.test(name))) {
			throw new Error(`Compatibility contract must declare ${field}`);
		}
		const available = envNames(join(current, file));
		const missing = contract[field].filter((name) => !available.has(name));
		if (missing.length) throw new Error(`Current ${file} is missing target-required configuration keys: ${missing.join(", ")}`);
	}
	for (const [field, directory] of [["current_support_files", current], ["target_support_files", target]]) {
		const entries = contract[field];
		const expected = ["agent-config.json", "compose.yml"];
		if (
			!Array.isArray(entries) ||
			entries.length !== expected.length ||
			entries.some((entry) => !expected.includes(entry?.path) || !/^[a-f0-9]{64}$/.test(entry?.sha256 ?? "")) ||
			new Set(entries.map((entry) => entry.path)).size !== expected.length
		) {
			throw new Error(`Compatibility contract must hash exact ${field}`);
		}
		for (const entry of entries) {
			if (digestFile(join(directory, entry.path)) !== entry.sha256) throw new Error(`Compatibility support file changed: ${field}/${entry.path}`);
		}
	}
}

function validateUpgradePath(currentInfo, targetInfo) {
	const before = currentInfo.manifest;
	const after = targetInfo.manifest;
	if (after.source_has_changes !== false) throw new Error("Target candidate was prepared from a dirty or unknown source tree");
	if (before.upstream_sha !== after.upstream_sha) {
		throw new Error("Database/container baseline changed; use an explicitly designed platform migration instead of an application upgrade");
	}
	if (before.dashboard_url !== after.dashboard_url || before.supabase_url !== after.supabase_url) {
		throw new Error("Target must be prepared for the current public dashboard and API origins");
	}
	if (before.migrations.length > after.migrations.length) throw new Error("Target schema is older than the current schema");
	for (let index = 0; index < before.migrations.length; index += 1) {
		const oldEntry = before.migrations[index];
		const newEntry = after.migrations[index];
		const targetSql = newEntry
			? readFileSync(join(target, "migrations", newEntry.name), "utf8")
			: "";
		if (
			oldEntry.name !== newEntry?.name ||
			!migrationHashesMatch(oldEntry.name, oldEntry.sha256, newEntry.sha256, targetSql)
		) {
			throw new Error(`Migration history is not append-only at ${oldEntry.name}`);
		}
	}
}

async function verifyBackup(currentInfo) {
	await command(
		process.execPath,
		[join(scriptDir, "deployment-backup.mjs"), "verify", "--backup", backup, "--key-file", keyFile],
		{ label: "encrypted backup verification", timeout: 300_000, interruptible: true },
	);
	const envelope = json(join(backup, "backup.json"));
	const payload = JSON.parse(envelope.payload);
	if (payload.type !== "aidr-cold-volumes" || payload.source_project !== currentInfo.manifest.project_name || payload.source_commit !== currentInfo.manifest.source_commit) {
		throw new Error("Verified backup belongs to a different project or source commit");
	}
	const started = Date.parse(payload.started_at);
	const completed = Date.parse(payload.completed_at);
	const age = Date.now() - started;
	if (
		!Number.isFinite(started) || !Number.isFinite(completed) ||
		new Date(started).toISOString() !== payload.started_at ||
		new Date(completed).toISOString() !== payload.completed_at ||
		started > completed || Date.now() - completed < -300_000 ||
		age < -300_000 || age > maxBackupAgeHours * 3_600_000
	) {
		throw new Error(`Verified backup is outside the ${maxBackupAgeHours}-hour upgrade window`);
	}
	return { sha256: digestFile(join(backup, "backup.json")), recovery_point_at: payload.started_at, completed_at: payload.completed_at, verified_at: new Date().toISOString() };
}

function composeArgs(...tail) {
	return ["compose", "--project-directory", current, "-f", join(current, "compose.yml"), ...tail];
}

function migrationSql(currentInfo, targetInfo) {
	const targetNames = targetInfo.manifest.migrations.map((entry) => quote(entry.name)).join(",");
	let sql = "BEGIN;\nDO $aidr_upgrade_lock$ BEGIN IF NOT pg_try_advisory_xact_lock(9112026) THEN RAISE EXCEPTION 'upgrade advisory lock unavailable'; END IF; END $aidr_upgrade_lock$;\n";
	sql += "CREATE TABLE IF NOT EXISTS public.aidr_schema_migrations(name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());\n";
	for (const entry of currentInfo.manifest.migrations) {
		const currentSql = readFileSync(join(current, "migrations", entry.name), "utf8");
		const compatibleHashes = compatibleInstalledHashes(entry.name, entry.sha256, currentSql)
			.map((hash) => quote(hash)).join(",");
		sql += `DO $check$ BEGIN IF NOT EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name=${quote(entry.name)} AND sha256 IN (${compatibleHashes})) THEN RAISE EXCEPTION 'current schema ledger mismatch'; END IF; END $check$;\n`;
	}
	if (targetNames) {
		sql += `DO $check$ BEGIN IF EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name NOT IN (${targetNames})) THEN RAISE EXCEPTION 'database contains a migration unknown to target'; END IF; END $check$;\n`;
	}
	for (const entry of targetInfo.manifest.migrations.slice(currentInfo.manifest.migrations.length)) {
		const migration = readFileSync(join(target, "migrations", entry.name), "utf8");
		sql += `SELECT NOT EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name=${quote(entry.name)}) AS apply_migration \\gset\n\\if :apply_migration\n${migration}\nINSERT INTO public.aidr_schema_migrations(name,sha256) VALUES(${quote(entry.name)},${quote(entry.sha256)});\n\\endif\n`;
	}
	sql += "ROLLBACK;\n";
	return sql;
}

async function dryRunMigrations(currentInfo, targetInfo) {
	// The dry-run always ends in ROLLBACK, so stopping it on a signal is safe.
	await docker(
		composeArgs("exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1"),
		{ input: migrationSql(currentInfo, targetInfo), label: "locked migration dry-run", interruptible: true },
	);
}

function treeHash(path) {
	if (!existsSync(path)) return null;
	const stat = statSync(path);
	if (!stat.isDirectory()) return digestFile(path);
	const rows = [];
	function visit(directory, prefix = "") {
		for (const name of readdirSync(directory).sort()) {
			const child = join(directory, name);
			const relativePath = prefix ? `${prefix}/${name}` : name;
			const childStat = statSync(child);
			if (childStat.isDirectory()) visit(child, relativePath);
			else if (childStat.isFile()) rows.push(`${relativePath}\0${digestFile(child)}\n`);
			else throw new Error(`Upgrade component contains an unsupported file type: ${child}`);
		}
	}
	visit(path);
	return digestBuffer(rows.join(""));
}

function desiredDeployment(currentInfo, targetInfo, binding) {
	return {
		...targetInfo.manifest,
		project_name: currentInfo.manifest.project_name,
		dashboard_url: currentInfo.manifest.dashboard_url,
		supabase_url: currentInfo.manifest.supabase_url,
		upgrade: {
			from_manifest_sha256: currentInfo.sha256,
			target_manifest_sha256: targetInfo.sha256,
			contract_sha256: binding.contract_sha256,
			backup_manifest_sha256: binding.backup.sha256,
			installed_at: binding.installed_at,
		},
	};
}

function prepareComponents(currentInfo, targetInfo, binding) {
	const payload = join(stateDir, "payload");
	if (existsSync(payload)) rmSync(payload, { recursive: true, force: true });
	mkdirSync(payload, { recursive: true, mode: 0o700 });
	for (const name of ["dashboard", "ingress", "backup", "maintenance", "auth-templates", "volumes/functions", "migrations"]) copyPath(join(target, name), join(payload, name));
	copyPath(join(target, "agent-config.json"), join(payload, "agent-config.json"));
	const targetCompose = readFileSync(join(target, "compose.yml"), "utf8");
	if (!/^name:\s*[^\r\n]+/m.test(targetCompose)) throw new Error("Target compose file has no explicit project name");
	writeFileSync(join(payload, "compose.yml"), targetCompose.replace(/^name:\s*[^\r\n]+/m, `name: ${currentInfo.manifest.project_name}`));
	writeJson(join(payload, "deployment.json"), desiredDeployment(currentInfo, targetInfo, binding));
	return ["dashboard", "ingress", "backup", "maintenance", "auth-templates", "volumes/functions", "migrations", "agent-config.json", "compose.yml", "deployment.json"].map((name) => ({
		name,
		current_sha256: treeHash(join(current, name)),
		target_sha256: treeHash(join(payload, name)),
	}));
}

async function preflight() {
	const currentInfo = validateManifest(current, "Current installation");
	const targetInfo = validateManifest(target, "Target candidate");
	validateUpgradePath(currentInfo, targetInfo);
	const contract = json(contractPath);
	validateContract(contract, currentInfo, targetInfo);
	validateSigningContinuity(join(current, "agent-config.json"));
	validateSigningContinuity(join(target, "agent-config.json"));
	const backupInfo = await verifyBackup(currentInfo);
	mkdirSync(stateDir, { recursive: true, mode: 0o700 });
	const binding = {
		current_manifest_sha256: currentInfo.sha256,
		target_manifest_sha256: targetInfo.sha256,
		contract_sha256: digestFile(contractPath),
		backup: backupInfo,
		installed_at: new Date().toISOString(),
	};
	const state = {
		schema_version: 1,
		status: "ready",
		last_completed_phase: "preflight",
		created_at: binding.installed_at,
		updated_at: binding.installed_at,
		...binding,
		paths: { current, target, backup, key_file: keyFile, contract: contractPath, recovery_output: recoveryOutput },
		max_backup_age_hours: maxBackupAgeHours,
		components: prepareComponents(currentInfo, targetInfo, binding),
		installed_components: [],
		checks: [
			"exact manifest and artifact hashes",
			"append-only migration history",
			"reviewed app/database compatibility contract and evidence",
			"authenticated encrypted backup bound to source project/commit and freshness window",
			"migration dry-run required after writer drain and before schema commit",
		],
	};
	writeJson(join(stateDir, "monitoring", "backup.json"), {
		schema_version: 1,
		status: "ok",
		completed_at: backupInfo.completed_at,
		verified_at: backupInfo.verified_at,
		recovery_point_at: backupInfo.recovery_point_at,
		manifest_sha256: backupInfo.sha256,
		source_project: currentInfo.manifest.project_name,
		source_commit: currentInfo.manifest.source_commit,
	});
	writeJson(statePath, state);
	return state;
}

function loadState() {
	if (!existsSync(statePath)) throw new Error("No successful preflight state exists; run preflight first");
	const state = json(statePath);
	if (state.schema_version !== 1 || !["ready", "running", "failed", "complete", "recovery-started", "recovered"].includes(state.status)) {
		throw new Error("Upgrade state is invalid");
	}
	for (const [name, expected] of Object.entries({ current, target, backup, key_file: keyFile, contract: contractPath, recovery_output: recoveryOutput })) {
		if (state.paths[name] !== expected) throw new Error(`Upgrade argument changed after preflight: ${name}`);
	}
	if (state.max_backup_age_hours !== maxBackupAgeHours) throw new Error("Backup freshness window changed after preflight");
	if (digestFile(join(target, "deployment.json")) !== state.target_manifest_sha256 || digestFile(contractPath) !== state.contract_sha256 || digestFile(join(backup, "backup.json")) !== state.backup.sha256) {
		throw new Error("Target, compatibility contract or backup changed after preflight");
	}
	return state;
}

function saveState(state, phase, status = "running") {
	state.last_completed_phase = phase;
	state.status = status;
	state.updated_at = new Date().toISOString();
	delete state.last_error;
	delete state.interrupted_by;
	writeJson(statePath, state);
}

function acquireLock() {
	mkdirSync(stateDir, { recursive: true, mode: 0o700 });
	if (existsSync(lockPath)) {
		let active = true;
		try {
			const owner = json(lockPath);
			if (Number.isInteger(owner.pid)) process.kill(owner.pid, 0);
			else active = false;
		} catch (error) {
			active = error?.code === "EPERM";
		}
		if (active) throw new Error("Another upgrade process holds the operation lock");
		unlinkSync(lockPath);
	}
	const fd = openSync(lockPath, "wx", 0o600);
	writeFileSync(fd, `${JSON.stringify({ pid: process.pid, started_at: new Date().toISOString() })}\n`);
	closeSync(fd);
}

function releaseLock() {
	try {
		if (existsSync(lockPath) && json(lockPath).pid === process.pid) unlinkSync(lockPath);
	} catch {
		// A malformed or replaced lock is retained for operator inspection.
	}
}

async function stageForMigration() {
	const stage = join(stateDir, "migration-stage");
	if (existsSync(stage)) rmSync(stage, { recursive: true, force: true });
	mkdirSync(stage, { recursive: true, mode: 0o700 });
	const currentManifest = json(join(current, "deployment.json"));
	// The migration runner only needs the existing Compose project/service
	// identity for `compose exec`. A minimal file avoids copying installation
	// secrets into transient upgrade storage.
	writeFileSync(join(stage, "compose.yml"), `name: ${currentManifest.project_name}\nservices:\n  db:\n    image: postgres:16\n`, { mode: 0o600 });
	copyPath(join(target, "migrations"), join(stage, "migrations"));
	copyPath(join(target, "deployment.json"), join(stage, "deployment.json"));
	try {
		// Never interrupted: the migration commits atomically and its outcome must be known.
		await command(process.execPath, [join(scriptDir, "deployment-migrate.mjs"), stage], { label: "atomic migration runner", timeout: 300_000 });
	} finally {
		rmSync(stage, { recursive: true, force: true });
	}
}

async function currentRunningServices(options = {}) {
	return (await docker(composeArgs("ps", "--services", "--status", "running"), { label: "running service inventory", ...options }))
		.split(/\r?\n/)
		.filter(Boolean);
}

const restartableWriterPhases = new Set(["writers_stopping", "writers_stopped", "migration_dry_run"]);
const postCommitPhases = new Set(["database_migrated", "artifacts_installed", "services_started"]);

async function restartOriginalWriters(state, label) {
	if (!restartableWriterPhases.has(state.last_completed_phase)) return false;
	const services = (state.running_services ?? []).filter((name) => name !== "db");
	if (services.length) await docker(composeArgs("start", ...services), { label });
	state.last_completed_phase = "preflight";
	state.writers_restarted_at = new Date().toISOString();
	state.updated_at = state.writers_restarted_at;
	writeJson(statePath, state);
	return true;
}

function boundMigrationInputs(state) {
	const currentInfo = validateManifest(current, "Current installation");
	const targetInfo = validateManifest(target, "Target candidate");
	if (currentInfo.sha256 !== state.current_manifest_sha256 || targetInfo.sha256 !== state.target_manifest_sha256) {
		throw new Error("Current or target manifest changed after preflight");
	}
	validateUpgradePath(currentInfo, targetInfo);
	return { currentInfo, targetInfo };
}

async function recheckBeforeWriterDrain(state) {
	const { currentInfo, targetInfo } = boundMigrationInputs(state);
	validateContract(json(contractPath), currentInfo, targetInfo);
	validateSigningContinuity(join(current, "agent-config.json"));
	validateSigningContinuity(join(stateDir, "payload", "agent-config.json"));
	const verified = await verifyBackup(currentInfo);
	if (verified.sha256 !== state.backup.sha256) throw new Error("Authenticated backup changed after preflight");
}

async function stopWriters(state) {
	const running = await currentRunningServices({ interruptible: true });
	if (!running.includes("db")) throw new Error("Current database must be running before upgrade");
	state.running_services = running;
	saveState(state, "writers_stopping");
	const writers = running.filter((name) => name !== "db");
	if (writers.length) {
		try {
			await docker(composeArgs("stop", "--timeout", "60", ...writers), { label: "maintenance service stop" });
		} catch (error) {
			try { await restartOriginalWriters(state, "source service restart after incomplete stop"); } catch { /* original stop error remains */ }
			throw error;
		}
	}
	saveState(state, "writers_stopped");
}

function installComponents(state) {
	const payload = join(stateDir, "payload");
	const previous = join(stateDir, "previous");
	mkdirSync(previous, { recursive: true, mode: 0o700 });
	for (const component of state.components) {
		const destination = join(current, component.name);
		const staged = join(payload, component.name);
		const old = join(previous, component.name);
		const actual = treeHash(destination);
		if (actual === component.target_sha256) {
			if (!state.installed_components.includes(component.name)) {
				state.installed_components.push(component.name);
				writeJson(statePath, state);
			}
			continue;
		}
		// A process can stop between moving the source aside and placing the
		// staged target. Resume only when the saved source still matches preflight.
		const sourceMovedAside = actual === null && existsSync(old);
		if (actual !== component.current_sha256 && !sourceMovedAside) throw new Error(`Current ${component.name} changed or is partially installed; automatic overwrite refused`);
		if (!existsSync(staged) || treeHash(staged) !== component.target_sha256) throw new Error(`Staged target component is missing or changed: ${component.name}`);
		if (existsSync(old)) {
			if (treeHash(old) !== component.current_sha256) throw new Error(`Previous component copy changed: ${component.name}`);
		} else if (component.current_sha256 !== null) {
			mkdirSync(dirname(old), { recursive: true });
			renameSync(destination, old);
		}
		if (!existsSync(destination)) renameSync(staged, destination);
		if (treeHash(destination) !== component.target_sha256) throw new Error(`Installed component hash mismatch: ${component.name}`);
		if (!state.installed_components.includes(component.name)) state.installed_components.push(component.name);
		writeJson(statePath, state);
	}
	saveState(state, "artifacts_installed");
}

function writeRollbackPlan(state, cause = state.last_error ?? "operator-requested rollback") {
	const plan = {
		schema_version: 1,
		created_at: new Date().toISOString(),
		cause,
		strategy: "authenticated encrypted backup recovery into a new isolated project",
		backup_manifest_sha256: state.backup.sha256,
		failed_target_manifest_sha256: state.target_manifest_sha256,
		recovery_output: recoveryOutput,
		command: {
			executable: process.execPath,
			arguments: [join(scriptDir, "deployment-backup.mjs"), "recover", "--backup", backup, "--output", recoveryOutput, "--key-file", keyFile, "--runtime", recoveryRuntime ?? "<reviewed-runtime-matching-backup-source>"],
		},
		acceptance_before_cutover: [
			"start the recovered project in isolation",
			"run deployment doctor and compare database/object evidence",
			"verify administrator login, enrollment, policy block and audit export",
			"change traffic only after approval; retain the failed project for investigation",
		],
		scope: "No in-place down-migration or automatic traffic switch is attempted.",
	};
	writeJson(planPath, plan);
	return plan;
}

function failState(state, error) {
	state.status = "failed";
	state.updated_at = new Date().toISOString();
	state.last_error = error.message;
	if (error.signal) state.interrupted_by = error.signal;
	else delete state.interrupted_by;
	// An interruption at a phase boundary after the schema commit leaves a known,
	// resumable state; only a failed step or an unknown migration outcome needs restore.
	state.requires_restore = state.last_completed_phase === "migration_running" || (!error.signal && postCommitPhases.has(state.last_completed_phase));
	writeJson(statePath, state);
	writeRollbackPlan(state, error.message);
}

async function runUpgrade(state) {
	if (state.status === "complete") return state;
	if (state.last_completed_phase === "migration_running") {
		throw new Error("Previous migration outcome is unknown; recover the verified backup into an isolated project before cutover");
	}
	const phases = ["preflight", "writers_stopping", "writers_stopped", "migration_dry_run", "migration_running", "database_migrated", "artifacts_installed", "services_started", "doctor_passed"];
	const atLeast = (phase) => phases.indexOf(state.last_completed_phase) >= phases.indexOf(phase);
	// A pending SIGINT/SIGTERM is checked at every phase boundary. The caller's
	// failure path then restarts the recorded writers (before the schema commit)
	// or keeps target services drained (after it) and records resumable state.
	if (state.last_completed_phase === "writers_stopping") await restartOriginalWriters(state, "source service restart after interrupted stop");
	throwIfInterrupted();
	if (!atLeast("writers_stopped")) {
		await recheckBeforeWriterDrain(state);
		throwIfInterrupted();
		await stopWriters(state);
	}
	throwIfInterrupted();
	if (!atLeast("migration_dry_run")) {
		const { currentInfo, targetInfo } = boundMigrationInputs(state);
		await dryRunMigrations(currentInfo, targetInfo);
		throwIfInterrupted();
		saveState(state, "migration_dry_run");
	}
	throwIfInterrupted();
	if (!atLeast("database_migrated")) {
		saveState(state, "migration_running");
		// A failed child can still have committed before it timed out or exited.
		// Keep writers drained until isolated recovery proves the database state.
		await stageForMigration();
		saveState(state, "database_migrated");
	}
	throwIfInterrupted();
	if (!atLeast("artifacts_installed")) installComponents(state);
	throwIfInterrupted();
	if (!atLeast("services_started")) {
		await docker(composeArgs("up", "-d", "--build", "--wait", "--wait-timeout", "180"), { label: "target service start", timeout: 300_000 });
		saveState(state, "services_started");
	}
	throwIfInterrupted();
	if (!atLeast("doctor_passed")) {
		// The doctor refuses a development manifest as production evidence, so the
		// installed manifest's own class decides which mode it is asked to verify.
		const doctorMode = json(join(current, "deployment.json")).development === true ? ["--development"] : [];
		// The doctor is read-only, so a signal stops it; resume restarts services and rechecks.
		await command(process.execPath, [join(scriptDir, "deployment-doctor.mjs"), "--deployment", current, "--online", ...doctorMode], { label: "online deployment doctor", timeout: 180_000, interruptible: true });
		saveState(state, "doctor_passed");
	}
	state.completed_at = new Date().toISOString();
	saveState(state, "complete", "complete");
	writeJson(join(stateDir, "upgrade-receipt.json"), {
		schema_version: 1,
		completed_at: state.completed_at,
		current_manifest_sha256: state.current_manifest_sha256,
		target_manifest_sha256: state.target_manifest_sha256,
		installed_manifest_sha256: digestFile(join(current, "deployment.json")),
		contract_sha256: state.contract_sha256,
		backup_manifest_sha256: state.backup.sha256,
		checks: state.checks,
		scope: "Local upgrade orchestration completed; customer traffic, identity, native-agent and business acceptance remain separate.",
	});
	return state;
}

// Read-only compatibility gate: the same manifest, append-only history, contract
// and signing-continuity checks preflight runs, without a backup, lock or state.
// Prints one JSON summary line for scripts/onprem-upgrade.mjs.
function check() {
	const currentInfo = validateManifest(current, "Current installation");
	const targetInfo = validateManifest(target, "Target candidate");
	validateUpgradePath(currentInfo, targetInfo);
	validateContract(json(contractPath), currentInfo, targetInfo);
	validateSigningContinuity(join(current, "agent-config.json"));
	validateSigningContinuity(join(target, "agent-config.json"));
	const summary = (info) => ({
		manifest_sha256: info.sha256,
		source_commit: info.manifest.source_commit,
		dashboard_image: info.manifest.dashboard_image ?? null,
		migrations: info.manifest.migrations.length,
	});
	const existing = existsSync(statePath) ? json(statePath) : null;
	return {
		schema_version: 1,
		compatible: true,
		current: summary(currentInfo),
		target: summary(targetInfo),
		new_migrations: targetInfo.manifest.migrations.slice(currentInfo.manifest.migrations.length).map((entry) => entry.name),
		upgrade_state: existing ? { status: existing.status ?? null, last_completed_phase: existing.last_completed_phase ?? null, target: existing.paths?.target ?? null } : null,
	};
}

async function main() {
	if (action === "check") {
		console.log(JSON.stringify(check()));
	} else if (action === "preflight") {
		if (existsSync(statePath)) throw new Error("An upgrade state already exists; use resume, or archive the reviewed state before a different upgrade");
		const state = await preflight();
		console.log(`Upgrade preflight passed. Exact target ${state.target_manifest_sha256}; no application or schema change was committed.`);
	} else if (action === "apply" || action === "resume") {
		let state;
		if (action === "apply" && !existsSync(statePath)) state = await preflight();
		else state = loadState();
		// A stopped-writer resume may be much later than preflight. Refuse stale
		// recovery material or a changed signer before touching the schema, while
		// leaving the recorded phase untouched for operator review.
		if (["writers_stopped", "migration_dry_run"].includes(state.last_completed_phase)) {
			await recheckBeforeWriterDrain(state);
		}
		try {
			await runUpgrade(state);
			console.log(`Upgrade completed and online doctor passed. Receipt: ${join(stateDir, "upgrade-receipt.json")}`);
		} catch (error) {
			failState(state, error);
			if (state.last_completed_phase === "migration_running" || postCommitPhases.has(state.last_completed_phase)) {
				try {
					const activeWriters = (await currentRunningServices()).filter((name) => name !== "db");
					if (activeWriters.length) await docker(composeArgs("stop", "--timeout", "60", ...activeWriters), { label: "failed target service stop" });
					if (["artifacts_installed", "services_started"].includes(state.last_completed_phase)) {
						state.last_completed_phase = "artifacts_installed";
						state.updated_at = new Date().toISOString();
						writeJson(statePath, state);
					}
				} catch { /* traffic must remain drained; rollback plan remains authoritative */ }
			}
			try { await restartOriginalWriters(state, "source service restart after upgrade failure"); } catch { /* rollback plan remains authoritative */ }
			throw error;
		}
	} else if (action === "rollback-plan") {
		const plan = writeRollbackPlan(loadState());
		console.log(`Rollback plan written for isolated recovery at ${plan.recovery_output}. No data or traffic was changed.`);
	} else {
		const state = loadState();
		if (existsSync(recoveryOutput)) throw new Error("Recovery output already exists; encrypted recovery never overwrites a directory");
		state.status = "recovery-started";
		writeJson(statePath, state);
		// Never interrupted: a partially written recovery project is worse than a late exit.
		await command(
			process.execPath,
			[join(scriptDir, "deployment-backup.mjs"), "recover", "--backup", backup, "--output", recoveryOutput, "--key-file", keyFile, "--runtime", recoveryRuntime],
			{ label: "isolated encrypted recovery", timeout: 600_000 },
		);
		state.status = "recovered";
		state.recovered_at = new Date().toISOString();
		state.updated_at = state.recovered_at;
		writeJson(statePath, state);
		console.log(`Backup recovered into ${recoveryOutput}. Services remain stopped pending acceptance and traffic cutover.`);
	}
}

const readOnly = action === "check";
if (!readOnly) acquireLock();
try {
	await main();
} catch (error) {
	console.error(error);
	process.exitCode = signalExitCodes[pendingSignal] ?? 1;
} finally {
	if (!readOnly) releaseLock();
}
