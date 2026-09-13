#!/usr/bin/env node
// Controlled self-hosted upgrade orchestration. Database rollback is deliberately
// a restore into a new project; this tool never attempts destructive down-migrations.
import { createHash } from "node:crypto";
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
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { parseArgs } from "node:util";

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
		"max-backup-age-hours": { type: "string", default: "24" },
		maintenance: { type: "boolean", default: false },
	},
});
const action = positionals[0];
if (!["preflight", "apply", "resume", "rollback-plan", "recover"].includes(action)) {
	throw new Error("Use preflight|apply|resume|rollback-plan|recover with --current, --target, --backup, --key-file and --contract");
}
for (const name of ["current", "target", "backup", "key-file", "contract"]) {
	if (!values[name]) throw new Error(`--${name} is required`);
}
if (["apply", "resume", "recover"].includes(action) && !values.maintenance) {
	throw new Error(`${action} requires --maintenance after the approved maintenance window has started`);
}

const current = resolve(values.current);
const target = resolve(values.target);
const backup = resolve(values.backup);
const keyFile = resolve(values["key-file"]);
const contractPath = resolve(values.contract);
const stateDir = join(current, ".aidr-upgrade");
const statePath = join(stateDir, "state.json");
const planPath = join(stateDir, "rollback-plan.json");
const lockPath = join(stateDir, "operation.lock");
const recoveryOutput = resolve(values["recovery-output"] ?? join(dirname(current), `${current.split(sep).at(-1)}-recovery`));
const maxBackupAgeHours = Number(values["max-backup-age-hours"]);
if (!Number.isFinite(maxBackupAgeHours) || maxBackupAgeHours <= 0 || maxBackupAgeHours > 168) {
	throw new Error("--max-backup-age-hours must be greater than zero and no more than 168");
}
if (current === target || target.startsWith(`${current}${sep}`) || current.startsWith(`${target}${sep}`)) {
	throw new Error("Current and target installations must be separate, non-nested directories");
}
if ([current, target, backup].some((path) => recoveryOutput === path || recoveryOutput.startsWith(`${path}${sep}`))) {
	throw new Error("Recovery output must be outside the current, target and backup directories");
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

function command(executable, args, options = {}) {
	const result = spawnSync(executable, args, {
		encoding: "utf8",
		timeout: options.timeout ?? 180_000,
		maxBuffer: 16 * 1024 * 1024,
		input: options.input,
	});
	if (result.status !== 0) {
		throw new Error(`${options.label ?? `${executable} ${args[0]}`} failed (exit ${result.status}); credentials and child output were withheld`);
	}
	return result.stdout.trim();
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
	if (manifest.migrations.length === 0 || manifest.artifacts.length === 0 || !/^[a-f0-9]{40}$/.test(manifest.source_commit ?? "")) {
		throw new Error(`${label} must identify a commit and non-empty migration/artifact inventories`);
	}
	const seenMigrations = new Set();
	for (const entry of manifest.migrations) {
		if (!entry || !/^\d{14}_[a-z0-9_]+\.sql$/.test(entry.name) || !/^[a-f0-9]{64}$/.test(entry.sha256)) {
			throw new Error(`${label} has an invalid migration inventory entry`);
		}
		if (seenMigrations.has(entry.name)) throw new Error(`${label} repeats migration ${entry.name}`);
		seenMigrations.add(entry.name);
		const migrationPath = join(directory, "migrations", entry.name);
		if (!existsSync(migrationPath) || digestFile(migrationPath) !== entry.sha256) {
			throw new Error(`${label} migration changed after preparation: ${entry.name}`);
		}
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
	for (const [field, file] of [["required_env_keys", ".env"], ["required_function_env_keys", ".env.functions"]]) {
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
		if (oldEntry.name !== newEntry?.name || oldEntry.sha256 !== newEntry.sha256) {
			throw new Error(`Migration history is not append-only at ${oldEntry.name}`);
		}
	}
}

function verifyBackup(currentInfo) {
	command(
		process.execPath,
		[join(scriptDir, "deployment-backup.mjs"), "verify", "--backup", backup, "--key-file", keyFile],
		{ label: "encrypted backup verification", timeout: 300_000 },
	);
	const envelope = json(join(backup, "backup.json"));
	const payload = JSON.parse(envelope.payload);
	if (payload.type !== "aidr-cold-volumes" || payload.source_project !== currentInfo.manifest.project_name || payload.source_commit !== currentInfo.manifest.source_commit) {
		throw new Error("Verified backup belongs to a different project or source commit");
	}
	const completed = Date.parse(payload.completed_at);
	const age = Date.now() - completed;
	if (!Number.isFinite(completed) || age < -300_000 || age > maxBackupAgeHours * 3_600_000) {
		throw new Error(`Verified backup is outside the ${maxBackupAgeHours}-hour upgrade window`);
	}
	return { sha256: digestFile(join(backup, "backup.json")), completed_at: payload.completed_at, verified_at: new Date().toISOString() };
}

function composeArgs(...tail) {
	return ["compose", "--project-directory", current, "-f", join(current, "compose.yml"), ...tail];
}

function migrationSql(currentInfo, targetInfo) {
	const targetNames = targetInfo.manifest.migrations.map((entry) => quote(entry.name)).join(",");
	let sql = "BEGIN;\nDO $aidr_upgrade_lock$ BEGIN IF NOT pg_try_advisory_xact_lock(9112026) THEN RAISE EXCEPTION 'upgrade advisory lock unavailable'; END IF; END $aidr_upgrade_lock$;\n";
	sql += "CREATE TABLE IF NOT EXISTS public.aidr_schema_migrations(name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());\n";
	for (const entry of currentInfo.manifest.migrations) {
		sql += `DO $check$ BEGIN IF NOT EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name=${quote(entry.name)} AND sha256=${quote(entry.sha256)}) THEN RAISE EXCEPTION 'current schema ledger mismatch'; END IF; END $check$;\n`;
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

function dryRunMigrations(currentInfo, targetInfo) {
	docker(
		composeArgs("exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres", "-v", "ON_ERROR_STOP=1"),
		{ input: migrationSql(currentInfo, targetInfo), label: "locked migration dry-run" },
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
	for (const name of ["dashboard", "volumes/functions", "migrations"]) copyPath(join(target, name), join(payload, name));
	copyPath(join(target, "agent-config.json"), join(payload, "agent-config.json"));
	const targetCompose = readFileSync(join(target, "compose.yml"), "utf8");
	if (!/^name:\s*[^\r\n]+/m.test(targetCompose)) throw new Error("Target compose file has no explicit project name");
	writeFileSync(join(payload, "compose.yml"), targetCompose.replace(/^name:\s*[^\r\n]+/m, `name: ${currentInfo.manifest.project_name}`));
	writeJson(join(payload, "deployment.json"), desiredDeployment(currentInfo, targetInfo, binding));
	return ["dashboard", "volumes/functions", "migrations", "agent-config.json", "compose.yml", "deployment.json"].map((name) => ({
		name,
		current_sha256: treeHash(join(current, name)),
		target_sha256: treeHash(join(payload, name)),
	}));
}

function preflight() {
	const currentInfo = validateManifest(current, "Current installation");
	const targetInfo = validateManifest(target, "Target candidate");
	validateUpgradePath(currentInfo, targetInfo);
	const contract = json(contractPath);
	validateContract(contract, currentInfo, targetInfo);
	const backupInfo = verifyBackup(currentInfo);
	dryRunMigrations(currentInfo, targetInfo);
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
		components: prepareComponents(currentInfo, targetInfo, binding),
		installed_components: [],
		checks: [
			"exact manifest and artifact hashes",
			"append-only migration history",
			"reviewed app/database compatibility contract and evidence",
			"authenticated encrypted backup bound to source project/commit and freshness window",
			"live database ledger and target migrations under advisory lock with rollback",
		],
	};
	writeJson(join(stateDir, "monitoring", "backup.json"), {
		schema_version: 1,
		status: "ok",
		completed_at: backupInfo.completed_at,
		verified_at: backupInfo.verified_at,
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

function stageForMigration(state) {
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
		command(process.execPath, [join(scriptDir, "deployment-migrate.mjs"), stage], { label: "atomic migration runner", timeout: 300_000 });
	} finally {
		rmSync(stage, { recursive: true, force: true });
	}
}

function currentRunningServices() {
	return docker(composeArgs("ps", "--services", "--status", "running"), { label: "running service inventory" })
		.split(/\r?\n/)
		.filter(Boolean);
}

function stopWriters(state) {
	const running = currentRunningServices();
	if (!running.includes("db")) throw new Error("Current database must be running before upgrade");
	state.running_services = running;
	const writers = running.filter((name) => name !== "db");
	if (writers.length) {
		try {
			docker(composeArgs("stop", "--timeout", "60", ...writers), { label: "maintenance service stop" });
		} catch (error) {
			try { docker(composeArgs("start", ...writers), { label: "source service restart after incomplete stop" }); } catch { /* original stop error remains */ }
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
		} else {
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
			arguments: [join(scriptDir, "deployment-backup.mjs"), "recover", "--backup", backup, "--output", recoveryOutput, "--key-file", keyFile],
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
	state.requires_restore = ["database_migrated", "artifacts_installed", "services_started"].includes(state.last_completed_phase);
	writeJson(statePath, state);
	writeRollbackPlan(state, error.message);
}

function runUpgrade(state) {
	if (state.status === "complete") return state;
	const phases = ["preflight", "writers_stopped", "database_migrated", "artifacts_installed", "services_started", "doctor_passed"];
	const atLeast = (phase) => phases.indexOf(state.last_completed_phase) >= phases.indexOf(phase);
	if (!atLeast("writers_stopped")) stopWriters(state);
	if (!atLeast("database_migrated")) {
		stageForMigration(state);
		saveState(state, "database_migrated");
	}
	if (!atLeast("artifacts_installed")) installComponents(state);
	if (!atLeast("services_started")) {
		docker(composeArgs("up", "-d", "--build", "--wait", "--wait-timeout", "180"), { label: "target service start", timeout: 300_000 });
		saveState(state, "services_started");
	}
	if (!atLeast("doctor_passed")) {
		command(process.execPath, [join(scriptDir, "deployment-doctor.mjs"), "--deployment", current, "--online"], { label: "online deployment doctor", timeout: 180_000 });
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

acquireLock();
try {
	if (action === "preflight") {
		if (existsSync(statePath)) throw new Error("An upgrade state already exists; use resume, or archive the reviewed state before a different upgrade");
		const state = preflight();
		console.log(`Upgrade preflight passed. Exact target ${state.target_manifest_sha256}; no application or schema change was committed.`);
	} else if (action === "apply" || action === "resume") {
		let state;
		if (action === "apply" && !existsSync(statePath)) state = preflight();
		else state = loadState();
		try {
			runUpgrade(state);
			console.log(`Upgrade completed and online doctor passed. Receipt: ${join(stateDir, "upgrade-receipt.json")}`);
		} catch (error) {
			failState(state, error);
			if (state.requires_restore) {
				try {
					const activeWriters = currentRunningServices().filter((name) => name !== "db");
					if (activeWriters.length) docker(composeArgs("stop", "--timeout", "60", ...activeWriters), { label: "failed target service stop" });
					if (["artifacts_installed", "services_started"].includes(state.last_completed_phase)) {
						state.last_completed_phase = "artifacts_installed";
						state.updated_at = new Date().toISOString();
						writeJson(statePath, state);
					}
				} catch { /* traffic must remain drained; rollback plan remains authoritative */ }
			}
			if (state.last_completed_phase === "writers_stopped") {
				const services = (state.running_services ?? []).filter((name) => name !== "db");
				if (services.length) {
					try {
						docker(composeArgs("start", ...services), { label: "source service restart" });
						state.last_completed_phase = "preflight";
						state.updated_at = new Date().toISOString();
						writeJson(statePath, state);
					} catch { /* rollback plan remains authoritative */ }
				}
			}
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
		command(
			process.execPath,
			[join(scriptDir, "deployment-backup.mjs"), "recover", "--backup", backup, "--output", recoveryOutput, "--key-file", keyFile],
			{ label: "isolated encrypted recovery", timeout: 600_000 },
		);
		state.status = "recovered";
		state.recovered_at = new Date().toISOString();
		state.updated_at = state.recovered_at;
		writeJson(statePath, state);
		console.log(`Backup recovered into ${recoveryOutput}. Services remain stopped pending acceptance and traffic cutover.`);
	}
} finally {
	releaseLock();
}
