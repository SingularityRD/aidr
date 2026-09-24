#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { compatibleInstalledHashes } from "./lib/migration-hash-compat.mjs";
import {
	buildAtomicMigrationSql,
	MIGRATION_FILENAME_PATTERN,
	migrationOrderError,
} from "./lib/migration-contract.mjs";

const output = resolve(process.argv[2] || ".aidr-deploy");
const manifest = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
if (manifest.mode !== "self-hosted") throw new Error("For hosted Supabase, apply canonical migrations with the Supabase CLI to your selected project.");
const orderError = migrationOrderError(manifest.migrations);
if (orderError) throw new Error(`Invalid migration manifest: ${orderError}`);
if (manifest.migrations.length === 0) throw new Error("Invalid migration manifest: migration inventory must not be empty");
// Read, verify and assemble the whole plan before touching the database.
const sql = buildAtomicMigrationSql(manifest.migrations.map((entry) => {
	if (!MIGRATION_FILENAME_PATTERN.test(entry.name) || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error("Invalid migration manifest");
	return { ...entry, sql: readFileSync(join(output, "migrations", entry.name), "utf8") };
}), compatibleInstalledHashes);
const composeArgs = ["compose", "--project-directory", output, "-f", join(output, "compose.yml"), "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres"];
function docker(args, options) {
	const testDriver = process.env.AIDR_MIGRATION_TEST_DOCKER_DRIVER;
	if (testDriver) {
		if (process.env.NODE_ENV !== "test") throw new Error("The Docker test driver is only available with NODE_ENV=test");
		return spawnSync(process.execPath, [resolve(testDriver), ...args], options);
	}
	return spawnSync("docker", args, options);
}
// Supabase's database can report healthy before Storage creates its schema on
// first boot. The canonical migrations depend on storage.buckets, so wait for
// that specific prerequisite rather than requiring an operator to retry.
const readyUntil = Date.now() + 90_000;
let storageReady = false;
while (Date.now() < readyUntil) {
	const probe = docker([...composeArgs, "-tAc", "SELECT to_regclass('storage.buckets') IS NOT NULL"], { encoding: "utf8", timeout: 10_000 });
	if (probe.status === 0 && probe.stdout.trim() === "t") { storageReady = true; break; }
	await new Promise((resolveWait) => setTimeout(resolveWait, 1_000));
}
if (!storageReady) throw new Error("Storage schema did not become ready within 90 seconds; check the storage and db service logs before migrating.");
const result = docker([...composeArgs, "-v", "ON_ERROR_STOP=1"], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
if (result.status !== 0) { console.error(result.stderr || "Database migration failed"); process.exit(1); }
console.log(`Verified/applied ${manifest.migrations.length} migrations atomically. Existing matching migrations were skipped.`);
