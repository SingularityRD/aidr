#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { compatibleInstalledHashes } from "./lib/migration-hash-compat.mjs";
import {
	forbiddenMigrationControls,
	MIGRATION_FILENAME_PATTERN,
	migrationOrderError,
} from "./lib/migration-contract.mjs";

const output = resolve(process.argv[2] || ".aidr-deploy");
const manifest = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
if (manifest.mode !== "self-hosted") throw new Error("For hosted Supabase, apply canonical migrations with the Supabase CLI to your selected project.");
const orderError = migrationOrderError(manifest.migrations);
if (orderError) throw new Error(`Invalid migration manifest: ${orderError}`);
if (manifest.migrations.length === 0) throw new Error("Invalid migration manifest: migration inventory must not be empty");
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
const migrations = manifest.migrations.map((entry) => {
	if (!MIGRATION_FILENAME_PATTERN.test(entry.name) || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error("Invalid migration manifest");
	const sql = readFileSync(join(output, "migrations", entry.name), "utf8");
	if (createHash("sha256").update(sql).digest("hex") !== entry.sha256) throw new Error(`Migration changed since preparation: ${entry.name}`);
	const forbidden = forbiddenMigrationControls(sql);
	if (forbidden.length) throw new Error(`${entry.name}:${forbidden[0].line}: forbidden ${forbidden[0].control}`);
	return { ...entry, sql };
});
// One transaction and an advisory lock prevent partial or concurrent application.
let sql = "BEGIN;\nSELECT pg_advisory_xact_lock(9112026);\nCREATE TABLE IF NOT EXISTS public.aidr_schema_migrations(name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());\nREVOKE ALL ON public.aidr_schema_migrations FROM anon, authenticated;\n";
const manifestNames = migrations.map(({ name }) => `'${name}'`).join(",");
sql += `DO $check$ BEGIN IF EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name NOT IN (${manifestNames})) THEN RAISE EXCEPTION 'database contains a migration absent from the deployment manifest'; END IF; END $check$;\n`;
for (const entry of migrations) {
	const compatibleHashes = compatibleInstalledHashes(entry.name, entry.sha256, entry.sql);
	const allowed = compatibleHashes.map((hash) => `'${hash}'`).join(",");
	sql += `DO $check$ BEGIN IF EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name='${entry.name}' AND sha256 NOT IN (${allowed})) THEN RAISE EXCEPTION 'migration checksum mismatch'; END IF; END $check$;\n`;
	for (const installedHash of compatibleHashes.slice(1)) {
		sql += `UPDATE public.aidr_schema_migrations SET sha256='${entry.sha256}' WHERE name='${entry.name}' AND sha256='${installedHash}';\n`;
	}
	sql += `SELECT NOT EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name='${entry.name}') AS apply_migration \\gset\n\\if :apply_migration\n${entry.sql}\nINSERT INTO public.aidr_schema_migrations(name,sha256) VALUES('${entry.name}','${entry.sha256}');\n\\endif\n`;
}
sql += "NOTIFY pgrst, 'reload schema';\nCOMMIT;\n";
const result = docker([...composeArgs, "-v", "ON_ERROR_STOP=1"], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
if (result.status !== 0) { console.error(result.stderr || "Database migration failed"); process.exit(1); }
console.log(`Verified/applied ${migrations.length} migrations atomically. Existing matching migrations were skipped.`);
