#!/usr/bin/env node
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const output = resolve(process.argv[2] || ".aidr-deploy");
const manifest = JSON.parse(readFileSync(join(output, "deployment.json"), "utf8"));
if (manifest.mode !== "self-hosted") throw new Error("For hosted Supabase, apply canonical migrations with the Supabase CLI to your selected project.");
const composeArgs = ["compose", "--project-directory", output, "-f", join(output, "compose.yml"), "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres"];
// Supabase's database can report healthy before Storage creates its schema on
// first boot. The canonical migrations depend on storage.buckets, so wait for
// that specific prerequisite rather than requiring an operator to retry.
const readyUntil = Date.now() + 90_000;
let storageReady = false;
while (Date.now() < readyUntil) {
	const probe = spawnSync("docker", [...composeArgs, "-tAc", "SELECT to_regclass('storage.buckets') IS NOT NULL"], { encoding: "utf8", timeout: 10_000 });
	if (probe.status === 0 && probe.stdout.trim() === "t") { storageReady = true; break; }
	await new Promise((resolveWait) => setTimeout(resolveWait, 1_000));
}
if (!storageReady) throw new Error("Storage schema did not become ready within 90 seconds; check the storage and db service logs before migrating.");
const migrations = manifest.migrations.map((entry) => {
	if (!/^\d{14}_[a-z0-9_]+\.sql$/.test(entry.name) || !/^[a-f0-9]{64}$/.test(entry.sha256)) throw new Error("Invalid migration manifest");
	const sql = readFileSync(join(output, "migrations", entry.name), "utf8");
	if (createHash("sha256").update(sql).digest("hex") !== entry.sha256) throw new Error(`Migration changed since preparation: ${entry.name}`);
	return { ...entry, sql };
});
// One transaction and an advisory lock prevent partial or concurrent application.
let sql = "BEGIN;\nSELECT pg_advisory_xact_lock(9112026);\nCREATE TABLE IF NOT EXISTS public.aidr_schema_migrations(name text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now());\nREVOKE ALL ON public.aidr_schema_migrations FROM anon, authenticated;\n";
for (const entry of migrations) {
	sql += `DO $check$ BEGIN IF EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name='${entry.name}' AND sha256<>'${entry.sha256}') THEN RAISE EXCEPTION 'migration checksum mismatch'; END IF; END $check$;\n`;
	sql += `SELECT NOT EXISTS(SELECT 1 FROM public.aidr_schema_migrations WHERE name='${entry.name}') AS apply_migration \\gset\n\\if :apply_migration\n${entry.sql}\nINSERT INTO public.aidr_schema_migrations(name,sha256) VALUES('${entry.name}','${entry.sha256}');\n\\endif\n`;
}
sql += "NOTIFY pgrst, 'reload schema';\nCOMMIT;\n";
const result = spawnSync("docker", [...composeArgs, "-v", "ON_ERROR_STOP=1"], { input: sql, encoding: "utf8", maxBuffer: 8 * 1024 * 1024 });
if (result.status !== 0) { console.error(result.stderr || "Database migration failed"); process.exit(1); }
console.log(`Verified/applied ${migrations.length} migrations atomically. Existing matching migrations were skipped.`);
