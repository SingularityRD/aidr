#!/usr/bin/env node
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { source: { type: "string" }, recovered: { type: "string" } } });
if (!values.source || !values.recovered) throw new Error("--source and --recovered development installations required");
const source = resolve(values.source); const recovered = resolve(values.recovered);
assert.notEqual(source, recovered);
for (const dir of [source, recovered]) {
  const deployment = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
  assert.ok(deployment.development && ["localhost", "127.0.0.1"].includes(new URL(deployment.supabase_url).hostname), "Comparison requires isolated development data that has not changed since backup");
}
function docker(args) {
  const result = spawnSync("docker", args, { encoding: "utf8", timeout: 30000, maxBuffer: 64 * 1024 * 1024 });
  assert.equal(result.status, 0, "Docker inspection failed; inspect source/recovery locally"); return result.stdout.trim();
}
const compose = (dir) => ["compose", "--project-directory", dir, "-f", join(dir, "compose.yml")];
function volume(dir, service, destination) {
  const id = docker([...compose(dir), "ps", "-a", "-q", service]);
  const mount = JSON.parse(docker(["inspect", id]))[0].Mounts.find((entry) => entry.Destination === destination);
  assert.equal(mount.Type, "volume"); return mount.Name;
}
assert.notEqual(volume(source, "db", "/var/lib/postgresql/data"), volume(recovered, "db", "/var/lib/postgresql/data"), "Recovery must use a separate database volume");
const checks = [];
const tables = ["auth.users", "public.tenants", "public.tenant_members", "public.agents", "public.api_keys", "public.entitlements", "public.pilot_applications", "public.audit_logs", "public.admin_audit_logs", "public.tenant_runtime_policies", "public.runtime_policy_revisions", "public.agent_policy_assignments", "public.agent_policy_receipts", "public.audit_export_objects", "storage.objects", "public.aidr_schema_migrations"];
for (const table of tables) {
  // Compare deterministic row-set fingerprints inside PostgreSQL so passwords,
  // token hashes and audit payloads never leave the database in test output.
  const sql = `SELECT count(*)::text || ':' || md5(coalesce(string_agg(md5(to_jsonb(t)::text),'' ORDER BY md5(to_jsonb(t)::text)),'')) FROM ${table} t`;
  const query = (dir) => docker([...compose(dir), "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres", "-tA", "-c", sql]);
  assert.equal(query(source), query(recovered), `${table} row count or content mismatch`); checks.push(`${table} row count and content match`);
}
const policySql = "SELECT md5(coalesce(string_agg(tenant_id::text || ':' || version::text || ':' || policy::text,',' ORDER BY tenant_id),'')) FROM public.tenant_runtime_policies";
const queryPolicy = (dir) => docker([...compose(dir), "exec", "-T", "db", "psql", "-U", "postgres", "-d", "postgres", "-tA", "-c", policySql]);
assert.equal(queryPolicy(source), queryPolicy(recovered)); checks.push("policy tenant, version and contents match");
function storageHash(dir) {
  const name = volume(dir, "storage", "/var/lib/storage");
  const inventory = docker(["run", "--rm", "--network", "none", "--mount", `type=volume,src=${name},dst=/data,readonly`, "node:24.12.0-alpine3.23", "sh", "-c", "cd /data && find . -type f -exec sha256sum {} + | sort"]);
  return createHash("sha256").update(inventory).digest("hex");
}
assert.equal(storageHash(source), storageHash(recovered)); checks.push("every object path and file digest matches");
writeFileSync(join(recovered, "verification.json"), JSON.stringify({ passed: true, checked_at: new Date().toISOString(), checks, scope: "Isolated unchanged development snapshot. Does not prove offsite recovery or customer RPO/RTO." }, null, 2));
console.log(`${checks.length} recovery comparisons passed.`);
