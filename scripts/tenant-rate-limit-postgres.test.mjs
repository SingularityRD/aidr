import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-t22-quota-${randomUUID().slice(0, 8)}`;

function docker(args, input = "") {
  return new Promise((done, reject) => {
    const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 60_000 });
    let stdout = "", stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => done({ code, stdout: stdout.trim(), stderr }));
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}

async function sql(query) {
  const result = await docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"], query);
  assert.equal(result.code, 0, result.stderr);
  return result.stdout;
}

function consume(tenant, subject, window = 1, subjectLimit = 1, tenantLimit = 2) {
  return `select allowed from public.consume_tenant_rate_limit('${tenant}', '${subject}', 'ingest', ${window}, ${subjectLimit}, ${tenantLimit});`;
}

async function deniedBurst(tenant) {
  const result = await sql(Array.from({ length: 10 }, (_, i) => consume(tenant, `attack-${i}`)).join("\n"));
  assert.deepEqual(result.split(/\r?\n/), Array(10).fill("f"));
}

test("full tenant quota cannot allocate unbounded subject rows", { timeout: 180_000 }, async () => {
  const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
    "-e", "POSTGRES_PASSWORD=quota-fixture-only", "supabase/postgres:17.11.0.004"]);
  assert.equal(started.code, 0, started.stderr);
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      if ((await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0) { ready = true; break; }
      await new Promise(done => setTimeout(done, 100));
    }
    assert.ok(ready, "isolated PostgreSQL must start");
    await sql(`create schema if not exists extensions;
      create extension if not exists pgcrypto with schema extensions;
      create table public.tenants (id uuid primary key, status text not null);
      create table public.rate_limits (key text not null, window_start bigint not null,
        count integer not null default 0, tenant_id uuid, primary key (key, window_start));`);

    const original = readFileSync(resolve(root, "supabase/migrations/20260912000014_tenant_resource_limits.sql"), "utf8");
    const repaired = readFileSync(resolve(root, "supabase/migrations/20260923000048_tenant_rate_limit_subject_quota.sql"), "utf8");
    await sql(original);
    const [tenantA, tenantB, tenantC] = [randomUUID(), randomUUID(), randomUUID()];
    await sql(`insert into public.tenants(id,status) values
      ('${tenantA}','active'),('${tenantB}','active'),('${tenantC}','active');`);

    assert.equal(await sql(consume(tenantA, "seed-1")), "t");
    assert.equal(await sql(consume(tenantA, "seed-2")), "t");
    await deniedBurst(tenantA);
    assert.equal(await sql(`select count(*) from public.rate_limits where tenant_id='${tenantA}';`), "13",
      "the old function allocates a row for every denied new subject");

    await sql("truncate public.rate_limits;");
    await sql(repaired);
    assert.equal(await sql(consume(tenantA, "seed-1")), "t");
    assert.equal(await sql(consume(tenantA, "seed-2")), "t");
    await deniedBurst(tenantA);
    assert.equal(await sql(`select count(*) from public.rate_limits where tenant_id='${tenantA}';`), "3",
      "a full tenant keeps only its aggregate and two admitted subject rows");
    assert.equal(await sql(consume(tenantB, "seed-1")), "t", "another tenant has an independent quota");

    assert.equal(await sql(consume(tenantB, "seed-1")), "f", "subject ceiling still applies");
    assert.equal(await sql(`select count(*) from public.rate_limits where tenant_id='${tenantB}';`), "2");
    const raced = await Promise.all([
      sql(consume(tenantC, "race-1", 2, 1, 1)),
      sql(consume(tenantC, "race-2", 2, 1, 1)),
    ]);
    assert.deepEqual(raced.sort(), ["f", "t"], "tenant lock admits only one concurrent request");
    assert.equal(await sql(`select count(*) from public.rate_limits where tenant_id='${tenantC}';`), "2");
    assert.equal(await sql(`select has_function_privilege('authenticated',
      'public.consume_tenant_rate_limit(uuid,text,text,bigint,integer,integer,integer)', 'EXECUTE');`), "f");
  } finally {
    await docker(["rm", "--force", container]);
  }
});
