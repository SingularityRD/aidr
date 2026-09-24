import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-rate-prune-${randomUUID().slice(0, 8)}`;
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
async function lockedTenant(tenant) {
  const child = spawn("docker", ["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"],
    { stdio: ["pipe", "pipe", "pipe"], timeout: 15_000 });
  let output = "", error = "";
  child.stdout.on("data", chunk => { output += chunk; });
  child.stderr.on("data", chunk => { error += chunk; });
  child.stdin.write(`begin; select pg_advisory_xact_lock(hashtextextended('${tenant}'::text,2606));\n\\echo LOCKED\n`);
  for (let i = 0; i < 100 && !output.includes("LOCKED"); i++) {
    await new Promise(done => setTimeout(done, 20));
  }
  assert.ok(output.includes("LOCKED"), `tenant lock unavailable: ${error}`);
  return async () => {
    child.stdin.end("commit;\n\\q\n");
    await new Promise(done => child.on("close", done));
  };
}
const prune = (limit = 100, apply = false) =>
  sql(`set role service_role; select public.prune_expired_rate_limits(${limit},${apply});`)
    .then(value => JSON.parse(value));

test("rate-limit pruning is bounded, global/tenant scoped, dry-run first, and service-only", { timeout: 120_000 }, async () => {
  const started = await docker(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
    "-e", "POSTGRES_PASSWORD=rate-prune-fixture-only", "supabase/postgres:17.6.1.136"]);
  assert.equal(started.code, 0, started.stderr);
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      if ((await docker(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0) { ready = true; break; }
      await new Promise(done => setTimeout(done, 100));
    }
    assert.ok(ready, "isolated PostgreSQL must start");
    await sql(`create table public.tenants (id uuid primary key, status text not null);
      create table public.tenant_legal_holds (tenant_id uuid not null, released_at timestamptz);
      create table public.rate_limits (
      key text not null, window_start bigint not null, count integer not null default 0,
      tenant_id uuid, created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(), primary key (key,window_start));`);
    await sql(readFileSync(resolve(root, "supabase/migrations/20260923000052_rate_limit_pruning.sql"), "utf8"));
    const tenant = randomUUID(), held = randomUUID(), inactive = randomUUID();
    await sql(`insert into public.tenants(id,status) values
      ('${tenant}','active'),('${held}','active'),('${inactive}','closing');
      insert into public.tenant_legal_holds(tenant_id) values ('${held}');`);
    await sql(`insert into public.rate_limits(key,window_start,count,tenant_id,updated_at) values
      ('identity-reset:old',1,5,null,now()-interval '20 minutes'),
      ('device_start:old',2,5,null,now()-interval '20 minutes'),
      ('api:v1:tenant-old',3,5,'${tenant}',now()-interval '20 minutes'),
      ('identity-break-glass:margin',4,5,null,now()-interval '14 minutes'),
      ('api:v1:tenant-current',5,5,'${tenant}',now()-interval '1 minute'),
      ('api:v1:held',6,5,'${held}',now()-interval '20 minutes'),
      ('api:v1:closing',7,5,'${inactive}',now()-interval '20 minutes'),
      ('identity-reset:stale-clock',floor(extract(epoch from now())/600)::bigint,5,null,now()-interval '20 minutes'),
      ('device_start:stale-clock',floor(extract(epoch from now())/60)::bigint,5,null,now()-interval '20 minutes');`);
    const dry = await prune(2);
    assert.equal(dry.applied, false);
    assert.equal(dry.eligible, 2);
    assert.equal(dry.deleted, 0);
    assert.equal(dry.remaining, 1);
    assert.equal(dry.held_tenants_present, 1);
    assert.equal(dry.inactive_tenant_rows_present, 1);
    assert.equal(await sql("select count(*) from public.rate_limits;"), "9");
    const first = await prune(2, true);
    assert.equal(first.eligible, 2);
    assert.equal(first.deleted, 2);
    assert.equal(first.remaining, 1);
    const second = await prune(2, true);
    assert.equal(second.deleted, 1);
    assert.equal(second.remaining, 0);
    assert.equal((await prune(2, true)).deleted, 0);
    assert.equal(await sql("select count(*) from public.rate_limits;"), "6");
    assert.equal(await sql("select count(*) from public.rate_limits where key='identity-break-glass:margin';"), "1");
    assert.equal(await sql("select count(*) from public.rate_limits where key='api:v1:tenant-current';"), "1");
    assert.equal(await sql("select count(*) from public.rate_limits where key in ('api:v1:held','api:v1:closing');"), "2");
    assert.equal(await sql("select count(*) from public.rate_limits where key like '%:stale-clock';"), "2",
      "DB bucket time protects active windows even with a stale transaction timestamp");
    await sql(`update public.tenant_legal_holds set released_at=now() where tenant_id='${held}';
      update public.tenants set status='active' where id='${inactive}';`);
    assert.equal((await prune(2, true)).deleted, 2, "released and reactivated tenant counters can expire");
    assert.equal(await sql("select count(*) from public.rate_limits;"), "4");
    await sql(`insert into public.rate_limits(key,window_start,count,tenant_id,updated_at)
      values ('api:v1:locked',8,5,'${tenant}',now()-interval '20 minutes');`);
    const unlock = await lockedTenant(tenant);
    try {
      const blocked = await prune(2, true);
      assert.equal(blocked.deleted, 0);
      assert.equal(blocked.contended_tenants, 1);
      assert.equal(blocked.remaining, 1, "lock contention cannot issue a completion receipt");
    } finally {
      await unlock();
    }
    assert.equal((await prune(2, true)).deleted, 1, "releasing the tenant lock resumes pruning");
    for (const role of ["anon", "authenticated"]) {
      assert.equal(await sql(`select has_function_privilege('${role}', 'public.prune_expired_rate_limits(integer,boolean)', 'EXECUTE');`), "f");
    }
    assert.equal(await sql("select has_function_privilege('service_role', 'public.prune_expired_rate_limits(integer,boolean)', 'EXECUTE');"), "t");
    const invalid = await docker(["exec", "-i", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"],
      "set role service_role; select public.prune_expired_rate_limits(1001,true);");
    assert.notEqual(invalid.code, 0);
    assert.match(invalid.stderr, /invalid_rate_limit_prune/);
  } finally {
    await docker(["rm", "--force", container]);
  }
});
