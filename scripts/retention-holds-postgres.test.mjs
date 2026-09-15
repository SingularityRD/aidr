// Real PostgreSQL integration/concurrency test. Creates/removes its OWN offline
// container; never connects to an existing deployment. Requires cached image.
// Storage's schema is a minimal fixture, not a Storage API/server simulation.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-retention-test-${randomUUID()}`;
function command(args, input = "") {
  return new Promise((done, reject) => {
    const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"], timeout: 30_000 });
    let stdout = "", stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => done({ code, stdout: stdout.trim(), stderr }));
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}
// A blocking-lock regression must fail, not hang before the test can COMMIT.
const pgArgs = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=5000 -c lock_timeout=3000", container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
async function sql(text) {
  const result = await command(pgArgs, text);
  assert.equal(result.code, 0, result.stderr);
  return result.stdout;
}
async function denied(text, error) {
  const result = await command(pgArgs, text);
  assert.notEqual(result.code, 0, "statement must be refused");
  assert.match(result.stderr, error);
}
const rpc = async text => JSON.parse(await sql(`set role service_role; select ${text};`));
const delay = ms => new Promise(done => setTimeout(done, ms));
function session() {
  const child = spawn("docker", pgArgs, { stdio: ["pipe", "pipe", "pipe"], timeout: 30_000 });
  let output = "", stderr = "", pending;
  child.stdout.on("data", chunk => {
    output += chunk;
    if (pending && output.includes(pending.marker)) {
      const value = output.slice(0, output.indexOf(pending.marker)).trim();
      output = output.slice(output.indexOf(pending.marker) + pending.marker.length).trimStart();
      pending.done(value); pending = undefined;
    }
  });
  child.stderr.on("data", chunk => { stderr += chunk; });
  child.on("error", error => pending?.reject(error));
  child.on("close", code => pending?.reject(new Error(`psql session closed (${code}): ${stderr}`)));
  return {
    query(text) {
      assert.equal(pending, undefined);
      return new Promise((done, reject) => {
        const marker = randomUUID();
        pending = { marker, done, reject };
        child.stdin.write(`${text}\n\\echo ${marker}\n`);
      });
    },
    close() { child.stdin.end("rollback;\n\\q\n"); },
  };
}
async function waitForAdvisoryWait(application) {
  for (let i = 0; i < 100; i++) {
    if (await sql(`select exists(select 1 from pg_stat_activity where application_name='${application}' and wait_event='advisory');`) === "t") return;
    await delay(20);
  }
  assert.fail("concurrent hold placement did not reach the advisory lock");
}

test("retention migration and tenant-serialized hold protocol on real PostgreSQL", async t => {
  const started = await command(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
    "-e", "POSTGRES_PASSWORD=retention-fixture-only", "supabase/postgres:17.6.1.136"]);
  assert.equal(started.code, 0, started.stderr);
  try {
    let ready = false;
    for (let i = 0; i < 100; i++) {
      if ((await command(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0) { ready = true; break; }
      await delay(100);
    }
    assert.ok(ready, "disposable PostgreSQL must start");
    const storageGrant = await command(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
      `grant create on schema storage to postgres;
       create function auth.jwt() returns jsonb language sql stable as $$
         select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb
       $$;`);
    assert.equal(storageGrant.code, 0, storageGrant.stderr);
    await sql(`create table storage.buckets(id text primary key, name text, public boolean);
      create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
      create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);
    // Apply the COMPLETE canonical migration chain, including the new append-only
    // upgrade, so original hold triggers/permissions and table constraints are real.
    for (const name of readdirSync(resolve(root, "supabase/migrations")).filter(name => name.endsWith(".sql")).sort()) {
      const result = await command(pgArgs, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`);
      assert.equal(result.code, 0, `${name}: ${result.stderr}`);
    }
    const owner = randomUUID();
    await sql(`insert into auth.users(id,email) values ('${owner}','retention-${owner}@example.invalid');`);
    async function tenant() {
      const id = randomUUID();
      await sql(`insert into public.tenants(id,name,kind,created_by) values ('${id}','Retention fixture','enterprise','${owner}');`);
      return id;
    }
    const hold = id => `insert into public.tenant_legal_holds(tenant_id,hold_reference,reason,placed_by) values ('${id}','fixture','preserve evidence','${owner}');`;
    const release = id => sql(`set role service_role; update public.tenant_legal_holds set released_at=now(),released_by='${owner}',release_reason='release fixture' where tenant_id='${id}' and released_at is null;`);
    async function fixtures(id, suffix = "expired", expiry = "now()-interval '1 day'") {
      const path = `${id}/${randomUUID()}.json`;
      await sql(`insert into public.audit_export_objects(path,tenant_id,created_by,expires_at) values ('${path}','${id}','${owner}',${expiry});
        insert into public.billing_settlement_requests(tenant_id,request_id,settlement_id,receipt_hash,expires_at)
          values ('${id}','request_fixture_${suffix}',gen_random_uuid(),repeat('a',64),${expiry});
        insert into public.billing_webhook_events(event_id,tenant_id,payload,expires_at) values ('${id}_${suffix}','${id}','{}',${expiry});`);
      return path;
    }
    const count = (table, id) => sql(`select count(*) from public.${table} where tenant_id='${id}';`);
    const prepare = (apply = true, limit = 100) => rpc(`public.prepare_expired_audit_exports(${limit},${apply})`);
    const prune = (apply = true, limit = 100) => rpc(`public.prune_expired_billing_records(${limit},${apply})`);
    const ack = token => rpc(`public.ack_expired_audit_export('${token}')`);

    await t.test("held/unheld expiry, dry run, exact budgets, release then prune, settlement immutability", async () => {
      const held = await tenant(), free = await tenant();
      const heldPath = await fixtures(held), freePath = await fixtures(free);
      const currentPath = await fixtures(free, "current", "now()+interval '30 minutes'");
      await sql(`set role service_role; ${hold(held)}`);
      await sql(`insert into public.billing_settlements(tenant_id,settlement_id,request_id,provider,provider_customer_id,status,currency,lines,total_amount_minor,occurred_at,sequence,hash_input,receipt_hash)
        values ('${free}',gen_random_uuid(),'request_fixture_expired','provider_fixture','cus_fixture','quote_issued','USD','[{"sku":"fixture"}]',0,now(),0,'fixture',repeat('a',64));`);
      const before = await sql("select jsonb_agg(to_jsonb(s)) from public.billing_settlements s;");
      const dry = await prepare(false);
      assert.deepEqual(dry.objects.map(row => row.path), [freePath]);
      assert.equal(dry.held_exports, 1);
      assert.equal(dry.pending_authorizations, 0);
      assert.equal(dry.objects[0].authorization_id, null);
      const dryBilling = await prune(false);
      assert.equal(dryBilling.settlement_requests_eligible, 1);
      assert.equal(dryBilling.webhook_events_eligible, 1);
      assert.equal(dryBilling.settlement_requests_deleted, 0);
      assert.equal(dryBilling.webhook_events_deleted, 0);
      assert.equal(await count("billing_settlement_requests", free), "2");
      // Ahead-of-DB caller clocks cannot select future exports or break pruning.
      const batch = await rpc("public.prepare_expired_audit_exports(1,true,now()+interval '1 hour')");
      assert.deepEqual(batch.objects.map(row => row.path), [freePath]);
      assert.notEqual(batch.objects[0].path, currentPath);
      assert.equal((await prepare()).objects.length, 0, "authorization is not handed to a retry worker");
      assert.equal((await prepare()).pending_authorizations, 1);
      await denied(`set role service_role; ${hold(free)}`, /legal_hold_refused_pending_export_deletion/);
      await denied(`set role service_role; delete from public.audit_export_objects where path='${freePath}';`, /permission denied/);
      await denied(`delete from public.audit_export_objects where path='${freePath}';`, /foreign key constraint/);
      await denied(`begin isolation level repeatable read; select public.ack_expired_audit_export('${batch.objects[0].authorization_id}');`, /retention_requires_read_committed/);
      assert.equal((await ack(batch.objects[0].authorization_id)).ledger_rows_deleted, 1);
      await denied(`select public.ack_expired_audit_export('${batch.objects[0].authorization_id}');`, /export_authorization_not_found/);
      const deleted = await prune(true, 1);
      assert.equal(deleted.settlement_requests_deleted, 1);
      assert.equal(deleted.webhook_events_deleted, 1);
      for (const table of ["audit_export_objects", "billing_settlement_requests", "billing_webhook_events"]) {
        assert.equal(await count(table, held), "1");
        assert.equal(await count(table, free), "1");
      }
      await release(held);
      const released = await prepare();
      assert.deepEqual(released.objects.map(row => row.path), [heldPath]);
      await ack(released.objects[0].authorization_id);
      const releasedBilling = await prune();
      assert.equal(releasedBilling.settlement_requests_deleted, 1);
      assert.equal(releasedBilling.webhook_events_deleted, 1);
      for (const table of ["audit_export_objects", "billing_settlement_requests", "billing_webhook_events"]) assert.equal(await count(table, held), "0");
      assert.equal((await prepare()).objects.length, 0);
      assert.equal((await prune()).settlement_requests_deleted, 0);
      assert.equal(await sql("select jsonb_agg(to_jsonb(s)) from public.billing_settlements s;"), before);
    });

    await t.test("global per-table batch budgets bound multiple rows across multiple tenants", async () => {
      const tenants = [await tenant(), await tenant()];
      const paths = [];
      for (const id of tenants) {
        for (let i = 0; i < 3; i++) paths.push(await fixtures(id, `budget_${i}`));
      }
      const observed = [];
      for (let remaining = 6; remaining > 0; remaining--) {
        const exports = await prepare(true, 1);
        assert.equal(exports.objects.length, 1, "export limit is global, not per tenant");
        observed.push(exports.objects[0].path);
        await ack(exports.objects[0].authorization_id);
        const billing = await prune(true, 1);
        assert.equal(billing.settlement_requests_deleted, 1, "request limit is global, not per tenant");
        assert.equal(billing.webhook_events_deleted, 1, "webhook limit is global, not per tenant");
        for (const table of ["audit_export_objects", "billing_settlement_requests", "billing_webhook_events"]) {
          assert.equal(Number(await count(table, tenants[0])) + Number(await count(table, tenants[1])), remaining - 1);
        }
      }
      assert.deepEqual(new Set(observed), new Set(paths));
      assert.equal((await prepare()).objects.length, 0);
      assert.equal((await prune()).settlement_requests_deleted, 0);
      assert.equal((await prune()).webhook_events_deleted, 0);
    });

    await t.test("hold-first transaction excludes tenant without stalling other tenants", async () => {
      const held = await tenant(), free = await tenant();
      const heldPath = await fixtures(held), freePath = await fixtures(free);
      const a = session();
      try {
        await a.query(`begin; set role service_role; ${hold(held)}`);
        const exports = await prepare();
        assert.deepEqual(exports.objects.map(row => row.path), [freePath]);
        assert.equal(exports.contended_tenants, 1);
        const billing = await prune();
        assert.equal(billing.contended_tenants, 1);
        assert.equal(billing.settlement_requests_deleted, 1);
        assert.equal(billing.webhook_events_deleted, 1);
        await a.query("commit;");
        await ack(exports.objects[0].authorization_id);
        assert.equal((await prepare()).held_exports, 1);
        assert.equal((await prune()).settlement_requests_deleted, 0);
        assert.equal(await count("audit_export_objects", held), "1");
        assert.equal(await count("billing_settlement_requests", held), "1");
        await release(held);
        const released = await prepare();
        assert.deepEqual(released.objects.map(row => row.path), [heldPath]);
        await ack(released.objects[0].authorization_id);
        await prune();
      } finally { a.close(); }
    });

    await t.test("authorization-first concurrent hold waits, then refuses committed in-flight deletion", async () => {
      const id = await tenant();
      await fixtures(id);
      const a = session();
      let holdTask;
      try {
        const output = await a.query("begin; set role service_role; select public.prepare_expired_audit_exports(100,true);");
        const authorized = JSON.parse(output).objects[0];
        const application = `hold-${randomUUID()}`;
        holdTask = command(pgArgs, `set application_name='${application}'; set role service_role; ${hold(id)}`);
        await waitForAdvisoryWait(application);
        await a.query("commit;");
        const refused = await holdTask;
        assert.notEqual(refused.code, 0);
        assert.match(refused.stderr, /legal_hold_refused_pending_export_deletion/);
        assert.equal(await count("tenant_legal_holds", id), "0", "refusal is not an active hold");
        assert.equal((await prepare()).objects.length, 0, "even a fresh worker must not replay pending HTTP");
        await ack(authorized.authorization_id);
        await sql(`set role service_role; ${hold(id)}`);
        assert.equal((await prune()).settlement_requests_deleted, 0);
        await release(id); await prune();
      } finally { a.close(); if (holdTask) await holdTask; }
    });

    await t.test("billing-first concurrent hold waits for committed SQL deletion", async () => {
      const id = await tenant();
      await fixtures(id);
      const a = session();
      let holdTask;
      try {
        const result = JSON.parse(await a.query("begin; set role service_role; select public.prune_expired_billing_records(100,true);"));
        assert.equal(result.settlement_requests_deleted, 1);
        assert.equal(result.webhook_events_deleted, 1);
        const application = `hold-${randomUUID()}`;
        holdTask = command(pgArgs, `set application_name='${application}'; set role service_role; ${hold(id)}`);
        await waitForAdvisoryWait(application);
        await a.query("commit;");
        assert.equal((await holdTask).code, 0);
        assert.equal(await count("tenant_legal_holds", id), "1");
        assert.equal(await count("billing_settlement_requests", id), "0");
        assert.equal((await prepare()).objects.length, 0);
        await release(id);
        const exports = await prepare();
        await ack(exports.objects[0].authorization_id);
      } finally { a.close(); if (holdTask) await holdTask; }
    });

    await t.test("hold history and release assertions remain intact; permissions fail closed", async () => {
      const id = await tenant();
      await sql(`set role service_role; ${hold(id)}`);
      await denied(`delete from public.tenant_legal_holds where tenant_id='${id}';`, /legal_hold_history_is_immutable/);
      for (const mutation of ["reason='changed'", "hold_reference='changed'", "id=gen_random_uuid()", "tenant_id=gen_random_uuid()", "placed_by=gen_random_uuid()", "placed_at=now()+interval '1 hour'"]) {
        await denied(`update public.tenant_legal_holds set ${mutation}, released_at=now(),released_by='${owner}',release_reason='release' where tenant_id='${id}';`, /legal_hold_update_must_be_a_single_release/);
      }
      await denied(`update public.tenant_legal_holds set released_at=now() where tenant_id='${id}';`, /legal_hold_update_must_be_a_single_release/);
      await release(id);
      await denied(`update public.tenant_legal_holds set release_reason='again' where tenant_id='${id}';`, /legal_hold_update_must_be_a_single_release/);
      await denied(`begin isolation level repeatable read; ${hold(id)}`, /retention_requires_read_committed/);
      await denied("begin isolation level repeatable read; select public.prepare_expired_audit_exports();", /retention_requires_read_committed/);
      await denied("begin isolation level repeatable read; select public.prune_expired_billing_records();", /retention_requires_read_committed/);
      for (const role of ["anon", "authenticated"]) {
        for (const call of ["prepare_expired_audit_exports()", "prune_expired_billing_records()", `ack_expired_audit_export('${randomUUID()}')`]) {
          await denied(`set role ${role}; select public.${call};`, /permission denied/);
        }
      }
      await denied(`set role service_role; delete from public.audit_export_deletion_authorizations;`, /permission denied/);
      await denied("select public.prepare_expired_audit_exports(0);", /invalid_retention_batch/);
      await denied("select public.prune_expired_billing_records(1001);", /invalid_retention_batch/);
      await sql("insert into public.billing_webhook_events(event_id,payload,expires_at) values ('unattributed_fixture','{}',now()-interval '1 day');");
      const result = await prune();
      assert.equal(result.unattributed_webhooks_retained, 1);
      assert.equal(result.webhook_events_deleted, 0);
    });
  } finally {
    const removed = await command(["rm", "--force", container]);
    assert.equal(removed.code, 0, removed.stderr);
  }
});
