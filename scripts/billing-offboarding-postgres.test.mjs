// Real cached PostgreSQL integration/concurrency regression for immutable
// settlement retention during tenant offboarding. Creates and removes its own
// network-isolated container and applies the complete canonical migration chain.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as delay } from "node:timers/promises";
import { test } from "node:test";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const container = `aidr-billing-offboarding-${randomUUID()}`;
const pgArgs = ["exec", "-i", "-e", "PGOPTIONS=-c statement_timeout=10000 -c lock_timeout=5000",
  container, "psql", "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-U", "postgres", "-d", "postgres"];
const literal = value => `'${String(value).replaceAll("'", "''")}'`;

function command(args, input = "", timeout = 45_000) {
  return new Promise((done, reject) => {
    const child = spawn("docker", args, { stdio: ["pipe", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    const timer = setTimeout(() => child.kill(), timeout);
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.once("error", error => { clearTimeout(timer); reject(error); });
    child.once("close", code => { clearTimeout(timer); done({ code, stdout: stdout.trim(), stderr }); });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}
async function sql(text) {
  const result = await command(pgArgs, text);
  assert.equal(result.code, 0, result.stderr);
  return result.stdout;
}
async function denied(text, pattern) {
  const result = await command(pgArgs, text);
  assert.notEqual(result.code, 0, "statement must be refused");
  assert.match(result.stderr, pattern);
}
const rpc = async expression => JSON.parse(await sql(`set role service_role; select ${expression};`));

function session() {
  const child = spawn("docker", pgArgs, { stdio: ["pipe", "pipe", "pipe"] });
  let output = "", errors = "", pending;
  child.stdout.on("data", chunk => {
    output += chunk;
    if (!pending) return;
    const index = output.indexOf(`${pending.marker}\n`);
    if (index < 0) return;
    const value = output.slice(0, index).trim();
    output = output.slice(index + pending.marker.length + 1);
    const done = pending.done;
    pending = undefined;
    done(value);
  });
  child.stderr.on("data", chunk => { errors += chunk; });
  child.once("error", error => pending?.reject(error));
  child.once("close", code => pending?.reject(new Error(`psql exited ${code}: ${errors}`)));
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
  for (let attempt = 0; attempt < 200; attempt++) {
    if (await sql(`select exists(select 1 from pg_stat_activity where application_name=${literal(application)} and wait_event='advisory');`) === "t") return;
    await delay(20);
  }
  assert.fail("offboarding worker did not wait on the legal-hold advisory lock");
}

test("immutable settlement retention completes offboarding honestly on real PostgreSQL", async t => {
  const started = await command(["run", "--detach", "--rm", "--pull", "never", "--network", "none", "--name", container,
    "-e", "POSTGRES_PASSWORD=billing-offboarding-fixture", "supabase/postgres:17.6.1.136"]);
  assert.equal(started.code, 0, started.stderr);
  try {
    let ready = false;
    for (let attempt = 0; attempt < 100; attempt++) {
      if ((await command(["exec", container, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"])).code === 0) {
        ready = true;
        break;
      }
      await delay(100);
    }
    assert.ok(ready, "disposable PostgreSQL must start");
    const bootstrap = await command(["exec", "-i", container, "psql", "-X", "-v", "ON_ERROR_STOP=1", "-U", "supabase_admin", "-d", "postgres"],
      `grant create on schema storage to postgres;
       create function auth.jwt() returns jsonb language sql stable as $$
         select coalesce(nullif(current_setting('request.jwt.claims',true),''),'{}')::jsonb
       $$;`);
    assert.equal(bootstrap.code, 0, bootstrap.stderr);
    await sql(`create table storage.buckets(id text primary key, name text, public boolean);
      create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text, metadata jsonb);
      create function storage.foldername(name text) returns text[] language sql immutable as $$ select string_to_array(name, '/') $$;`);
    const owner = randomUUID();
    const legacyTenant = randomUUID();
    let legacyRun;
    for (const name of readdirSync(resolve(root, "supabase/migrations")).filter(name => name.endsWith(".sql")).sort()) {
      if (name === "20260916000008_billing_settlement_offboarding_retention.sql") {
        await sql(`insert into auth.users(id,email) values (${literal(owner)},${literal(`billing-offboard-${owner}@example.invalid`)});
          insert into public.tenants(id,name,kind,created_by) values (${literal(legacyTenant)},'Legacy empty receipt','enterprise',${literal(owner)});
          set role service_role;
          select public.request_tenant_offboarding(${literal(legacyTenant)},${literal(owner)})->>'run_id';`)
          .then(value => { legacyRun = value; });
        await sql(`set role service_role; update public.tenant_offboarding_phase_receipts
          set status='completed',completed_at=now() where run_id=${literal(legacyRun)} and phase='entitlements';`);
        assert.equal(await sql(`select operation from public.tenant_offboarding_phase_receipts
          where run_id=${literal(legacyRun)} and phase='billing_settlements';`), "delete_records");
      }
      const result = await command(pgArgs, `begin;\n${readFileSync(resolve(root, "supabase/migrations", name), "utf8")}\ncommit;`, 60_000);
      assert.equal(result.code, 0, `${name}: ${result.stderr}`);
    }
    assert.equal(await sql(`select operation || ':' || settlement_rows_retained from public.tenant_offboarding_phase_receipts
      where run_id=${literal(legacyRun)} and phase='billing_settlements';`), "retain_immutable_evidence:0");
    async function tenant(name) {
      const id = randomUUID();
      await sql(`insert into public.tenants(id,name,kind,created_by) values (${literal(id)},${literal(name)},'enterprise',${literal(owner)});
        insert into public.tenant_members(tenant_id,user_id,role) values (${literal(id)},${literal(owner)},'owner')
          on conflict (tenant_id,user_id) do update set role='owner',expires_at=null;
        update public.tenant_data_retention_policies set retention_days=0 where tenant_id=${literal(id)};`);
      return id;
    }
    async function settlement(id, suffix) {
      await sql(`insert into public.billing_settlements
        (tenant_id,settlement_id,request_id,provider,provider_customer_id,status,currency,lines,total_amount_minor,occurred_at,sequence,hash_input,receipt_hash)
        values (${literal(id)},gen_random_uuid(),${literal(`request_${suffix}_12345678`)},'provider_fixture',${literal(`cus_${suffix}`)},
          'quote_issued','USD','[{"sku":"fixture","quantity":3}]',0,now(),0,${literal(`fixture:${suffix}`)},repeat(${literal(suffix.slice(0, 1))},64));
        insert into public.billing_settlement_requests(tenant_id,request_id,settlement_id,receipt_hash)
          select tenant_id,request_id,settlement_id,receipt_hash from public.billing_settlements where tenant_id=${literal(id)};
        insert into public.billing_entitlement_projections(tenant_id,sku,seats) values (${literal(id)},'fixture',3);
        insert into public.entitlements(user_id,tenant_id,extra_agents) values (${literal(owner)},${literal(id)},3);`);
    }
    const request = id => rpc(`public.request_tenant_offboarding(${literal(id)},${literal(owner)})`);
    const batch = run => rpc(`public.run_tenant_offboarding_batch(${literal(run)},100)`);
    async function complete(run) {
      for (let attempt = 0; attempt < 150; attempt++) {
        const state = await batch(run);
        if (state.action === "invalidate_cache") {
          await rpc(`public.ack_tenant_offboarding_cache(${literal(run)},array['fixture-cache'],0)`);
        } else if (state.action === "delete_storage_objects") {
          assert.fail("fixture has no storage objects");
        } else if (state.status === "completed") return state;
      }
      assert.fail("offboarding did not complete within bounded batches");
    }
    const count = (table, id) => sql(`select count(*) from public.${table} where tenant_id=${literal(id)};`);

    await t.test("nonempty ledger is retained, inaccessible and explicitly receipted without entitlement resurrection", async () => {
      const id = await tenant("Retained ledger"), neighbor = await tenant("Neighbor");
      await settlement(id, "a".repeat(16));
      await settlement(neighbor, "b".repeat(16));
      const before = await sql(`select to_jsonb(s) from public.billing_settlements s where tenant_id=${literal(id)};`);
      const run = await request(id);
      const completed = await complete(run.run_id);
      assert.equal(completed.status, "completed");
      assert.equal(await count("billing_settlements", id), "1");
      assert.equal(await count("billing_settlements", neighbor), "1");
      assert.equal(await sql(`select to_jsonb(s) from public.billing_settlements s where tenant_id=${literal(id)};`), before);
      for (const table of ["billing_settlement_requests", "billing_entitlement_projections", "entitlements"]) {
        assert.equal(await count(table, id), "0", `${table} must be operationally erased`);
      }
      const receipt = JSON.parse(await sql(`select to_jsonb(p) from public.tenant_offboarding_phase_receipts p
        where run_id=${literal(run.run_id)} and phase='billing_settlements';`));
      assert.equal(receipt.operation, "retain_immutable_evidence");
      assert.equal(receipt.rows_deleted, 0);
      assert.equal(receipt.settlement_rows_retained, 1);
      assert.match(receipt.settlement_retention_digest, /^[0-9a-f]{64}$/);
      assert.match(receipt.settlement_retention_reason, /external finance\/legal retention/);
      assert.match(receipt.settlement_retention_owner_requirement, /retention owner must govern/);
      assert.equal(receipt.settlement_retention_digest,
        await sql(`select app.billing_settlement_retention_digest(${literal(id)});`));
      await denied(`update public.billing_settlements set status='cancelled' where tenant_id=${literal(id)};`, /billing_settlement_is_append_only/);
      await denied(`delete from public.billing_settlements where tenant_id=${literal(id)};`, /billing_settlement_is_append_only/);
      await denied(`set role service_role; select * from public.billing_settlements where tenant_id=${literal(id)};`, /permission denied/);
      await denied(`set role authenticated; select * from public.billing_settlements where tenant_id=${literal(id)};`, /permission denied/);
      await denied(`set role service_role; select public.list_billing_settlements(${literal(id)},${literal(owner)});`, /billing_forbidden/);
      await denied(`set role service_role; insert into public.billing_settlements
        (tenant_id,settlement_id,request_id,provider,provider_customer_id,status,currency,lines,total_amount_minor,occurred_at,sequence,hash_input,receipt_hash)
        values (${literal(id)},gen_random_uuid(),'request_after_close_123','provider_fixture','cus_closed','quote_issued','USD','[{"sku":"x"}]',0,now(),0,'x',repeat('c',64));`, /permission denied|tenant_not_active_for_billing_settlement/);
      await denied(`set role service_role; update public.tenant_offboarding_phase_receipts set settlement_rows_retained=0
        where run_id=${literal(run.run_id)} and phase='billing_settlements';`, /billing_settlement_retention_receipt_is_immutable/);
      await denied(`set role service_role; update public.tenant_offboarding_runs set tenant_id=${literal(neighbor)}
        where id=${literal(run.run_id)};`, /tenant_offboarding_run_identity_is_immutable/);
    });

    await t.test("empty ledger still completes with an explicit zero-row digest", async () => {
      const id = await tenant("Empty ledger");
      const run = await request(id);
      const emptyDigest = await sql(`select app.billing_settlement_retention_digest(${literal(id)});`);
      await denied(`set role service_role; update public.tenant_offboarding_phase_receipts
        set phase='billing_settlements',operation='retain_immutable_evidence',status='completed',completed_at=now(),
          rows_deleted=0,settlement_rows_retained=0,
          settlement_retention_digest=${literal(emptyDigest)},
          settlement_retention_reason='Immutable settlement ledger retained outside tenant operational access for external finance/legal retention.',
          settlement_retention_owner_requirement='External finance/legal retention owner must govern retention duration and authorized evidence access.'
        where run_id=${literal(run.run_id)} and phase='rate_limits';`, /billing_settlement_retention_receipt_is_immutable/);
      assert.equal((await complete(run.run_id)).status, "completed");
      const receipt = JSON.parse(await sql(`select jsonb_build_object('retained',settlement_rows_retained,'digest',settlement_retention_digest)
        from public.tenant_offboarding_phase_receipts where run_id=${literal(run.run_id)} and phase='billing_settlements';`));
      assert.equal(receipt.retained, 0);
      assert.equal(receipt.digest, await sql(`select encode(extensions.digest('','sha256'),'hex');`));
    });

    await t.test("settlement insertion and offboarding serialize in both lock orders", async () => {
      const id = await tenant("Concurrent settlement");
      const inserter = session();
      let worker;
      try {
        await inserter.query(`begin; set role service_role;
          select public.apply_billing_settlement(
            ${literal(id)},${literal(owner)},gen_random_uuid(),'request_insert_race_123','provider_fixture',
            'cus_insert_race',null,'quote_issued','USD','[{"sku":"race","quantity":1}]',
            0,null,0,0,now(),0,'race',repeat('e',64));`);
        const application = `billing-offboard-request-${randomUUID()}`;
        worker = command(pgArgs, `set application_name=${literal(application)}; set role service_role;
          select public.request_tenant_offboarding(${literal(id)},${literal(owner)});`);
        await waitForAdvisoryWait(application);
        await inserter.query("commit;");
        const requested = await worker;
        assert.equal(requested.code, 0, requested.stderr);
        const run = JSON.parse(requested.stdout);
        assert.equal(await count("billing_settlements", id), "1");
        await denied(`set role service_role; select public.apply_billing_settlement(
          ${literal(id)},${literal(owner)},gen_random_uuid(),'request_after_request_123','provider_fixture',
          'cus_after_request',null,'quote_issued','USD','[{"sku":"race","quantity":1}]',
          0,null,0,0,now(),0,'race2',repeat('f',64));`, /billing_forbidden/);
        assert.equal(await count("billing_settlements", id), "1");
        assert.equal(await count("billing_settlement_requests", id), "1");
        assert.equal((await complete(run.run_id)).status, "completed");
        assert.equal(await sql(`select settlement_rows_retained from public.tenant_offboarding_phase_receipts
          where run_id=${literal(run.run_id)} and phase='billing_settlements';`), "1");
      } finally {
        inserter.close();
        if (worker) await worker;
      }
    });

    await t.test("legal hold serializes against offboarding and blocks before retention evidence", async () => {
      const id = await tenant("Concurrent hold");
      await settlement(id, "d".repeat(16));
      const run = await request(id);
      const holder = session();
      let worker;
      try {
        await holder.query(`begin; set role service_role;
          insert into public.tenant_legal_holds(tenant_id,hold_reference,reason,placed_by)
          values (${literal(id)},'billing-offboard-concurrent','preserve financial evidence',${literal(owner)});`);
        const application = `billing-offboard-worker-${randomUUID()}`;
        worker = command(pgArgs, `set application_name=${literal(application)}; set role service_role;
          select public.run_tenant_offboarding_batch(${literal(run.run_id)},100);`);
        await waitForAdvisoryWait(application);
        await holder.query("commit;");
        const result = await worker;
        assert.equal(result.code, 0, result.stderr);
        assert.equal(JSON.parse(result.stdout).status, "blocked_legal_hold");
        assert.equal(await count("billing_settlements", id), "1");
        assert.equal(await sql(`select count(*) from public.tenant_offboarding_phase_receipts
          where run_id=${literal(run.run_id)} and phase='billing_settlements';`), "0");
        await denied(`update public.tenants set status='closed',closed_at=now() where id=${literal(id)};`, /billing_settlement_retention_evidence_missing/);
        await sql(`set role service_role; update public.tenant_legal_holds
          set released_at=now(),released_by=${literal(owner)},release_reason='test release'
          where tenant_id=${literal(id)} and released_at is null;`);
        assert.equal((await complete(run.run_id)).status, "completed");
        assert.equal(await count("billing_settlements", id), "1");
        assert.equal(await count("entitlements", id), "0");
      } finally {
        holder.close();
        if (worker) await worker;
      }
    });
  } finally {
    const removed = await command(["rm", "--force", container]);
    assert.equal(removed.code, 0, removed.stderr);
  }
});
