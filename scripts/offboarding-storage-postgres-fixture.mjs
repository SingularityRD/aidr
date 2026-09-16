// Called by retention-holds-postgres.test.mjs AFTER its existing tests, inside
// the same disposable, --network none PostgreSQL lifetime. SQL is never mocked.
// Only Storage's HTTP/bytes and the PostgREST transport are local fixtures; this
// does not claim provider-side erasure or external cache invalidation evidence.
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readFile, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const literal = value => `'${String(value).replaceAll("'", "''")}'`;
const array = (values, type = "text") => `array[${values.map(literal).join(",")}]::${type}[]`;

export async function testOffboardingStorage(t, {
  sql, denied, rpc, command, pgArgs, session, waitForAdvisoryWait,
  tenant, hold, release, owner, count,
}) {
  const bytes = new Map();
  const ambiguous = new Set();
  const lostResponses = new Set();
  const calls = [];
  const handlerErrors = [];
  const key = `fixture-only-${randomUUID()}`;
  const receipts = run => sql(`set role service_role; select coalesce(jsonb_agg(to_jsonb(p) order by phase_order),'[]') from public.tenant_offboarding_phase_receipts p where run_id=${literal(run)};`).then(JSON.parse);
  const requestRun = id => rpc(`public.request_tenant_offboarding(${literal(id)},${literal(owner)})`);
  const batch = run => rpc(`public.run_tenant_offboarding_batch(${literal(run)},100)`);
  const ackCall = (run, paths, tokens) => `public.ack_tenant_offboarding_objects(${literal(run)},${array(paths)},${array(tokens, "uuid")})`;
  const auths = id => count("audit_export_deletion_authorizations", id);
  const json = (response, status, value) => {
    response.writeHead(status, { "content-type": "application/json" });
    response.end(JSON.stringify(value));
  };

  const server = createServer(async (request, response) => {
    try {
      assert.equal(request.headers.apikey, key);
      assert.equal(request.headers.authorization, `Bearer ${key}`);
      const url = new URL(request.url, "http://127.0.0.1");
      let text = "";
      for await (const chunk of request) text += chunk;
      const body = text ? JSON.parse(text) : null;
      calls.push({ method: request.method, path: url.pathname, body });
      if (request.method === "POST" && url.pathname.startsWith("/rest/v1/rpc/")) {
        const name = url.pathname.slice("/rest/v1/rpc/".length);
        let result;
        if (name === "request_tenant_offboarding") {
          result = await rpc(`public.request_tenant_offboarding(${literal(body.p_tenant_id)},${literal(body.p_requested_by)})`);
        } else if (name === "run_tenant_offboarding_batch") {
          assert.ok(Number.isSafeInteger(body.p_batch_size));
          result = await rpc(`public.run_tenant_offboarding_batch(${literal(body.p_run_id)},${body.p_batch_size})`);
        } else if (name === "ack_tenant_offboarding_objects") {
          for (const path of body.p_paths) assert.equal(bytes.has(path), false, "ACK must follow fixture-byte absence");
          result = await rpc(ackCall(body.p_run_id, body.p_paths, body.p_authorization_ids));
        } else {
          throw new Error(`Unexpected fixture RPC ${name}`);
        }
        return json(response, 200, result);
      }
      if (request.method === "GET" && url.pathname === "/rest/v1/tenant_offboarding_phase_receipts") {
        const filter = url.searchParams.get("run_id");
        assert.ok(filter?.startsWith("eq."));
        return json(response, 200, await receipts(filter.slice(3)));
      }
      if (request.method === "DELETE" && url.pathname === "/storage/v1/object/aidr-audit-exports") {
        assert.ok(Array.isArray(body.prefixes) && body.prefixes.length > 0);
        // HTTP must occur AFTER committed authorization, while its ledger row
        // still exists. This is checked in a fresh real PostgreSQL transaction.
        const authorized = Number(await sql(`select count(*) from public.audit_export_deletion_authorizations a join public.audit_export_objects o using(path) where a.offboarding_run_id is not null and a.path=any(${array(body.prefixes)});`));
        assert.equal(authorized, body.prefixes.length);
        for (const path of body.prefixes) {
          assert.ok(bytes.has(path), "a fresh worker must never issue a second DELETE");
          bytes.delete(path);
        }
        // Model an ambiguous provider response AFTER the provider removed bytes.
        // Lack of an exact response is deliberately NOT a successful deletion.
        if (body.prefixes.some(path => lostResponses.has(path))) {
          response.destroy(); // Lost response, not a delayed request or widened timeout.
          return;
        }
        const result = body.prefixes.some(path => ambiguous.has(path)) ? [] : body.prefixes.map(name => ({ name })).reverse();
        return json(response, 200, result);
      }
      const infoPrefix = "/storage/v1/object/info/aidr-audit-exports/";
      if (request.method === "GET" && url.pathname.startsWith(infoPrefix)) {
        const path = decodeURIComponent(url.pathname.slice(infoPrefix.length));
        return json(response, bytes.has(path) ? 200 : 404, bytes.has(path) ? { name: path } : { code: "not_found" });
      }
      throw new Error(`Unexpected fixture route ${request.method} ${url.pathname}`);
    } catch (error) {
      handlerErrors.push(error);
      json(response, 500, { code: "fixture_failed", message: String(error) });
    }
  });
  await new Promise((done, reject) => {
    server.once("error", reject);
    server.listen(0, "127.0.0.1", done);
  });
  // Keep fixture artifacts for inspection. Never use os.tmpdir() or recursively
  // remove files: every write is under this worktree and contains fixture data.
  let directory;
  try {
    await mkdir(join(root, ".tmp-test"), { recursive: true });
    directory = await mkdtemp(join(root, ".tmp-test", "offboarding-storage-"));
    await writeFile(join(directory, "deployment.json"), JSON.stringify({
      supabase_url: `http://127.0.0.1:${server.address().port}`, development: true,
    }));
    await writeFile(join(directory, ".env"), `SERVICE_ROLE_KEY=${key}\n`, { mode: 0o600 });
    t.diagnostic(`Offboarding fixture evidence retained at ${directory}`);

    async function cli(id, maxBatches = 1, expected = 2) {
      const errorStart = handlerErrors.length;
      const child = spawn(process.execPath, [join(root, "scripts/deployment-offboarding.mjs"), directory,
        "--tenant", id, "--apply", "--requested-by", owner,
        "--batch-size", "100", "--max-batches", String(maxBatches)], {
        cwd: root, stdio: ["ignore", "pipe", "pipe"], timeout: 30_000,
      });
      let stdout = "", stderr = "";
      child.stdout.setEncoding("utf8").on("data", chunk => { stdout += chunk; });
      child.stderr.setEncoding("utf8").on("data", chunk => { stderr += chunk; });
      const code = await new Promise((done, reject) => {
        child.once("error", reject);
        child.once("close", done);
      });
      assert.equal(handlerErrors.length, errorStart, handlerErrors.slice(errorStart).map(String).join("\n"));
      assert.equal(code, expected, `CLI exited ${code}: ${stderr}\n${stdout}`);
      if (expected === 1) return { stderr };
      const evidence = JSON.parse(stdout);
      assert.deepEqual(JSON.parse(await readFile(join(directory, `offboarding-evidence-${id}.json`), "utf8")), evidence);
      assert.equal(evidence.tenant_id, id);
      assert.equal(evidence.backup_scope, "excluded_external_retention");
      assert.match(evidence.backup_exception, /Backup copies are excluded/);
      return evidence;
    }
    async function seed(objects = 1) {
      const id = await tenant();
      // Snapshot zero-day policies BEFORE requesting, without rewriting receipts.
      await sql(`update public.tenant_data_retention_policies set retention_days=0 where tenant_id=${literal(id)};`);
      const paths = Array.from({ length: objects }, () => `${id}/${randomUUID()}.json`).sort();
      for (const path of paths) {
        await sql(`insert into public.audit_export_objects(path,tenant_id,created_by,expires_at) values (${literal(path)},${literal(id)},${literal(owner)},now()-interval '1 day');`);
        bytes.set(path, Buffer.from(`private fixture evidence ${path}`));
      }
      return { id, paths };
    }
    const storageCalls = () => calls.filter(call => call.method === "DELETE");
    const ackCalls = () => calls.filter(call => call.path === "/rest/v1/rpc/ack_tenant_offboarding_objects");
    async function assertPending(id, paths, beforeDeletes, beforeAcks) {
      const evidence = await cli(id);
      assert.equal(evidence.complete, false);
      assert.equal(evidence.storage_reconciliation_required, true);
      assert.equal(evidence.storage_batches, 0);
      assert.equal(storageCalls().length, beforeDeletes);
      assert.equal(ackCalls().length, beforeAcks);
      assert.equal(await auths(id), String(paths.length));
      assert.equal(await count("audit_export_objects", id), String(paths.length));
      return evidence;
    }
    async function refuseClosure(id, run, error) {
      for (const statement of [
        `update public.tenant_offboarding_phase_receipts set status='completed',completed_at=now() where run_id=${literal(run)} and phase='audit_export_objects'`,
        `update public.tenant_offboarding_runs set status='completed',completed_at=now() where id=${literal(run)}`,
        `update public.tenants set status='closed',closed_at=now() where id=${literal(id)}`,
      ]) await denied(`set role service_role; ${statement};`, error);
    }

    await t.test("actual CLI holds Storage bytes, releases then prunes, and executes the complete cache/DLP/billing chain", async () => {
      const held = await seed(), free = await seed(2);
      await sql(`insert into public.billing_settlement_requests(tenant_id,request_id,settlement_id,receipt_hash,expires_at)
        values (${literal(held.id)},'request_offboard_held',gen_random_uuid(),repeat('a',64),now()-interval '1 day');
        insert into public.billing_webhook_events(event_id,tenant_id,payload,expires_at)
        values (${literal(held.id)},${literal(held.id)},'{}',now()-interval '1 day');
        insert into public.billing_settlement_requests(tenant_id,request_id,settlement_id,receipt_hash,expires_at)
        values (${literal(free.id)},'request_offboard_chain',gen_random_uuid(),repeat('b',64),now()+interval '1 day');
        insert into public.billing_webhook_events(event_id,tenant_id,payload,expires_at)
        values (${literal(free.id)},${literal(free.id)},'{}',now()+interval '1 day');
        insert into public.tenant_dlp_policies(tenant_id,version,policy,updated_by)
        values (${literal(free.id)},1,jsonb_build_object('tenantId',${literal(free.id)},'version',1),${literal(owner)});
        insert into public.dlp_policy_revisions(tenant_id,version,policy,updated_by)
        values (${literal(free.id)},1,jsonb_build_object('tenantId',${literal(free.id)},'version',1),${literal(owner)});`);
      await sql(`set role service_role; ${hold(held.id)}`);
      const blocked = await cli(held.id);
      assert.equal(blocked.status, "blocked_legal_hold");
      assert.equal(blocked.storage_batches, 0);
      assert.equal(storageCalls().length, 0);
      assert.equal(await auths(held.id), "0");
      assert.ok(bytes.has(held.paths[0]));
      assert.equal(await count("audit_export_objects", held.id), "1");
      const applied = await cli(free.id);
      assert.equal(applied.storage_batches, 1);
      assert.equal(applied.complete, false);
      assert.equal(await auths(free.id), "0");
      assert.equal(await count("audit_export_objects", free.id), "0");
      for (const path of free.paths) assert.equal(bytes.has(path), false);
      assert.ok(bytes.has(held.paths[0]));
      assert.equal(await count("billing_settlement_requests", free.id), "1", "Storage phase does not bypass commercial retention");
      const deletion = calls.findIndex(call => call.method === "DELETE");
      const acknowledgment = calls.findIndex(call => call.path.endsWith("/ack_tenant_offboarding_objects"));
      const infos = calls.slice(deletion + 1, acknowledgment).filter(call => call.path.startsWith("/storage/v1/object/info/"));
      assert.equal(infos.length, free.paths.length);
      assert.ok(acknowledgment > deletion);
      assert.deepEqual(storageCalls()[0].body.prefixes, free.paths);
      assert.equal(applied.phase_receipts.find(row => row.phase === "audit_export_objects").rows_deleted, 2);
      const acceptedAck = ackCalls()[0].body;
      await denied(`set role service_role; select ${ackCall(applied.run_id, acceptedAck.p_paths, acceptedAck.p_authorization_ids)};`, /offboarding_object_phase_not_active/);
      await rpc("public.prune_expired_billing_records(100,true)");
      assert.equal(await count("billing_settlement_requests", held.id), "1");
      assert.equal(await count("billing_webhook_events", held.id), "1");
      await release(held.id);
      assert.equal((await cli(held.id)).storage_batches, 1);
      await rpc("public.prune_expired_billing_records(100,true)");
      for (const table of ["audit_export_objects", "billing_settlement_requests", "billing_webhook_events"]) assert.equal(await count(table, held.id), "0");
      assert.equal(bytes.has(held.paths[0]), false);

      const cache = await cli(free.id, 100);
      assert.equal(cache.cache_invalidation.action_returned, true);
      assert.equal(cache.complete, false);
      const byPhase = new Map((await receipts(applied.run_id)).map(row => [row.phase, row]));
      for (const [phase, order] of [["tenant_cache", 41], ["dlp_policy_revisions", 42], ["tenant_dlp_policies", 43], ["enterprise_invoice_orders", 90], ["billing_settlements", 91]]) {
        assert.equal(byPhase.get(phase)?.phase_order, order, `${phase} survives complete-chain dispatcher patches`);
        assert.equal(byPhase.get(phase)?.retention_days, 0);
      }
      assert.equal(byPhase.get("tenant_cache").status, "running");
      assert.equal(byPhase.get("billing_settlements").rows_deleted, 0);
      await rpc(`public.ack_tenant_offboarding_cache(${literal(applied.run_id)},${array([`tenant:${free.id}:*`])},0)`);
      const completed = await cli(free.id, 100, 0);
      assert.equal(completed.complete, true);
      assert.equal(completed.cache_invalidation.acknowledged, true);
      assert.equal(completed.cache_invalidation.receipt.tenant_id, free.id);
      assert.ok(completed.phase_receipts.every(row => row.status === "completed"));
      for (const phase of ["dlp_policy_revisions", "tenant_dlp_policies"]) {
        assert.equal(completed.phase_receipts.find(row => row.phase === phase).rows_deleted, 1);
      }
      for (const table of ["audit_export_objects", "audit_export_deletion_authorizations", "dlp_policy_revisions", "tenant_dlp_policies", "billing_settlements", "billing_settlement_requests", "billing_webhook_events"]) assert.equal(await count(table, free.id), "0");
      assert.equal(await sql(`select status from public.tenants where id=${literal(free.id)};`), "closed");
      assert.equal(await sql(`select status from public.tenant_offboarding_runs where id=${literal(applied.run_id)};`), "completed");
    });

    await t.test("ambiguous actual Storage DELETE preserves ledger/authorization and CLI retry does not DELETE or ACK", async () => {
      const fixture = await seed(2);
      for (const path of fixture.paths) ambiguous.add(path);
      const deletes = storageCalls().length, acks = ackCalls().length;
      const failed = await cli(fixture.id, 1, 1);
      assert.match(failed.stderr, /inexact result/);
      assert.equal(storageCalls().length, deletes + 1);
      assert.equal(ackCalls().length, acks);
      for (const path of fixture.paths) assert.equal(bytes.has(path), false);
      const run = await requestRun(fixture.id);
      const before = await receipts(run.run_id);
      const pending = await assertPending(fixture.id, fixture.paths, deletes + 1, acks);
      assert.equal(pending.run_id, run.run_id);
      assert.deepEqual(await receipts(run.run_id), before, "pending retry cannot advance any phase");
      await refuseClosure(fixture.id, run.run_id, /offboarding_pending_storage_authorization/);
    });

    await t.test("lost Storage response after removing bytes leaves durable pending state without a second DELETE or ACK", async () => {
      const fixture = await seed();
      lostResponses.add(fixture.paths[0]);
      const deletes = storageCalls().length, acks = ackCalls().length;
      const failed = await cli(fixture.id, 1, 1);
      assert.match(failed.stderr, /fetch failed/);
      assert.equal(storageCalls().length, deletes + 1);
      assert.equal(ackCalls().length, acks);
      assert.equal(bytes.has(fixture.paths[0]), false);
      const evidence = await assertPending(fixture.id, fixture.paths, deletes + 1, acks);
      await refuseClosure(fixture.id, evidence.run_id, /offboarding_pending_storage_authorization/);
    });

    await t.test("existing immutable billing settlement guard remains fail-closed at commercial offboarding", async () => {
      // The existing settlement purge cannot delete append-only settlements.
      // Document that pre-existing limitation without weakening its finance guard
      // or claiming this tenant completed. Empty-ledger completion is tested above.
      const fixture = await seed(0);
      await sql(`insert into public.billing_settlements(tenant_id,settlement_id,request_id,provider,provider_customer_id,status,currency,lines,total_amount_minor,occurred_at,sequence,hash_input,receipt_hash)
        values (${literal(fixture.id)},gen_random_uuid(),'request_offboard_immutable','provider_fixture','cus_fixture','quote_issued','USD','[{"sku":"fixture"}]',0,now(),0,'fixture',repeat('c',64));`);
      const before = await sql(`select to_jsonb(s) from public.billing_settlements s where tenant_id=${literal(fixture.id)};`);
      const run = await requestRun(fixture.id);
      let reachedCommercial = false;
      for (let i = 0; i < 100; i++) {
        const next = (await receipts(run.run_id)).filter(row => row.status !== "completed")
          .sort((a, b) => Date.parse(a.eligible_at) - Date.parse(b.eligible_at) || a.phase_order - b.phase_order)[0];
        assert.ok(next);
        if (next.phase === "entitlements") {
          await denied(`set role service_role; select public.run_tenant_offboarding_batch(${literal(run.run_id)},100);`, /billing_settlement_is_append_only/);
          reachedCommercial = true;
          break;
        }
        const state = await batch(run.run_id);
        assert.equal(state.action, undefined);
      }
      assert.equal(reachedCommercial, true);
      assert.equal(await sql(`select to_jsonb(s) from public.billing_settlements s where tenant_id=${literal(fixture.id)};`), before);
      assert.equal(await sql(`select status from public.tenants where id=${literal(fixture.id)};`), "closing");
      assert.notEqual(await sql(`select status from public.tenant_offboarding_runs where id=${literal(run.run_id)};`), "completed");
      assert.notEqual((await receipts(run.run_id)).find(row => row.phase === "entitlements").status, "completed");
    });

    await t.test("crash after direct authorization is not replayed; ACK requires exact whole-batch run/path/token binding", async () => {
      const fixture = await seed(2), foreign = await seed();
      const run = await requestRun(fixture.id), foreignRun = await requestRun(foreign.id);
      await refuseClosure(fixture.id, run.run_id, /offboarding_storage_residue/);
      await denied(`set role service_role; insert into public.tenant_offboarding_runs(tenant_id,requested_by,status,completed_at)
        values (${literal(fixture.id)},${literal(owner)},'completed',now());`, /offboarding_storage_residue/);
      const authorized = await batch(run.run_id);
      const foreignAuthorized = await batch(foreignRun.run_id);
      assert.equal(authorized.action, "delete_storage_objects");
      assert.deepEqual(authorized.paths, fixture.paths);
      const tokens = authorized.objects.map(row => row.authorization_id);
      assert.equal(new Set(tokens).size, 2);
      assert.deepEqual(authorized.objects.map(row => row.path), fixture.paths);
      await assertPending(fixture.id, fixture.paths, storageCalls().length, ackCalls().length);
      for (const path of fixture.paths) assert.ok(bytes.has(path), "crashed worker never reached Storage");
      const wrongPairs = [
        [run.run_id, [`${fixture.id}/${randomUUID()}.json`, fixture.paths[1]], tokens],
        [run.run_id, fixture.paths, [randomUUID(), tokens[1]]],
        [run.run_id, fixture.paths, [...tokens].reverse()],
        [run.run_id, [fixture.paths[0]], [tokens[0]]],
        [run.run_id, [foreign.paths[0], fixture.paths[1]], [foreignAuthorized.objects[0].authorization_id, tokens[1]]],
        [foreignRun.run_id, fixture.paths, tokens],
      ];
      for (const [id, paths, ids] of wrongPairs) await denied(`set role service_role; select ${ackCall(id, paths, ids)};`, /offboarding_object_authorization_mismatch/);
      await denied(`set role service_role; select ${ackCall(run.run_id, [fixture.paths[0], fixture.paths[0]], tokens)};`, /invalid_offboarding_object_ack/);
      await denied(`set role service_role; select public.ack_expired_audit_export(${literal(tokens[0])});`, /offboarding_authorization_requires_bound_ack/);
      await denied(`set role service_role; select public.ack_tenant_offboarding_objects(${literal(run.run_id)},${array(fixture.paths)});`, /permission denied/);
      for (const role of ["anon", "authenticated"]) {
        await denied(`set role ${role}; select ${ackCall(run.run_id, fixture.paths, tokens)};`, /permission denied/);
        await denied(`set role ${role}; select public.run_tenant_offboarding_batch(${literal(run.run_id)},100);`, /permission denied/);
      }
      await denied(`begin isolation level repeatable read; select ${ackCall(run.run_id, fixture.paths, tokens)};`, /retention_requires_read_committed/);
      await denied(`begin isolation level repeatable read; select public.run_tenant_offboarding_batch(${literal(run.run_id)},100);`, /retention_requires_read_committed/);
      await refuseClosure(fixture.id, run.run_id, /offboarding_pending_storage_authorization/);
      assert.equal(await auths(fixture.id), "2");
      assert.equal(await count("audit_export_objects", fixture.id), "2");
    });

    await t.test("maintenance-owned pending authorization also fences the actual offboarding CLI", async () => {
      const fixture = await seed();
      const prepared = await rpc("public.prepare_expired_audit_exports(100,true)");
      const authorized = prepared.objects.find(object => object.path === fixture.paths[0]);
      assert.ok(authorized?.authorization_id);
      assert.equal(await sql(`select offboarding_run_id is null from public.audit_export_deletion_authorizations where path=${literal(fixture.paths[0])};`), "t");
      const evidence = await assertPending(fixture.id, fixture.paths, storageCalls().length, ackCalls().length);
      await refuseClosure(fixture.id, evidence.run_id, /offboarding_pending_storage_authorization/);
      assert.ok(bytes.has(fixture.paths[0]));
      const retry = await rpc("public.prepare_expired_audit_exports(100,true)");
      assert.equal(retry.objects.some(object => object.path === fixture.paths[0]), false);
    });

    await t.test("export registration waiting on quota lock cannot insert residue after offboarding starts", async () => {
      const fixture = await seed(0);
      const path = `${fixture.id}/${randomUUID()}.json`;
      const a = session();
      let registration;
      try {
        await a.query(`begin; select pg_advisory_xact_lock(hashtextextended(${literal(fixture.id)},2615));`);
        const application = `export-register-${randomUUID()}`;
        registration = command(pgArgs, `set application_name=${literal(application)}; set role service_role;
          select * from public.register_audit_export_object(${literal(fixture.id)},${literal(owner)},${literal(path)},10,1000);`);
        await waitForAdvisoryWait(application);
        // The original registration function checked active BEFORE waiting on
        // seed2615; the new INSERT guard must recheck under offboarding's seed2606.
        await requestRun(fixture.id);
        assert.equal(await sql(`select status from public.tenants where id=${literal(fixture.id)};`), "closing");
        await a.query("commit;");
        const result = await registration;
        assert.notEqual(result.code, 0);
        assert.match(result.stderr, /tenant_not_active_for_export/);
        assert.equal(await count("audit_export_objects", fixture.id), "0");
        assert.equal(await auths(fixture.id), "0");
      } finally { a.close(); if (registration) await registration; }
    });

    await t.test("hold-before-authorization concurrent offboarding waits and then observes the committed hold", async () => {
      const fixture = await seed();
      const run = await requestRun(fixture.id);
      const a = session();
      let worker;
      try {
        await a.query(`begin; set role service_role; ${hold(fixture.id)}`);
        const application = `offboard-after-hold-${randomUUID()}`;
        worker = command(pgArgs, `set application_name=${literal(application)}; set role service_role; select public.run_tenant_offboarding_batch(${literal(run.run_id)},100);`);
        await waitForAdvisoryWait(application);
        await a.query("commit;");
        const result = await worker;
        assert.equal(result.code, 0, result.stderr);
        assert.equal(JSON.parse(result.stdout).status, "blocked_legal_hold");
        assert.equal(await auths(fixture.id), "0");
        assert.equal(await count("audit_export_objects", fixture.id), "1");
        assert.ok(bytes.has(fixture.paths[0]));
        const deletes = storageCalls().length;
        assert.equal((await cli(fixture.id)).status, "blocked_legal_hold");
        assert.equal(storageCalls().length, deletes);
        await release(fixture.id);
        assert.equal((await cli(fixture.id)).storage_batches, 1);
        assert.equal(bytes.has(fixture.paths[0]), false);
      } finally { a.close(); if (worker) await worker; }
    });

    await t.test("authorization-before-hold concurrent offboarding refuses hold after commit and never reissues Storage authority", async () => {
      const fixture = await seed();
      const run = await requestRun(fixture.id);
      const a = session();
      let holdTask;
      try {
        const authorized = JSON.parse(await a.query(`begin; set role service_role; select public.run_tenant_offboarding_batch(${literal(run.run_id)},100);`));
        assert.equal(authorized.action, "delete_storage_objects");
        const application = `hold-after-offboard-${randomUUID()}`;
        holdTask = command(pgArgs, `set application_name=${literal(application)}; set role service_role; ${hold(fixture.id)}`);
        await waitForAdvisoryWait(application);
        await a.query("commit;");
        const refused = await holdTask;
        assert.notEqual(refused.code, 0);
        assert.match(refused.stderr, /legal_hold_refused_pending_export_deletion/);
        assert.equal(await count("tenant_legal_holds", fixture.id), "0");
        await assertPending(fixture.id, fixture.paths, storageCalls().length, ackCalls().length);
        assert.ok(bytes.has(fixture.paths[0]));
      } finally { a.close(); if (holdTask) await holdTask; }
    });
  } finally {
    server.closeAllConnections();
    await new Promise((done, reject) => server.close(error => error ? reject(error) : done()));
  }
}
