import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { test } from "node:test";

// Exercises the actual shipped reaper over HTTP. This server models RPC state;
// the separate PostgreSQL suite verifies the real migration/locking semantics.
async function fixture(t, failure) {
  const dir = mkdtempSync(join(tmpdir(), "aidr-retention-"));
  const heldTenant = randomUUID(), freeTenant = randomUUID();
  const state = {
    hold: true, storageDeletes: [], acknowledgements: [],
    exports: [
      { tenant: heldTenant, path: `${heldTenant}/${randomUUID()}.json`, expired: true },
      { tenant: freeTenant, path: `${freeTenant}/${randomUUID()}.csv`, expired: true },
      { tenant: freeTenant, path: `${freeTenant}/${randomUUID()}.json`, expired: false },
    ],
    billing: [{ tenant: heldTenant, expired: true }, { tenant: freeTenant, expired: true }, { tenant: freeTenant, expired: false }],
    pending: new Map(),
  };
  const heldPath = state.exports[0].path, freePath = state.exports[1].path, currentPath = state.exports[2].path;
  const isHeld = row => state.hold && row.tenant === heldTenant;
  const server = createServer(async (req, res) => {
    let text = "";
    for await (const chunk of req) text += chunk;
    const body = text ? JSON.parse(text) : {};
    const reply = (status, data) => { res.writeHead(status, { "Content-Type": "application/json" }); res.end(JSON.stringify(data)); };
    if (req.url === "/rest/v1/rpc/prepare_expired_audit_exports") {
      if (failure === "prepare") return reply(500, { error: "authorization failed" });
      const objects = state.exports.filter(row => row.expired && !isHeld(row) && ![...state.pending.values()].includes(row.path)).map(row => {
        const token = body.p_apply ? randomUUID() : null;
        if (token) state.pending.set(token, row.path);
        return { path: row.path, authorization_id: failure === "token" ? null : token };
      });
      if (failure === "prepare-lost" && objects.length > 0 && body.p_apply) return reply(503, { error: "prepare committed, response lost" });
      return reply(200, { cutoff: body.p_cutoff, objects, held_exports: state.exports.filter(row => row.expired && isHeld(row)).length,
        pending_authorizations: state.pending.size, contended_tenants: 0 });
    }
    if (req.url === "/storage/v1/object/aidr-audit-exports" && req.method === "DELETE") {
      state.storageDeletes.push(body.prefixes);
      assert.ok(!body.prefixes.includes(heldPath) || !state.hold, "never send a held tenant path to Storage");
      assert.ok(!body.prefixes.includes(currentPath), "never delete an unexpired export");
      for (const path of body.prefixes) assert.ok([...state.pending.values()].includes(path), "authorization precedes HTTP");
      if (failure === "storage") return reply(503, { error: "unknown external outcome" });
      if (failure === "partial") return reply(200, []);
      if (failure === "duplicate") return reply(200, body.prefixes.map(() => ({ name: body.prefixes[0] })));
      if (failure === "wrong-path") return reply(200, [{ name: heldPath }]);
      return reply(200, body.prefixes.map(name => ({ name })));
    }
    if (req.url === "/rest/v1/rpc/ack_expired_audit_export") {
      state.acknowledgements.push(body.p_authorization_id);
      if (failure === "ack") return reply(503, { error: "ack failed" });
      const path = state.pending.get(body.p_authorization_id);
      assert.ok(path);
      state.exports = state.exports.filter(row => row.path !== path);
      state.pending.delete(body.p_authorization_id);
      if (failure === "ack-lost") return reply(503, { error: "ack committed, response lost" });
      return reply(200, { ledger_rows_deleted: 1 });
    }
    if (req.url === "/rest/v1/rpc/prune_expired_billing_records") {
      const eligible = state.billing.filter(row => row.expired && !isHeld(row));
      if (body.p_apply) state.billing = state.billing.filter(row => !eligible.includes(row));
      return reply(200, { settlement_requests_eligible: eligible.length, webhook_events_eligible: eligible.length,
        settlement_requests_deleted: body.p_apply ? eligible.length : 0, webhook_events_deleted: body.p_apply ? eligible.length : 0,
        contended_tenants: 0, unattributed_webhooks_retained: 0 });
    }
    reply(500, { error: `unsupported route ${req.method} ${req.url}; direct ledger access is forbidden` });
  });
  await new Promise(done => server.listen(0, "127.0.0.1", done));
  writeFileSync(join(dir, "deployment.json"), JSON.stringify({ development: true, supabase_url: `http://127.0.0.1:${server.address().port}` }));
  writeFileSync(join(dir, ".env"), "SERVICE_ROLE_KEY=private-fixture-key\n");
  t.after(async () => { await new Promise(done => server.close(done)); rmSync(dir, { recursive: true, force: true }); });
  const run = (apply = true) => new Promise((done, reject) => {
    const child = spawn(process.execPath, [resolve(dirname(fileURLToPath(import.meta.url)), "deployment-maintenance.mjs"), dir, ...(apply ? ["--apply"] : [])], { stdio: ["ignore", "pipe", "pipe"], timeout: 10_000 });
    let stdout = "", stderr = "";
    child.stdout.on("data", chunk => { stdout += chunk; });
    child.stderr.on("data", chunk => { stderr += chunk; });
    child.on("error", reject);
    child.on("close", code => done({ code, stdout, stderr }));
  });
  const evidence = () => JSON.parse(readFileSync(join(dir, "maintenance-evidence.json"), "utf8"));
  return { state, heldPath, freePath, currentPath, run, evidence, dir };
}

test("held/unheld exports and billing: dry-run, apply, release-then-prune, repeat", async t => {
  const f = await fixture(t);
  let result = await f.run(false);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(f.state.storageDeletes.length, 0);
  assert.equal(f.state.pending.size, 0);
  assert.equal(f.state.exports.length, 3);
  assert.equal(f.state.billing.length, 3);
  assert.equal(f.evidence().selected, 1);
  assert.equal(f.evidence().removed, 0);
  result = await f.run();
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(f.state.storageDeletes, [[f.freePath]]);
  assert.deepEqual(f.state.exports.map(row => row.path), [f.heldPath, f.currentPath]);
  assert.equal(f.state.billing.length, 2);
  assert.equal(f.evidence().removed, 1);
  assert.equal(f.evidence().export_retention.held_exports, 1);
  assert.equal(f.evidence().export_retention.pending_authorizations, 0);
  assert.equal(f.evidence().billing_retention.settlement_requests, 1);
  assert.equal(f.evidence().billing_retention.webhook_events, 1);
  assert.equal(f.evidence().status, "completed");
  result = await f.run();
  assert.equal(result.code, 0, result.stderr);
  assert.equal(f.evidence().removed, 0);
  assert.equal(f.state.storageDeletes.length, 1);
  f.state.hold = false;
  result = await f.run();
  assert.equal(result.code, 0, result.stderr);
  assert.deepEqual(f.state.storageDeletes, [[f.freePath], [f.heldPath]]);
  assert.deepEqual(f.state.exports.map(row => row.path), [f.currentPath]);
  assert.equal(f.state.billing.length, 1);
  assert.equal(f.evidence().removed, 1);
  assert.equal(f.evidence().billing_retention.settlement_requests, 1);
  assert.equal(f.evidence().billing_retention.webhook_events, 1);
});

test("multiple authorized paths require distinct exact Storage confirmations", async t => {
  const f = await fixture(t, "duplicate");
  const tenant = f.freePath.split("/")[0];
  f.state.exports.push({ tenant, path: `${tenant}/${randomUUID()}.json`, expired: true });
  const result = await f.run();
  assert.equal(result.code, 1, result.stderr);
  assert.match(result.stderr, /Storage did not confirm every authorized path/);
  assert.equal(f.state.storageDeletes[0].length, 2);
  assert.equal(f.state.acknowledgements.length, 0);
  assert.equal(f.state.pending.size, 2);
  assert.equal(f.state.exports.length, 4);
  assert.equal(f.evidence().status, "incomplete");
});

for (const failure of ["prepare-lost", "ack-lost"]) {
  test(`${failure}: committed RPC with lost response cannot fabricate or replay a deletion`, async t => {
    const f = await fixture(t, failure);
    const result = await f.run();
    assert.equal(result.code, 1, result.stderr);
    assert.equal(f.evidence().status, "incomplete");
    assert.equal(f.evidence().removed, undefined);
    const prepared = failure === "prepare-lost";
    assert.equal(f.state.pending.size, prepared ? 1 : 0);
    assert.equal(f.state.exports.length, prepared ? 3 : 2);
    assert.equal(f.state.storageDeletes.length, prepared ? 0 : 1);
    const retry = await f.run();
    assert.equal(retry.code, prepared ? 2 : 0, retry.stderr);
    assert.equal(f.state.storageDeletes.length, prepared ? 0 : 1);
    assert.equal(f.evidence().removed, 0);
    assert.equal(f.evidence().status, prepared ? "incomplete" : "completed");
  });
}

for (const failure of ["prepare", "token", "storage", "partial", "wrong-path", "ack"]) {
  test(`${failure} failure cannot create a deletion receipt, release authorization, or blindly retry`, async t => {
    const f = await fixture(t, failure);
    writeFileSync(join(f.dir, "maintenance-evidence.json"), JSON.stringify({ status: "completed", complete: true, removed: 999 }));
    const result = await f.run();
    assert.equal(result.code, 1, result.stderr);
    assert.equal(f.evidence().status, "incomplete", "previous success must be replaced before work");
    assert.equal(f.evidence().complete, false);
    assert.equal(f.evidence().removed, undefined, "no count from just sending an HTTP request");
    assert.equal(f.state.exports.length, 3, "ledger retained on any uncertain result");
    if (["prepare", "token"].includes(failure)) assert.equal(f.state.storageDeletes.length, 0);
    if (failure !== "ack") assert.equal(f.state.acknowledgements.length, 0);
    if (failure !== "prepare") {
      assert.equal(f.state.pending.size, 1);
      const deletes = f.state.storageDeletes.length;
      const retry = await f.run();
      assert.equal(retry.code, 2, retry.stderr);
      assert.equal(f.state.storageDeletes.length, deletes, "new run must not replay an old authorization");
      assert.equal(f.evidence().export_retention.pending_authorizations, 1);
      assert.equal(f.evidence().removed, 0);
      assert.equal(f.evidence().status, "incomplete");
    }
  });
}
