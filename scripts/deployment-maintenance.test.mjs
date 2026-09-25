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
  const heldTenant = randomUUID(), freeTenant = randomUUID(), inactiveTenant = randomUUID(), noPolicyTenant = randomUUID();
  const state = {
    hold: true, storageDeletes: [], acknowledgements: [], stored: new Set(),
    exports: [
      { tenant: heldTenant, path: `${heldTenant}/${randomUUID()}.json`, expired: true },
      { tenant: freeTenant, path: `${freeTenant}/${randomUUID()}.csv`, expired: true },
      { tenant: freeTenant, path: `${freeTenant}/${randomUUID()}.json`, expired: false },
    ],
    billing: [{ tenant: heldTenant, expired: true }, { tenant: freeTenant, expired: true }, { tenant: freeTenant, expired: false }],
    telemetry: [
      { tenant: heldTenant, expired: true, active: true, hasPolicy: true },
      { tenant: freeTenant, expired: true, active: true, hasPolicy: true },
      { tenant: freeTenant, expired: false, active: true, hasPolicy: true },
      { tenant: freeTenant, expired: true, active: false, hasPolicy: true },
      { tenant: freeTenant, expired: true, active: true, hasPolicy: false },
    ],
    trialSubjects: [{ expired: true }, { expired: false }],
    invitations: [
      { tenant: heldTenant, expired: true, retentionElapsed: true, active: true, hasPolicy: true, accepted: false },
      { tenant: freeTenant, expired: true, retentionElapsed: true, active: true, hasPolicy: true, accepted: false },
      { tenant: freeTenant, expired: true, retentionElapsed: false, active: true, hasPolicy: true, accepted: false },
      { tenant: freeTenant, expired: true, retentionElapsed: true, active: true, hasPolicy: true, accepted: true },
      { tenant: freeTenant, expired: false, retentionElapsed: true, active: true, hasPolicy: true, accepted: false },
      { tenant: inactiveTenant, expired: true, retentionElapsed: true, active: false, hasPolicy: true, accepted: false },
      { tenant: noPolicyTenant, expired: true, retentionElapsed: true, active: true, hasPolicy: false, accepted: false },
    ],
    rateLimits: [{ expired: true }, { expired: true, tenant: freeTenant }, { expired: false }],
    approvals: [
      { tenant: heldTenant, due: true },
      { tenant: freeTenant, due: true },
      { tenant: freeTenant, due: false },
    ],
    pending: new Map(),
  };
  const heldPath = state.exports[0].path, freePath = state.exports[1].path, currentPath = state.exports[2].path;
  state.stored = new Set(state.exports.map(row => row.path));
  if (failure === "missing") state.stored.delete(freePath);
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
      return reply(200, body.prefixes.filter(name => state.stored.delete(name)).map(name => ({ name })));
    }
    if (req.url?.startsWith("/storage/v1/object/info/aidr-audit-exports/") && req.method === "GET") {
      if (failure === "info-unavailable") return reply(503, { error: "storage unavailable" });
      const path = req.url.slice("/storage/v1/object/info/aidr-audit-exports/".length);
      return reply(state.stored.has(path) ? 200 : 404, {});
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
      return reply(200, { settlement_requests_eligible: 0, webhook_events_eligible: eligible.length,
        settlement_requests_deleted: 0, webhook_events_deleted: body.p_apply ? eligible.length : 0,
        contended_tenants: 0, unattributed_webhooks_retained: 0 });
    }
    if (req.url === "/rest/v1/rpc/prune_expired_telemetry_events") {
      const due = state.telemetry.filter(row => row.expired && row.active && row.hasPolicy && !isHeld(row)).slice(0, body.p_limit);
      const held = new Set(state.telemetry.filter(row => row.expired && row.active && row.hasPolicy && isHeld(row)).map(row => row.tenant));
      const missingPolicy = new Set(state.telemetry.filter(row => row.active && !row.hasPolicy).map(row => row.tenant));
      if (body.p_apply) state.telemetry = state.telemetry.filter(row => !due.includes(row));
      return reply(200, { applied: body.p_apply, cutoff: body.p_cutoff, events_eligible: due.length,
        events_deleted: body.p_apply ? due.length : 0, active_tenants_missing_policy: missingPolicy.size,
        missing_policy_tenants_truncated: false, held_tenants: held.size, held_tenants_truncated: false,
        hold_race_skips: 0, contended_tenants: 0 });
    }
    if (req.url === "/rest/v1/rpc/purge_expired_ga_trial_subjects") {
      const due = state.trialSubjects.filter(row => row.expired).slice(0, body.p_limit);
      if (body.p_apply) state.trialSubjects = state.trialSubjects.filter(row => !due.includes(row));
      return reply(200, { eligible: due.length, deleted: body.p_apply ? due.length : 0,
        remaining: state.trialSubjects.filter(row => row.expired).length, applied: body.p_apply });
    }
    if (req.url === "/rest/v1/rpc/prune_expired_team_invitations") {
      if (failure === "invitation-prune-invalid") return reply(200, { eligible: 1, deleted: 2, remaining: 0, applied: body.p_apply });
      const retentionDue = row => row.expired && row.retentionElapsed && !row.accepted;
      const due = state.invitations.filter(row => retentionDue(row) && row.active && row.hasPolicy && !isHeld(row)).slice(0, body.p_limit);
      const held = new Set(state.invitations.filter(row => retentionDue(row) && row.active && row.hasPolicy && isHeld(row)).map(row => row.tenant));
      const inactive = new Set(state.invitations.filter(row => retentionDue(row) && !row.active && row.hasPolicy).map(row => row.tenant));
      const missingPolicy = new Set(state.invitations.filter(row => row.expired && !row.accepted && row.active && !row.hasPolicy).map(row => row.tenant));
      if (body.p_apply) state.invitations = state.invitations.filter(row => !due.includes(row));
      const remaining = state.invitations.some(row => retentionDue(row) && row.active && row.hasPolicy && !isHeld(row));
      return reply(200, { applied: body.p_apply, cutoff: new Date().toISOString(), eligible: due.length,
        deleted: body.p_apply ? due.length : 0, remaining: remaining ? 1 : 0, contended_tenants: 0, hold_race_skips: 0,
        active_tenants_missing_policy: missingPolicy.size, missing_policy_tenants_truncated: false,
        held_tenants_present: held.size, held_tenants_truncated: false,
        inactive_tenant_rows_present: inactive.size, inactive_tenant_rows_truncated: false });
    }
    if (req.url === "/rest/v1/rpc/prune_expired_approval_requests") {
      if (failure === "approval-prune-invalid") return reply(200, { eligible: 1, deleted: 2, remaining: 0, applied: body.p_apply });
      const due = state.approvals.filter(row => row.due && !isHeld(row)).slice(0, body.p_limit);
      const held = new Set(state.approvals.filter(row => row.due && isHeld(row)).map(row => row.tenant));
      if (body.p_apply) state.approvals = state.approvals.filter(row => !due.includes(row));
      return reply(200, { applied: body.p_apply, cutoff: new Date().toISOString(), eligible: due.length,
        deleted: body.p_apply ? due.length : 0,
        remaining: state.approvals.some(row => row.due && !isHeld(row)) ? 1 : 0,
        contended_tenants: 0, hold_race_skips: 0, active_tenants_missing_policy: 0,
        missing_policy_tenants_truncated: false, held_tenants_present: held.size, held_tenants_truncated: false });
    }
    if (req.url === "/rest/v1/rpc/prune_expired_rate_limits") {
      if (failure === "rate-prune-invalid") return reply(200, { eligible: 1, deleted: 2, remaining: 0, applied: body.p_apply });
      const due = state.rateLimits.filter(row => row.expired).slice(0, body.p_limit);
      if (body.p_apply) state.rateLimits = state.rateLimits.filter(row => !due.includes(row));
      return reply(200, { eligible: due.length, deleted: body.p_apply ? due.length : 0,
        remaining: state.rateLimits.some(row => row.expired) ? 1 : 0,
        applied: body.p_apply, cutoff: new Date(Date.now() - 15 * 60_000).toISOString(),
        contended_tenants: 0, held_tenants_present: 0, inactive_tenant_rows_present: 0 });
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
  return { state, heldPath, freePath, currentPath, heldTenant, run, evidence, dir };
}

test("held/unheld exports and billing: dry-run, apply, release-then-prune, repeat", async t => {
  const f = await fixture(t);
  let result = await f.run(false);
  assert.equal(result.code, 0, result.stderr);
  assert.equal(f.state.storageDeletes.length, 0);
  assert.equal(f.state.pending.size, 0);
  assert.equal(f.state.exports.length, 3);
  assert.equal(f.state.billing.length, 3);
  assert.equal(f.state.telemetry.length, 5);
  assert.equal(f.state.trialSubjects.length, 2);
  assert.equal(f.state.invitations.length, 7);
  assert.equal(f.state.rateLimits.length, 3);
  assert.equal(f.evidence().selected, 1);
  assert.equal(f.evidence().removed, 0);
  assert.equal(f.evidence().rate_limit_pruning.deleted, 0);
  assert.equal(f.evidence().team_invitation_retention.deleted, 0);
  assert.equal(f.evidence().team_invitation_retention.eligible_observed, 1);
  assert.equal(f.evidence().team_invitation_retention.remaining, 1);
  assert.equal(f.state.invitations.length, 7, "dry-run never removes invitation PII");
  assert.equal(f.evidence().approval_request_retention.eligible_observed, 1);
  assert.equal(f.evidence().approval_request_retention.deleted, 0);
  assert.equal(f.state.approvals.length, 3, "dry-run never removes approval requests");
  result = await f.run();
  assert.equal(result.code, 2, result.stderr);
  assert.deepEqual(f.state.storageDeletes, [[f.freePath]]);
  assert.deepEqual(f.state.exports.map(row => row.path), [f.heldPath, f.currentPath]);
  assert.equal(f.state.billing.length, 2);
  assert.equal(f.evidence().removed, 1);
  assert.equal(f.evidence().export_retention.held_exports, 1);
  assert.equal(f.evidence().export_retention.pending_authorizations, 0);
  assert.equal(f.evidence().billing_retention.settlement_requests, 0);
  assert.equal(f.evidence().billing_retention.webhook_events, 1);
  assert.equal(f.evidence().telemetry_retention.eligible_observed, 1);
  assert.equal(f.evidence().telemetry_retention.events_deleted, 1);
  assert.equal(f.evidence().trial_subject_retention.deleted, 1);
  assert.equal(f.evidence().trial_subject_retention.remaining, 0);
  assert.equal(f.state.trialSubjects.length, 1);
  assert.equal(f.evidence().team_invitation_retention.deleted, 1);
  assert.equal(f.evidence().team_invitation_retention.remaining, 0);
  assert.equal(f.evidence().team_invitation_retention.held_tenants_present, 1);
  assert.equal(f.evidence().team_invitation_retention.active_tenants_missing_policy, 1);
  assert.equal(f.evidence().team_invitation_retention.inactive_tenant_rows_present, 1);
  assert.equal(f.state.invitations.length, 6, "held, young, accepted, unexpired, inactive, and policyless invites remain");
  assert.equal(f.evidence().rate_limit_pruning.deleted, 2);
  assert.equal(f.evidence().rate_limit_pruning.remaining, 0);
  assert.equal(f.state.rateLimits.length, 1);
  assert.equal(f.evidence().approval_request_retention.deleted, 1);
  assert.equal(f.evidence().approval_request_retention.held_tenants_present, 1);
  assert.equal(f.evidence().approval_request_retention.complete, true);
  assert.equal(f.state.approvals.length, 2, "held and not-yet-due approval requests remain");
  assert.equal(f.evidence().telemetry_retention.held_tenants, 1);
  assert.equal(f.evidence().telemetry_retention.active_tenants_missing_policy, 1);
  assert.equal(f.state.telemetry.length, 4);
  assert.equal(f.evidence().status, "incomplete", "missing telemetry policy cannot produce a completed receipt");
  assert.equal(f.evidence().telemetry_retention.complete, false);
  result = await f.run();
  assert.equal(result.code, 2, result.stderr);
  assert.equal(f.evidence().removed, 0);
  assert.equal(f.state.storageDeletes.length, 1);
  f.state.hold = false;
  result = await f.run();
  assert.equal(result.code, 2, result.stderr);
  assert.deepEqual(f.state.storageDeletes, [[f.freePath], [f.heldPath]]);
  assert.deepEqual(f.state.exports.map(row => row.path), [f.currentPath]);
  assert.equal(f.state.billing.length, 1);
  assert.equal(f.evidence().removed, 1);
  assert.equal(f.evidence().billing_retention.settlement_requests, 0);
  assert.equal(f.evidence().billing_retention.webhook_events, 1);
  assert.equal(f.evidence().telemetry_retention.events_deleted, 1);
  assert.equal(f.evidence().team_invitation_retention.deleted, 1, "held invitation becomes eligible only after release");
  assert.equal(f.evidence().approval_request_retention.deleted, 1, "held approval request becomes eligible only after release");
  assert.equal(f.state.approvals.length, 1);
  assert.equal(f.state.invitations.length, 5);
  assert.equal(f.evidence().telemetry_retention.complete, false);
  assert.equal(f.state.telemetry.length, 3, "unexpired, non-active, and policy-less events are preserved");
  f.state.telemetry.find(row => !row.hasPolicy).hasPolicy = true;
  f.state.invitations.find(row => !row.hasPolicy).hasPolicy = true;
  result = await f.run();
  assert.equal(result.code, 0, result.stderr);
  assert.equal(f.evidence().status, "completed");
  assert.equal(f.evidence().telemetry_retention.complete, true);
  assert.equal(f.evidence().team_invitation_retention.complete, true);
  assert.equal(f.state.invitations.length, 4, "only retained accepted, young, unexpired, and inactive invitations remain");
  assert.equal(f.state.telemetry.length, 2, "retention resumes when the missing policy is configured");
  assert.equal(f.evidence().rate_limit_pruning.deleted, 0, "repeated maintenance is idempotent");
});

test("invalid approval-request deletion receipt cannot complete maintenance", async t => {
  const f = await fixture(t, "approval-prune-invalid");
  const result = await f.run();
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Invalid approval-request retention response/);
});

test("invalid rate-limit deletion receipt cannot complete maintenance", async t => {
  const f = await fixture(t, "rate-prune-invalid");
  const result = await f.run();
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Invalid rate-limit pruning response/);
  assert.equal(f.evidence().complete, false);
  assert.equal(f.evidence().status, "incomplete");
});

test("invalid invitation deletion receipt cannot complete maintenance", async t => {
  const f = await fixture(t, "invitation-prune-invalid");
  const result = await f.run();
  assert.equal(result.code, 1);
  assert.match(result.stderr, /Invalid team-invitation retention response/);
  assert.equal(f.evidence().complete, false);
  assert.equal(f.evidence().status, "incomplete");
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

test("an upload that never created an object releases quota after exact-path absence proof", async t => {
  const f = await fixture(t, "missing");
  const result = await f.run();
  assert.equal(result.code, 2, result.stderr);
  assert.deepEqual(f.state.storageDeletes, [[f.freePath]]);
  assert.equal(f.state.acknowledgements.length, 1);
  assert.deepEqual(f.state.exports.map(row => row.path), [f.heldPath, f.currentPath]);
  assert.equal(f.evidence().removed, 1);
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
    assert.equal(retry.code, 2, retry.stderr);
    assert.equal(f.state.storageDeletes.length, prepared ? 0 : 1);
    assert.equal(f.evidence().removed, 0);
    assert.equal(f.evidence().status, "incomplete");
  });
}

for (const failure of ["prepare", "token", "storage", "partial", "wrong-path", "info-unavailable", "ack"]) {
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
