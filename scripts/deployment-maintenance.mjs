#!/usr/bin/env node
import { readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";

const isCount = n => Number.isInteger(n) && n >= 0;

async function main() {
  const args = process.argv.slice(2), dir = resolve(args[0] || ".aidr-deploy");
  const apply = args.includes("--apply");
  const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
  const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter(s => s.includes("=")).map(s => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=")+1)]));
  const base = new URL(manifest.supabase_url);
  if (base.protocol !== "https:" && !(manifest.development && ["localhost", "127.0.0.1"].includes(base.hostname))) throw new Error("Maintenance requires HTTPS or a loopback development deployment");
  if (!env.SERVICE_ROLE_KEY) throw new Error("Deployment service credential missing");
  // Replace stale success evidence BEFORE any authorization or external side effect.
  writeFileSync(join(dir, "maintenance-evidence.json"), JSON.stringify({
    checked_at: new Date().toISOString(), applied: apply, status: "incomplete", complete: false,
    scope: "Run has not completed. Pending export authorizations require fenced-worker reconciliation, not blind Storage retries.",
  }, null, 2));
  async function request(path, method = "GET", body) {
    const response = await fetch(new URL(path, base), { method, headers: { apikey: env.SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SERVICE_ROLE_KEY}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error(`Maintenance request failed (${response.status}); reconcile outstanding authorizations before any Storage retry`);
    const text = await response.text(); return text ? JSON.parse(text) : null;
  }
  let cutoff = new Date().toISOString();
  let selected = 0, removed = 0, complete = false;
  let exportRetention;
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/prepare_expired_audit_exports", "POST", { p_limit: 100, p_apply: apply, p_cutoff: cutoff });
    if (!result || !Array.isArray(result.objects) || typeof result.cutoff !== "string" || !Number.isFinite(Date.parse(result.cutoff))
      || ![result.held_exports, result.pending_authorizations, result.contended_tenants].every(isCount)) {
      throw new Error("Invalid retention response");
    }
    cutoff = result.cutoff;
    exportRetention = { held_exports: result.held_exports, pending_authorizations: result.pending_authorizations, contended_tenants: result.contended_tenants };
    const rows = result.objects;
    if (rows.length === 0) {
      complete = result.pending_authorizations === 0 && result.contended_tenants === 0;
      break;
    }
    const paths = rows.map(row => row.path);
    if (paths.some(path => typeof path !== "string" || !/^[a-f0-9-]{36}\/[a-f0-9-]{36}\.(csv|json)$/.test(path))) throw new Error("Invalid export path in retention ledger");
    if (new Set(paths).size !== paths.length || (apply && rows.some(row => typeof row.authorization_id !== "string" || !/^[a-f0-9-]{36}$/.test(row.authorization_id)))) {
      throw new Error("Invalid export deletion authorization");
    }
    selected += paths.length;
    if (!apply) break;
    // The durable authorization prevents hold placement across this HTTP gap.
    // Never expire, retry or cancel it on timeout: the Storage outcome is unknown.
    // Storage API deletes bytes and metadata together, not via storage.objects SQL.
    const deleted = await request("/storage/v1/object/aidr-audit-exports", "DELETE", { prefixes: paths });
    if (!Array.isArray(deleted) || deleted.length !== paths.length
      || new Set(deleted.map(row => row.name)).size !== paths.length
      || deleted.some(row => !paths.includes(row.name))) {
      throw new Error("Storage did not confirm every authorized path; authorization and ledger retained for reconciliation");
    }
    for (const row of rows) {
      const ack = await request("/rest/v1/rpc/ack_expired_audit_export", "POST", { p_authorization_id: row.authorization_id });
      if (ack?.ledger_rows_deleted !== 1) throw new Error("Invalid export deletion acknowledgement");
      removed += 1;
    }
  }
  // Billing retention: expired request-idempotency keys and processed webhook ids
  // only. The settlement ledger (public.billing_settlements) is append-only
  // financial evidence and this stage never selects, updates or deletes it, so a
  // settled record cannot be reached by pruning. Dry runs count without deleting.
  const billing = { settlement_requests: 0, webhook_events: 0, eligible: 0, batches: 0, complete: false, contended_tenants: 0, unattributed_webhooks_retained: 0 };
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/prune_expired_billing_records", "POST", { p_limit: 100, p_apply: apply });
    if (!result || typeof result !== "object"
      || ![result.settlement_requests_eligible, result.webhook_events_eligible,
        result.settlement_requests_deleted, result.webhook_events_deleted,
        result.contended_tenants, result.unattributed_webhooks_retained].every(isCount)) {
      throw new Error("Invalid billing retention response");
    }
    billing.eligible += result.settlement_requests_eligible + result.webhook_events_eligible;
    billing.settlement_requests += result.settlement_requests_deleted;
    billing.webhook_events += result.webhook_events_deleted;
    billing.batches += 1;
    billing.contended_tenants = result.contended_tenants;
    billing.unattributed_webhooks_retained = result.unattributed_webhooks_retained;
    if (!apply) break;
    if (result.settlement_requests_deleted + result.webhook_events_deleted === 0) {
      billing.complete = result.contended_tenants === 0 && result.unattributed_webhooks_retained === 0;
      break;
    }
  }
  const evidence = {
    checked_at: new Date().toISOString(),
    action: "expire-private-audit-exports-and-billing-idempotency-keys",
    applied: apply, selected, removed, complete, cutoff,
    status: !apply ? "dry_run" : complete && billing.complete ? "completed" : "incomplete",
    export_retention: exportRetention,
    billing_retention: billing,
    scope: "Deletes authorized expired temporary export objects and unheld expired billing request/webhook idempotency keys only; source audit records remain append-only and the append-only settlement ledger is never touched. Counts acknowledge Storage API responses, not an independent deletion receipt or backup erasure. Held data is excluded from completion.",
  };
  writeFileSync(join(dir, "maintenance-evidence.json"), JSON.stringify(evidence, null, 2));
  console.log(JSON.stringify(evidence));
  if (apply && (!complete || !billing.complete)) process.exitCode = 2;
}

// Report failures without abrupt unhandled-rejection teardown of HTTP handles.
main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
