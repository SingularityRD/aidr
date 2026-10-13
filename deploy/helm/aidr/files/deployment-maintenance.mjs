#!/usr/bin/env node
// Retention, erasure and digest maintenance for a deployment.
//
//   node scripts/deployment-maintenance.mjs <deployment-dir> [--apply]
//       Compose/systemd installs: reads <dir>/deployment.json and <dir>/.env.
//   node scripts/deployment-maintenance.mjs <evidence-dir> --from-env [--apply]
//       Kubernetes CronJob (deploy/helm, maintenance.enabled): reads the API
//       origin from AIDR_MAINTENANCE_API_URL and the service credential from
//       SERVICE_ROLE_KEY. Plain HTTP is accepted only for an in-cluster
//       Service name (no dot, *.svc or *.svc.cluster.local).
//
// Every run (re)writes <dir>/maintenance-evidence.json and prints it; an
// incomplete --apply run exits 2, a failed one exits 1.
//
// deploy/helm/aidr/files/deployment-maintenance.mjs must stay a byte-identical
// copy (the chart ships it in a ConfigMap; deploy/helm/chart.test.mjs checks):
//   cp scripts/deployment-maintenance.mjs deploy/helm/aidr/files/
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { resolve, join } from "node:path";

const isCount = n => Number.isInteger(n) && n >= 0;
const clusterInternalHost = host => /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$/.test(host)
  && (!host.includes(".") || host.endsWith(".svc") || host.endsWith(".svc.cluster.local"));

function loadTarget(args) {
  const dir = resolve(args.find(arg => !arg.startsWith("--")) || ".aidr-deploy");
  if (args.includes("--from-env")) {
    const url = (process.env.AIDR_MAINTENANCE_API_URL ?? "").trim();
    if (!url) throw new Error("AIDR_MAINTENANCE_API_URL is required with --from-env");
    const base = new URL(url);
    if (base.protocol !== "https:" && !(base.protocol === "http:" && clusterInternalHost(base.hostname))) {
      throw new Error("Maintenance requires HTTPS or an in-cluster Service URL");
    }
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    return { dir, base, serviceRoleKey: (process.env.SERVICE_ROLE_KEY ?? "").trim() };
  }
  const manifest = JSON.parse(readFileSync(join(dir, "deployment.json"), "utf8"));
  const env = Object.fromEntries(readFileSync(join(dir, ".env"), "utf8").split(/\r?\n/).filter(s => s.includes("=")).map(s => [s.slice(0, s.indexOf("=")), s.slice(s.indexOf("=")+1)]));
  const base = new URL(manifest.supabase_url);
  if (base.protocol !== "https:" && !(manifest.development && base.protocol === "http:" && ["localhost", "127.0.0.1", "[::1]"].includes(base.hostname))) throw new Error("Maintenance requires HTTPS or a loopback development deployment");
  return { dir, base, serviceRoleKey: env.SERVICE_ROLE_KEY };
}

async function main() {
  const args = process.argv.slice(2);
  const apply = args.includes("--apply");
  const { dir, base, serviceRoleKey } = loadTarget(args);
  if (!serviceRoleKey) throw new Error("Deployment service credential missing");
  // Replace stale success evidence BEFORE any authorization or external side effect.
  writeFileSync(join(dir, "maintenance-evidence.json"), JSON.stringify({
    checked_at: new Date().toISOString(), applied: apply, status: "incomplete", complete: false,
    scope: "Run has not completed. Pending export authorizations require fenced-worker reconciliation, not blind Storage retries.",
  }, null, 2));
  async function request(path, method = "GET", body) {
    const response = await fetch(new URL(path, base), { method, headers: { apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}`, "Content-Type": "application/json" }, body: body === undefined ? undefined : JSON.stringify(body), signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error(`Maintenance request failed (${response.status}); reconcile outstanding authorizations before any Storage retry`);
    const text = await response.text(); return text ? JSON.parse(text) : null;
  }
  async function verifyExportAbsent(path) {
    const response = await fetch(new URL(`/storage/v1/object/info/aidr-audit-exports/${path}`, base), {
      headers: { apikey: serviceRoleKey, Authorization: `Bearer ${serviceRoleKey}` },
      signal: AbortSignal.timeout(30000),
    });
    if (response.status !== 404) throw new Error(`Storage did not confirm exact export absence (${response.status}); authorization retained`);
  }
  let cutoff = new Date().toISOString();
  let selected = 0, removed = 0, exportsComplete = false;
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
      exportsComplete = result.pending_authorizations === 0 && result.contended_tenants === 0;
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
    // An upload may have failed before creating an object. Its ledger row still
    // needs an exact-path absence check before ACK and quota release.
    if (!Array.isArray(deleted) || new Set(deleted.map(row => row?.name)).size !== deleted.length
      || deleted.some(row => typeof row?.name !== "string" || !paths.includes(row.name))) {
      throw new Error("Storage did not confirm every authorized path; authorization and ledger retained for reconciliation");
    }
    for (const path of paths) await verifyExportAbsent(path);
    for (const row of rows) {
      const ack = await request("/rest/v1/rpc/ack_expired_audit_export", "POST", { p_authorization_id: row.authorization_id });
      if (ack?.ledger_rows_deleted !== 1) throw new Error("Invalid export deletion acknowledgement");
      removed += 1;
    }
  }
  // Settlement request keys remain durable financial idempotency evidence.
  // Routine billing retention removes only completed, attributed webhook ids
  // for active tenants without legal holds. Dry runs count without deleting.
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
  const telemetry = { eligible_observed: 0, events_deleted: 0, batches: 0, complete: false,
    active_tenants_missing_policy: 0, missing_policy_tenants_truncated: false,
    held_tenants: 0, held_tenants_truncated: false, hold_race_skips: 0, contended_tenants: 0 };
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/prune_expired_telemetry_events", "POST", {
      p_limit: 100, p_apply: apply, p_cutoff: cutoff,
    });
    if (!result || typeof result !== "object"
      || ![result.events_eligible, result.events_deleted, result.active_tenants_missing_policy, result.held_tenants,
        result.hold_race_skips, result.contended_tenants].every(isCount)
      || typeof result.missing_policy_tenants_truncated !== "boolean"
      || typeof result.held_tenants_truncated !== "boolean"
      || result.applied !== apply || result.events_deleted > result.events_eligible
      || (!apply && result.events_deleted !== 0)
      || typeof result.cutoff !== "string" || !Number.isFinite(Date.parse(result.cutoff))) {
      throw new Error("Invalid telemetry retention response");
    }
    telemetry.eligible_observed += result.events_eligible;
    telemetry.events_deleted += result.events_deleted;
    telemetry.batches += 1;
    telemetry.active_tenants_missing_policy = result.active_tenants_missing_policy;
    telemetry.missing_policy_tenants_truncated = result.missing_policy_tenants_truncated;
    telemetry.held_tenants = result.held_tenants;
    telemetry.held_tenants_truncated = result.held_tenants_truncated;
    telemetry.hold_race_skips += result.hold_race_skips;
    telemetry.contended_tenants = result.contended_tenants;
    if (!apply) {
      telemetry.complete = result.events_eligible === 0 && result.contended_tenants === 0
        && result.hold_race_skips === 0 && result.active_tenants_missing_policy === 0
        && !result.missing_policy_tenants_truncated;
      break;
    }
    if (result.events_deleted === 0) {
      telemetry.complete = result.contended_tenants === 0 && result.hold_race_skips === 0
        && result.active_tenants_missing_policy === 0 && !result.missing_policy_tenants_truncated;
      break;
    }
  }
  const trialSubjects = { eligible: 0, deleted: 0, remaining: 0, batches: 0, complete: false };
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/purge_expired_ga_trial_subjects", "POST", {
      p_limit: 100, p_apply: apply,
    });
    if (!result || ![result.eligible, result.deleted, result.remaining].every(isCount)
      || result.applied !== apply || result.deleted > result.eligible
      || (!apply && result.deleted !== 0)) throw new Error("Invalid trial-subject retention response");
    trialSubjects.eligible += result.eligible;
    trialSubjects.deleted += result.deleted;
    trialSubjects.remaining = result.remaining;
    trialSubjects.batches += 1;
    if (!apply || result.remaining === 0 || result.deleted === 0) {
      trialSubjects.complete = result.remaining === 0;
      break;
    }
  }
  // Public waitlist sign-ups (e-mail, name, company, free text) without a
  // tenant are deleted 365 days after sign-up (migration 20261013000100).
  const waitlist = { eligible: 0, deleted: 0, remaining: 0, batches: 0, complete: false };
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/purge_expired_waitlist_signups", "POST", { p_limit: 500, p_apply: apply });
    if (!result || ![result.eligible, result.deleted, result.remaining].every(isCount)
      || result.applied !== apply || result.deleted > result.eligible || result.retention_days !== 365
      || (!apply && result.deleted !== 0)
      || typeof result.cutoff !== "string" || !Number.isFinite(Date.parse(result.cutoff))) {
      throw new Error("Invalid waitlist retention response");
    }
    waitlist.eligible += result.eligible;
    waitlist.deleted += result.deleted;
    waitlist.remaining = result.remaining;
    waitlist.batches += 1;
    if (!apply || result.remaining === 0 || result.deleted === 0) {
      waitlist.complete = result.remaining === 0;
      break;
    }
  }
  // Invitations contain recipient email/token hashes. Remove only expired,
  // unaccepted invitations after the tenant's configured identity-membership
  // retention window; the RPC enforces active-tenant and legal-hold semantics.
  const invitations = { eligible_observed: 0, deleted: 0, remaining: 0, batches: 0, complete: false,
    contended_tenants: 0, hold_race_skips: 0, active_tenants_missing_policy: 0,
    missing_policy_tenants_truncated: false, held_tenants_present: 0, held_tenants_truncated: false,
    inactive_tenant_rows_present: 0, inactive_tenant_rows_truncated: false };
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/prune_expired_team_invitations", "POST", {
      p_limit: 100, p_apply: apply,
    });
    if (!result || ![result.eligible, result.deleted, result.remaining, result.contended_tenants,
      result.hold_race_skips, result.active_tenants_missing_policy, result.held_tenants_present,
      result.inactive_tenant_rows_present].every(isCount)
      || typeof result.missing_policy_tenants_truncated !== "boolean"
      || typeof result.held_tenants_truncated !== "boolean"
      || typeof result.inactive_tenant_rows_truncated !== "boolean"
      || result.applied !== apply || result.deleted > result.eligible || result.remaining > 1
      || (!apply && result.deleted !== 0)
      || typeof result.cutoff !== "string" || !Number.isFinite(Date.parse(result.cutoff))) {
      throw new Error("Invalid team-invitation retention response");
    }
    invitations.eligible_observed += result.eligible;
    invitations.deleted += result.deleted;
    invitations.remaining = result.remaining;
    invitations.batches += 1;
    invitations.contended_tenants += result.contended_tenants;
    invitations.hold_race_skips += result.hold_race_skips;
    invitations.active_tenants_missing_policy = result.active_tenants_missing_policy;
    invitations.missing_policy_tenants_truncated = result.missing_policy_tenants_truncated;
    invitations.held_tenants_present = result.held_tenants_present;
    invitations.held_tenants_truncated = result.held_tenants_truncated;
    invitations.inactive_tenant_rows_present = result.inactive_tenant_rows_present;
    invitations.inactive_tenant_rows_truncated = result.inactive_tenant_rows_truncated;
    if (!apply || result.remaining === 0 || result.deleted === 0) {
      invitations.complete = result.remaining === 0 && result.contended_tenants === 0
        && result.hold_race_skips === 0 && result.active_tenants_missing_policy === 0
        && !result.missing_policy_tenants_truncated;
      break;
    }
  }
  // Managed-mode dashboard approval requests carry a redacted summary. Remove
  // only decided or expired requests older than each active tenant's telemetry
  // retention; the RPC enforces active-tenant, policy and legal-hold semantics.
  const approvals = { eligible_observed: 0, deleted: 0, remaining: 0, batches: 0, complete: false,
    contended_tenants: 0, hold_race_skips: 0, active_tenants_missing_policy: 0,
    missing_policy_tenants_truncated: false, held_tenants_present: 0, held_tenants_truncated: false };
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/prune_expired_approval_requests", "POST", {
      p_limit: 100, p_apply: apply,
    });
    if (!result || ![result.eligible, result.deleted, result.remaining, result.contended_tenants,
      result.hold_race_skips, result.active_tenants_missing_policy, result.held_tenants_present].every(isCount)
      || typeof result.missing_policy_tenants_truncated !== "boolean"
      || typeof result.held_tenants_truncated !== "boolean"
      || result.applied !== apply || result.deleted > result.eligible || result.remaining > 1
      || (!apply && result.deleted !== 0)
      || typeof result.cutoff !== "string" || !Number.isFinite(Date.parse(result.cutoff))) {
      throw new Error("Invalid approval-request retention response");
    }
    approvals.eligible_observed += result.eligible;
    approvals.deleted += result.deleted;
    approvals.remaining = result.remaining;
    approvals.batches += 1;
    approvals.contended_tenants += result.contended_tenants;
    approvals.hold_race_skips += result.hold_race_skips;
    approvals.active_tenants_missing_policy = result.active_tenants_missing_policy;
    approvals.missing_policy_tenants_truncated = result.missing_policy_tenants_truncated;
    approvals.held_tenants_present = result.held_tenants_present;
    approvals.held_tenants_truncated = result.held_tenants_truncated;
    if (!apply || result.remaining === 0 || result.deleted === 0) {
      approvals.complete = result.remaining === 0 && result.contended_tenants === 0
        && result.hold_race_skips === 0 && result.active_tenants_missing_policy === 0
        && !result.missing_policy_tenants_truncated;
      break;
    }
  }
  // AI governance (docs/ai-governance.md): mark lapsed intake/exception/policy
  // change requests expired (each audited) and delete closed decision records
  // older than each active, unheld tenant's security_audit retention.
  // Enforcement never waits for this sweep; the policy overlay ignores an
  // exception from its end date on.
  const governance = { expired: 0, eligible_observed: 0, deleted: 0, remaining: 0, batches: 0, complete: false,
    contended_tenants: 0, hold_race_skips: 0, active_tenants_missing_policy: 0, held_tenants_present: 0 };
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/run_ai_governance_maintenance", "POST", { p_limit: 100, p_apply: apply });
    if (!result || ![result.expired, result.eligible, result.deleted, result.remaining, result.contended_tenants,
      result.hold_race_skips, result.active_tenants_missing_policy, result.held_tenants_present].every(isCount)
      || typeof result.expiry_remaining !== "boolean"
      || typeof result.missing_policy_tenants_truncated !== "boolean"
      || result.applied !== apply || result.deleted > result.eligible || result.remaining > 1
      || (!apply && result.deleted !== 0)
      || typeof result.cutoff !== "string" || !Number.isFinite(Date.parse(result.cutoff))) {
      throw new Error("Invalid AI governance maintenance response");
    }
    governance.expired += result.expired;
    governance.eligible_observed += result.eligible;
    governance.deleted += result.deleted;
    governance.remaining = result.remaining;
    governance.batches += 1;
    governance.contended_tenants += result.contended_tenants;
    governance.hold_race_skips += result.hold_race_skips;
    governance.active_tenants_missing_policy = result.active_tenants_missing_policy;
    governance.held_tenants_present = result.held_tenants_present;
    const more = result.expiry_remaining || (result.remaining > 0 && result.deleted > 0);
    if (!apply || !more) {
      governance.complete = !result.expiry_remaining && result.remaining === 0 && result.contended_tenants === 0
        && result.hold_race_skips === 0 && result.active_tenants_missing_policy === 0
        && !result.missing_policy_tenants_truncated;
      break;
    }
  }
  const rateLimits = { eligible: 0, deleted: 0, remaining: 0, batches: 0, complete: false,
    contended_tenants: 0, held_tenants_present: 0, inactive_tenant_rows_present: 0 };
  for (let batch = 0; batch < 100; batch++) {
    const result = await request("/rest/v1/rpc/prune_expired_rate_limits", "POST", {
      p_limit: 1000, p_apply: apply,
    });
    if (!result || ![result.eligible, result.deleted, result.remaining, result.contended_tenants,
      result.held_tenants_present, result.inactive_tenant_rows_present].every(isCount)
      || result.applied !== apply || result.deleted > result.eligible
      || result.remaining > 1 || result.held_tenants_present > 1 || result.inactive_tenant_rows_present > 1
      || (!apply && result.deleted !== 0)
      || typeof result.cutoff !== "string" || !Number.isFinite(Date.parse(result.cutoff))) {
      throw new Error("Invalid rate-limit pruning response");
    }
    rateLimits.eligible += result.eligible;
    rateLimits.deleted += result.deleted;
    rateLimits.remaining = result.remaining;
    rateLimits.batches += 1;
    rateLimits.contended_tenants += result.contended_tenants;
    rateLimits.held_tenants_present = result.held_tenants_present;
    rateLimits.inactive_tenant_rows_present = result.inactive_tenant_rows_present;
    if (!apply || result.remaining === 0 || result.deleted === 0) {
      rateLimits.complete = result.remaining === 0 && result.contended_tenants === 0;
      break;
    }
  }
  // Scheduled governance summaries (supabase/functions/governance-digest): the
  // function claims due schedules under a lease, mails counts-only summaries to
  // each workspace's owners/admins and records every outcome. A failed send is
  // retried by a later run; a dry run only counts due schedules. A dispatch
  // failure is recorded in the evidence (and keeps the run incomplete) instead
  // of discarding the retention receipts gathered above.
  const governanceDigest = { due: 0, processed: 0, sent: 0, partial: 0, failed: 0, no_transport: 0,
    no_recipients: 0, errors: 0, batches: 0, mail_transport: null, complete: false, error: null };
  const digestCounts = ["due", "processed", "sent", "partial", "failed", "no_transport", "no_recipients", "errors"];
  try {
    for (let batch = 0; batch < 20; batch++) {
      const result = await request("/functions/v1/governance-digest", "POST", { action: "dispatch", apply, limit: 50 });
      if (!result || result.ok !== true || result.applied !== apply || !digestCounts.every(key => isCount(result[key]))
        || result.processed > 50
        || result.sent + result.partial + result.failed + result.no_transport + result.no_recipients + result.errors !== result.processed
        || !["resend", "none"].includes(result.mail_transport)) {
        throw new Error("Invalid governance digest dispatch response");
      }
      if (batch === 0) governanceDigest.due = result.due;
      for (const key of digestCounts.slice(1)) governanceDigest[key] += result[key];
      governanceDigest.batches += 1;
      governanceDigest.mail_transport = result.mail_transport;
      if (!apply || result.processed < 50) {
        // Lost claims (errors) are released by their lease and retried next run.
        governanceDigest.complete = result.errors === 0;
        break;
      }
    }
  } catch (error) {
    governanceDigest.complete = false;
    governanceDigest.error = error instanceof Error && error.message.startsWith("Invalid governance digest")
      ? "invalid_dispatch_response" : "dispatch_unavailable";
  }
  const retentionComplete = exportsComplete && billing.complete && telemetry.complete && trialSubjects.complete
    && waitlist.complete && invitations.complete && approvals.complete && governance.complete && rateLimits.complete;
  const evidence = {
    checked_at: new Date().toISOString(),
    action: "expire-private-audit-exports-billing-webhooks-telemetry-trial-subjects-waitlist-signups-team-invitations-approval-requests-ai-governance-records-and-rate-limits",
    applied: apply, selected, removed,
    complete: retentionComplete && governanceDigest.complete, cutoff,
    status: !apply ? "dry_run" : retentionComplete && governanceDigest.complete ? "completed" : "incomplete",
    export_retention: exportRetention,
    billing_retention: billing,
    telemetry_retention: telemetry,
    trial_subject_retention: trialSubjects,
    waitlist_retention: waitlist,
    team_invitation_retention: invitations,
    approval_request_retention: approvals,
    ai_governance_maintenance: governance,
    rate_limit_pruning: rateLimits,
    governance_digest: governanceDigest,
    scope: "Deletes authorized expired temporary export objects, completed attributed billing webhooks for active unheld tenants, expired events for active tenants according to each tenant's telemetry retention policy, pseudonymous trial-subject digests at the original 14-day expiry, public waitlist sign-ups without a tenant 365 days after sign-up, expired unaccepted team invitations only after each active tenant's existing identity_membership retention window, decided or expired dashboard approval requests only after each active tenant's telemetry retention window, and operational rate-limit counters at least 15 minutes after their last update. Accepted and unexpired invitations are preserved; held and inactive-tenant invitation rows are retained. Active tenants missing identity_membership policy and contention/hold-race cases keep the run incomplete. Tenant rate-limit counters under legal hold or outside active tenancy are retained for the tenant lifecycle; global counters have no tenant association. Settlement request keys remain durable; unfinished, unattributed, held, and inactive-tenant webhooks are retained. Events without a telemetry policy and non-active tenants are not selected; legal-hold tenants are preserved. The append-only settlement ledger is never touched. Counts acknowledge Storage API responses, not an independent deletion receipt or backup erasure. The run also dispatches due governance summaries (counts-only e-mail to workspace owners/admins) and records their delivery outcome; a dry run only counts due schedules.",
  };
  writeFileSync(join(dir, "maintenance-evidence.json"), JSON.stringify(evidence, null, 2));
  console.log(JSON.stringify(evidence));
  if (apply && (!retentionComplete || !governanceDigest.complete)) process.exitCode = 2;
}

// Report failures without abrupt unhandled-rejection teardown of HTTP handles.
main().catch(error => {
  console.error(error.message);
  process.exitCode = 1;
});
