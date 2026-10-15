# AIDR v6 data-flow and privacy evidence register

Status: **engineering inventory; customer/legal acceptance open**. This register is tied to
the source paths below and the synthetic `privacy-verify.mjs` local gate. It is not a
DPA, a production egress capture, or evidence that a customer's selected region and
retention settings have been applied. The owner must complete each customer-specific
column before contract approval. `docs/privacy.md` describes user-facing defaults.

## Data classes and boundaries

| Flow | Source and fields | Destination and default trigger | Observed code boundary | Customer evidence still required |
|---|---|---|---|---|
| Local detection and evidence | Tool inputs, extracted URLs/paths, verdicts, incident correlation | Runtime process; local JSONL audit/incident files when enabled | `packages/core/src/evaluator.ts`, `audit.ts`, `audit-log.ts`, `response-audit.ts` | Endpoint disk ACL, retention, backup/restore, legal hold, local log access |
| Managed telemetry | Installation/agent ID, runtime/version, verdict, hashes of tool summary/artifacts in default `hash` mode, incident fields when sync enabled | Durable local queue then configured control-plane `/v1/ingest`; only managed mode with `send_audit_logs` | `packages/core/src/evaluator.ts`, `managed.ts`, `clients/control-plane.ts`, `telemetry-queue.ts`, `supabase/functions/ingest/events.ts`, `index.ts` | Captured wire payload for exact build, deployed server-side minimization, tenant region, queue deletion and DB retention |
| Central discovery | Tenant/collector/cycle IDs, origin, reachability/error code | Configured discovery function when collected/uploaded | `supabase/functions/discovery/logic.ts` accepts origins only; path/query/credentials are rejected | Collector target scope, customer-approved inventory, DB retention, cross-tenant test |
| AIG deep scan | Scan type, target and options; target may contain full user-controlled text | Configured `AIG_BRIDGE_URL`, default loopback sidecar | `packages/core/src/aig-scan-client.ts` sends JSON target to bridge | Verify bridge host and network boundary, scan persistence, subprocessor if remote, deletion/export path |
| URL reputation | Extracted URL and product/version, optional auth | Configured or built-in URL reputation endpoint when enabled | `packages/core/src/clients/url-check.ts` | Exact URL domains, URL sensitivity, provider/region, retention, field opt-out packet capture |
| File and package reputation | SHA-256 hashes, package names and registry metadata | Configured file reputation endpoint and package registries when enabled | `packages/core/src/clients/file-check.ts`, `package-registry.ts` | Exact providers and domains, metadata retention and subprocessor approval |
| Version check | AIDR/runtime versions, OS/version/architecture, installation ID | Version endpoint when update check runs | `packages/core/src/version-check.ts` | Customer egress allowlist, opt-out verification and retention |
| Runtime diagnostics | Redacted error and event metadata | Sentry only with explicit `SENTRY_ENABLED=true`/`1` and a real `SENTRY_DSN`; the deprecated tracing compatibility API is local-only and emits no telemetry | `packages/core/src/telemetry-redaction.ts`, `tracing.ts`, `sentry.ts` | Exact Sentry project/region, sampling, access, retention, raw export canary |
| Browser diagnostics | Browser Sentry events, traces and breadcrumbs | Configured browser DSN; otherwise no Sentry init | `packages/dashboard/src/sentry.ts`, `main.tsx`; `sendDefaultPii: false` | Browser network trace, consent/legal basis, provider/region/retention |
| Response webhooks | Quarantine identifiers, original path, hash, size, threat ID; Slack alert data | Operator-configured webhook or Slack URL | `packages/core/src/quarantine.ts` | Payload review: original path is sensitive; destination ownership and secret storage |
| Exports and support | Tenant audit records or allowlisted diagnostic summary | Customer-selected export or consent-gated local bundle | `supabase/functions/audit-export/index.ts`, `scripts/support-bundle.mjs` | Recipient access, signed export custody, customer consent, deletion, storage region |
| Persistence and disaster recovery | Managed events/incidents, credentials, queue, DB/object backup | Customer or operator-selected control plane, local filesystem and offsite destination | `supabase/migrations`, `scripts/deployment-backup.mjs`, `scripts/deployment-backup-offsite.mjs` | Restorable backup, encryption/key custody, independent deletion and expiry proof |
| Authentication and email | Email, user/factor/session identifiers, SSO provider identity; one-time sign-in/recovery links | Configured Auth and email service when a user signs in or recovers | `packages/dashboard/src/ui/pages/LoginPage.tsx`, `RecoveryPage.tsx`, `supabase/functions/identity-security/index.ts` | Actual Auth/SMTP host, regional routing, mail processor, retention and recovery-link handling |
| Legal acceptance | Actor/tenant identifiers, Terms/Privacy version, hash and URL, approval reference, audit time | Control-plane audit log when a configured trial begins | `supabase/migrations/20260923000041_ga_trial_legal_consent.sql`, `supabase/functions/pilot-status/index.ts` | Approved documents and basis, immutable record retention, deletion/legal hold treatment |
| Hosted payments | Customer/tenant identifiers, plan/seats and provider settlement identifiers | Explicitly enabled provider checkout/portal/webhook | `supabase/functions/billing-checkout/index.ts`, `billing-portal/provider.ts`, `stripe-webhook/index.ts` | Live provider contract, data fields, region, financial retention and reconciliation |
| Directory provisioning | Email/display name, external/group identifiers, membership and provisioning token | Customer-configured SCIM or directory sync | `supabase/functions/scim/index.ts`, `scim-admin/index.ts`, `azure-ad-groups/index.ts` | IdP and directory processor, scopes, retention, deprovision/deletion evidence |
| Cloud edge proxy | Request URL, headers/body, device-start client IP and upstream response | Cloud-hosted product origin request | `deploy/cloudflare/worker.mjs`, `wrangler.jsonc` | Exact ingress/upstream packet capture, Cloudflare placement/logging, regional processing proof |
| Public waitlist and pilot applications | Waitlist e-mail, name, company, free-text message; pilot application status, cohort and free-text notes | Public `waitlist-signup` intake; signed-in pilot application and admin decision | `supabase/functions/waitlist-signup/index.ts`, `supabase/migrations/20261013000100_waitlist_pilot_retention_erasure.sql` | Public waitlist rows deleted 365 days after sign-up by the maintenance worker; operator DSAR export/erasure by e-mail with hashed receipt; audit-log copies of pilot decision notes retained (`retention-holds.md`) |
| Manual team invitation | Recipient email, team/role, one-time invitation URL and expiry | Operator creates/resends a link, then chooses a delivery channel | `supabase/functions/team-invite/index.ts`, `packages/dashboard/src/enterprise/admin-panel.tsx` | Operator custody and external delivery channel, recipient, expiry and deletion evidence |

The table is a source-grounded inventory of principal paths, not a complete live
destination/domain enumeration. The additional authentication, payment and
infrastructure rows are inventory entries, not accepted processor records. Never
present a modelled provider or region as an observed deployed destination.

## Automated local gate

Run from the repository root:

```sh
node scripts/privacy-verify.mjs
```

The gate runs synthetic canaries against the managed client wire and durable
queue, default remote hash/full projection, direct ingest normalization, runtime
and browser diagnostics, deprecated endpoint sanitization compatibility,
discovery origin validation, and
the support-bundle self-test. It writes status and source hashes to
`.release-evidence/privacy-canary-v6.json`; the evidence file contains no
canary values. **LOCAL_PASS** means only those paths passed for the hashed
source files. It does not cover customer network configuration, server logs,
third-party retention, legal authorization or a production traffic capture.

The 2026-09-13 local run passed all six synthetic boundary canaries and the
13-check support-bundle self-test. The source hashes and timestamps are in the
evidence JSON. Regenerate it after any relevant source change.

## Machine-readable completion template

The source-grounded rows above are also represented by the
[`privacy-data-flow-matrix.json`](./privacy-data-flow-matrix.json) template and
[`privacy-data-flow-matrix.schema.json`](./privacy-data-flow-matrix.schema.json).
The dependency-free local validator checks the matrix shape, duplicate flow IDs,
explicit `unknown` declarations and acceptance-state consistency:

```sh
pnpm verify:commercial-compliance
```

A valid run may remain `open`; unknown values are reported and are never treated
as proof of a deployed destination, region, retention behavior or acceptance.

## Local fixes and remaining field acceptance

1. **Server-side ingest minimization:** the current source now projects events
   to an allowlisted storage schema in `normalizeIngestEvents`, dropping unknown
   fields and raw tool summaries before `events.payload` is written. The
   direct-ingest synthetic canary passed locally. This still needs deployed
   endpoint/DB capture and compatibility review for every emitted event type;
   a unit projection does not prove production retention or access controls.
2. **Unexpected managed event fields:** `redactRemoteEvent` now projects a
   narrow allowlist before applying `hash`/`full`, so additional free-form
   fields are omitted. The synthetic raw prompt canary passed locally. Review
   compatibility and capture the deployed wire payload before customer claims.
   Non-OK ingest responses are also projected to published error codes and
   bounded seat counts, so arbitrary upstream error text is not returned or
   copied into queue diagnostics.
3. **Structured diagnostics:** runtime telemetry and browser Sentry now
   suppress structured `prompt`, `tool_input`, `tool_output` and content keys.
   Their synthetic raw prompt canary passed locally. Arbitrary error messages
   still require review because generic prose cannot be classified by a
   credential regex alone.
   Browser Sentry additionally drops attached `user` identity and projects
   request metadata to a query-free URL and HTTP method; a synthetic email
   and arbitrary request-body/header canary passes locally.
4. **Customer-specific acceptance:** capture an exact-build allowlisted packet
   trace in both self-hosted and cloud modes with all optional features and
   opt-outs exercised. Record destination host, IP, provider, region, purpose,
   data class, controller/processor, credential custody, access role, retention,
   deletion owner and proof for each observed flow. Include AIG, browser
   tracing, response webhooks, support/export and backup paths.
5. **Deletion and retention:** record an event and local queue canary, then
   verify configured DB retention, export removal, backup expiry and any legal
   hold with timestamps and independent restore/deletion evidence. Source code
   alone cannot establish these operational outcomes.
6. **Commercial signoff:** privacy/security and counsel must approve the exact
   candidate, DPA, subprocessor list, regional routing, DSAR/deletion process
   and corresponding customer-facing statements.

Until all mandatory field and legal items have evidence, T37 remains **OPEN**
for sales and production claims despite the local canary passing.
