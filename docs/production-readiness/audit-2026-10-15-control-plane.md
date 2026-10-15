# Control-plane audit — 15 October 2026

Scope: `supabase/` (migrations and Edge Functions), `packages/dashboard`, `packages/sdk`, `packages/mcp-gateway`, and the
pinned self-hosted images that `scripts/deployment-prepare.mjs` writes. `deploy/` was read-only for this pass, because
another workstream was using it. Method: every finding from the 12 October GA audit in this scope was re-run against its
reproduction or a regression test; the open sales and readiness items that code can close were worked on; and a fresh
read of the current code checked tenant isolation, authorization, rate limits, SSRF, webhooks, audit completeness and
dashboard honesty. **This is an internal engineering review, not the independent assessment SEC-EXT-001 requires.**

Result: no cross-tenant read or write and no privilege escalation was found. One gate had regressed (AIDR-019) and is
fixed. Six new issues were fixed with tests (SEC-1..6). Eleven low-severity items are recorded with a reason (SEC-7..16,
T37-1). The 22 re-verified GA findings are all closed. Two closures are weaker than the audit asked for (MSC-4, MSC-14)
and are noted below.

Commits on this branch: `cfd8d605`, `c5ca7275`, `58214258`, `2d1d4ea9`, `f4c0847d`, `c768aef0`, `b2af5cae` and the commit
that adds this document.

## 1. Re-verification of the 12 October findings

| ID | Status | Re-run | Proof |
|---|---|---|---|
| CP-1 | Closed | Requester IP/runtime/version/OS/hostname are stored (`device-start/index.ts:188-193`, migration `20261013000530`). `/verify` never prefills `?code=`; there is a warning, the requester context is shown, and a confirm checkbox must be ticked before the button works. `device-verify` needs a lookup and then an explicit authorize. | `supabase/functions/__tests__/device-code.test.ts:138-210`, `packages/dashboard/src/__tests__/verify-page.test.tsx:101,113` |
| CP-2 | Closed (code) | Tenant key ids `aidr-tenant-pack-v2.<tenant>.<fingerprint>` plus separate shared/vendor keys (`_shared/pack-keys.ts`, `scripts/intel-pack-keys.mjs`). The round trip publish → entitlement → core loader decrypt passes. Handing the vendor shared key to a customer is an operational step. | `supabase/functions/__tests__/intel-pack-keys.test.ts:186` |
| CP-3 | Closed | Supabase Cloud: `20261013000200` schedules pg_cron jobs per data class and records each run. Helm (read only): `deploy/helm/aidr/templates/maintenance-cronjob.yaml` is present. | `node --test scripts/retention-pg-cron-postgres.test.mjs` 3/3 (Docker); `deploy/helm/chart.test.mjs:405` |
| CP-4 | Closed | 365-day waitlist purge and DSAR export/erase by e-mail (`20261013000100`). | `node --test scripts/waitlist-pilot-retention-postgres.test.mjs` 2/2 |
| CP-5 | Closed | `node scripts/check-edge-functions-typed.mjs`: all 59 functions are Deno type-checked. | `scripts/check-edge-functions-typed.test.mjs:11` |
| CP-6 | Closed | Separate `v1:unsigned-aggregate` and `v2:signed-aggregate` buckets (`version-check/index.ts:37-38,105-108`). | `supabase/functions/__tests__/version-check-contract.test.ts:222` |
| CP-7 | Closed | TTL and epoch are bounds-checked; a bad value gives 500 naming the variable (`revocations/index.ts:48-52`). | `supabase/functions/__tests__/revocation-timing.test.ts:24,28,80` |
| CP-8 | Closed | `expires_at` and label bounds in the table and RPCs (`20261013000510`). Renew keeps the row's scope prefix (`api-keys/index.ts:260`). Expired keys are rejected (`_shared/api-key-auth.ts:226`). | `supabase/functions/__tests__/api-key-hygiene.test.ts:35,95,196,306` |
| CP-9 | Closed | `decide_approval_request` refuses requester == approver and audits the attempt (`20261013000520:198-209`); the edge returns 403 (`approval-requests/index.ts:572`). | `supabase/functions/__tests__/approval-requests-contract.test.ts:660-704` |
| MSC-1 | Closed | Copying the quarantine fields into `approvedToolsets`, even with the state seal recomputed, still gives `manifest_rejected`. Only an operator-signed approval releases the toolset. | `packages/mcp-gateway/src/__tests__/approval-signing.test.mjs:100,118,152` |
| MSC-2 | Closed | The library has no `approve()` and the approve command is not importable (`library-approval.test.mjs:76,84,141,159`). Built Claude Code hook, isolated HOME: the literal approve command, the `aidr-mcp-appr*.mjs`, `aidr-mcp-a*.mjs` and `*approve.mjs` globs → deny CLT-SELF-007; the library import and `cat` of the attestation state → deny CLT-SELF-009. | as listed |
| MSC-3 | Closed | Injection split across two blocks, split mid-word, and an AWS key split across blocks → `output_blocked`. | `packages/mcp-gateway/src/__tests__/gateway.test.mjs:465` |
| MSC-4 | Closed, docs route | The README states stdio mode is not a credential-isolation boundary, and every start prints a warning. `"stdioUpstreamCredentials": "refuse"` is opt-in; the default is `"warn"` (`packages/mcp-gateway/src/config.mjs:565`). Making refuse the default is a product decision. | `stdio.test.mjs:173`, `standalone.test.mjs:324` |
| MSC-5 | Closed | An expired manifest → startup refused with `manifest_expired`; an 8-day lifetime → `manifest_lifetime_too_long`; `manifestPolicy.maxLifetimeDays` is configurable up to 90; expiry warning, precise runtime reason, hot reload. | `manifest-lifecycle.test.mjs:51-163` |
| MSC-6 | Closed | A foreign Host gets 421 `host_forbidden` on POST and `/healthz`; `allowedHosts` setting. | `transport-guards.test.mjs:33,60` |
| MSC-7 | Closed | base64, base64url, hex and double-base64 injection are blocked. The README states inspection is pattern-based. | `gateway.test.mjs:487` |
| MSC-8 | Closed | The 403 body is `{error, requestId}`. An init error reaches `next()` as a fixed-message error with no paths; nextjs returns 503. | `packages/sdk/src/__tests__/http-middleware-hardening.test.ts:79,112,134` |
| MSC-9 | Closed | Header payloads are inspected (credential headers excepted); oversized header sets are denied; `inspectHeaders:false` turns it off. | `http-middleware-hardening.test.ts:168,183,222,231` |
| MSC-10 | Closed | Local enforcement works with no `apiKey`; a blank key is rejected; the remote leg still needs a key. | `http-middleware-hardening.test.ts:60,68` |
| MSC-14 | Closed on POSIX | A relative `stateDir` is refused (ran here). The group/other-writable check (`core/src/mcp-attestation.ts:732-745`) is POSIX-only, and its test is skipped on Windows. Windows ACLs are not checked, which the README states. | `approval-signing.test.mjs:184,204` |
| MSC-15 | Closed | gzip → 415 `unsupported_content_encoding`; UTF-16 charset → 415 `unsupported_charset`; undeclared UTF-16 or invalid UTF-8 → 400 `invalid_request_encoding`. | `transport-guards.test.mjs:80` |
| MSC-16 | Closed | An empty or missing threats dir throws `AIDRInitError`; the wrapped function never runs; express calls `next(err)`. | `packages/sdk/src/__tests__/data-dir-resolution.test.ts:199,219,240` |

Commands: `node --test` over 8 gateway suites, 108 pass and 2 skipped on win32. `vitest` over 3 SDK suites, 40/40.
13 supabase suites, 378/378 (the 60 s timeout is needed for `intel-pack-keys`).

## 2. Readiness and sales items

| Item | Result |
|---|---|
| **AIDR-019** (dashboard → Edge contract) | **Regressed, fixed.** `node scripts/check-supabase-edge-contracts.mjs` failed with "installer-update: contract manifest entry has no browser call site". `installer-update` is a machine route, so its browser manifest entry was removed (`docs/production-readiness/edge-function-contract-manifest.json`). Its contract test now asserts that (`supabase/functions/__tests__/installer-update-contract.test.ts:287`). New guard: every table and RPC the dashboard queries is created by a migration, and `referrals` / `public.users` are no longer referenced (`supabase/functions/__tests__/dashboard-database-objects.test.ts`). The gate now passes: 36 functions and 59/59 config-guarded. Live browser enrollment and live IdP acceptance stay external. |
| **T19** (SCIM group → role) | **Code side closed.** Exact `Group.externalId` mapping, highest-role precedence and reconciliation on every change already existed (`20260923000049:18-25`), and `azure-ad.ts` grants no roles. Added: owner-only attribution of which group granted each member's role (`20261015000200_scim_role_grant_attribution.sql`, `scim-admin/index.ts:404`, `ScimPage.tsx:334-560`). `Group.externalId` is now byte-exact (`scim/scim.ts:265`). Closing tests: `node --test scripts/scim-group-role-mapping-postgres.test.mjs` 8/8 covers forged metadata (:129), look-alike names and homoglyphs (:152), precedence and removal (:177), deactivation (:218), replay (:253), paging and owner-only (:278) and tenant mixing (:302). Open externally: live Entra/Okta provisioning, and the Clerk per-grant directory proof. |
| **T38** (tenant custom DLP labels) | **Code side closed except a `monitor` action.** Labels, keyword/regex/detector matchers, redact/block/ask, CAS/history/audit and signed delivery already existed. Added: a structural ReDoS check (`packages/core/src/dlp/policy.ts:60,110`), a fixed list of checksum validators (`policy.ts:227`, `scanner.ts:270-284`), policy-wide caps (`policy.ts:457`), and editor support for detectors and validators (`dlp-editor.tsx:587`, ~2115). Tests: `packages/core/src/__tests__/dlp/tenant-custom-labels.test.ts`; `dlp-policy-store.test.ts:242,291`; `dlp-editor.test.tsx:858,1087,1105`. Not done: a `monitor` action (needs evaluator/telemetry changes outside DLP) and separate file/prompt scopes. After upgrading, an already-saved risky pattern such as `(a\|b)+` is refused. |
| **T37** (data flow and redaction proof) | **Code proof added.** `packages/core/src/__tests__/data-flow-proof.test.ts` (26 pass, 1 expected fail) and `supabase/functions/__tests__/ingest-data-flow-canary.test.ts` (3 pass). They assert, per egress path and feature toggle, the exact body key allowlist, no canary or secret in URL/headers/body, one credential, hashed-not-raw fields, and no request when a feature is off, in local mode or un-enrolled. The allowlist is published in `docs/production-readiness/data-flow-proof.generated.json` with a drift check. Four paths are not yet in `privacy-data-flow-matrix.json`: approval requests, false-positive reports, billing-checkout and federated share. See T37-1. |
| **AIDR-079 / AIDR-080** (image CVEs) | See section 4. |

## 3. Fresh audit findings

| ID | Sev | Area | Repro | Status |
|---|---|---|---|---|
| SEC-1 | P3 | AuthZ gate | `response-playbooks/index.ts:306` `trigger_automation` runs with no user session (per-grant secret), but the matrix gate only saw the route-level session guard, so it was never declared. | **Fixed.** The gate parses `action ===` dispatch and fails on undeclared public actions (`scripts/verify-endpoint-auth-matrix.mjs`; tests in `scripts/verify-endpoint-auth-matrix.test.mjs`). |
| SEC-2 | P3 | Tenant isolation | `get_approval_settings` (`20261013000520:123`) checked membership but not the tenant identity barrier. | **Fixed.** `20261015000400_approval_settings_identity_barrier.sql`; test `scripts/control-plane-security-audit.test.mjs` (SEC-2). |
| SEC-3 | P2 | Audit | Publishing a whole-tenant audit export left no lasting record of who did it. | **Fixed.** `20261015000410_audit_export_publication_audit.sql` writes `audit.export.published` in the publishing transaction. Test: SEC-3 in the same file. |
| SEC-4 | P2 | Audit / AuthZ | `enroll/index.ts:363` minted a device key, then wrote its audit row best-effort. A token creator later demoted to viewer could still spend an outstanding token. | **Fixed.** `20261015000420_enrollment_exchange_atomic_audit.sql` makes it atomic and requires a current owner/admin/member; `enroll/index.ts:361-368`. Test: SEC-4. |
| SEC-5 | P2 | Audit | Break-glass recovery deleted MFA factors before writing the audit row. | **Fixed.** Audit first, abort on failure (`identity-security/index.ts:424-444`). Test: `supabase/functions/__tests__/identity-security.test.ts` (SEC-5). |
| SEC-6 | P3 | Fleet integrity | An unbound tenant key could heartbeat a retired agent and show it as protected. | **Fixed.** 409 `agent_retired` (`connector-heartbeat/index.ts:128-136`). Test: `connector-heartbeat-contract.test.ts` (SEC-6). |
| SEC-7 | P3 | Fleet keys | Re-enrolling a retired machine id does not count against the fleet key seat cap (`20261014000210:300`, `20261014120100:165`). The tenant seat limit still applies. | Reported. Documented design; revoking the key is the control. |
| SEC-8 | P3 | AuthZ consistency | Members can create, renew and revoke full write API keys at AAL1 (`api-keys/index.ts:178,192`); the same holds for fleet-keys and delegated-credentials `grant`. | Reported. Policy change that also needs dashboard flow changes. |
| SEC-9 | P3 | Intra-tenant | An unbound tenant key can poll any approval request in its tenant, including the decision token (`20260926000001:438-443`). | Reported. Approval-flow design. |
| SEC-10 | P3 | Info leak | `approval-requests/index.ts:444-448` reads the row by id before the membership and barrier checks. No cross-tenant data is returned. | Reported. |
| SEC-11 | P3 | Retention | `false_positive_reports`, `license_imports`, `fleet_enrollment_keys` and `agent_retirement_settings` are not removed by tenant offboarding, because offboarding sets a status and no cascade runs. | Reported. Offboarding phase-map change. |
| SEC-12 | P3 | Audit | `save_policy_document_draft` is not audited (publishing is). | Reported. Drafts are not enforced. |
| SEC-13 | P3 | Audit | `identity-security` `revoke_sessions` (others) ignores its audit result (`:845`); `governance-digest` `send_test` audits after sending. | Reported. |
| SEC-14 | P3 | Rate limit | `discovery` collector-credential lookups have no budget for unknown credentials (`discovery/index.ts:66`); `pilot-apply` and `operator-admin` have none (both need a session; operator-admin also needs operator status and MFA). | Reported. |
| SEC-15 | P3 | Webhooks | `paddle-webhook` keeps only the last `h1` signature and trusts `custom_data.tenant_id`. | Reported. The route is disabled (410) by default. |
| SEC-16 | P3 | Docs | `20261014120200:27-28` says the database checks the canonical digest; it only compares the values the caller passes. | Reported. |
| T37-1 | P3 | Privacy | `packages/core/src/evaluator.ts` (~2110) syncs runtime policy when `control_plane.enabled && token`, regardless of mode. A local-mode install with `auth.api_key` set therefore sends `GET /v1/policy` with that key and may apply the result. No tool-call content leaves the endpoint. `docs/configuration.md:242` says local mode does not sync. | Reported, recorded as `it.fails` in `data-flow-proof.test.ts`. Gating on managed mode breaks two existing tests that encode the current behaviour (`remote-policy.test.ts`, `remote-policy-governance.test.ts`), so the owner must choose between the docs and the behaviour. |

Checked and sound (evidence: `node scripts/verify-endpoint-auth-matrix.mjs` 59 routes; `pnpm supabase:check` 99/99;
`node --test scripts/security-definer-search-path.test.mjs scripts/rls-audit-owner-hardening.test.mjs`):

- **RLS.** Every new 2026-10-13/14 table has RLS and no `using (true)`. Secret columns are excluded by column grants (SIEM ciphertext and payload, fleet `key_hash`). Views are `security_invoker` or revoked.
- **Service-role scoping.** Each route derives the tenant from `auth.getUser` plus membership, or from the API key, before any service-role query. No route updates or deletes by id alone.
- **SSRF.** OIDC uses `_shared/safe-fetch.ts`; notifications use `notification-delivery.ts:551-574` (no redirects; re-resolution at fetch time is a documented residual). SIEM pins the resolved address and blocks IMDS (`siem-forwarding.ts:424`).
- **Webhooks.** Stripe and Paddle verify the raw body in constant time, cap the timestamp tolerance and deduplicate event ids. The scheduler routes compare a bearer of at least 32 characters with `sameSecret`.
- **Rate limits.** Every public route carries one (gate-enforced), and so do the expensive actions: SIEM test, reports, audit export, compliance report, notification tests.

### Dashboard (IT/security team view, no-fake-data rule)

| ID | Sev | Finding | Status |
|---|---|---|---|
| DASH-1 | P2 | A missing `allowed_agents` was shown as seat limit "0" (`AgentDetailPage.tsx`). | **Fixed**: shows "unknown". Test: `packages/dashboard/src/__tests__/fleet-view.test.tsx`. |
| DASH-2 | — | No mock, demo, faker or random data is reachable from `main.tsx`; `/demo` only redirects to sign-in. | **Guarded** by `packages/dashboard/src/__tests__/no-demo-data.test.ts` (walks the production import graph). |
| DASH-3 | — | A grep of the production bundle (`pnpm -C packages/dashboard build`) found no demo data. | Verified. |
| DASH-4 | P1 | Agents list had no search, filter, sort or paging. | **Fixed**, URL-persisted (`ui/pages/AgentsPage.tsx`, `ui/fleet-view.ts`). |
| DASH-5 | P1 | Stale agents were not visible. | **Fixed**: Stale badge and count at 4 h, matching `agent_offline_minutes` 240. |
| DASH-6 | P1 | Events had no filters, and the 500-row cap applied before filtering. | **Fixed**: server-side range/type/decision/severity/agent/rule filters with allowlisted deep links (`ui/pages/EventsPage.tsx`). |
| DASH-7 | P2 | No exports of agents or events. | **Fixed**: CSV, and JSON for events, with formula-injection neutralised. |
| DASH-8 | P1 | Connector protection state (`connector_heartbeats`) was never shown. | **Fixed** on agent detail; shows "unavailable" when unreadable. |
| DASH-9 | P2 | RBAC hiding of retire controls. | Verified and tested; server enforcement is in the RPC and RLS. |
| DASH-10 | P2 | No per-agent policy version or receipt (`agent_policy_receipts` is service-role only). | Open: needs a read RPC. |
| DASH-11 | P2 | The agents query has no limit, so the PostgREST row cap can truncate large fleets silently. | Open: server paging. |
| DASH-12 | P2 | Events cannot page past 500 rows, and there is no user filter. | Open: keyset paging. |
| DASH-13 | P2 | Incidents have no export, and their filters are not in the URL. | Open. |
| DASH-14 | P3 | No index on the `events` JSON filter fields. | Open. |
| DASH-15 | P3 | Refresh does a full page reload. | Open. |

## 4. Container images (AIDR-079 / AIDR-080)

Trivy 0.73.0 (winget), DB 2026-10-15T01:13:01Z, `--scanners vuln --pkg-types os,library`, empty ignore file, no VEX,
linux/amd64, images pulled through `mirror.gcr.io`. The index digests were checked against `hub.docker.com` and match.
Counts are package/target occurrences.

| ID | Image | Pin | CRIT / HIGH | Candidate | CRIT / HIGH | Action |
|---|---|---|---:|---|---:|---|
| IMG-1 | imgproxy | v4.0.17 | 0 / 4 | **v4.0.18** `sha256:03aec670…feb6` | 0 / 0 | **Bumped** (`scripts/deployment-prepare.mjs:646`, test updated). `/health` 200 as uid 999 in a local container. |
| IMG-2 | studio (loopback admin only) | 2026.10.05 | 17 / 323 | **2026.10.12-sha-3699278** `sha256:948770ec…a7a8` | 5 / 285 | **Bumped** (`scripts/deployment-prepare.mjs:654`). Native Studio acceptance is pending, as for earlier Studio bumps. |
| IMG-3 | storage-api | v1.80.2 | 1 / 57 | v1.83.1 | 1 / 52 | Not bumped: three minor versions with new tenant migrations (see 2026-10-11 triage); needs native acceptance. |
| IMG-4 | realtime | v2.134.10 | 3 / 141 | v2.143.4 | 3 / 141 | Not bumped: no scanner benefit. |
| IMG-5 | gotrue, postgres-meta, edge-runtime, envoy, postgrest | unchanged | 0/9, 8/87, 4/56, 0/0, 0/0 | no newer non-RC tag (envoy v1.39.3 also 0/0) | — | Keep. |
| IMG-6 | postgres | 17.11.0.004 | 0 / 23 | — | — | Keep. |
| IMG-7 | dashboard base `node:24.21.0-alpine3.24` (`deploy/dashboard/Dockerfile`) | — | stock 0 / 8 | `node:24.22.0-alpine3.24` | stock 0 / 4 | **Not changed: `deploy/` was out of scope.** All of the stock HIGH findings are npm-bundled packages that the dashboard image deletes, and the residual zlib CVE-2026-85091 (MEDIUM) is still in 24.22.0 (alpine 3.24.2 `zlib 1.3.2-r0`). The bump is still recommended to the `deploy/` owner. |

The Helm chart pins (`deploy/helm/aidr/values.yaml`) contain neither imgproxy nor studio, so they do not drift.
AIDR-080 stays BLOCKED_EXTERNAL: the remaining CRITICALs are in images with no fixed upstream tag. AIDR-079 stays
open for the landing image and the MEDIUM zlib finding.

## 5. Gates run for this record

See the final section of the session report: `pnpm check`, `pnpm lint`, `pnpm supabase:check` and `pnpm test`.
`scripts/deployment-prepare.test.mjs` passes 24 of 27 in this worktree. The 3 failures are environmental: the
`deploy/upstream` submodule is not checked out, and the dashboard and core builds were absent at the time of that run.
