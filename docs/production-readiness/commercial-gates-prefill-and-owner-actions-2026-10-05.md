# Commercial hard gates — repo pre-fill and owner action checklist (5 October 2026)

**Source status updated:** 6 October 2026. Release acceptance remains open.

**All 13 hard gates remain `open`; the production profile uses 12 and excludes investor-only INV-001. Nothing in this document approves a gate.** The receipts' source/input descriptions were refreshed on 6 October; all decisions, REQUIRED human identity fields and null candidate/approval/evidence fields remain unchanged. Source base is `7f3ec0ad009abf5b032b8116b296d8604fee884e` plus uncommitted changes. No accepted signed candidate or current `.release-evidence/v8-evidence-index.json` is held. Earlier 0 unapproved claim hits / 54 files, 19 data flows / 200 unknowns and one licence row / 15 unknowns are historical. Current preparation has 25 source-inventory flows / 177 explicit unknowns and two OPEN licence reviews / 8 owner-approval-expiry unknowns. None are deployment or Legal acceptance. Use the [current release report](../../RELEASE_READINESS_REPORT.md) for current test/candidate evidence.

What this document adds: for each gate, (a) what the repository can already supply, with paths, (b) what is still missing, and (c) a who/what/where action. Evidence must bind to **one signed Release Candidate** (`candidate_digest` = SHA-256 of `release-inventory.json`); no RC exists yet (`releaseCandidate: null`).

The Supabase control plane in `aidr` and the managed web app in `aidr-landing` are separate deployment paths. The former has tenant/RBAC and SSO/SCIM source implementations. The latter uses Clerk, Firestore and Polar, with personal tenants and operator-bound Clerk organizations that preserve the existing tenant/storage anchor. Shared requests recheck current administrator/member roles, and policy publication requires two distinct current organization administrators. This source implementation still needs live organization, role-removal, two-account approval and Firestore-rule acceptance. Native Clerk enterprise SSO needs provider configuration and acceptance; no managed SCIM endpoint is shipped. Each path needs its own provider, data-flow and deployed acceptance evidence.

Companion artifacts and their scope:

| Artifact | Path |
|---|---|
| Vendor questionnaire draft, with source scope and acceptance limits | [`security-questionnaire-answers.md`](./security-questionnaire-answers.md) |
| Secret-history triage + redacted ledger | [`secret-history-triage-2026-10-05.md`](./secret-history-triage-2026-10-05.md), [`evidence/secret-history-ledger-2026-10-05.csv`](./evidence/secret-history-ledger-2026-10-05.csv) |
| Current enterprise implementation and earlier historical inspection | [`enterprise-feature-verification-2026-10-05.md`](./enterprise-feature-verification-2026-10-05.md) |
| Tenant-isolation / auth security review | [`tenant-isolation-security-review-2026-10-05.md`](./tenant-isolation-security-review-2026-10-05.md) |
| Exact wheel/native/dpkg notice review inputs, with current and historical snapshots separated | [`bridge-notice-review-pack-2026-10-06.md`](./bridge-notice-review-pack-2026-10-06.md) |
| SBOM generator / licence report / release-signing proof | see "Offline supply-chain tooling" below |

## Offline supply-chain tooling (verified locally)

| Capability | Command | Recorded result and scope |
|---|---|---|
| CycloneDX SBOM (lockfile-derived, deterministic, no network) | `pnpm sbom` (`node scripts/generate-sbom.mjs [--output f]`) | The current local inventory has 216 components (204 libraries). All 30 selected SHA-locked PyPI wheels have metadata and shipped licence-file digests verified against official PyPI. The [metadata manifest](../../services/aig-bridge/pypi-runtime-licenses.json) is inventory evidence, not counsel approval or a signed candidate. |
| Licence report (offline, from the SBOM) | `pnpm license:report -- [--markdown f] [--strict]` (`scripts/generate-license-report.mjs`, test `scripts/generate-license-report.test.mjs`) | 202 permissive, 2 review-required, **0 UNKNOWN** at the declared library-metadata level. Review is required for `certifi` (MPL-2.0) and pure `psycopg` (LGPLv3). The binary wheel is removed from current locks; its 14-library record is historical. [The current review pack](./bridge-notice-review-pack-2026-10-06.md) archives actual wheel texts and scoped system-libpq native copyright materials. The strict report exits 1 pending real licence review; no exception was fabricated. Full OS/image and candidate-bound source/notice obligations remain outside this declared-library report. |
| Provenance (SLSA-style statement binding artifacts, SBOM, lockfile) | `scripts/generate-provenance.mjs`; `scripts/provenance.test.mjs` | The earlier inspection recorded 5 passing tests, including subject-digest mismatch, omitted manifest, lockfile and SBOM tamper detection. Re-run and bind the proof to the release candidate. |
| Release signing and verification (FCR-01) | `scripts/release-sign.mjs`, `scripts/release-verify.mjs`, `scripts/release-signing-lib.mjs`; tests `scripts/release-signing.test.mjs`, `scripts/release-key-isolation.test.mjs` | The earlier inspection recorded 26/26 tests using throwaway Ed25519 keys generated inside the test (`generateKeyPairSync`), no real key involved: signs exact release and runs installer only after verification; **artifact tamper** rejected before installer runs; **modified detached signature** rejected; **wrong signer / allow-list and revoked key id or fingerprint** rejected; **expired release and over-long validity window** rejected; **rollback and same-sequence equivocation** rejected (older candidate only when protected policy allows); anti-rollback state not advanced when installer fails; unsafe receipt destinations and concurrent-lock cases fail closed; private keys/trust policy kept outside the signed bundle. These fixture tests are not production publisher acceptance. |
| Production dependency audit | `pnpm audit --prod`, `node scripts/audit-production-deps.mjs` | The [current release report](../../RELEASE_READINESS_REPORT.md) records clean production/build audits for `aidr` and a clean runtime audit for `aidr-landing`. Landing's development ESLint chain retains one unpatched high advisory. A runtime audit result does not close that development-tool finding or the independent assessment gate. |

Still requiring owners and release acceptance: production publisher key custody and signing of an actual candidate, review of the two declared licences, scoped system-native terms and full container/OS licence inventories, and CI-produced attestations. Python wheel metadata extraction itself is no longer missing.

## Gate-by-gate

Legend: **Pre-fill** = source implementation or recorded local evidence, with its stated scope. **Missing** = remaining implementation, environment, measurement or owner acceptance. **Actions** = who / what / where.

### COM-001 — Commercial Release Manifest (Commercial/Sales + Finance/Billing)

- **Pre-fill:** locked product decisions in the registry `commercialDecision` (direct-GA, five connectors, hybrid, EU/US/APAC, cloud online + enterprise invoice, 14-day / 1-agent trial, private registry, 99.9% monthly target). Manifest template [`commercial-release-manifest-template.md`](./commercial-release-manifest-template.md) and order template [`enterprise-order-entitlement-template.md`](./enterprise-order-entitlement-template.md); billing mechanics [`billing-v6.md`](./billing-v6.md), [`invoice-entitlement-v6.md`](./invoice-entitlement-v6.md), [`invoice-finance-authority.md`](./invoice-finance-authority.md).
- **Missing:** every price, tax/currency treatment, SKU, renewal/cancellation term and the approved manifest itself (template is DRAFT / NOT APPROVED).
- **Actions:**
  1. Commercial owner + Finance: complete the manifest for the RC in `docs/production-readiness/` (copy of the template), obtain named approvals.
  2. Finance: provision invoice finance operators in the target database (`invoice_finance_operators`, per `invoice-finance-authority.md`); run the quote-to-offboarding rehearsal; store the redacted record under `.release-evidence/`.
  3. Release engineering: sign the manifest with the production publisher key; record `evidence_path` + `evidence_sha256` in the COM-001 receipt only after approval.

### COM-002 — Licences, notices, chain of title (Legal + Engineering)

- **Pre-fill:** root `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES`; workspace licence declarations; historical [`com-002-license-audit-2026-09-23.md`](./com-002-license-audit-2026-09-23.md); exception register [`license-exception-register.json`](./license-exception-register.json); current SBOM and SHA-locked Python wheel metadata above. There are no UNKNOWN declared library licences in this local inventory; two require review. The current wheel/system-libpq [notice review archive](./bridge-notice-review-pack-2026-10-06.md) exists; full image scope and Legal/source obligations remain open.
- **Missing:** counsel approval; contributor/employee/contractor chain of title; disposition of the two review-required libraries and current system/static-native terms; applicable obligations for the collected 110 dpkg package notices, selected non-dpkg/static and other Supabase/upstream-image inventories; exception register owner/disposition/expiry; DRL 1.1 attribution check for `threats/`.
- **Actions:**
  1. Engineering: bind the verified wheel metadata, measured native records and collected 110-package dpkg notice snapshot to exact RC artifacts; complete selected non-dpkg/static and other compose-image inventories. Legal reviews the applicable copyright/source obligations. An inventory pass does not grant distribution rights.
  2. Legal: review `THIRD_PARTY_NOTICES` against the full transitive npm/PyPI/image set (the file is a direct-dependency baseline); sign chain-of-title (contributor agreements, vendored AIG provenance under `vendor/ai-infra-guard/`).
  3. Legal: assign owner/reviewer/expiry in `license-exception-register.json`; record counsel approval bound to the RC digest.

### COM-003 — Privacy / data-flow truth (Privacy/DPO + Legal + Security)

- **Pre-fill:** data-flow matrix [`privacy-data-flow-matrix.json`](./privacy-data-flow-matrix.json), updated 6 October with 25 inventory flows DF-001..DF-025, source-known destination/access/deletion boundaries and separate managed Clerk/Firestore/Polar, contact, privacy text-service and MCP paths. Actual configured domains, region, lawful basis and approved retention remain explicit unknowns. Register [`data-flow-privacy-v6.md`](./data-flow-privacy-v6.md), historical handoff [`com-003-privacy-acceptance-2026-09-23.md`](./com-003-privacy-acceptance-2026-09-23.md), and local canary tooling are engineering inputs. Questionnaire PRV-* answers retain source/acceptance limits.
- **Missing:** deployment-specific destinations, regions, access owners, retention and deletion per flow; exact-build packet capture and opt-out tests; DPA / TOM / SCC; subprocessor list; deletion/export receipt on a real tenant.
- **Actions:**
  1. Security/QA: run exact-build egress capture for each enabled flow on the RC (managed, on-prem, air-gapped profiles); attach redacted reports.
  2. Privacy/DPO: verify the enabled flow subset and fill actual domains, regions, lawful basis, retention, access owner and transfer/deletion evidence for DF-001..DF-025; approve the notice text in `docs/privacy.md`. Source descriptions do not establish runtime values.
  3. Legal: execute the applicable data-processing/security terms; maintain a separate enabled-provider list for each path. The Supabase control plane includes its selected hosting, SMTP and optional services; legacy Stripe/Paddle routes count only when enabled. The managed web app includes Clerk, Firebase/Firestore, Polar, selected hosting and optional services. Approval of one path does not approve the other.

### COM-004 — Billing and entitlements (Finance/Billing + Product)

- **Pre-fill:** the Supabase path has `supabase/functions/billing-checkout`, `billing-portal`, `invoice-entitlement`, legacy `stripe-webhook`/`paddle-webhook`, entitlement Ed25519 verification and Postgres rehearsal scripts. The separate managed app has Polar checkout/webhook and entitlement code under `aidr-landing/src/lib/billing/`, with Clerk/Firestore account identity. Presence of legacy routes does not select a provider or enable them for direct GA.
- **Missing:** an approved provider and SKU catalogue for each sold path, test-mode payment-to-entitlement/webhook acceptance, invoice/reconciliation evidence, revocation and deletion receipts.
- **Actions:** Finance approves the provider and catalogue per path; Engineering runs its database and real provider test-mode journey, stores logs; Finance signs reconciliation evidence.

### COM-005 — Support operations (Support/CS + Operations)

- **Pre-fill:** [`support-sla-template.md`](./support-sla-template.md), runbooks (`docs/runbooks/incident-response.md`, `support-bundle.md`, `support-v7.md`, `alerting.md`), support bundle tooling `scripts/support-bundle.mjs` + `scripts/verify-support-bundle.mjs`, `SECURITY.md`.
- **Missing:** published support schedule and severity SLA, a reachable ticket system and security mailbox with an owner, status page, on-call roster, timestamped ticket drill.
- **Actions:** Support lead publishes the schedule and stands up the channels; Operations names on-call and escalation; run and timestamp a Sev1/Sev3 drill; deployed-route crawl of support/status/security/privacy/terms links on the production host.

### COM-010 — Five direct-GA connectors (Product + QA + Engineering + Support)

- **Pre-fill:** connector packages (`packages/claude-code`, `packages/extension` for Cursor and VS Code, `packages/openclaw`, `packages/opencode`); [`native-host-matrix-v6.md`](./native-host-matrix-v6.md); `scripts/external-gates-doctor.mjs`; [`external-gates-runbook.md`](./external-gates-runbook.md); fail-closed connector entry-point policy (CLAUDE.md); package consumer checks (`scripts/check-package-consumers.mjs`, `scripts/verify-package-install.mjs`). Codex is outside the registry's five-connector direct-GA scope.
- **Missing:** real-host E2E reports on supported host versions, private-registry install logs, rollback/disable drill, per-connector support owner and limitations text. Questionnaire END-03 notes a disabled-hook case that fails open at the host level.
- **Actions:** QA executes gates 18/19/27 on real Cursor, VS Code, Claude Code, OpenClaw and OpenCode hosts with live credentials supplied via secret manager (never committed); Product publishes the supported-host matrix and limitations; Support names owners.

### COM-011 — Regions and residency (Operations + Privacy/DPO + Legal)

- **Pre-fill:** declarative [`deploy/regions.manifest.json`](../../deploy/regions.manifest.json) (explicitly not evidence), [`com-011-region-residency-audit-2026-09-23.md`](./com-011-region-residency-audit-2026-09-23.md) (pilot project `eu-central-1` only), backup/restore tooling under `deploy/backup/`.
- **Missing:** production EU/US/APAC projects, tenant placement test, cross-region negative test, backup/deletion receipts, DPA/SCC approval, edge-function region pinning receipts.
- **Actions:** Operations provisions per-region projects; Engineering adds region pin and receipts; Privacy/Legal approve transfer mechanisms; run cross-region negative tests and attach.

### COM-012 — Invoice orders and private registry (Finance + Release Engineering + Support)

- **Pre-fill:** invoice intake (`invoice-entitlement`), signed release bundle tooling (`release-sign.mjs`/`release-verify.mjs`), pack distribution (`packs-manifest`, `packs-download`, `revocations` functions), air-gap image bundle `scripts/build-airgap-images.mjs` with offline `--verify` (tests pass).
- **Missing:** registry provider decision and authenticated registry, entitlement-to-download test, revocation/offboarding test on a real registry, signed air-gap manifest (current manifest is unsigned digests).
- **Actions:** Release engineering selects and provisions the private registry and credentials process; signs the air-gap manifest with the production key; Finance/Support run invoice-to-entitlement and revocation tests.

### COM-013 — 99.9% availability SLA (Operations + Legal + Support + Finance)

- **Pre-fill:** SLI tooling `scripts/monthly-sli-report.mjs`, `scripts/verify-monthly-sli-report.mjs`, schemas and HA references in `deploy/ha/`, load/noisy-neighbour scripts (`scripts/load-test.mjs`, `scripts/verify-noisy-neighbor-live.mjs`), resource sizing docs, [`load-capacity-v6.md`](./load-capacity-v6.md).
- **Missing:** an observation window on a deployed control plane, approved SLA schedule with exclusions and service credits, incident drill, managed-cloud HA evidence.
- **Actions:** Operations runs the managed control plane and collects a full month of SLI observations; Legal/Finance approve credits; Support runs an incident drill.

### SEC-EXT-001 — Independent assessment (Security Lead + independent assessor)

- **Pre-fill:** internal pre-assessment inputs: [`tenant-isolation-security-review-2026-10-05.md`](./tenant-isolation-security-review-2026-10-05.md) for its recorded source scope, [`security-questionnaire-answers.md`](./security-questionnaire-answers.md), SBOM and dependency reports, and [`secret-history-triage-2026-10-05.md`](./secret-history-triage-2026-10-05.md). The pinned official history scan records 132 detections and the same two owner-confirm items; the earlier 184-row ledger is historical. Clean current-tree scans do not resolve those owner decisions. Acceptance procedure: [`sec-ext-001-assessment-acceptance.md`](./sec-ext-001-assessment-acceptance.md). **An internal review is not an independent assessment.**
- **Missing:** engaged assessor, signed scope, report, remediation/retest letter.
- **Actions:** Security Lead freezes a signed RC, contracts an independent assessor (scope: tenant isolation/RLS, identity and recovery, connectors, cloud and on-prem boundaries, update provenance, secrets), keeps the signed report under `.release-evidence/`, binds it via the manifest described in the acceptance doc.

### POV-001 — Customer acceptance run (Customer Success + Product + evaluator)

- **Pre-fill:** [`pov-001-customer-acceptance-run-sheet.md`](./pov-001-customer-acceptance-run-sheet.md), [`controlled-demo-runbook.md`](./controlled-demo-runbook.md), [`customer-investor-validation-master-plan.md`](./customer-investor-validation-master-plan.md), historical [`first-customer-buyer-handoff-2026-09-23.md`](./first-customer-buyer-handoff-2026-09-23.md), and the questionnaire and feature verification with their stated source and local-test scopes.
- **Missing:** named evaluator, signed charter, independent run, reservations log.
- **Actions:** Customer Success schedules the evaluator, executes the run sheet on the RC, records intervention/deviation log and the evaluator's written result. Product scopes each deployment separately: the Supabase control plane has tenant OIDC and TCP/TLS/UDP syslog transport, plus SAML policy request/approval source and dashboard UI in migration `20261005230000_saml_policy_administration.sql`; later local native PostgreSQL verification is recorded in the release report. Live IdP, SAML cutover/recovery, collector-side SIEM receipt and deployed acceptance remain open. The managed app now has operator-bound organization administration and two-administrator publication source; live Clerk/Firestore acceptance, native SSO configuration and managed directory/SCIM scope remain open. The separate privacy service supports one configured mTLS text route and requires real brokers, approved NER and selected-application routing; it does not establish coverage of every product exit. Source implementation and local tests are not customer acceptance receipts.

### INV-001 — Investor metric dictionary (Product + Finance + Legal)

- **Pre-fill:** [`investor-metric-dictionary.json`](./investor-metric-dictionary.json) with schema and validator (`scripts/validate-investor-metric-dictionary.mjs`, run by `pnpm test`).
- **Missing:** approved formulas/denominators/sources/windows/owners/reviewers; no traction or financial source data exists in the repository.
- **Actions:** Finance and Product supply sources and reviewers for each metric; Legal approves limitation wording; publish only dictionary-backed metrics.

### CLM-001 — Claim registry (Product/Marketing + Commercial + Legal)

- **Pre-fill:** claim registry and automated source/build checks. The earlier inspection recorded 14 claims and 0 unapproved pattern hits across 54 claim-facing files; that snapshot does not attest the later worktree or deployed bytes. The current release report includes `aidr-landing` source and build checks with their limits.
- **Missing:** registry snapshot bound to the RC, build-output scan JSON of the final artifacts and landing deployment, and "Sales Approved" review.
- **Actions:** Marketing runs the gate scan on the built artifacts and landing build for the RC; Legal and Commercial sign off each claim; keep any claim that depends on an open gate blocked.

## Cross-cutting owner checklist (single list)

| # | Owner | Action | Where |
|---|---|---|---|
| 1 | Security Lead | Sign the 2 owner-confirm secret findings; rerun history + current-tree scans with pinned official gitleaks 8.30.1 on the RC | `secret-history-triage-2026-10-05.md` |
| 2 | Security Lead | Contract independent assessor (SEC-EXT-001) | `sec-ext-001-assessment-acceptance.md` |
| 3 | Release Eng | Approve production publisher-key custody and independent signer policy; sign RC and any selected air-gap manifest; preserve CI attestations | `scripts/release-sign.mjs`, `build-airgap-images.mjs`; no specific HSM/KMS product is mandated |
| 4 | Release Eng | Provision authenticated private registry; entitlement and revocation test | COM-012 |
| 5 | Legal | Counsel review of LICENSE/NOTICE/THIRD_PARTY_NOTICES; chain of title; exception register | COM-002 |
| 6 | Legal + DPO | DPA/TOM/SCC, subprocessor list, notice approval, retention per flow | COM-003, COM-011 |
| 7 | Finance | Provider of record, price/tax manifest, finance operator provisioning, reconciliation | COM-001, COM-004 |
| 8 | Operations | Regional production projects, SLI month, HA/restore drill on a second host, status page, on-call | COM-011, COM-013, COM-005 |
| 9 | Support | Publish SLA schedule; ticket and security mailboxes; drill | COM-005 |
| 10 | QA | Real-host E2E for the five connectors; Supabase OIDC/SAML/SCIM and SIEM acceptance; managed-app personal and organization/two-administrator provider journeys within the selected deployment scope | COM-010, enterprise-feature doc |
| 11 | Engineering + Legal | Bind verified wheel metadata to the RC; review two library licences and scoped 17-path system-native inventory; full image SBOMs/notices | COM-002 |
| 12 | Customer Success | Named evaluator, signed charter, run | POV-001 |
| 13 | Product + Finance | Metric sources/reviewers | INV-001 |
| 14 | Marketing + Commercial | Scan release artifacts and landing build; claim sign-off | CLM-001 |
