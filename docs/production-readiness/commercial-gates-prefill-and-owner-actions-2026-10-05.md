# Commercial hard gates — repo pre-fill and owner action checklist (5 October 2026)

**All 13 hard gates remain `open`. Nothing in this document marks, implies or recommends a PASS.** The receipts in [`commercial-gate-receipts.json`](./commercial-gate-receipts.json) were not edited. Re-confirmed on this branch: `node scripts/verify-commercial-gate-receipts.mjs` lists all 13 as open; `node docs/scripts/claim-check.mjs --mode=gate` exits FAIL by design (0 unapproved claim hits across 54 claim-facing files; candidate digest `unknown`); `node scripts/verify-commercial-compliance.mjs` reports templates valid-but-open (19 data flows, 200 unknown values; 1 licence exception with 15 unknown values); `node scripts/validate-backlog.mjs` and `node scripts/verify-repo-hygiene.mjs` pass.

What this document adds: for each gate, (a) what the repository can already supply, with paths, (b) what is still missing, and (c) a who/what/where action. Evidence must bind to **one signed Release Candidate** (`candidate_digest` = SHA-256 of `release-inventory.json`); no RC exists yet (`releaseCandidate: null`).

Companion artifacts produced in this pass:

| Artifact | Path |
|---|---|
| Vendor questionnaire answers (109 questions, cites code) | [`security-questionnaire-answers.md`](./security-questionnaire-answers.md) |
| Secret-history triage + redacted ledger | [`secret-history-triage-2026-10-05.md`](./secret-history-triage-2026-10-05.md), [`evidence/secret-history-ledger-2026-10-05.csv`](./evidence/secret-history-ledger-2026-10-05.csv) |
| Enterprise feature verification (VERIFIED / PARTIAL / MISSING) | [`enterprise-feature-verification-2026-10-05.md`](./enterprise-feature-verification-2026-10-05.md) |
| Tenant-isolation / auth security review | [`tenant-isolation-security-review-2026-10-05.md`](./tenant-isolation-security-review-2026-10-05.md) |
| SBOM generator / licence report / release-signing proof | see "Offline supply-chain tooling" below |

## Offline supply-chain tooling (verified locally)

| Capability | Command | Result on this branch |
|---|---|---|
| CycloneDX SBOM (lockfile-derived, deterministic, no network) | `pnpm sbom` (`node scripts/generate-sbom.mjs [--output f]`) | 217 components (205 libraries). Non-commercial mode succeeds; `AIDR_RELEASE_MODE=commercial` deliberately exits non-zero because 31 PyPI runtime packages (`services/aig-bridge/requirements-runtime.lock`) have no licence metadata. |
| Licence report (offline, from the SBOM; new) | `pnpm license:report -- [--markdown f] [--strict]` (`scripts/generate-license-report.mjs`, test `scripts/generate-license-report.test.mjs`) | 174 permissive (MIT 136, Apache-2.0 20, ISC 11, BSD-3 4, BSD-2 2, 0BSD 1), 0 copyleft/review-required among declared licences, **31 UNKNOWN** (the PyPI set). UNKNOWN is never assumed safe; `--strict` exits 1 while any exist. Engineering inventory only, not legal approval. |
| Provenance (SLSA-style statement binding artifacts, SBOM, lockfile) | `scripts/generate-provenance.mjs`; `scripts/provenance.test.mjs` | 5 tests pass, including subject-digest mismatch, omitted manifest, lockfile and SBOM tamper detection. |
| Release signing and verification (FCR-01) | `scripts/release-sign.mjs`, `scripts/release-verify.mjs`, `scripts/release-signing-lib.mjs`; tests `scripts/release-signing.test.mjs`, `scripts/release-key-isolation.test.mjs` | 26/26 tests pass using throwaway Ed25519 keys generated inside the test (`generateKeyPairSync`), no real key involved: signs exact release and runs installer only after verification; **artifact tamper** rejected before installer runs; **modified detached signature** rejected; **wrong signer / allow-list and revoked key id or fingerprint** rejected; **expired release and over-long validity window** rejected; **rollback and same-sequence equivocation** rejected (older candidate only when protected policy allows); anti-rollback state not advanced when installer fails; unsafe receipt destinations and concurrent-lock cases fail closed; private keys/trust policy kept outside the signed bundle. |
| Production dependency audit | `pnpm audit --prod`, `node scripts/audit-production-deps.mjs` | Was 6 moderate advisories (`ip-address`, `hono`, `fast-uri`; no high/critical); fixed by raising `pnpm.overrides` in `package.json` (`ip-address` 10.7.3, `hono` 4.13.7, `fast-uri` 3.1.8). Now 0 advisories. |

Not done locally and requiring owners: production publisher key ceremony and HSM/KMS custody, signing of an actual candidate, SBOM/licence texts for the Python wheels and container images, CI-produced attestations.

## Gate-by-gate

Legend: **Pre-fill** = verifiable from the repository today. **Missing** = cannot be supplied by the repo. **Actions** = who / what / where.

### COM-001 — Commercial Release Manifest (Commercial/Sales + Finance/Billing)

- **Pre-fill:** locked product decisions in the registry `commercialDecision` (direct-GA, five connectors, hybrid, EU/US/APAC, cloud online + enterprise invoice, 14-day / 1-agent trial, private registry, 99.9% monthly target). Manifest template [`commercial-release-manifest-template.md`](./commercial-release-manifest-template.md) and order template [`enterprise-order-entitlement-template.md`](./enterprise-order-entitlement-template.md); billing mechanics [`billing-v6.md`](./billing-v6.md), [`invoice-entitlement-v6.md`](./invoice-entitlement-v6.md), [`invoice-finance-authority.md`](./invoice-finance-authority.md).
- **Missing:** every price, tax/currency treatment, SKU, renewal/cancellation term and the approved manifest itself (template is DRAFT / NOT APPROVED).
- **Actions:**
  1. Commercial owner + Finance: complete the manifest for the RC in `docs/production-readiness/` (copy of the template), obtain named approvals.
  2. Finance: provision invoice finance operators in the target database (`invoice_finance_operators`, per `invoice-finance-authority.md`); run the quote-to-offboarding rehearsal; store the redacted record under `.release-evidence/`.
  3. Release engineering: sign the manifest with the production publisher key; record `evidence_path` + `evidence_sha256` in the COM-001 receipt only after approval.

### COM-002 — Licences, notices, chain of title (Legal + Engineering)

- **Pre-fill:** root `LICENSE`, `NOTICE`, `THIRD_PARTY_NOTICES`; ten workspace manifests declare `Proprietary`; [`com-002-license-audit-2026-09-23.md`](./com-002-license-audit-2026-09-23.md); exception register [`license-exception-register.json`](./license-exception-register.json); new SBOM + licence report above (npm side fully declared and permissive; PyPI side unknown).
- **Missing:** counsel approval; contributor/employee/contractor chain of title; Python wheel licence files (Core Metadata `License-Expression`/`License-File`); container base-image/OS and Supabase/upstream image notices; exception register owner/disposition/expiry; DRL 1.1 attribution check for `threats/`.
- **Actions:**
  1. Engineering: after the RC wheels are built, extract wheel Core Metadata + licence files for the 31 packages, feed into the SBOM so `AIDR_RELEASE_MODE=commercial pnpm sbom` passes; generate image SBOMs for the compose images.
  2. Legal: review `THIRD_PARTY_NOTICES` against the full transitive npm/PyPI/image set (the file is a direct-dependency baseline); sign chain-of-title (contributor agreements, vendored AIG provenance under `vendor/ai-infra-guard/`).
  3. Legal: assign owner/reviewer/expiry in `license-exception-register.json`; record counsel approval bound to the RC digest.

### COM-003 — Privacy / data-flow truth (Privacy/DPO + Legal + Security)

- **Pre-fill:** data-flow matrix [`privacy-data-flow-matrix.json`](./privacy-data-flow-matrix.json) (19 flows DF-001..DF-019, each with source files, purpose, fields; destinations/regions/retention deliberately `unknown`), register [`data-flow-privacy-v6.md`](./data-flow-privacy-v6.md), handoff [`com-003-privacy-acceptance-2026-09-23.md`](./com-003-privacy-acceptance-2026-09-23.md), local canary `scripts/privacy-verify.mjs` / `scripts/privacy-canary.test.mjs`. Questionnaire answers PRV-* cite code for what is and is not sent.
- **Missing:** deployment-specific destinations, regions, access owners, retention and deletion per flow; exact-build packet capture and opt-out tests; DPA / TOM / SCC; subprocessor list; deletion/export receipt on a real tenant.
- **Actions:**
  1. Security/QA: run exact-build egress capture for each enabled flow on the RC (managed, on-prem, air-gapped profiles); attach redacted reports.
  2. Privacy/DPO: fill `destination`, `region`, `retention`, `owner` for DF-001..DF-019 (replace `unknown`), approve the notice text in `docs/privacy.md`.
  3. Legal: execute DPA/TOM/SCC with the customer template; maintain subprocessor list (Supabase, Cloudflare, Stripe/Paddle, Sentry if enabled, email provider).

### COM-004 — Billing and entitlements (Finance/Billing + Product)

- **Pre-fill:** `supabase/functions/billing-checkout`, `billing-portal`, `invoice-entitlement`, `stripe-webhook`, `paddle-webhook` (legacy, disabled for direct GA per the isolation review), entitlement Ed25519 verification (`entitlements-ed25519.test.ts`), Postgres rehearsal scripts (`scripts/billing-*-postgres*.mjs`, `scripts/test-invoice-finance-postgres.mjs`).
- **Missing:** provider-of-record decision, SKU/entitlement test run against a real provider test mode, invoice/reconciliation evidence, revocation and deletion receipt.
- **Actions:** Finance decides provider of record; Engineering runs the Postgres billing suites against a disposable database and the provider's test mode (not live), stores logs; Finance signs reconciliation evidence.

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

- **Pre-fill (this pass):** internal pre-assessment inputs an assessor can start from: [`tenant-isolation-security-review-2026-10-05.md`](./tenant-isolation-security-review-2026-10-05.md) (no critical/high; 2 medium fixed), [`security-questionnaire-answers.md`](./security-questionnaire-answers.md), SBOM, clean `pnpm audit --prod`, secret-history triage. Acceptance procedure in [`sec-ext-001-assessment-acceptance.md`](./sec-ext-001-assessment-acceptance.md). **An internal review is not an independent assessment.**
- **Missing:** engaged assessor, signed scope, report, remediation/retest letter.
- **Actions:** Security Lead freezes a signed RC, contracts an independent assessor (scope: tenant isolation/RLS, identity and recovery, connectors, cloud and on-prem boundaries, update provenance, secrets), keeps the signed report under `.release-evidence/`, binds it via the manifest described in the acceptance doc.

### POV-001 — Customer acceptance run (Customer Success + Product + evaluator)

- **Pre-fill:** [`pov-001-customer-acceptance-run-sheet.md`](./pov-001-customer-acceptance-run-sheet.md), [`controlled-demo-runbook.md`](./controlled-demo-runbook.md), [`customer-investor-validation-master-plan.md`](./customer-investor-validation-master-plan.md), [`first-customer-buyer-handoff-2026-09-23.md`](./first-customer-buyer-handoff-2026-09-23.md); this pass's questionnaire and feature verification give the evaluator an honest status per feature.
- **Missing:** named evaluator, signed charter, independent run, reservations log.
- **Actions:** Customer Success schedules the evaluator (for example the target enterprise), executes the run sheet on the RC, records intervention/deviation log and the evaluator's written result; Product reviews limitations (SSO is not sale-ready until live Entra/Okta acceptance, OIDC is not offered, syslog transport not shipped).

### INV-001 — Investor metric dictionary (Product + Finance + Legal)

- **Pre-fill:** [`investor-metric-dictionary.json`](./investor-metric-dictionary.json) with schema and validator (`scripts/validate-investor-metric-dictionary.mjs`, run by `pnpm test`).
- **Missing:** approved formulas/denominators/sources/windows/owners/reviewers; no traction or financial source data exists in the repository.
- **Actions:** Finance and Product supply sources and reviewers for each metric; Legal approves limitation wording; publish only dictionary-backed metrics.

### CLM-001 — Claim registry (Product/Marketing + Commercial + Legal)

- **Pre-fill:** 14 registered claims; `claim-check --mode=gate` scans 54 claim-facing files with 0 unapproved pattern hits (this document and the questionnaire avoid the banned patterns such as "real-time", "local-only", certification wording, "launch-ready").
- **Missing:** registry snapshot bound to the RC, build-output scan JSON of the final artifacts, "Sales Approved" review, landing-site scan (separate repository, not touched here).
- **Actions:** Marketing runs the gate scan on the built artifacts and landing build for the RC; Legal and Commercial sign off each claim; keep any claim that depends on an open gate blocked.

## Cross-cutting owner checklist (single list)

| # | Owner | Action | Where |
|---|---|---|---|
| 1 | Security Lead | Sign the 2 owner-confirm secret findings; rerun history + current-tree scans with pinned official gitleaks 8.30.1 on the RC | `secret-history-triage-2026-10-05.md` |
| 2 | Security Lead | Contract independent assessor (SEC-EXT-001) | `sec-ext-001-assessment-acceptance.md` |
| 3 | Release Eng | Production publisher key ceremony (HSM/KMS), sign RC, sign air-gap manifest, CI attestations | `scripts/release-sign.mjs`, `build-airgap-images.mjs` |
| 4 | Release Eng | Provision authenticated private registry; entitlement and revocation test | COM-012 |
| 5 | Legal | Counsel review of LICENSE/NOTICE/THIRD_PARTY_NOTICES; chain of title; exception register | COM-002 |
| 6 | Legal + DPO | DPA/TOM/SCC, subprocessor list, notice approval, retention per flow | COM-003, COM-011 |
| 7 | Finance | Provider of record, price/tax manifest, finance operator provisioning, reconciliation | COM-001, COM-004 |
| 8 | Operations | Regional production projects, SLI month, HA/restore drill on a second host, status page, on-call | COM-011, COM-013, COM-005 |
| 9 | Support | Publish SLA schedule; ticket and security mailboxes; drill | COM-005 |
| 10 | QA | Real-host E2E for the five connectors; live Entra and Okta SAML/SCIM acceptance | COM-010, enterprise-feature doc |
| 11 | Engineering | Wheel licence extraction so commercial SBOM passes; image SBOMs | COM-002 |
| 12 | Customer Success | Named evaluator, signed charter, run | POV-001 |
| 13 | Product + Finance | Metric sources/reviewers | INV-001 |
| 14 | Marketing + Commercial | Scan release artifacts and landing build; claim sign-off | CLM-001 |
