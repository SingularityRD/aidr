# Singularity AIDR Customer & Investor Validation / Sale-Readiness Master Plan

## Document control

| Field | Value |
|---|---|
| Document status | Active internal source of truth |
| Current release decision | **NO-GO** |
| Locked commercial profile | Direct GA; all connectors; hybrid; EU/US/APAC; enterprise invoice; private registry; 99.9% monthly managed control-plane/dashboard API target |
| Baseline date | 2026-08-04 |
| Baseline commit | 4abbdc165fdf3d39809043fb0c33fa16324eb486 |
| Primary audience | Product, Engineering, QA, Security, DevOps/SRE, Sales, Customer Success, Legal |
| External audience | Customer technical evaluators, investor technical advisers, procurement and security teams |
| Review cadence | Daily while P0 blockers are open; weekly after Release Candidate |
| Final approvers | Product Owner, Engineering Lead, QA Lead, Security Lead, Operations Owner, Commercial/Sales Owner, Legal, Privacy/DPO, Finance/Billing, Support/Customer Success |

This document is the authoritative plan for turning the current AIDR codebase into a product that can be independently tested by customers and investors, sold with defensible claims, deployed safely, operated reliably, and supported after purchase.

It deliberately separates four different states:

1. A feature exists in source code.
2. A feature passes isolated tests.
3. A feature works end to end in a production-like environment.
4. A feature is safe and supportable enough to be sold.

Only the fourth state qualifies as sale-ready.

“Every line works” is not a technically provable release claim. Line coverage proves only that a line executed under a test; it does not prove correct behavior, security or customer value. The defensible objective used by this plan is stricter and auditable: every shipped source file and external claim is inventoried; every active entry point has an owner; every security decision path is linked to a requirement, threat, test and evidence record; and critical paths pass coverage, mutation, property/fuzz, two-person review and real-host E2E gates.

---

## 1. Executive decision

### 1.1 Current verdict

The current repository is **not production-ready, not sale-ready, and not ready for an uncontrolled customer evaluation**.

The baseline audit identified CI, package, AIG, dashboard, data, security and commercial gaps. A subsequent working-tree repair wave closed some mechanical defects, but those reports are not immutable Release Candidate evidence and do not change this verdict. In particular:

- `pnpm check`, `pnpm build:release`, `pnpm quality:gate`, and the dashboard typecheck/build were re-run successfully in this working tree; each still must be re-run from a clean, pinned Release Candidate and archived with a commit/digest.
- The quality gate passes with 102 lint warnings; warning disposition, clean-clone reproducibility and the complete evidence index remain open.
- `pnpm test:e2e` now fails closed instead of silently succeeding: Claude/OpenClaw/OpenCode/Cursor/VS Code report pending tests because real hosts, credentials and evaluator environments are not provisioned. This is an honest **NO-GO**, not a test pass.
- AIG is now backed by the pinned Tencent `v4.5.1` source and has a verified local server/agent/bridge runtime. A benign `https://example.com` task, an MCP SSE fixture, an Agent-Scan HTTP fixture and a `JailBench-Tiny` jailbreak fixture completed through the bridge. These close the previous “empty/dead AIG” finding and prove the four request/result control-plane paths, but synthetic/benign fixtures are not detection-recall evidence: no authorized known-positive vulnerable fixture, result-to-incident mapping, shared HA task ownership, signed dataset promotion or upstream authentication exists yet.
- Dashboard route/build and onboarding hardening have been applied, but deployed-RC browser route/console/accessibility, Supabase reset/RLS/tenant isolation and billing contract evidence are not present.
- The dashboard’s direct-GA billing surface is now invoice/order only: public pricing is quoted by order, checkout/portal calls are opt-in legacy paths, and backend checkout/webhook functions return `410 disabled_for_direct_ga` by default. Finance/provider-of-record and entitlement/offboarding evidence remain open.
- Browser-facing Supabase functions now enforce an explicit `AIDR_ALLOWED_ORIGINS` allowlist and answer Supabase client preflights before any auth/database operation; hosted origin configuration and a deployed browser trace remain open evidence.
- Abuse throttles on device bootstrap, enrollment, credential issuance, and waitlist intake fail closed if rate-limit storage is unavailable; staging must still prove the deployed RPC/table path and alert on throttling failures.
- Node production dependency auditing now reports one narrowly source-checked React Router RSC-only advisory exception; the pinned AIG Python runtime audit reports zero known vulnerabilities. Both still require immutable-RC evidence and an owner-approved exception/upgrade policy before release.
- Coverage/mutation, release signing/SBOM/provenance, rollback and independent security assessment still require fresh evidence for the same candidate.
- Baseline license metadata was mechanically reconciled to proprietary first-party terms with preserved third-party notices; Legal sale readiness remains explicitly blocked until counsel approves the license/NOTICE/package matrix and the generated transitive notice/SBOM bundle.
- Pricing/entitlement, privacy/DPA/subprocessor/region, support/SLA/ticket, pentest closure, signed customer PoV and investor metric evidence are external hard gates. They cannot be inferred from source code or a passing build.

### 1.2 Positive signals worth preserving

- 117 test files and 1,948 tests pass in the current unit/integration suite, including the dashboard DOM suite now covered by the root Vitest glob and the controlled synthetic demo behavior.
- The latest local coverage run measured 76.08% lines, 77.58% functions and 63.76% branches; this is engineering signal, not a critical-path acceptance threshold.
- Release builds complete for several packages.
- The core detection engine has substantial tests for command, URL, file, package and threat-rule behavior.
- Claude Code has the strongest connector-level integration coverage.
- The public landing domain responds successfully.
- Device authorization, managed control plane and incident concepts are represented in code and documentation.
- Security, deployment, alerting and incident-response documents already exist and can be consolidated rather than created from zero.

### 1.2.1 Working-tree implementation evidence (re-run required)

The following results were reported during the 2026-08-04 repair wave. They are useful engineering evidence, but they are not a signed Release Candidate, customer acceptance, legal approval or production proof. The command, exact commit, environment, log path and SHA-256 must be recorded in the evidence registry before any gate can close.

| Check | Reported result | What it proves | What it does not prove | Gate status |
|---|---|---|---|---|
| `pnpm check` | **PASS** in the final working-tree run | TypeScript/build ordering is executable in the current worktree | Clean-clone reproducibility, deployed revision or customer behavior | Re-run on immutable RC / open |
| `pnpm build:release` | **PASS**; 8 package contracts, SBOM copy, no-sourcemap and leaky-path checks executed | Current package outputs can be built and contract-checked | Commercial signatures/provenance, consumer install on supported hosts | Re-run on immutable RC / open |
| `pnpm quality:gate` | **PASS** with 102 lint warnings; tests 1,948/1,948 and coverage completed | Unit/coverage/build orchestration completes in the current worktree | Warning policy, full critical-path coverage/mutation, immutable RC evidence | Re-run on immutable RC / open |
| `pnpm test:e2e` | **FAIL-CLOSED**: Claude 7, OpenClaw 5, OpenCode 13, Cursor 9, VS Code 8 pending; collected=executed=0 for each | Missing hosts/credentials cannot create a false-green release signal; JSON+JUnit evidence is retained | Any real-host connector or customer PoV pass | Hard NO-GO |
| `pnpm audit:prod` | One high advisory remains and is allowed only by a source-checked React Router RSC-only exception; no critical/moderate/low | Dependency gate is deterministic and fails on any new/path-shifted advisory | Vendor risk acceptance, exploitability review or clean zero-advisory report | Conditional technical exception / open |
| `pip-audit -r services/aig-bridge/requirements.txt` (Python 3.12 Docker runtime) | **PASS**: no known vulnerabilities after FastAPI 0.141.1 and python-multipart 0.0.32 upgrade | AIG bridge’s pinned direct dependency set is auditable in the supported Python runtime | Transitive image/OS CVE scan, signed image provenance or upstream AIG/data E2E | Re-run in immutable CI image / open |
| `pnpm supabase:check` | **PASS**: 9 unique ordered migrations; local reset/lint reported PASS | Migration ordering/config contract is executable locally | Reconciliation with any live project history, production RLS/tenant isolation | Re-run against linked project / open |
| `pnpm -C packages/dashboard exec tsc --noEmit` | **PASS** | Dashboard source typechecks | Deployed routes, browser console, accessibility, Supabase schema/RLS | Re-run on deployed RC / open |
| `pnpm -C packages/dashboard run build` | **PASS** | Dashboard bundle can be generated | DNS/TLS/version provenance and production smoke | Re-run on deployed RC / open |
| `pnpm -C packages/dashboard run test:route-smoke:static` | **PASS (static-only)**; default credentialed smoke correctly fails setup without Supabase env | Route/security contracts and secret masking are mechanically checked | Real browser, deployed Supabase, console/axe and customer behavior | Hard evidence open |
| `python -m compileall -q services/aig-bridge/app services/aig-bridge/tests` | **PASS** | Python bridge syntax and focused test imports compile | FastAPI runtime test execution, upstream AIG, signed dataset, scan-to-incident path | Re-run in pinned Python env / open |
| `docker run python:3.12-slim … pip-audit + PYTHONPATH=/work pytest -q tests` | **PASS**: no known vulnerabilities; 18/18 bridge contract/security tests | Pinned Docker runtime dependencies execute AIG v4 response mapping, persistence, SSRF/source-sandbox/header/idempotency tests | Real upstream AIG, signed dataset, scan-to-incident path | Re-run in immutable image / open |
| `docker compose --env-file .env.aig -f docker-compose.aig.yml config --quiet` | **PASS** | Compose file parses after auth/source-volume repair | Healthy multi-service deployment and outage/security behavior | Re-run with vendor source / open |
| `docker build --pull=false -t aidr-aig-bridge-check services/aig-bridge` | **PASS**; Python 3.12 image builds with no embedded API key | Bridge image is buildable and does not bake a secret into ENV | CVE scan, signed image provenance, upstream AIG | Re-run in CI / open |
| `pnpm aig:verify` | **PASS with explicit portability warning**: pinned commit `31c72a9799c8b19d89bcb331d4f8038f05462b8f` (`v4.5.1`), generated indexes contain 1,925 CVEs/133 fingerprints/14 MCP categories; 10 case-colliding upstream path groups reported | Source and generated consumer indexes are present, versioned and non-empty | Complete case-sensitive checkout on Windows, signed data promotion, installed-consumer hash proof | Open until Linux immutable-RC evidence |
| AIG server/agent container builds | **PASS**: Tencent `v4.5.1` `Dockerfile` and `Dockerfile_Agent` both build | Upstream binaries can be built from the pinned source | Image digest/signature, OS CVE scan, HA worker identity | Re-run in release image / open |
| AIG compose runtime | **PASS locally**: server, one agent and bridge healthy; host binds `127.0.0.1:8088/8099`; `/api/v1/health` reports `cve_count=1891`, `threat_intel_ready=true`, while `aig_agent` remains `unknown` because upstream has no worker-health route | Real source, worker, bridge, knowledge endpoints and private demo bind operate together | Capability-specific worker readiness, public-ingress hardening, durable queue/task ownership, load/soak and outage recovery | Open |
| AIG bridge benign infra E2E | **PASS locally**: current secure-default task `950135f2-afc6-44a4-9caa-68099a60ee8f` (previous `e85c1384-02f2-4415-ac5a-13041dd437d4`) reached `completed`; AIG evidence contained `https://example.com`, HTTP 200, title and empty fingerprint | Correct AIDR→bridge→AIG-agent→result path and `done`→`completed` normalization after rebuilding/recreating the stack | Known-positive CVE fixture, incident mapping, four scan types, immutable evidence archive | Open |
| AIG MCP synthetic control-plane E2E | **PASS locally**: task `6e4e7514-31be-4ecd-9029-ee4393730b55` connected to the real AIG MCP worker over SSE and completed with evaluator score 100 | Exact v4 `prompt` URL mapping, MCP SDK compatibility shim, streamed evaluator response and result envelope work | Synthetic fixture reports no findings; no category/severity recall or known-positive detection proof | Open |
| AIG Agent-Scan synthetic control-plane E2E | **PASS locally**: task `6ffdd7f1-8b39-4e2c-9dc3-f8523c67f112` completed with score 100 and an `agent-security-report@1` envelope | Inline provider YAML → v4 `agent_data` mapping, worker execution and terminal result mapping work | Fixture reported `total_tests=0`; no injection finding or real agent coverage proof | Open |
| AIG Jailbreak synthetic control-plane E2E | **PASS locally**: task `ea1f6f01-44b2-4d3a-aec9-82b2beb8ed2e` completed `JailBench-Tiny` with 100 safe evaluations | v4 model-list/dataset mapping, target/evaluator connectivity and 100-result envelope work | Synthetic target/evaluator; replace with authorized vulnerable/patched model and independently verify ASR | Open |
| AIG terminal error normalization | **PASS locally**: non-MCP/invalid agent/invalid model tasks returned terminal `failed` rather than polling forever; result endpoint’s “not available yet” state consults status | Safe failure contract and no upstream log/token leakage in public result | Timeout/cancellation/incident mapping and durable queue recovery remain open | Open |
| AIG bridge auth/tenant/idempotency negative E2E | **PASS locally**: duplicate key reused task; changed payload returned 409; cross-tenant poll 404; missing auth 401 | Boundary controls are active in the running stack | Durable/shared registry across restart/replicas and full adversarial matrix | Open |
| AIG bridge restart durability E2E | **PASS locally**: task `48639a69-84df-448d-bc19-b6601e1646e9` remained tenant-owned across bridge restart and completed with evidence | Same-host persistent registry prevents restart orphaning | Shared-store/multi-replica semantics and recovery under DB failure | Open |
| AIG bridge liveness/readiness smoke in the built image | **PASS**: `/api/v1/livez` 200 `alive`; `/api/v1/readyz` 503 with unreachable AIG and missing auth | Health endpoints fail closed and distinguish process liveness from AIG readiness | Healthy upstream AIG, signed datasets, scan-to-incident E2E | Re-run against deployed RC / open |
| `node docs/scripts/claim-check.mjs --mode=inventory` | Executes claim scan and hashes every configured connector/dashboard/CLI/SDK release artifact; archive the dynamic counts and hit list from each RC | Claim/evidence drift is observable and release artifact provenance is hashed | Claim approval, legal sign-off or customer validation | Hard NO-GO until registry closes |
The machine-readable commercial/investor registry is [`docs/production-readiness/commercial-go-evidence-registry.json`](./commercial-go-evidence-registry.json). The claim check is [`docs/scripts/claim-check.mjs`](../scripts/claim-check.mjs). In `--mode=gate`, any unapproved release-facing claim, missing claim/artifact root, open hard gate, invalid registry, or license/NOTICE/package conflict exits non-zero. A passing inventory scan is not a release approval.

### 1.3 Locked commercial launch decision

The product decision is now explicit and single-track. The evidence is still open; locking the decision does not turn an unproven capability into a claim.

| Decision | Locked choice | Evidence status |
|---|---|---|
| Launch model | Direct GA | **Open** — all hard gates and same-RC sign-off required |
| Connector scope | All advertised connectors: Claude Code, Cursor, VS Code, OpenClaw and OpenCode | **Open** — real-host matrix, private-registry install, rollback and support proof required for every connector |
| Deployment | Hybrid: local/edge enforcement plus managed control plane; private AIG bridge where enabled | **Open** — tenant routing, outage, privacy, region and broker evidence required |
| Regions | EU, US and APAC tenant placement | **Open** — residency, subprocessors, transfer, backup and deletion evidence required per region |
| Billing | Enterprise invoice / quote-based order; no self-service checkout claim | **Open** — provider-of-record, entitlement, invoice/reconciliation and offboarding rehearsal required |
| Distribution | Authenticated private registry for CLI, SDK, connectors, plugins and signed artifacts | **Open** — signed package, revocation, audit, air-gapped and customer install evidence required |
| Availability commitment | 99.9% monthly availability target for managed control plane and dashboard API | **Open** — approved SLI/SLA, exclusions, maintenance, service credits and measured observation window required |

The machine-readable choices are in [`commercial-go-evidence-registry.json`](./commercial-go-evidence-registry.json). Product, Legal, Privacy/DPO, Finance/Billing, Operations, Security, Support and Customer Success must sign the corresponding evidence rows before any direct-GA, regional, private-registry or 99.9-SLA statement is used externally.

### 1.3.1 Historical launch alternatives — superseded

This historical section is retained only for traceability. It is not an authorized launch path. The locked decision is direct GA with all advertised connectors, hybrid tenancy, EU/US/APAC placement, enterprise invoicing and private-registry distribution. Until every hard gate is closed, the only permitted external posture is a controlled, non-sale evaluation under a signed Evaluation Charter.

---

## 2. Definition of sale-ready

AIDR is sale-ready only when all of the following are true:

### 2.1 Product correctness

- A new customer can discover, authenticate, enroll a device, install a supported connector, receive protection and see an incident without manual database intervention.
- Benign actions are allowed and malicious fixtures are blocked according to documented policy.
- All externally advertised features have traceable implementation and test evidence.
- Unsupported, experimental or incomplete features are hidden or clearly labelled.

### 2.2 Independent testability

- A customer receives an isolated validation tenant and a documented test kit.
- The environment contains deterministic benign and malicious fixtures.
- The customer can execute the test cases without access to internal secrets.
- Expected results, actual results and timestamps are exportable.
- Failed prerequisites stop the evaluation instead of silently skipping tests.

### 2.3 Security

- No open critical production vulnerability exists. A high finding may be accepted only when it is not exploitable in the shipped configuration, compensating controls are tested, an expiry and remediation owner exist, and Product, Engineering and Security approve it; customer-facing legal/privacy impact additionally requires the relevant approver.
- Authentication, authorization, RLS, tenant isolation and secret handling pass negative tests.
- Release artefacts are signed, reproducible and accompanied by an SBOM.
- A third-party penetration test or equivalent independent assessment has no unresolved critical/high finding.

### 2.4 Reliability and operations

- Production SLOs are defined and measured.
- Monitoring, alerting, backup, restore, rollback and incident response are exercised.
- A documented support model and severity SLA exist.
- The product behaves predictably during network, control-plane and AIG outages.

### 2.5 Commercial and legal readiness

- Product claims match tested behavior.
- Licensing, attribution, privacy, data-processing and support terms are reviewed.
- Pricing and entitlements match the actual enforcement model.
- One approved Commercial Release Manifest fixes the SKU, price, metering unit, currency, tax assumptions, minimum commitment, included direct-GA capabilities and explicit exclusions, hybrid deployment model, EU/US/APAC data region, retention, 99.9% SLA, support, licence rights, renewal, cancellation and offboarding terms for the Release Candidate.
- A sample quote-to-offboarding lifecycle succeeds: Order Form to entitlement provisioning, seat change, invoice/reconciliation, cancellation, access revocation, export and deletion receipt.
- Procurement evidence can be supplied without engineering improvisation.

### 2.6 Evidence

- Every release gate produces an immutable or signed artefact.
- The deployed commit, package versions, container digests and test reports refer to the same Release Candidate.
- No final GO decision relies only on screenshots, old audit files or verbal confirmation.

### 2.7 Decision profiles

Readiness is not one ambiguous flag:

| Decision | Meaning | Minimum rule |
|---|---|---|
| Evaluation GO | A named organization may access an isolated synthetic-data sandbox under an Evaluation Charter | G0, G1 and environment/security prerequisites green; no hard evaluation blocker |
| Assisted-sale GO | A contracted customer may use the explicitly scoped assisted product | G0–G8 green for the sold scope; all exclusions written into the Order Form/limitations |
| Production/GA GO | The advertised product may be offered broadly with production data and SLA | All GA capability, security, reliability, support and commercial gates green |

Every gate-registry item must be classified as **hard**, **conditional** or **informational**. Conditional GO is allowed only for P2/P3 defects or capabilities removed from the contractual scope. It is never allowed for a critical vulnerability, tenant-isolation failure, silent omission of a mandatory suite, unknown deployed revision, unrecoverable customer data or falsified evidence.

---

## 3. Scope and support classification

### 3.1 Product components

| Component | Responsibility | Current readiness | Required launch classification |
|---|---|---:|---|
| packages/core | Detection, policy, audit, reputation clients, integrity | Strong foundation, incomplete wiring in advanced modules | GA after critical-path assurance |
| packages/claude-code | Claude Code hooks and MCP tools | Best connector candidate | Primary GA connector |
| packages/extension | Cursor and VS Code hooks/extensions | Partial; real host tests absent | Direct-GA target; hard gate until both host E2E suites pass |
| packages/openclaw | OpenClaw plugin | Partial; real gateway tests skipped | Direct-GA target; hard gate until gateway E2E passes |
| packages/opencode | OpenCode plugin | Partial; real binary tests skipped | Direct-GA target; hard gate until binary E2E passes |
| packages/cli | Setup/status/config experience | Package outputs repaired in working tree; consumer evidence open | Direct-GA distribution after private-registry install and E2E |
| packages/sdk | Universal integration SDK | Package outputs repaired in working tree; consumer evidence open | Direct-GA distribution after private-registry install and ESM/CJS/TS E2E |
| packages/dashboard | Auth, onboarding, agents, incidents, keys, billing | Partial and split across active/orphaned code | GA for proven routes only |
| Supabase functions | Enrollment, reputation, ingest, billing and API operations | Partial and insufficiently contract-tested | GA after fresh-schema and RLS gates |
| AIG bridge and vendor stack | Deep infra/MCP/agent/jailbreak scanning | Infra plumbing verified against Tencent v4.5.1; four-capability/incident/HA proof open | Mandatory hardening before an AIG security claim |
| Threat data | YAML rules, compiled AIG indexes, intel packs | Generated indexes non-empty; source portability, signature and positive fixture open | Versioned, signed, installed-consumer and fixture evidence |
| CI/release | Build, tests, security checks, package publication | Mechanical gates repaired in working tree; RC signing/provenance evidence open | Must be deterministic, signed and blocking |
| Observability | Sentry, logs, metrics, traces, alerts | Code and docs exist; operational proof missing | Mandatory for production |

### 3.2 Feature maturity labels

Every customer-visible feature must carry exactly one maturity label:

- **GA:** Fully supported, contractually claimable, monitored and covered by release gates.
- **Beta:** Testable with known limitations; not subject to full SLA.
- **Experimental:** Internal or design-partner only; no production promise.
- **Hidden:** Present in code but not accessible or marketed.
- **Removed:** Dead or misleading code eliminated from release.

No feature may be sold based solely on file existence.

### 3.3 Direct-GA scope (locked; evidence open)

Mandatory:

- Public landing and login.
- Approved pilot or enterprise tenant creation.
- Device authorization and enrollment.
- Claude Code installation.
- Cursor and VS Code extension installation.
- OpenClaw plugin installation.
- OpenCode plugin installation.
- Local command, URL, file and package protection.
- Audit log and cloud event ingestion.
- Agents and incidents dashboard.
- API key or enrollment-token administration.
- AIG infrastructure and MCP scan.
- Health, observability and incident support.

Conditional evidence gates (not a reduced commercial scope):

- Every connector remains hard-blocked from the direct-GA claim until its real-host E2E, private-registry install, rollback and support evidence passes.
- SDK and CLI remain hard-blocked from distribution until private-registry consumer tests pass for ESM/CJS/TypeScript and supported operating systems.
- Enterprise invoice entitlements remain hard-blocked until the provider-of-record and quote-to-offboarding rehearsal passes.

Not included in the direct-GA claim until completed:

- Federated learning.
- Automatic containment/quarantine/rollback.
- Full connector-wide output scanning.
- Enterprise pages that are not routed.
- Referral and multi-provider billing experiments.
- Unwired behavioral/novelty features.

---

## 4. Historical verified baseline (superseded by the current working-tree evidence in §1.2.1)

### 4.1 Audit commands and outcomes

| Check | Result | Release interpretation |
|---|---|---|
| pnpm install --frozen-lockfile | Completes; AIG postinstall emits zero CVEs/fingerprints and modifies generated files | Fail |
| pnpm quality:gate | Stops at lint | Fail |
| pnpm lint | Invalid Biome configuration | Fail |
| pnpm check from clean state | Core package declarations unresolved in dependent packages | Fail |
| pnpm test | 111 files / 1,910 tests pass | Positive, insufficient alone |
| pnpm test:coverage | Threshold passes | Conditional; only 101 files represented |
| pnpm build:release | Completes | Conditional; package contract failures not detected |
| pnpm test:e2e | Exit 0 | Fail; all 43 executions skipped |
| pnpm knip | Reports 67 unused files and numerous unused exports/dependencies | Fail until classified |
| pnpm audit --prod --audit-level high | 99 findings: 1 critical, 38 high, 55 moderate, 5 low | Fail |
| docker compose config for AIG | Invalid container_name/replicas combination | Fail |
| Live landing HTTP probe | 200 | Positive |
| dashboard.aidr.singularityrd.com DNS probe | Does not resolve | Fail for documented architecture |

### 4.2 Source inventory

| Area | Production files | Approximate lines |
|---|---:|---:|
| Core | 105 | 23,200 |
| Claude Code | 9 | 975 |
| OpenClaw | 11 | 613 |
| OpenCode | 10 | 624 |
| Extension | 11 | 1,347 |
| Dashboard | 46 | 8,688 |
| SDK | 16 | 4,014 |
| CLI | 8 | 386 |
| AIG bridge | 9 | 773 |
| Supabase functions | 21 | 2,507 |
| Scripts | 17 | 2,061 |
| **Total** | **263** | **45,188** |

### 4.3 Hard blocker register

| ID | Blocker | Impact | Closure evidence |
|---|---|---|---|
| P0-001 | Biome configuration is invalid | CI cannot start meaningful validation | Clean lint report on all supported sources |
| P0-002 | Clean typecheck fails due build/dependency ordering | Fresh clone cannot prove compilation | Clean clone typecheck on OS/Node matrix |
| P0-003 | E2E command passes with all tests skipped | False-green release signal | Zero skipped tests; real-host results |
| P0-004 | CLI main/bin artefacts are missing | Customer install cannot work as advertised | Packed tarball installed and executed |
| P0-005 | SDK type declarations and CLI bin are missing | Published SDK contract is broken | ESM/CJS/TS consumer test |
| P0-006 | AIG source is now pinned, but upstream data has case-colliding paths and Windows completeness is not guaranteed | A clean Windows clone can silently omit/alter source data | Linux immutable checkout, `pnpm aig:verify`, signed source/data manifest |
| P0-007 | AIG Compose contract is repaired locally | A future clean checkout could regress the direct-binary/loopback/private-network assumptions | `docker compose config`, healthy server/agent/bridge and RC evidence |
| P0-008 | Infra payload/result contract and all four request/terminal-result contracts are mapped to Tencent v4.5.1; positive detection evidence remains unproven | Unsupported scan types or empty fixtures can fail or mislead during a customer demo | OpenAPI/contract suite plus authorized known-positive/patched evidence for every claimed scan type |
| P0-009 | Generated indexes are non-empty, but signed promotion and a known-positive fixture are absent | Deep-scan claim is not yet defensible as a detection result | Non-zero signed indexes plus vulnerable/patched fixture match |
| P0-010 | AIG bridge/client is wired and benign task E2E passes; result-to-incident path is absent | Findings may not become an actionable AIDR incident/evidence item | Customer-visible scan-to-incident trace with correlation ID |
| P0-011 | Critical/high dependency vulnerabilities | Security/procurement blocker | Zero unwaived critical/high findings |
| P0-012 | Coverage excludes critical files and most sources | “Every line” assurance cannot be claimed | all:true coverage and critical thresholds |
| P0-013 | Live deployment source provenance is unclear | Cannot prove tested code is deployed | Version endpoint and signed deployment manifest |
| P0-014 | Documented dashboard domain does not resolve | Customer path is broken/confusing | DNS, TLS and route probes pass |
| P0-015 | Supabase schemas/functions have competing paths and generated database types drift from migrations | Fresh environment may not match dashboard/runtime | One schema authority, generated-type diff and contract tests |
| P0-016 | Dead, orphaned and placeholder features are present | Misleading claims and security surface | Classify, wire, hide or remove every item |
| P0-017 | Fail-open behavior lacks explicit commercial policy | Security expectations may be violated | Threat model, config and failure tests |
| P0-018 | Licensing metadata is contradictory | Procurement and investment due diligence risk | Counsel-approved license/NOTICE set |
| P0-019 | Supabase cannot be proven from zero: local config is absent and migration version/order collisions exist | Database reset can fail before the initial schema exists | Unique chronological migrations, local config/seed, two consecutive resets, N-1 snapshot migration and restore report |
| P0-020 | Tenant identity is undefined across user- and team-scoped models | VAL-012 has no authoritative isolation boundary | Approved tenancy ADR, immutable tenant_id migration and two-tenant negative matrix across every store |
| P0-021 | Release workflow invokes a missing root release command and can enter publish logic from branch pushes | Untested or unintended artefacts may be published | Protected RC tag-to-promotion pipeline, approvals, immutable digest and rollback/yank drill |
| P0-022 | AIG has no approved trust broker, upload transport or per-task sandbox | Static connector secrets, local paths, SSRF and customer-data leakage are possible | Private broker, short-lived tenant-scoped identity, content-addressed upload, egress sandbox and deletion receipt |
| P0-023 | AIG readiness and packaged dataset behavior can return false healthy/fallback data | Customer sees success while a capability or threat dataset is absent | Per-capability 503 readiness and installed-consumer known-positive test against the exact signed dataset hash |
| P0-024 | Customer privacy claims do not fully describe managed telemetry and AIG payloads | DPA/procurement statements may be inaccurate | Mode-by-mode field-level data-flow map, payload tests, opt-in, retention/location/subprocessor approval |
| P0-025 | Pricing, providers, licence model and packaging differ across repo documents/code | Quote, entitlement and buyer diligence cannot rely on one truth | Signed Commercial Release Manifest and quote-to-offboarding rehearsal |
| P0-026 | Generated artefacts include wall-clock/random metadata | “Reproducible build” cannot be proven by whole-file hash | Deterministic payload hash using SOURCE_DATE_EPOCH/content metadata, separated from attestation metadata |
| P0-027 | Current CI/workflows can modify source/lockfiles and use mutable action/dependency inputs | PR/build provenance is not trustworthy | Read-only PR workflows, pinned actions/images, least privilege and no source synthesis during verification |
| P0-028 | Branch/release conventions disagree (`master` versus `main`/Changesets base branch) | Release PR/publish may target the wrong branch or protection set | One canonical protected branch asserted in CI, workflow, Changesets, docs and origin/HEAD |
| P0-041 | Tencent AIG v4.5.1 has no upstream authentication and hard-codes the worker registration ID; bridge durability is local SQLite only | A public AIG bind or multi-worker/bridge replica can expose or orphan work | Private network/no public AIG port, unique reviewed worker identity, shared transactional task/tenant registry and multi-replica drill |
| P0-042 | No known-positive AIG vulnerable fixture or four-capability scan evidence is archived | A benign completion proves plumbing, not security detection coverage | Versioned vulnerable/patched infra, MCP, agent and jailbreak fixtures with expected findings |
| P0-043 | AIG v4.5.1 depends on an MCP SDK compatibility shim because the published `mcp>=1.23.0` range resolves to SDK 2.x with renamed APIs | An unreviewed dependency refresh can silently break MCP/Agent scans | Lock the supported SDK/shim contract, run the worker-level MCP test, and rebuild the immutable image on every dependency update |
| P0-029 | Artefact manifests are optional/partial and have no mandatory verification/SBOM promotion gate | A tested package can ship unsigned or unverifiable | Sign and verify every shipped package/container/plugin/dashboard artefact; archive SBOM/provenance and fail closed |
| P0-030 | Dashboard deploy script installs unfrozen dependencies and publishes directly without immutable post-deploy proof | Live UI may not match tested RC or be safely rollbackable | Frozen install, digest/version manifest, protected deployment and post-deploy smoke/rollback evidence |
| P0-031 | Claude plugin/marketplace and missing workspace `landing` source have unclear artefact provenance | Customer may install stale or untested content from another source | Source/workspace consistency check plus atomic plugin/landing build, signature and consumer-install evidence |
| P0-032 | Secret scanning depends on a missing/gitignored `.gitleaks.toml` symlink from hidden external state | Clean checkout cannot reproduce the security gate | Versioned sanitized config or immutable injected config/checksum plus full-history CI scan |
| P0-033 | Privacy notices/configuration do not match raw URL, command, path and managed event payload behavior | Buyer may receive false “local-only” or anonymization claims | Field-level mode/payload assertions; omission/HMAC where possible; pseudonymization labelled accurately |
| P0-034 | Sentry, browser tracing and OTLP paths are not uniformly redacted or destination-controlled | URLs, headers, breadcrumbs, reasons or request data may leave the tenant | Outbound allowlist, `sendDefaultPii=false`, complete beforeSend/breadcrumb/request scrubbing and retention/region/subprocessor proof |
| P0-035 | Audit log “immutable” claim conflicts with team-admin DELETE/UPDATE/CASCADE paths and denormalized identity data | Security evidence can be rewritten or erased without a controlled process | Append-only/WORM or signed hash-chain export, break-glass/legal-erasure workflow and verification test |
| P0-036 | Production dashboard links `/pilot` and `/pricing` to routes absent from the live router | Onboarding/first-demo can 404 before protection starts | Deployed-RC browser route/link crawl, no 404/console error, auth returnTo preservation and wire/hide every route |
| P0-037 | Built landing/dashboard UI contains “launch-ready/go live in minutes/central reporting” claims outside approved evidence | A customer sees a sale claim while the release is explicitly NO-GO | Scan built HTML/JS strings against Claim Registry and fail on unapproved launch/all/real-time/automatic copy |
| P0-038 | Onboarding polling has no expiry/cancel/retry contract and enrollment/API secrets render in raw DOM | Evaluator can hang indefinitely or expose credentials on screen-share/DOM | State-machine/expiry/network-recovery tests, one-time masked reveal/copy/expiry controls and screenshot/clipboard redaction policy |
| P0-039 | Browser proof uses MemoryRouter/manual mounts and incident/schema fallbacks can be silent | Tests can pass while deployed routes/actions, schema or mocks fail | Deployed-RC browser smoke/link crawl, visible timestamped errors/retry, no mock/fallback in GA and zero browser console errors |
| P0-040 | Customer-facing support/status/privacy/terms/docs links and reachable ticket path are absent or inconsistent | Buyer cannot obtain help, report an incident or validate contractual support | Visible support/status/legal links, ticket drill with measured SLA and documented diagnostic consent |

### 4.4 P1 blockers

- Output scanning is not consistently wired across connectors.
- Advanced policy/behavioral modules are partially implemented or duplicated.
- Dashboard enterprise modules are not routed.
- CLI, SDK and dashboard have insufficient unit coverage.
- Onboarding expiry, retry and recovery behavior needs proof.
- Marketplace install/update/uninstall paths are not verified.
- Alerting and incident runbooks describe systems that have not been exercised.
- Billing documentation describes both manual/Paddle and multiple experimental provider paths.
- Password recovery, MFA/SSO scope and enterprise access expectations are not settled.
- Release notes, support policy and compatibility matrix are not customer-ready.
- Test discovery has no expected-suite/test-ID manifest, so “zero skipped” could still mean a suite was never collected.
- Performance/SLO targets lack a workload envelope, SLI formula, minimum sample size and error-budget semantics.
- Support/security response targets conflict across current documents.
- Data retention/deletion/region/subprocessor coverage is incomplete for event/webhook/waitlist payloads, local artifacts, telemetry and backups.
- Customer documentation still contains non-RC marketplace/source-checkout steps, branch/platform-count drift and broken relative links.
- Dashboard accessibility/mobile navigation and raw JSON/secret presentation need a real-browser/assistive-technology proof, not MemoryRouter page mounts.
- Current delivery estimates are not defensible before the AIG/upstream, schema, vulnerability and external-assessment discovery spikes finish.

---

## 5. Readiness gate model

A version-controlled gate registry is the machine-readable source of truth. For every requirement it records: gate ID, decision profile, hard/conditional/informational class, scope, owner, expected evidence, automated check, current result, waiver ID and expiry. CI must include a negative control proving that an intentionally broken hard requirement stops promotion.

### Gate G0 — Scope and claim freeze

Required:

- GA/Beta/Experimental/Hidden classification completed.
- First-sale package and supported platform matrix approved.
- Marketing claims mapped to testable requirements.
- Claim Registry covers repository docs, live sites, sales material, email templates, investor deck and data room; superseded material is labelled and cannot be externally shared.
- Commercial Release Manifest and customer-facing privacy data-flow matrix are drafted.
- Billing decision recorded: enterprise invoice/quote-based direct-GA; self-service checkout is out of scope for this Release Candidate.
- Fail-open/fail-closed semantics approved by Product and Security.

Evidence:

- Signed feature scope.
- Claim-to-evidence matrix.
- Published limitations draft.

### Gate G1 — Reproducible build

Required:

- Clean clone install succeeds without tracked changes.
- Lint, typecheck and build pass.
- Lockfile is deterministic.
- Generated threat data is reproducible.
- Every package contract path exists.
- CI is read-only on PRs, least-privileged and uses immutable action/image/dependency inputs.
- Release uses a protected RC tag/environment, builds an artefact once, verifies its digest/signature/SBOM/provenance, promotes that same digest and proves rollback/yank.
- The expected-test manifest matches discovery and execution; a missing suite, host, credential or binary is a setup failure rather than a skip.

Evidence:

- CI run URLs.
- Build logs.
- Reproducibility hashes.
- Package consumer-test report.

### Gate G2 — Product golden path

Required:

- Authentication and tenant creation work.
- An approved tenancy ADR defines the immutable boundary used by auth, API keys, enrollment, billing, events, exports and AIG tasks.
- Unique ordered migrations create the database from zero twice and migrate an N-1 production-like snapshot to the Release Candidate.
- Device authorization and enrollment work.
- Primary connector installs.
- Benign and malicious test cases behave correctly.
- Events reach the dashboard.
- Incident evidence is exportable.
- Every customer-visible href/declared route reaches a real page on the deployed RC; pilot/pricing/auth returnTo flows do not 404.
- Browser smoke runs against the deployed RC (not only MemoryRouter mounts), with zero console errors, visible retry/error states and no mock/fallback data in GA.

Evidence:

- Automated golden-path E2E report.
- Video recording.
- Correlated logs/traces.

### Gate G3 — AIG integration

Required:

- Stack deploys reproducibly.
- AIG is private behind a control-plane job broker or equivalent short-lived tenant-scoped service identity; connectors contain no reusable bridge secret.
- All four scan types satisfy the API contract.
- Upload/source scans use content-addressed tenant sandboxes; host paths and arbitrary egress are rejected.
- CVE/fingerprint data is non-empty, signed, fresh and present in the packed/installed runtime; fallback or empty data makes readiness fail.
- `/livez` is process liveness and `/readyz` returns 503 unless the requested capability, worker, DB/queue, model/provider and signed dataset are ready.
- AIG findings are represented in AIDR incidents/policies.
- Security, readiness and outage behavior pass.

Evidence:

- AIG contract report.
- Positive/negative scan reports.
- Container digests and SBOM.
- Failure-mode report.

### Gate G4 — Security and privacy

Required:

- Threat model approved.
- SAST/SCA/secrets/container/DAST gates pass.
- RLS and tenant isolation tests pass.
- Tenant isolation passes across DB, object storage, AIG tasks/uploads/results, queues/caches, telemetry, exports, enrollment/API keys and JIT support access.
- Privacy inventory, outbound-domain manifest, opt-in, retention, export/deletion and real-payload assertions match customer-facing notices; Sentry/OTLP and browser tracing are included.
- Audit immutability, break-glass erasure, local-file ACLs, webhook/waitlist TTLs and all processor deletion/region receipts are verified.
- External security assessment has no unresolved critical/high item.

Evidence:

- Security report bundle.
- Signed risk exceptions, if any.
- Data-flow diagram and data inventory.

### Gate G5 — Reliability and operations

Required:

- SLOs are measured.
- Each SLO has an SLI formula, workload envelope, measurement window, exclusions, minimum sample, error budget and burn-rate alert; pre-release acceptance budgets are separate from post-launch monthly SLOs.
- Load, soak and resilience tests pass.
- Dashboards and alerts are active.
- Numeric per-data-class RPO/RTO, backup/key recovery, clean-account restore and rollback are rehearsed with reconciliation.
- Named vendor-outage and emergency kill-switch BCP procedures are exercised.
- On-call and support routing are operational.

Evidence:

- Performance report.
- Alert screenshots/test events.
- Restore and rollback exercise reports.

### Gate G6 — Customer validation

Required:

- Isolated customer validation environment is ready.
- Customer test kit is complete.
- At least one internal red-team session passes.
- A signed Evaluation Charter fixes scope, Release Candidate, tests, thresholds, permitted support, data/recording rules, stop conditions, defect/retest process and customer decision roles.
- A guided session is followed by a 2–5 business-day independent sandbox/PoV.
- Mandatory scenarios pass 100%, there is no P0/P1, no hidden reset/deploy/DB intervention occurs, all assistance is logged and the customer signs the result and reservations.
- Secret display, clipboard, screen-share and DOM redaction behavior is demonstrated; support/status/contact paths and the ticket drill are customer-visible.

Evidence:

- Customer scorecard.
- Defect closure report.
- Acceptance record.

### Gate G7 — Commercial/legal

Required:

- Pricing, entitlement and contract claims match implementation.
- The Commercial Release Manifest is approved and a sample Order Form passes quote-to-entitlement, seat change, invoicing/reconciliation, cancellation, revocation, export and deletion.
- License/NOTICE, IP chain-of-title, privacy, DPA/SCC/TOM, subprocessor/data-residency, MSA/Order Form, SLA/support, BCP/DR and vulnerability-disclosure terms are approved.
- Security questionnaire and procurement pack are ready.
- Sales scripts contain no unsupported claim.

Evidence:

- Approved commercial pack.
- Legal sign-off.
- Sales enablement checklist.

### 5.7 Commercial/investor hard-stop evidence matrix

The following are hard gates, not documentation tasks. An engineer cannot close them with a screenshot, source file, unit test, roadmap item, verbal assurance or a successful build. Each row must be closed for the same Release Candidate with an immutable evidence record and the named approver. Until then, the relevant sale or investor claim is blocked.

| Registry ID | Domain | Current status | Required external evidence | Non-waivable condition |
|---|---|---|---|---|
| COM-001 | Commercial Release Manifest | Open | Approved SKU/price/meter/currency/tax/deployment/region/retention/SLA/support/licence/renewal/offboarding manifest; quote-to-offboarding rehearsal | No quote or pricing claim may be treated as final without the manifest |
| COM-002 | Licensing/IP | Open | Counsel-approved LICENSE/NOTICE/package matrix, attribution, source/vendor provenance and chain-of-title; non-empty LICENSE | One-byte/contradictory metadata is a legal hard stop |
| COM-003 | Privacy/DPA | Open | Field-level managed/AIG/telemetry/browser payload map, outbound domains, retention/deletion/region/subprocessors, DPA/TOM/SCC and deletion receipt | “Local-only”, anonymization or no-data-leaves-device claims are blocked until proven |
| COM-004 | Billing/entitlements | Open | Provider-of-record, SKU/entitlement tests, invoice/reconciliation, seat change, cancellation, revocation, export and deletion evidence | Invoiced capability/price must match enforcement |
| COM-005 | Support/operations | Open | Published support schedule/SLA, visible status/security/privacy/terms/docs links, reachable ticket drill with timestamps and escalation | Customer cannot be sold a support promise that has not been exercised |
| SEC-EXT-001 | Independent security | Open | Independent pentest/equivalent report scoped to the RC, remediation and retest letter, expiry-controlled exceptions | Unresolved critical is never waivable; high needs approved non-exploitability evidence |
| POV-001 | Customer validation | Open | Signed Evaluation Charter, independent synthetic-data sandbox/PoV, mandatory scenarios, intervention/deviation log, customer result and reservations | Source tests cannot substitute for an external acceptance record |
| INV-001 | Investor metrics | Open | Metric dictionary with formula/denominator/source/RC/window/sample/owner/reviewer/limitation and approved source records | Unverified traction, compliance, customer or performance claims stay out of the data room |
| CLM-001 | Claim approval | Open | Claim Registry, release-facing build scan JSON/hash, claim-to-evidence links and Sales/Legal approval | `claim-check --mode=gate` must be zero-unapproved for the release scope |

The live state is tracked in [`commercial-go-evidence-registry.json`](./commercial-go-evidence-registry.json). The registry intentionally records these rows as `open`; changing a status to `closed` without the required external record is falsified evidence and itself a non-waivable NO-GO.

### Gate G8 — Final sale authorization

Required:

- All hard gates are green for the same Release Candidate.
- Two complete dress rehearsals pass from reset environments.
- Rollback candidate is available.
- Product, Engineering, QA, Security, Operations, Commercial/Sales, Legal, Privacy/DPO, Finance/Billing and Support/Customer Success sign the applicable release record.

No single role may waive a gate. Critical vulnerabilities, tenant-isolation failures, mandatory-suite omission, unknown deployed revision, failed customer-data recovery and falsified evidence are non-waivable.

---

## 6. Validation environment architecture

### 6.1 Environment tiers

| Environment | Purpose | Data | Access | Deployment policy |
|---|---|---|---|---|
| Local developer | Fast unit/debug loop | Synthetic only | Engineers | Mutable |
| Ephemeral CI | Per-PR automated tests | Generated fixtures | CI identity | Destroy after run |
| Integration | Shared service contracts | Synthetic | Engineering/QA | Auto-deploy from main |
| Staging | Production-like release rehearsal | Synthetic + approved test accounts | Internal | Release Candidate only |
| Customer validation | Independent buyer/investor testing | Dedicated synthetic tenant | Customer + observers | Immutable during session |
| Production | Paying users | Real customer data | Least privilege | Signed release only |
| DR | Restore and continuity tests | Encrypted replicas | SRE/Security | Isolated |

### 6.2 Customer validation topology

~~~mermaid
flowchart LR
    Tester["Customer or investor tester"]
    Browser["Validation dashboard"]
    Workstation["Isolated test workstation"]
    Connector["AIDR connector"]
    Core["AIDR core"]
    Supabase["Validation Supabase project"]
    Functions["Edge functions and control plane"]
    Broker["Tenant-scoped AIG job broker"]
    Uploads["Content-addressed upload store"]
    Bridge["Private authenticated AIG bridge"]
    AIG["Pinned AIG scanner stack"]
    Fixtures["Safe validation fixtures"]
    Observability["Logs, metrics, traces and evidence store"]

    Tester --> Browser
    Tester --> Workstation
    Workstation --> Connector
    Connector --> Core
    Core --> Functions
    Browser --> Supabase
    Functions --> Supabase
    Functions --> Broker
    Functions --> Uploads
    Broker --> Bridge
    Bridge --> Uploads
    Bridge --> AIG
    AIG --> Fixtures
    Core --> Observability
    Functions --> Observability
    Bridge --> Observability
    Browser --> Observability
~~~

### 6.3 Required isolation

- Use a separate Supabase project for customer validation.
- Use separate OAuth applications and redirect URLs.
- Use separate AIG databases, volumes, agent workers and API keys.
- Use separate Sentry project/environment and log index.
- Use a dedicated DNS zone or subdomain.
- Use a separate cloud account/project or equivalent hard resource boundary where practical; record the selected provider, region and data-residency decision in an ADR.
- Do not reuse production service-role keys.
- Do not expose internal admin credentials to evaluators.
- Keep AIG bridge/worker/DB/queue private; only the control plane/job broker may reach them using workload identity, mTLS or short-lived audience/scope-bound credentials.
- Restrict scanner egress with an allowlisting proxy and explicitly block loopback, RFC1918, link-local, metadata, DNS-rebinding and redirect escape paths unless a signed test scope requires a dedicated isolated target.
- Run each untrusted upload/scan in a tenant/job sandbox with CPU, memory, time, file-count, archive-depth and decompression limits.
- Create one tenant per evaluating organization.
- Destroy or archive the tenant according to agreed retention after the test.
- Expire evaluator accounts automatically and produce resource-destroy/data-deletion receipts.
- Require MFA and just-in-time, reason-coded access for support/admin intervention; preserve tamper-evident audit records.
- Prevent cross-tenant queries with RLS and explicit negative tests.

### 6.4 Suggested validation endpoints

Names are illustrative and must be created through infrastructure-as-code:

- validation.aidr.singularityrd.com
- api.validation.aidr.singularityrd.com
- status.validation.aidr.singularityrd.com

The AIG bridge must not have a public evaluator endpoint. If a private service name is required, it belongs to the private service-discovery zone and is reachable only from the broker identity. Before provisioning, an infrastructure ADR must name the hosting platform, Supabase lifecycle, DNS/TLS/WAF, AIG orchestrator, network/egress rules, secrets manager, region, observability stores and teardown mechanism.

### 6.5 Environment manifest

Every environment must publish a machine-readable manifest containing:

- Environment name.
- Git commit SHA.
- Release Candidate identifier.
- Package versions.
- Dashboard build identifier.
- Supabase migration version.
- Authoritative tenant-model/tenancy ADR version.
- Edge Function versions.
- Threat-rule version and hash.
- AIG source revision.
- AIG data version and CVE/fingerprint counts.
- Container image digests.
- Upload/fixture manifest hashes.
- Expected and discovered mandatory suite/test counts.
- Cloud provider, region and data-residency classification.
- Deployment timestamp.
- Feature flags.
- Supported connector versions.

The manifest must contain no secret.

### 6.6 Secrets

- Store secrets in the platform secret manager, never committed files.
- Use separate secrets per environment and service.
- Rotate validation secrets before each external evaluation.
- Redact tokens, API keys, authorization headers and uploaded content from logs.
- Pass secret references to AIG jobs; do not place raw LLM/API tokens in task payloads, URLs or persisted job state.
- Use short-lived evaluator access.
- Log secret access and administrative changes.
- Test missing, expired and revoked secrets.

### 6.7 Data reset

Provide an idempotent reset operation that:

- Deletes the previous validation tenant.
- Recreates users, roles and entitlements.
- Seeds deterministic agents, events and fixtures.
- Resets AIG tasks and scan data.
- Clears caches and local managed state.
- Rotates enrollment codes.
- Produces a reset receipt with timestamp and seed version.

Reset must never accept a production project identifier.

---

## 7. Validation data and fixtures

### 7.1 Fixture principles

- Fixtures must be safe to execute in an isolated environment.
- Do not depend on live malicious infrastructure.
- Expected verdicts must be version controlled.
- Every fixture requires an owner, category, severity and rationale.
- Positive and negative variants must exist.
- Fixtures must be deterministic and resettable.
- Customer-visible examples must not expose proprietary threat signatures unnecessarily.

### 7.2 Required fixture sets

**Commands**

- Benign shell operations.
- Pipe-to-shell simulations that do not execute external payloads.
- Obfuscated command variants.
- Persistence attempts against disposable paths.
- Credential-access patterns using fake secrets.
- Platform-specific Windows/macOS/Linux variants.

**URLs**

- Trusted first-party fixture domain.
- Known blocked synthetic domain.
- Redirect chain.
- Unicode/punycode domain.
- Encoded IP and loopback/metadata SSRF forms.
- Offline/timeout endpoint.

**Files**

- Benign project file.
- Fake environment file with synthetic API keys.
- Sensitive-path fixture.
- Path traversal and symlink cases.
- Oversized file and binary file.

**Packages**

- Known good npm/PyPI fixture.
- Nonexistent package.
- New package.
- Typosquat fixture.
- Package with synthetic malicious install script.
- Registry unavailable/timeout.

**Plugins and MCP**

- Clean plugin.
- Plugin containing a safe malicious-pattern fixture.
- MCP server with benign tools.
- MCP server with command-injection fixture.
- MCP server with prompt-injection fixture.
- MCP server with data-exfiltration fixture.
- MCP auth failure and timeout cases.

**AIG infrastructure**

- Known vulnerable container/image or mocked service with an expected CVE.
- Patched counterpart.
- Unreachable target.
- Slow target.
- Malformed target.
- Multiple-target scan.

**Agent and jailbreak**

- Deterministic agent endpoint.
- Prompt-injection test set.
- Prompt-leak fixture.
- Role-play bypass fixture.
- Safe refusal baseline.

### 7.3 Expected-result schema

Each fixture record must include:

- fixture_id
- fixture_version
- product_area
- input_reference
- expected_verdict
- expected_rule_or_finding
- expected_severity
- maximum_latency_ms
- privacy_classification
- supported_platforms
- cleanup_action
- evidence_requirements

---

## 8. Workstream WS0 — Governance, scope and claims

Owner: Product Owner
Approvers: Engineering Lead, Security Lead, Sales Lead

### Tasks

- [ ] Inventory every feature and claim visible in repository docs, landing/dashboard, live sites, README, pitch/investor decks, sales scripts/email, procurement answers and data-room documents.
- [ ] Match each feature to source modules and runtime entry points.
- [ ] Assign GA/Beta/Experimental/Hidden/Removed status.
- [ ] Create the Claim Registry with exact claim text, audience, scope, maturity, Release Candidate, evidence, owner, review/expiry date and `Sales Approved` status.
- [ ] Label historical/strategy material “not a current product claim”; archive superseded price, domain, compliance and architecture statements.
- [ ] Add CI scans for banned/expired claims, old prices/domains and unearned certification language.
- [ ] Scan built landing/dashboard/plugin HTML/JS strings and UI copy, not only Markdown/sales files; reject unapproved “launch-ready”, “go live in minutes”, “all”, “real-time” or “automatic” claims.
- [ ] Decide the first-sale connector scope.
- [ ] Document the enterprise-invoice provider-of-record, entitlement lifecycle and private-registry access; self-service checkout remains out of scope unless the locked decision is formally changed.
- [ ] Approve the Commercial Release Manifest and one quote-to-offboarding test case.
- [ ] Decide whether API keys are fallback-only or a supported primary flow.
- [ ] Define fail-open/fail-closed behavior by operation and customer tier.
- [ ] Define offline grace behavior.
- [ ] Define data sent to the control plane.
- [ ] Define AIG scan data locality and retention.
- [ ] Approve a mode-by-mode privacy matrix for local, managed, telemetry and each AIG scan type.
- [ ] Remove or rewrite unsupported “comprehensive”, “all”, “real-time” or “automatic” claims.
- [ ] Create the claim-to-evidence matrix.
- [ ] Approve the customer-facing known-limitations document.

### Exit criteria

- Every external claim has an evidence owner.
- No Experimental/Hidden feature appears in standard sales material.
- Sales and Engineering use the same support matrix.
- Only versioned `Sales Approved` material may be shared externally.

---

## 9. Workstream WS1 — Build, CI and release integrity

Owner: Build/Platform Engineer
Approvers: Engineering Lead, QA Lead

### Clean-build tasks

- [ ] Fix Biome configuration for the pinned Biome version.
- [ ] Expand lint scope to TypeScript, TSX, scripts and relevant config.
- [ ] Add Python lint/format/type checks for the AIG bridge.
- [ ] Correct workspace build/typecheck ordering.
- [ ] Ensure core declarations are available before dependent typechecks.
- [ ] Ensure postinstall does not modify tracked files.
- [ ] Define reproducible payload hashes independently from signed attestation timestamps; use SOURCE_DATE_EPOCH or content-derived generation metadata.
- [ ] Fail build when AIG source/data are required but absent.
- [ ] Pin Node and pnpm versions consistently across CI/release/docs.
- [ ] Test supported Node versions explicitly.
- [ ] Validate package manager build-script allowlist.
- [ ] Choose one canonical protected release branch and assert it against origin/HEAD, workflow triggers, Changesets config, docs and branch protection.
- [ ] Add a source/workspace consistency check: every listed workspace has a tracked source directory or an explicit external provenance record.

### CI tasks

- [ ] Split quality gate into visible jobs: lint, typecheck, unit, coverage, contract, E2E, package, security, build.
- [ ] Make all required jobs branch-protection checks.
- [ ] Fail if any required suite reports skipped/todo tests.
- [ ] Maintain an expected capability/test manifest by GA/Beta platform cell and assert discovered = expected, executed = expected and mandatory skipped = 0.
- [ ] Treat a missing host binary, credential, fixture, test file or environment prerequisite as setup failure in release runs.
- [ ] Preserve first-attempt results; do not let retries hide flakiness, and allow no flaky test in a release suite.
- [ ] Include dashboard TSX tests.
- [ ] Include Python tests.
- [ ] Include Supabase schema and Edge Function tests.
- [ ] Include AIG Compose validation.
- [ ] Include package tarball/VSIX consumer tests.
- [ ] Include deployed-RC browser smoke/link crawl, accessibility/axe and browser-console assertions; manual page mounts do not satisfy the route gate.
- [ ] Include knip/dead-code classification.
- [ ] Include duplicate-code report with an agreed threshold.
- [ ] Upload JUnit, coverage, security and package reports.
- [ ] Add CI concurrency and cancellation rules.
- [ ] Sign and verify every shipped package, container, VSIX/plugin, dashboard bundle and deployment manifest; signing must fail closed when a key/identity is missing.
- [ ] Generate and verify SBOM/provenance for each shipped artefact, not only core/SDK manifests.
- [ ] Isolate/disable documentation and analytics workflows that synthesize source, modify lockfiles or auto-push during verification; run generated-output checks in a separate controlled job.
- [ ] Assert the root release command exists and is the only publish entry point; fail closed when a workflow calls an undefined script.
- [ ] Add Windows, Ubuntu and macOS matrix where runtime behavior differs.
- [ ] Add Node 20, 22 and 24 compatibility matrix or narrow the published engine range.
- [ ] Inventory every workflow; make PR verification read-only, forbid source/lockfile synthesis and automatic push from verification jobs.
- [ ] Pin GitHub Actions by full commit SHA, set explicit least-privilege permissions and prove untrusted PRs cannot access publish credentials.
- [ ] Replace branch-push publication with protected RC tag/environment approval and trusted publishing/OIDC where supported.
- [ ] Build once, verify once and promote the same immutable digest through registry staging/dist-tag; test rollback, deprecation and yank.

### Package contract tasks

- [ ] Verify every main/module/types/exports/bin target exists.
- [ ] Pack each npm package.
- [ ] Install each tarball in a fresh consumer project.
- [ ] Run ESM import.
- [ ] Run CommonJS require where advertised.
- [ ] Compile a TypeScript consumer.
- [ ] Execute every CLI bin with --help and a smoke command.
- [ ] Verify executable bit/shebang, npm `files` allowlist, lifecycle behavior with scripts disabled, Node engine matrix and package install from the target registry.
- [ ] Scan packed contents for secrets, licence/NOTICE, source maps and unintended internal files.
- [ ] Pin `vsce`/`ovsx` versions in a reviewed lockfile or build container; record marketplace publisher metadata, uploaded artefact digest/signature and promotion result.
- [ ] Resolve the private Claude package’s declared `health.cjs` bin contract: remove it if internal-only or ship/test it in the signed plugin/tarball consumer flow.
- [ ] Build and install Cursor VSIX.
- [ ] Build and install VS Code VSIX.
- [ ] Verify extension activation and uninstallation.
- [ ] Verify package contents contain required threat/allowlist assets.
- [ ] Verify no workspace dependency reference leaks into published packages.
- [ ] Verify artefact manifest signatures.
- [ ] Generate SBOM and provenance attestation.
- [ ] Assert every expected shipped artefact root exists before leak/source-map/signature/SBOM scans; missing directories are failures, not empty success.
- [ ] Make leak/source-map scanners deterministic and unit-tested (no global-regex state leakage); cover CLI, SDK, connectors, dashboard, plugin, containers and deployment manifests.
- [ ] Build and install the root Claude plugin/marketplace artefact atomically with its referenced `dist`, signature and consumer smoke test; reject stale/mismatched plugin manifests.
- [ ] Test dashboard deployment from the exact RC with frozen dependencies, version/digest manifest, post-deploy smoke and rollback evidence.

### Exit criteria

- Fresh clone to signed artefact is one deterministic pipeline.
- Package consumer tests pass outside the monorepo.
- No green release can contain missing entry points.

---

## 10. Workstream WS2 — Core correctness and “every line” assurance

Owner: Core Engineering Lead
Approvers: QA Lead, Security Lead

The assurance unit is not a raw line. It is a shipped file and decision path with traceability. Create a signed Source Assurance Ledger containing: file path and hash, package, classification, runtime entry/reverse dependency, customer claim, threat/decision paths, owner/reviewer, unit/property/fuzz/mutation/E2E IDs, coverage result, manual-review record, shipped artefact and waiver/expiry. Generated and external files need provenance and contract checks; dead/experimental files must not silently ship.

### Source classification

- [ ] Enumerate all 263 production files.
- [ ] Mark each as active, generated, external, dead or experimental.
- [ ] Identify runtime entry points and reverse dependency paths.
- [ ] Remove dead files or explicitly exclude them from shipped artefacts.
- [ ] Add owners for every active security-critical module.
- [ ] Generate and diff the Source Assurance Ledger on every Release Candidate; fail on an unclassified shipped file or claim without an entry point/evidence chain.

### Static correctness

- [ ] Enable strict TypeScript checks consistently.
- [ ] Resolve implicit any and unused-code warnings.
- [ ] Consolidate policy.ts and policy-engine.ts or document distinct contracts.
- [ ] Remove unsafe module-level mutable state in critical paths.
- [ ] Validate all configuration schemas.
- [ ] Validate all external responses before use.
- [ ] Audit exception handling and fallback verdicts.

### Coverage policy

- [ ] Configure coverage to include all active source files, not only imported files.
- [ ] Remove blanket exclusions for evaluator, managed, session-start, control-plane and integrity.
- [ ] Require 100% line and branch coverage for critical policy/auth/integrity decision code.
- [ ] Require at least 90% line and 80% branch coverage for other active modules.
- [ ] Require documented waivers for genuinely unreachable defensive branches.
- [ ] Publish per-package and changed-lines coverage.

Coverage and mutation thresholds are provisional risk targets until the critical-module list, mutation tool/configuration, equivalent-mutant adjudication process and baseline are approved. Thresholds may be raised, but may not replace threat, contract or E2E evidence.

### Advanced assurance

- [ ] Run mutation testing on evaluator, engine, policy, extractors, auth and AIG mapping.
- [ ] Require at least 85% mutation score for critical modules.
- [ ] Add property-based tests for URL, command and path normalization.
- [ ] Add fuzz tests for JSON/stdin hook inputs.
- [ ] Add fuzz tests for YAML threat rules.
- [ ] Add Unicode, null-byte, encoding and large-input cases.
- [ ] Test cache poisoning and cross-artifact allowlist smuggling.
- [ ] Test race conditions in approval and cache stores.
- [ ] Test corrupted local state and atomic recovery.
- [ ] Test time skew, expiry and revocation.

### Manual review

- [ ] Perform two-person review of every allow/block decision path.
- [ ] Review fail-open paths against the approved threat model.
- [ ] Review secret and PII redaction.
- [ ] Review filesystem operations and permissions.
- [ ] Review remote update/signature verification.

### Exit criteria

- Every active source file is accounted for.
- Critical mutation/coverage thresholds pass.
- No unreviewed fail-open path exists.

---

## 11. Workstream WS3 — Connector validation

Owner: Connector Engineering Lead
Approvers: QA Lead

### Shared requirements

- [ ] All connectors use the same core version and threat dataset.
- [ ] Tool input mapping is documented and contract-tested.
- [ ] Allow/ask/deny results are consistent.
- [ ] Audit records have consistent schema and correlation IDs.
- [ ] Enrollment and managed-state behavior is consistent.
- [ ] Offline behavior is tested.
- [ ] Install, upgrade, downgrade, disable and uninstall are tested.
- [ ] Unsupported host versions fail with actionable messages.
- [ ] Exercise emergency-disable/kill-switch and known-good re-release/pin for extension and Claude marketplace artefacts; unpublish alone is not rollback evidence.
- [ ] Every advertised cell records OS build, x64/arm64 architecture, shell, locale, filesystem/permission model, proxy/TLS-interception behavior and host auto-update policy.
- [ ] Paths with spaces/Unicode, WSL/remote-container behavior and restricted corporate endpoints are either tested or explicitly unsupported.

### Claude Code

- [ ] Marketplace install from a clean machine.
- [ ] Hook registration validation.
- [ ] PreToolUse allow/ask/deny.
- [ ] PostToolUse/output scanning.
- [ ] Session-start plugin scan.
- [ ] MCP approval tools.
- [ ] Device enrollment.
- [ ] Invalid stdin and process crash recovery.
- [ ] Real Claude Code E2E with controlled credentials.

### Cursor

- [ ] VSIX installation in supported Cursor versions.
- [ ] Extension activation.
- [ ] Managed hook installation.
- [ ] Hook health command.
- [ ] Allow/deny result enforcement.
- [ ] Scope setting behavior.
- [ ] Update and uninstall cleanup.
- [ ] Real Cursor host E2E.

### VS Code

- [ ] VSIX installation in supported VS Code versions.
- [ ] Extension activation and command registration.
- [ ] Managed hook behavior.
- [ ] Windows/macOS/Linux path handling.
- [ ] Update and uninstall cleanup.
- [ ] Real VS Code extension-host E2E.

### OpenClaw

- [ ] npm install and plugin registration.
- [ ] Gateway startup.
- [ ] before_tool_call enforcement.
- [ ] Approval tool flow.
- [ ] Plugin scanning.
- [ ] Real model/gateway E2E.
- [ ] Gateway restart and cache behavior.

### OpenCode

- [ ] npm/local install strategy is finalized.
- [ ] Plugin configuration.
- [ ] Tool mapping.
- [ ] Approval/allowlist tools.
- [ ] Session plugin scan.
- [ ] Real OpenCode binary E2E.

### Connector support matrix

| Connector | OS | Architecture | Runtime/host | Corporate network | Initial status |
|---|---|---|---|---|---|
| Claude Code | Advertised Windows/macOS/Ubuntu builds | x64 and arm64 where offered | Explicit Node/host current + previous list | Direct and supported proxy/TLS mode | GA candidate |
| Cursor | Advertised supported OS builds | Explicit list | Explicit Cursor list | Supported proxy/TLS mode | Direct-GA target; hard until pass |
| VS Code | Advertised Windows/macOS/Ubuntu builds | Explicit list | Current + previous VS Code | Supported proxy/TLS mode | Direct-GA target; hard until pass |
| OpenClaw | Explicit supported builds | Explicit list | Explicit gateway/model list | Supported proxy/TLS mode | Direct-GA target; hard until pass |
| OpenCode | Explicit supported builds | Explicit list | Explicit binary list | Supported proxy/TLS mode | Direct-GA target; hard until pass |

### Exit criteria

- No connector suite is skipped.
- Every GA connector passes on every advertised OS/host version.
- Beta labels and limitations are visible to customers.

---

## 12. Workstream WS4 — Supabase, dashboard and control plane

Owner: Platform/Backend Lead
Approvers: Frontend Lead, Security Lead, QA Lead

### Database

- [ ] Select one authoritative schema path.
- [ ] Add a repository-tracked local Supabase configuration and synthetic seed; CI must not depend on an undocumented remote project.
- [ ] Give every migration a unique, chronological identifier and order; prove no migration alters a table before its creation.
- [ ] Convert package-local SQL files into ordered migrations or retire them.
- [ ] Resolve competing users, subscriptions, entitlements and seat models.
- [ ] Run database reset from zero twice in CI to prove deterministic/idempotent setup.
- [ ] Generate database.types.ts from the resulting schema.
- [ ] Fail CI when generated types differ.
- [ ] Add indexes for validated query patterns.
- [ ] Add migration rollback/forward strategy.
- [ ] Test migration from an N-1 production-like schema/data snapshot to RC, including forward repair or clean-account restore when DDL rollback is unsafe.
- [ ] Reconcile table/column/function inventories between generated types, migrations and deployed schema; fail on either missing or orphaned objects.

### Tenancy ADR

- [ ] Decide whether the immutable isolation boundary is organization/team or individual user; document ownership, membership and lifecycle semantics.
- [ ] Add one immutable `tenant_id` contract to users/memberships, API keys, enrollment/device state, agents, events/incidents, billing/entitlements, exports and every AIG job/upload/result.
- [ ] Define migration/backfill and uniqueness rules for existing user-scoped data.
- [ ] Define 404-versus-403 behavior without leaking object existence.
- [ ] Version the ADR and make VAL-012 expected results derive from it.

### RLS and tenant isolation

- [ ] Enable RLS on every customer-data table.
- [ ] Test owner access.
- [ ] Test cross-user denial.
- [ ] Test cross-team denial.
- [ ] Test admin/service-role paths.
- [ ] Test deleted/disabled user access.
- [ ] Test invitation and membership changes.
- [ ] Test storage bucket policies if file uploads are used.
- [ ] Test object storage, AIG tasks/results/uploads, queue/cache keys, telemetry, exports, API/enrollment keys and support/admin tooling—not only SQL tables.
- [ ] Require MFA, just-in-time elevation, reason and immutable audit for support access.

### Edge Functions

- [ ] Inventory every dashboard functions.invoke call.
- [ ] Inventory every deployed/tracked Edge Function.
- [ ] Implement, remove or hide missing functions.
- [ ] Validate environment variables at startup.
- [ ] Require authentication except explicitly public endpoints.
- [ ] Validate origins and CORS.
- [ ] Apply consistent rate limiting.
- [ ] Add request/response schemas.
- [ ] Add idempotency for enrollment, ingest and webhooks.
- [ ] Add contract tests against local Supabase.
- [ ] Add deployment version metadata.

### Authentication

- [ ] GitHub OAuth.
- [ ] Google OAuth if marketed.
- [ ] Magic link if marketed.
- [ ] Callback allowlist and returnTo validation.
- [ ] Session refresh and expiry.
- [ ] Logout and token revocation.
- [ ] Account disabled/deleted state.
- [ ] Password recovery only if password auth is offered.
- [ ] MFA/SSO either implemented or explicitly out of scope.

### Device authorization

- [ ] Start request.
- [ ] Short code uniqueness.
- [ ] Single use.
- [ ] Expiry.
- [ ] Brute-force/rate-limit protection.
- [ ] Approval by correct tenant/user.
- [ ] Polling intervals and timeout.
- [ ] Enrollment token issuance.
- [ ] Hash-only server storage.
- [ ] Revocation.
- [ ] Offline grace.
- [ ] Re-enrollment after device reset.

### Dashboard

- [ ] Route inventory matches shipped features.
- [ ] Remove or wire orphaned enterprise/billing/referral pages.
- [ ] Crawl every internal href/declared route on the deployed RC, including `/pilot`, `/pricing`, auth returnTo and error links; fail on 404, redirect loop, missing auth state or console error.
- [ ] Loading, empty, error and retry states on every active page.
- [ ] Pagination for agents/events/incidents.
- [ ] Accessible forms, focus, labels and keyboard behavior.
- [ ] Responsive desktop and minimum supported viewport.
- [ ] Browser matrix: Chrome, Edge, Firefox, Safari.
- [ ] Sentry release correlation.
- [ ] CSP, security headers and cache policy.
- [ ] Source maps handled securely.
- [ ] Deployment version visible in support diagnostics.
- [ ] WCAG 2.2 AA target is tested with automated checks plus keyboard, focus, screen-reader and manual review; publish an honest VPAT/conformance status only after evidence exists.
- [ ] One customer-facing language is release-consistent, or every supported locale is complete and tested.
- [ ] Run axe (zero critical/serious findings), contrast (4.5:1 normal/3:1 large), 200% zoom/reflow, keyboard/focus/no-trap, NVDA/VoiceOver labels and reduced-motion checks on desktop and minimum/mobile viewport.
- [ ] Provide accessible alternate navigation when mobile CSS hides links; add table captions/scope, form label/id and status/error announcements.
- [ ] Mask one-time API/enrollment secrets in DOM/screenshare, offer explicit copy/reveal/expiry/revoke controls and redact raw JSON/risk details according to the privacy matrix.
- [ ] Onboarding state machine covers approved/pending/denied/unknown, expiry, cancellation, backoff/retry and recovery; no indefinite polling.
- [ ] Disable/hide Supabase mock and silent schema fallbacks in GA; failures are timestamped, visible and retryable.

### Billing and entitlements

Locked decision: **enterprise invoice / quote-based direct-GA**. Self-service checkout is out of scope for this Release Candidate and must not appear as an available purchase path.

- [x] Disable or hide incomplete self-service checkout in the direct-GA dashboard; the invoice-only default is enforced by `VITE_AIDR_COMMERCIAL_MODE` (legacy self-service requires an explicit opt-in).
- [ ] Choose and approve one invoice provider/source of truth.
- [ ] Define manual/enterprise entitlement workflow with tenant-scoped audit.
- [ ] Test seat/agent quantity increase and decrease against the signed Order Form.
- [ ] Test over-limit, suspension, expiry, revocation and reinstatement behavior.
- [ ] Reconcile invoice, entitlement, private-registry access and dashboard state.
- [ ] Test cancellation, export, access revocation and deletion receipt.
- [ ] Define tax, currency, invoice, credit and dispute responsibilities.
- [ ] Do not enable checkout, trial, portal or self-service webhook paths until a new commercial decision and evidence row are approved.

### Exit criteria

- A fresh validation tenant completes the golden path without SQL edits.
- Cross-tenant negative tests pass.
- Dashboard shows no dead navigation or broken action.

---

## 13. Workstream WS5 — AIG production integration

Owner: AIG Integration Lead
Approvers: Security Lead, Platform Lead, QA Lead

### 13.1 Source and licensing

- [ ] Restore AIG as a valid submodule or pinned source archive.
- [ ] Record upstream repository, revision and checksum.
- [ ] Verify licence obligations and additional attribution.
- [ ] Include NOTICE in container, package, UI and customer documents where required.
- [ ] Define the upstream update process.
- [ ] Scan upstream source and dependencies.

### 13.2 Build and deployment

- [ ] Make docker compose config valid.
- [ ] Remove conflicting container_name/replicas usage.
- [ ] Decide agent scaling model.
- [ ] Pin base images by digest.
- [ ] Run containers as non-root where possible.
- [ ] Minimize capabilities; justify SYS_ADMIN/seccomp exceptions.
- [ ] Add read-only filesystem where possible.
- [ ] Add resource limits for the actual target orchestrator.
- [ ] Add network policy and no unnecessary host ports.
- [ ] Keep the bridge private and accept jobs only from an authenticated control-plane broker; never embed a reusable shared bridge secret in local connectors.
- [ ] Define per-task sandboxing and an egress proxy with DNS re-resolution/redirect checks.
- [ ] Add persistent-volume backup and cleanup.
- [ ] Add image health/readiness probes.
- [ ] Produce Kubernetes manifests only if Kubernetes is launch scope.

### 13.3 API contract

- [ ] Define OpenAPI as the source of truth.
- [ ] Generate or validate TypeScript types against it.
- [ ] Align bridge port defaults.
- [ ] Align infra request/response.
- [ ] Align MCP request/response.
- [ ] Align agent request/response.
- [ ] Align jailbreak request/response.
- [ ] Implement task status/result endpoints for every async scan type.
- [ ] Define one canonical durable state machine for submit/queued/running/succeeded/failed/cancelled/expired and legal transitions.
- [ ] Require an idempotency key on task creation and persist request/result identity; retry only safe network, 429 and selected 5xx cases.
- [ ] Treat 404 as missing/unauthorized—not as pending—and prove restart/recovery/retention behavior.
- [ ] Normalize status values.
- [ ] Define error schema and HTTP mappings.
- [ ] Implement cancellation and timeout.
- [ ] Implement pagination/streaming for large findings if required.
- [ ] Version the API.

### 13.4 Security

- [ ] Authenticate broker-to-bridge requests using workload identity/mTLS or short-lived tenant/audience/scope-bound tokens with replay protection.
- [ ] Separate bridge inbound credentials from upstream AIG credentials.
- [ ] Rotate credentials.
- [ ] Reject wildcard CORS with credentials.
- [ ] Validate target schemes and addresses.
- [ ] Protect against SSRF and cloud metadata access.
- [ ] Validate URL ownership/scan authorization and reject DNS rebinding, redirect escape, loopback, private/link-local and metadata ranges at the egress enforcement layer.
- [ ] Replace remote local-path scans with content-addressed upload acquisition; allow source scans only inside the tenant/job sandbox.
- [ ] Validate uploaded archives against malware, traversal, symlink/hardlink escape, file-count/depth and decompression bombs.
- [ ] Enforce size, duration and concurrency limits.
- [ ] Redact LLM tokens and target headers; pass a vault secret reference/one-use credential rather than a raw token in the job payload.
- [ ] Add per-tenant quota/fair scheduling, cancellation, abuse detection and emergency kill switch.
- [ ] Encrypt sensitive task data at rest.
- [ ] Apply tenant ownership to tasks and results.
- [ ] Add audit events for scan creation, access and deletion.

### 13.5 Threat data

- [ ] Fail build if expected CVE/fingerprint sources are absent.
- [ ] Require non-zero minimum counts.
- [ ] Sign compiled indexes.
- [ ] Record upstream revision and generation timestamp.
- [ ] Validate schema and duplicates.
- [ ] Add known-positive CVE tests.
- [ ] Add known-negative patched-version tests.
- [ ] Prove the exact signed dataset hash is included in every packed tarball/container/installed connector and is loaded by the real consumer process.
- [ ] Fail readiness when an embedded fallback, empty dataset, stale dataset or signature mismatch is active.
- [ ] Distinguish upstream-derived rules from locally curated hard-coded categories and document provenance for both.
- [ ] Implement atomic update and rollback.
- [ ] Monitor age/staleness.

### 13.6 Runtime wiring

- [ ] Export AIG public APIs intentionally.
- [ ] Connect AIG to a customer-visible CLI/dashboard action.
- [ ] Define when deep scans trigger automatically versus manually.
- [ ] Persist task state.
- [ ] Poll with backoff.
- [ ] Convert findings into normalized AIDR incidents.
- [ ] Preserve original AIG evidence and attribution.
- [ ] Add correlation IDs across connector, bridge, AIG and dashboard.
- [ ] Define policy effect: informational, warn, ask or block.
- [ ] Define degraded mode when AIG is unavailable.
- [ ] Implement `/livez` for process liveness and `/readyz` returning 503 unless the requested infra/MCP/agent/jailbreak capability, worker, DB/queue, model/provider and signed dataset are ready.
- [ ] Make orchestrator health checks, preflight and customer UI consume capability readiness rather than a single optimistic boolean.
- [ ] Version/pin model provider, model, prompt and evaluation suite for agent/jailbreak evidence; run stochastic cases repeatedly and report success rate/sample size.

### 13.7 AIG test matrix

| ID | Scenario | Expected result |
|---|---|---|
| AIG-001 | Bridge liveness, upstream down | Liveness healthy; readiness false |
| AIG-002 | Unauthenticated request | 401/403 |
| AIG-003 | Invalid target | 4xx validation error |
| AIG-004 | Infra known vulnerable fixture | Expected CVE finding |
| AIG-005 | Infra patched fixture | No matching vulnerability |
| AIG-006 | MCP command-injection fixture | Correct category/severity |
| AIG-007 | MCP clean fixture | No high-risk finding |
| AIG-008 | Agent injection fixture | Expected finding |
| AIG-009 | Jailbreak fixture | Expected suite result |
| AIG-010 | Status and result polling | Valid state transitions |
| AIG-011 | Scan timeout | Failed/expired with clear reason |
| AIG-012 | Task tenant isolation | Cross-tenant access denied |
| AIG-013 | Oversized upload | Rejected before processing |
| AIG-014 | SSRF target | Rejected |
| AIG-015 | Index update failure | Old signed version remains active |
| AIG-016 | Bridge restart mid-task | Recoverable state or explicit failure |
| AIG-017 | Load/concurrency limit | Bounded queue and stable service |
| AIG-018 | Result-to-incident mapping | Dashboard correlation preserved |
| AIG-019 | Connector has no reusable bridge secret | Only broker-issued scoped identity succeeds |
| AIG-020 | DNS rebinding/redirect/metadata target | Blocked by egress enforcement with audit event |
| AIG-021 | Source host-path and archive escape | Host path rejected; safe upload sandbox contains extraction |
| AIG-022 | Duplicate submit/retry | One durable task/result for one idempotency key |
| AIG-023 | Capability dependencies fail independently | `/livez` stays process-accurate; `/readyz` returns 503 for affected capability |
| AIG-024 | Packed consumer dataset | Installed artefact finds known-positive CVE using manifest hash; fallback/empty fails readiness |
| AIG-025 | Raw token/log canary | No token/header/query secret appears in payload persistence, logs, traces or export |
| AIG-026 | Cancellation/kill switch/quota | Tenant-bounded cancellation and emergency stop work without cross-tenant impact |

### AIG exit criteria

- Four scan types pass contract and E2E suites.
- CVE/fingerprint indexes are non-empty, signed, fresh and proven inside the installed consumer process with their exact manifest hash.
- Private broker identity, upload sandbox, target authorization/egress policy, deletion receipt, tenant quota and kill switch pass adversarial tests.
- Liveness/readiness and all four capability states fail honestly under dependency fault injection.
- AIG is no longer reported as dead code.
- Security review approves the exposed surface.
- Customer can run a scan and export evidence without engineer intervention.

---

## 14. Workstream WS6 — Security, privacy and supply chain

Owner: Security Lead
Approvers: Engineering Lead, Legal/Privacy Owner

### Threat modeling

- [ ] Model connector/hook trust boundaries.
- [ ] Model local config/cache/audit files.
- [ ] Model Supabase auth and service-role use.
- [ ] Model device authorization.
- [ ] Model ingest/reputation endpoints.
- [ ] Model AIG target/upload/LLM-token paths.
- [ ] Model package/extension release supply chain.
- [ ] Review fail-open decisions.
- [ ] Map threats to controls and tests.

### Automated security gates

- [ ] pnpm audit or equivalent SCA.
- [ ] Python dependency audit.
- [ ] Container image scan.
- [ ] CodeQL.
- [ ] Semgrep with reviewed rules.
- [ ] Secret scan on full git history and changes.
- [ ] IaC and Dockerfile scan.
- [ ] SBOM generation.
- [ ] Generate SBOM in a standard format, signed provenance/attestation and VEX where exploitability is assessed; verify them before promotion.
- [ ] Licence scan.
- [ ] DAST against validation environment.
- [ ] Pin Actions by SHA, containers by digest and Python/JavaScript dependencies by reviewed lock/hash; declare build-network policy.
- [ ] Enforce digest locks for every container/workflow image (including the AIG bridge, Semgrep and threat-sync jobs) and fail CI on mutable image tags.
- [ ] Use protected environments, two-person production approval and short-lived trusted publishing/OIDC rather than long-lived publish tokens where supported.

### Vulnerability policy

| Severity | Release rule | Remediation target |
|---|---|---|
| Critical | Absolute NO-GO | Immediate |
| High | NO-GO unless non-exploitability/compensating controls are proven and Product + Engineering + Security sign a time-bounded exception; add Legal/Privacy for customer-facing impact | 7 days |
| Moderate | Fix before GA or document accepted risk | 30 days |
| Low | Backlog with owner | 90 days |

### Authentication and authorization

- [ ] Default deny for administrative operations.
- [ ] RLS negative tests.
- [ ] IDOR testing.
- [ ] OAuth state/PKCE/redirect validation.
- [ ] Token expiry/revocation.
- [ ] API key scope and rotation.
- [ ] Device-code brute-force defense.
- [ ] Role and team privilege escalation tests.
- [ ] Append-only/tamper-evident security and administrative audit design; retention/privacy erasure must not permit ordinary tenant admins to rewrite history.

### Privacy

- [ ] Inventory every collected field.
- [ ] Build a mode-by-mode field-level data-flow matrix covering local, managed, event ingestion and each AIG scan: field, purpose, lawful basis, destination/domain, subprocessor, region, retention and deletion behavior.
- [ ] Identify controller/processor roles.
- [ ] Define purpose and lawful basis.
- [ ] Minimize tool-call content sent remotely.
- [ ] Define retention by data class.
- [ ] Treat hash as pseudonymization, not anonymization; prefer omission or keyed HMAC for low-entropy URLs/paths/commands and document reversibility/lookup risk.
- [ ] Reconcile configuration docs with runtime defaults for audit/telemetry sending; no buyer-facing “disabled/local-only” statement ships without a default/config test.
- [ ] Implement export and deletion workflows.
- [ ] Document subprocessors.
- [ ] Prepare DPA and privacy notice.
- [ ] Require explicit AIG opt-in and target authorization; use synthetic data until the governing Evaluation Agreement/DPA permits other data.
- [ ] Assert actual outbound payload schemas and destination domains against the approved privacy matrix in CI/E2E.
- [ ] Maintain an explicit outbound domain/region allowlist for reputation, OAuth/email, billing, Sentry and OTLP; reject arbitrary endpoints in production builds.
- [ ] Set `sendDefaultPii=false` (or equivalent) and scrub Sentry beforeSend, breadcrumbs, request URLs/headers, exceptions, stack/tags and browser route/query data for core/dashboard/extension.
- [ ] Test log/trace redaction with raw URL/tool/reason/token canaries; assert no secret, header, raw reason or session identifier crosses the approved boundary.
- [ ] Inventory and bound event/webhook/waitlist payload JSON; add TTL/deletion jobs and minimize provider webhook retention.
- [ ] Secure local audit/metrics files with restrictive permissions/encryption/retention and verify rotation/secure deletion.
- [ ] Verify backups follow deletion/retention policy.
- [ ] Include auth, object storage, AIG jobs/uploads/results, Sentry/OTLP, reputation, billing, OAuth/email and backups in deletion/region/subprocessor/transfer evidence; capture provider confirmations, key destruction and legal-hold behavior.

### Independent assessment

- [ ] Reserve an independent penetration test provider during Phase 0 and commission the test on the validation Release Candidate.
- [ ] Include dashboard/API/device auth/AIG/connector surfaces.
- [ ] Sign Rules of Engagement defining authorization, scope, stop conditions, test data, reporting and emergency contacts.
- [ ] Record tester independence/qualification, severity standard, validity period and exact Release Candidate.
- [ ] Retest fixes.
- [ ] Define delta-retest triggers: material auth, tenancy, AIG/network, migration or release-supply-chain change invalidates affected evidence.
- [ ] Produce executive and technical reports.

### Detection-effectiveness validation

- [ ] Use a versioned benign/malicious corpus whose oracle is reviewed independently from the rule author.
- [ ] Reserve a blind holdout and adversarial variants; do not tune on the complete acceptance set.
- [ ] Report TP, FP, FN and TN, confusion matrix, sample size and confidence interval per detector/platform.
- [ ] Require deterministic P0 golden fixtures to pass 100%; Product and Security sign acceptable FP/FN thresholds for the broader corpus at claim freeze.
- [ ] Sign/hash the fixture manifest and report corpus/model/prompt drift between Release Candidates.

### Exit criteria

- No unwaived critical/high finding.
- Privacy and security questionnaires can be answered with evidence.
- Audit append/delete/erasure policy, telemetry redaction and processor deletion receipts are verified for the exact Release Candidate.
- Release SBOM and provenance are archived.

---

## 15. Workstream WS7 — Reliability, performance and operations

Owner: SRE/Operations Lead
Approvers: Product Owner, Engineering Lead

### Proposed SLOs

These are provisional objectives, not current claims. Before use, every row needs a queryable SLI numerator/denominator, error semantics, inclusion/exclusion rule, minimum sample, workload/hardware profile, measurement window, owner, error budget and fast/slow burn alert. A 24-hour pre-release test is an acceptance check; it cannot prove a 30-day production SLO.

| Capability | Target |
|---|---|
| Local allow/deny decision | p95 under 50 ms; p99 under 100 ms for local-only path |
| Hook process completion | p95 under 200 ms excluding optional remote lookup |
| Dashboard authenticated API | p95 under 300 ms |
| Event ingestion visibility | 99% visible in dashboard within 5 seconds |
| Dashboard availability | 99.9% monthly for paid tier |
| Control-plane availability | 99.9% monthly |
| AIG task submission | 99.5% successful when ready |
| AIG async task completion | 99% excluding invalid targets |
| Crash-free connector sessions | At least 99.9% |
| Data durability | Numeric RPO by data class plus measured dedupe/replay/restore reconciliation |

Create two reports: **pre-release performance acceptance** under a fixed workload envelope, and **post-launch operational SLO** over a rolling 30-day window. Targets become contractually claimable only after the required observation period.

### Performance tests

- [ ] Define launch capacity in tenants, agents/tenant, decisions/events per second, retained events, dashboard query volume, AIG concurrent jobs, upload size and scan duration.
- [ ] Version hardware, region, runtime, fixture/data size, concurrency, sample count and latency/error calculation.
- [ ] Run 1× sustained launch load, 10× bounded burst and 24-hour soak while measuring latency, errors, queue age, CPU/RAM/disk and event loss.
- [ ] Cold and warm local decision latency.
- [ ] Large threat-rule set.
- [ ] Large allowlist/cache.
- [ ] Large file and command input boundaries.
- [ ] Concurrent connector processes.
- [ ] Ingest at expected customer and 10x burst load.
- [ ] Dashboard agents/incidents pagination.
- [ ] AIG concurrent task queue.
- [ ] Long-running AIG scan.
- [ ] 24-hour soak test.

### Resilience tests

- [ ] No network.
- [ ] DNS failure.
- [ ] Supabase timeout/5xx.
- [ ] Reputation service timeout.
- [ ] AIG bridge down.
- [ ] AIG worker unavailable.
- [ ] Partial database outage.
- [ ] Corrupted cache/config/managed state.
- [ ] Disk full/read-only home.
- [ ] Clock skew.
- [ ] Duplicate events/webhooks.
- [ ] Connector host restart.
- [ ] Deployment rollback during traffic.
- [ ] Supabase/Vercel-or-selected-host/OAuth/AIG/LLM/npm/registry vendor outage and degraded-mode BCP.
- [ ] Telemetry pipeline loss and clock-synchronization failure.
- [ ] Emergency AIG/connector/threat-rule kill switch with scoped recovery.

### Observability

- [ ] Structured logs with release and correlation IDs.
- [ ] Metrics for decisions, latency, errors, enrollments, ingest and scans.
- [ ] Distributed traces where remote calls occur.
- [ ] Sentry release mapping.
- [ ] PII/secret redaction.
- [ ] Customer/tenant-safe diagnostic bundle.
- [ ] Health dashboard.
- [ ] Business KPI dashboard.
- [ ] Measure metric/log/trace loss and sampling; validate correlation propagation and clock synchronization.
- [ ] Define telemetry access control, retention and tamper evidence.

### Alert catalogue

- [ ] Authentication error-rate alert.
- [ ] Enrollment failure-rate alert.
- [ ] Event-ingest error/lag alert.
- [ ] Dashboard availability alert.
- [ ] AIG readiness/queue/failure alert.
- [ ] Threat-data staleness alert.
- [ ] Security scan failure alert.
- [ ] Release error regression alert.
- [ ] Backup failure alert.
- [ ] Certificate/DNS expiry alert.

Every alert requires owner, severity, threshold/SLI, runbook, dedup/suppression policy, maintenance behavior and escalation. Exercise a synthetic incident from telemetry generation through page, acknowledgment, status update and closure; record MTTA/MTTR and false-alarm budget.

### Recovery

- [ ] Database backup schedule.
- [ ] Restore test.
- [ ] AIG volume backup/cleanup.
- [ ] Release rollback.
- [ ] Package deprecation/dist-tag rollback.
- [ ] Extension emergency-disable strategy.
- [ ] Threat-intel rollback.
- [ ] Numeric RPO/RTO for database, auth, object storage, events, AIG tasks/uploads, threat data and signing keys.
- [ ] Backup frequency, retention, encryption, key recovery and named restore owner.
- [ ] Restore into a clean project/account from a production-scale-like snapshot; reconcile checksums, row/object counts, tenant samples and lost-event window.
- [ ] Migration forward-repair/rollback and data compatibility after a bad release.
- [ ] Run the recovery procedure with an operator who did not author the runbook.

### Support and service operations

- [ ] Approve support hours, timezone, channels and escalation path.
- [ ] Define P0–P3 acknowledgment, update and restore/workaround targets; reconcile them with SECURITY.md, SLA and vulnerability policy.
- [ ] Define planned maintenance, status communication and breach/customer-notification workflow.
- [ ] Publish a customer/vendor shared-responsibility matrix and diagnostic-data consent process.
- [ ] Run a real ticket drill from customer report through acknowledgment, triage, status update, recovery and closure.

### Exit criteria

- SLOs are measured, not estimated.
- Alert tests reach the on-call owner.
- Restore and rollback exercises succeed.

---

## 16. Workstream WS8 — Customer experience and documentation

Owner: Product/Customer Success
Approvers: Engineering, Security, Sales

### Documentation set

- [ ] Product overview with accurate maturity labels.
- [ ] Supported platforms and versions.
- [ ] Installation per connector.
- [ ] Upgrade/downgrade/uninstall.
- [ ] Device authorization.
- [ ] Configuration reference.
- [ ] Data-flow and privacy explanation.
- [ ] Threat and verdict explanation.
- [ ] AIG scan guide and limitations.
- [ ] Incident interpretation.
- [ ] Troubleshooting.
- [ ] Known limitations.
- [ ] Security policy and vulnerability disclosure.
- [ ] Support and SLA.
- [ ] Status page.
- [ ] Release notes.
- [ ] Admin and tenant-management guide.
- [ ] Evaluation Agreement/Charter and Rules of Engagement.
- [ ] Customer onboarding/offboarding, connector uninstall, device/key revocation and deletion-receipt guide.
- [ ] Procurement pack: MSA, Order Form/SOW, DPA, Privacy Notice, subprocessors/regions, SLA/Support Schedule, BCP/DR summary, security architecture, pentest letter, SBOM/VEX, OSS/AIG attribution, vulnerability disclosure and current certification status.
- [ ] Accessibility conformance status; label certifications, VPAT, insurance, export/sanctions and compliance artefacts honestly as held, planned, not held or not applicable.

### Documentation quality

- [ ] All commands are executed in docs CI.
- [ ] All links are checked.
- [ ] Clean consumer sandbox executes every install/verify command; link crawler checks relative links, route URLs, domains, branch/release instructions, platform count and version.
- [ ] Customer Dashboard guide covers onboarding/pilot approval, route limitations, troubleshooting, support/status/contact, privacy/terms and accessibility status.
- [ ] Screenshots match Release Candidate.
- [ ] No stale domain or environment variable.
- [ ] No secret-like example values.
- [ ] Terminology is consistent.
- [ ] Customer documentation is versioned.
- [ ] Internal runbooks are clearly separated from external docs.
- [ ] Customer-facing UI/docs use one consistent release language or a complete tested locale set.

### Time-to-value targets

- Assisted customer: protected first agent within 15 minutes, measured from receipt of a prerequisites-complete access package; support interventions are counted and reported.
- Self-service customer: protected first agent within 10 minutes, measured from first authenticated visit with no human intervention.
- Evaluator: complete primary validation script within 60 minutes.

### Exit criteria

- A technically competent evaluator can complete the test kit without undocumented steps.
- Support can diagnose failures using the documented diagnostic bundle.

---

## 17. Golden-path validation scenarios

### VAL-001 — New customer onboarding

Preconditions:

- Clean validation tenant.
- Approved test user.
- Supported browser.

Steps:

1. Open the validation landing page.
2. Sign in using the supported primary provider.
3. Complete any pilot/tenant approval step.
4. Open onboarding.
5. Select Claude Code.
6. Generate a device code.

Expected:

- Session and tenant are correct.
- Device code is short-lived and single-use.
- UI shows exact install and verification instructions.
- Audit events contain no secret.

Evidence:

- Browser recording.
- Auth/device event IDs.
- Screenshot of environment version.

### VAL-002 — Device verification and enrollment

Steps:

1. Start the connector on a clean workstation.
2. Obtain verification URL/code.
3. Approve in browser.
4. Poll and complete enrollment.
5. Restart connector.

Expected:

- Device appears once in Agents.
- Managed state is stored locally with secure permissions.
- Reusing or cross-tenant approving the code fails.

### VAL-003 — Benign action

Steps:

1. Run a harmless fixture command.
2. Write a benign fixture file.
3. Fetch a trusted fixture URL.

Expected:

- Actions are allowed within latency budget.
- Audit records show allow and reasons.
- No false incident is created.

### VAL-004 — Malicious action blocked

Steps:

1. Run a safe pipe-to-shell simulation fixture.
2. Attempt a sensitive-path fixture write.
3. Use a synthetic credential-exposure fixture.

Expected:

- Defined action is blocked or asks for approval.
- Rule, severity and explanation are visible.
- Nothing harmful executes.
- Incident appears in the dashboard.

### VAL-005 — Approval and allowlist

Steps:

1. Trigger an ask verdict.
2. Approve the specific action.
3. Retry.
4. Add/remove an allowlist entry.
5. Attempt allowlist smuggling with a different artefact.

Expected:

- Approval is scoped, short-lived and auditable.
- Retry succeeds only for the approved action.
- Smuggling attempt remains blocked.

### VAL-006 — Incident investigation

Steps:

1. Open the incident.
2. Inspect agent, event, rule and timeline.
3. Filter/search.
4. Export evidence.

Expected:

- Correlation is complete.
- Sensitive values are redacted.
- Export is attributable to release/environment/tenant.

### VAL-007 — Offline/degraded behavior

Steps:

1. Disconnect network after enrollment.
2. Run benign and malicious local fixtures.
3. Restore network.

Expected:

- Local protection continues.
- Cloud-only degradation is explained.
- Buffered data behavior matches policy.
- Recovery does not duplicate or lose events.

### VAL-008 — AIG infrastructure scan

Steps:

1. Submit the known-vulnerable fixture.
2. Observe task state.
3. Retrieve result.
4. Submit patched fixture.

Expected:

- Vulnerable fixture produces expected CVE.
- Patched fixture does not.
- Result is visible as an AIDR incident/evidence item.

### VAL-009 — AIG MCP scan

Steps:

1. Scan clean MCP fixture.
2. Scan command-injection/prompt-injection fixture.
3. Compare category results.

Expected:

- Findings match expected category/severity.
- Headers/tokens are not exposed in logs.
- Cross-tenant result access fails.

### VAL-010 — AIG unavailable

Steps:

1. Disable the bridge or worker.
2. Request a scan.
3. Continue local protection.
4. Restore AIG.

Expected:

- Readiness becomes false.
- Scan request returns actionable error or queues according to policy.
- Local AIDR protections remain predictable.
- Recovery is observable.

### VAL-011 — Upgrade and rollback

Steps:

1. Install previous supported version.
2. Enroll and create baseline state.
3. Upgrade to Release Candidate.
4. Validate state migration.
5. Roll back.

Expected:

- No state corruption.
- Config compatibility follows published policy.
- Rollback remains functional.
- For extensions/marketplace plugins, rollback is proven by a known-good re-release/pin or emergency disable; unpublishing does not claim to auto-downgrade already installed clients.

### VAL-012 — Tenant isolation

Steps:

1. Create two validation tenants.
2. Attempt cross-tenant reads/writes for agents, events, incidents, API/enrollment keys, exports, object storage, AIG tasks/uploads/results, queues/caches and telemetry/support tooling using user, admin and service identities.

Expected:

- All unauthorized operations are denied.
- Security events are generated.

### VAL-013 — Billing/entitlement

Run the enterprise-invoice provisioning flow for the direct-GA sale; self-service checkout is out of scope for this Release Candidate.

Expected:

- Checkout and signed webhook update entitlement exactly once.
- Seat limit is enforced server-side.
- Cancellation/refund/expiry transitions are correct.

### VAL-014 — Data export/deletion

Expected:

- User/tenant data can be enumerated, exported and deleted according to policy.
- Retention exceptions are documented.

### VAL-015 — False positive, override and policy tuning

Trigger an independently labelled benign edge case, inspect the explanation, apply the narrowest permitted override, retry and then revoke it. The override must be tenant- and artefact-scoped, time-bounded, auditable and unable to suppress a materially different malicious fixture.

### VAL-016 — Invitation, RBAC and account removal

Invite an evaluator, exercise each supported role, attempt privilege escalation, demote/remove the user and replay an old session. Access must follow the tenancy ADR immediately; revoked sessions and JIT support privileges must fail and generate immutable audit evidence.

### VAL-017 — API/enrollment key rotation and revocation

Create, scope, rotate and revoke keys/codes; attempt reuse, brute force, cross-tenant use and replay. No plaintext secret appears in DB, logs, traces, screen recording or export.

### VAL-018 — Connector and device deprovisioning

Uninstall the connector, revoke the device, remove managed state and verify the host no longer reports protected. Reinstallation must require an approved enrollment path and must not resurrect revoked credentials.

### VAL-019 — Customer-controlled fixture

The customer supplies an authorized, safe fixture under the Evaluation Charter. The team records its hash before execution, predicts acceptance rules without modifying detection during the run and reports the result, limitations and any support intervention honestly.

### VAL-020 — Support and incident escalation

Open a customer ticket for a synthetic service incident. Measure acknowledgment, triage, status communication, escalation, workaround/recovery and closure against the approved support schedule; verify diagnostic-data consent and redaction.

### VAL-021 — Assisted entitlement and seat lifecycle

Starting from an approved Order Form, provision entitlement without ad-hoc SQL, add/remove a seat, attempt over-limit use, cancel the account and reconcile the commercial record with enforced access and immutable audit events.

### VAL-022 — Tenant closure and deletion receipt

Expire evaluator access, export agreed data, revoke users/devices/keys, delete tenant-scoped DB/object/AIG/telemetry data according to policy, record any backup-retention exception and issue a signed deletion/resource-destroy receipt.

### VAL-023 — Customer-visible route and link crawl

From a clean browser profile, crawl every navigation item, internal href, route declared in the manifest, auth returnTo, pilot/pricing link, error/retry link and footer legal/support link. Each route must resolve on the deployed RC with the correct auth boundary, no console error, no redirect loop and visible version/data-freshness information.

### VAL-024 — Enrollment expiry and secret presentation

Exercise approved, pending, denied, unknown, expired, cancelled and network-recovery enrollment states. Verify bounded polling/backoff, actionable renewal, single-use code behavior, masked DOM/clipboard/screen-share presentation, expiry/revoke controls and absence of raw secrets in logs, traces, screenshots or exports.

### VAL-025 — Accessibility and independent browser acceptance

Run the browser kit at the declared desktop/mobile viewports with keyboard-only navigation, focus/no-trap, axe critical/serious scan, contrast, zoom/reflow, reduced motion and NVDA/VoiceOver checks. The customer records any assistive-technology limitation and signs the exact RC result; a MemoryRouter/manual page mount cannot replace this case.

---

## 18. Customer and investor evaluation program

### 18.1 Evaluator roles

- Customer security lead.
- Customer platform/DevOps engineer.
- Customer developer/end user.
- Procurement or compliance observer.
- Investor technical adviser.
- Internal facilitator.
- Internal observer/recorder.
- Incident responder on standby.

### 18.2 Access package

Provide:

- Validation URL.
- Temporary user accounts.
- Tenant identifier.
- Supported workstation image or setup instructions.
- Release Candidate/version manifest.
- Test case workbook.
- Known limitations.
- Support contact.
- Evidence export instructions.
- Data retention/deletion statement.
- Signed Evaluation Agreement/NDA and Evaluation Charter.
- BYOD versus supplied-VM decision; OS/runtime/admin-right and proxy/network allowlist prerequisites.
- Explicit differences from production, account/tenant expiry and offboarding/deletion-receipt procedure.

Do not provide:

- Service-role keys.
- Production credentials.
- Internal admin access.
- Unscoped AIG tokens.

### 18.3 Evaluation Charter

Before access is issued, both parties approve:

- Objectives, in-scope/out-of-scope capabilities and immutable Release Candidate.
- Mandatory/optional test IDs and exact success/performance thresholds.
- Permitted internal assistance, support-contact rules and how interventions are counted.
- Test authorization/Rules of Engagement, safe targets, stop conditions and emergency contacts.
- Data classification, DPA status, synthetic-data requirement, logging/recording consent and retention/deletion.
- Defect severity, evidence, fix/retest and environment-reset/deployment-change rules.
- Customer roles authorized to sign the technical result and commercial reservations.

### 18.4 90-minute guided technical evaluation agenda

| Time | Activity |
|---:|---|
| 0–10 min | Scope, architecture, maturity labels, version manifest |
| 10–25 min | Login, onboarding and device enrollment |
| 25–40 min | Benign and malicious local protection |
| 40–50 min | Approval, audit and incident investigation |
| 50–65 min | AIG infra/MCP scans |
| 65–75 min | Offline/degraded behavior |
| 75–85 min | Security, privacy and operational evidence |
| 85–90 min | Feedback, unresolved questions and next steps |

The guided session is orientation, not independent product acceptance. It must be followed by a 2–5 business-day sandbox/PoV in which the customer executes the mandatory kit. Assisted and unassisted time-to-value, intervention count, environment deviations and defects are reported separately.

### 18.5 Investor-focused proof

Investor claims should be supported with:

- Time to first protected agent.
- Supported connector matrix.
- Detection fixture pass rate.
- False-positive baseline.
- Local decision latency.
- AIG coverage counts and scan evidence.
- Multi-tenant architecture and security posture.
- Release velocity and automated gate coverage.
- Customer validation completion rate.
- A clearly labelled moat hypothesis: cross-runtime enforcement + local protection + deep AIG scanning + incident evidence; treat it as proven only when IP ownership, comparative benchmarks and customer evidence support it.

Every investor metric needs a dictionary entry: formula/denominator, source, environment/release, sample size, observation period, owner/reviewer, target-versus-actual status, confidence interval or limitation. Technical product diligence and corporate/financial diligence use separate indexes. Unverified ARR, customer, compliance or market statements must not enter the evidence pack.

Avoid:

- “All agents/platforms are fully supported” before matrix proof.
- “1,300+ CVEs” while compiled count is zero.
- “Real-time” without measured latency.
- “Production-ready” without signed gate record.
- Compliance certification claims that have not been independently obtained.

### 18.6 Session rules

- Freeze deployment during the session.
- Record the environment manifest before starting.
- Run preflight.
- Never silently skip a failed case.
- Log every support intervention, reset, deployment/configuration change and evaluator-blocking prerequisite.
- Capture every defect with evidence.
- Separate product defect from environment/user error.
- Reset environment between organizations.
- Deliver the test report within one business day.
- Require the customer decision owner to sign passed/failed cases, reservations and agreed retest scope.

---

## 19. Preflight and demo runbook

### 19.1 Automated preflight

A future demo:preflight command must check:

- DNS and TLS.
- Dashboard route health.
- Supabase connectivity.
- OAuth configuration.
- Required Edge Functions and versions.
- Database migration version.
- Validation tenant and roles.
- Connector package availability.
- Artefact signatures.
- Threat rule count/version.
- AIG bridge readiness.
- AIG capability `/readyz` for infra/MCP/agent/jailbreak, not only process health.
- AIG worker availability.
- AIG CVE/fingerprint counts.
- Expected-versus-discovered mandatory suite/test counts and platform capability manifest.
- Fixture endpoints.
- Observability ingestion.
- Evidence storage.
- Privacy outbound-domain/payload canary.
- Evaluator account/tenant expiry and teardown receipt.
- Gate registry status, Release Candidate digest and no expired waiver.
- No active P0 incident.

Any failed mandatory check returns non-zero and displays remediation.

### 19.2 Manual preflight

- [ ] Presenter workstation power/network.
- [ ] Clean browser profile.
- [ ] Screen sharing permissions.
- [ ] Font/zoom and terminal visibility.
- [ ] Backup test account.
- [ ] Backup validation workstation/VM.
- [ ] Recorded fallback demonstration.
- [ ] Label any recording/fallback as illustrative; it cannot replace live evidence for a mandatory case.
- [ ] Incident response contact available.
- [ ] Customer consent for recording.

### 19.3 Dress rehearsal acceptance

- Two full runs from reset state.
- Different internal operators.
- No manual DB edit.
- No test skip.
- No unexplained console error.
- No secret in screen/log/export.
- No hidden deployment, reset, DB edit or configuration mutation.
- Expected suite/test count exactly matches execution evidence.
- Total primary flow within planned time.

---

## 20. Evidence and buyer data room

### 20.1 Evidence directory model

~~~text
readiness/
  release-candidate-id/
    00-index/
    01-scope-and-claims/
    02-build-and-packages/
    03-tests-and-coverage/
    04-aig/
    05-security/
    06-performance/
    07-reliability/
    08-deployment/
    09-customer-validation/
    10-legal-and-commercial/
    11-final-signoff/
~~~

### 20.2 Mandatory artefacts

- Release manifest.
- Commit SHA and tags.
- CI run links.
- Unit/integration/E2E reports.
- Skip count: zero.
- Coverage report.
- Mutation report.
- Package consumer report.
- SBOM.
- Dependency and container scan reports.
- SAST/DAST reports.
- Penetration-test executive summary.
- AIG positive/negative scan evidence.
- RLS/tenant-isolation report.
- Performance and soak report.
- Backup/restore report.
- Rollback report.
- Signed known-limitations document.
- Customer validation scorecard.
- Final GO record.
- Gate registry export with hard/conditional/informational classification and negative-control result.
- Expected-test/capability manifest plus collected/executed/skipped JUnit counts.
- Source Assurance Ledger and claim-to-evidence registry.
- Commercial Release Manifest, approved SKU/price/entitlement, sample Order Form and quote-to-offboarding report.
- Evaluation Charter, Rules of Engagement, customer signed result/reservations and assistance/environment-deviation log.
- Privacy field-level data-flow matrix, outbound-domain manifest, DPA/subprocessor/region status and deletion/resource-destroy receipt.
- MSA/SOW, SLA/Support Schedule, BCP/DR summary, IP chain-of-title, OSS/AIG redistribution review, vulnerability disclosure and accessibility status.
- Restore drill with RPO/RTO, checksum/count reconciliation and runbook-independent operator result.
- Investor metric dictionary and separate corporate/financial diligence index.

Evidence marked `planned`, `not held` or `not applicable` must remain visibly labelled; a placeholder is never buyer proof.

### 20.3 Buyer data-room access controls

- [ ] Split public, NDA, security-sensitive and restricted/legal layers.
- [ ] Record buyer, purpose, document owner/version, confidentiality class, expiry, watermark and download/revocation audit.
- [ ] Apply least privilege, short-lived links and automatic access expiry.
- [ ] Redact secrets, personal data, exploit details and other customers’ evidence.
- [ ] Test access removal and evidence-index integrity before sharing.

### 20.4 Evidence record format

Each artefact must state:

- Evidence ID.
- Release Candidate.
- Environment.
- Timestamp and timezone.
- Tool/version.
- Command or procedure.
- Input/fixture version.
- Expected result.
- Actual result.
- Pass/fail.
- Owner/reviewer.
- Hash or immutable URL.
- Related requirement/claim.

---

## 21. RACI

Legend: R = Responsible, A = Accountable, C = Consulted, I = Informed

| Workstream | Product | Eng Lead | Core | Platform | Frontend | QA | Security | SRE | Legal | Sales/CS |
|---|---|---|---|---|---|---|---|---|---|---|
| Scope/claims | A/R | C | C | C | C | C | C | I | C | C |
| Build/CI/packages | I | A | C | R | C | C | C | C | I | I |
| Core assurance | I | A | R | C | I | R | C | I | I | I |
| Connectors | C | A | R | C | I | R | C | I | I | C |
| Supabase/control plane | C | A | C | R | R | R | C | C | I | C |
| AIG | C | A | C | R | C | R | C | C | C | I |
| Security/privacy | C | C | C | C | C | C | A/R | C | C | I |
| Reliability/operations | C | C | C | R | C | C | C | A/R | I | I |
| Customer validation | A | C | C | C | C | R | C | C | I | R |
| Legal/commercial | C | I | I | I | I | I | C | I | A/R | C |
| Final GO | A | A | I | I | I | A | A | A | C | I |

Named individuals must replace role-only ownership before execution begins.

Final GO additionally requires named accountable sign-off from Commercial/Sales, Legal, Privacy/DPO, Finance/Billing and Support/Customer Success. Their approval cannot be inferred from an “informed” RACI cell. Waivers require the same domain approver when they affect pricing/entitlement, contract/licence, personal data, finance or support commitments.

---

## 22. Delivery roadmap

### Staffing assumption

Recommended minimum:

- 1 Engineering Lead.
- 1 Core/connector engineer.
- 1 Platform/AIG engineer.
- 1 Frontend engineer.
- 1 QA automation engineer.
- Part-time Security/SRE/Product/Legal support.

With fewer people, duration increases and workstreams become sequential.

### Phase 0 — Discovery, authority and forecast (must happen first)

- Freeze claims, first-sale scope and the Commercial Release Manifest draft.
- Reserve the independent penetration-test provider and design-partner window.
- Restore/pin the AIG source or formally remove AIG from the proposed scope.
- Produce the AIG API/upstream compatibility spike, Supabase migration reset report, tenancy ADR draft, vulnerability triage and deployment-provenance audit.
- Confirm the deployed application’s source repository/commit and the target hosting/resource model.

Exit: G0 is green and the team publishes P50/P90 engineering effort, elapsed external lead time, assumptions, confidence and decision points. No sale date is committed before this exit.

### Phase 1 — Reproducible release foundation

- Clean clone/build/typecheck/lint and package contracts.
- Expected-suite manifest and no-skip enforcement.
- Release workflow repair, immutable actions/images, provenance/SBOM/signature and rollback/yank drill.
- Critical/high dependency triage and licence/IP review.

Exit: G1 green.

### Phase 2 — Authoritative backend and primary golden path

- Ordered Supabase migrations/config/seed and two-reset/N-1 migration proof.
- Tenancy ADR/data migration, RLS and all-store isolation.
- Auth/device enrollment, Claude Code install, ingest/agents/incidents, validation reset/teardown.

Exit: G2 green for the explicitly scoped primary connector.

### Phase 3 — AIG production integration

- Private broker identity, content-addressed upload sandbox, egress/target authorization, API state machine/idempotency and capability readiness.
- Runtime dataset packaging/signature/known-positive proof.
- Four scan contracts, positive/negative/adversarial fixtures, result-to-incident flow, outage/kill-switch tests.

Exit: G3 green, or AIG is removed from every contractual/marketing claim.

### Phase 4 — Security, platform and effectiveness

- Two-tenant negative suite, SCA/container/secrets/DAST, detection corpus/holdout/mutation/fuzz, real-host platform matrix and privacy payload assertions.
- Independent assessment/retest against the RC.

Exit: G4 green; “substantially green” is not a release state.

### Phase 5 — Reliability and external evaluation

- Capacity workload, load/burst/soak, alert/telemetry, backup/restore/RTO/RPO, rollback and vendor-outage BCP.
- Customer test kit, guided session, independent 2–5 day PoV and signed results.

Exit: G5 and G6 green.

### Phase 6 — Commercial close and sale authorization

- Fix RC findings and re-test deltas.
- Approve MSA/Order Form/DPA/SLA/support/procurement/data-room pack, SKU/entitlement and quote-to-offboarding.
- Complete two dress rehearsals, evidence archive and all-domain sign-offs.

Exit: G7 and G8 decision for the exact Release Candidate.

### Estimate policy

Do not use the prior “8–12 engineer-days” AIG demo or “4–6 week sale-ready” statements as commitments. After Phase 0, publish separate P50/P90 ranges for:

- **Demoable:** guided internal run with approved synthetic fixtures.
- **Customer-evaluable:** immutable sandbox plus signed Evaluation Charter and independent PoV.
- **Assisted-sale ready:** contracted scope with support, privacy, security and recovery evidence.
- **Production/GA:** all advertised capabilities, SLO observation, external assessment and commercial terms.

Each range must state staffing, external-provider lead time, unresolved risks, confidence and the gate that can invalidate it. Phase names describe required order, not calendar promises.

---

## 23. Critical path

~~~mermaid
flowchart LR
    Scope["Scope and claims"]
    Build["Clean build and CI"]
    Packages["Package contracts"]
    Backend["Supabase golden path"]
    Connector["Primary connector E2E"]
    AIG["AIG contract and runtime"]
    Security["Security and tenant isolation"]
    Reliability["Load, recovery and operations"]
    Validation["External validation"]
    Legal["Commercial and legal"]
    Go["Final GO"]

    Scope --> Build
    Build --> Packages
    Build --> Backend
    Packages --> Connector
    Backend --> Connector
    Backend --> AIG
    Connector --> Security
    AIG --> Security
    Security --> Reliability
    Reliability --> Validation
    Scope --> Legal
    Validation --> Go
    Legal --> Go
~~~

No schedule optimization should bypass Build, Backend, AIG, Security or Reliability gates.

---

## 24. Risk register

| ID | Risk | Probability | Impact | Trigger | Mitigation | Owner |
|---|---|---:|---:|---|---|---|
| R-001 | AIG upstream source/API differs from assumed architecture | High | Critical | Contract tests fail | Pin upstream, spike early, scope scan types | AIG Lead |
| R-002 | Clean CI remains false-green | High | Critical | Skipped/missing suite | No-skip and report assertions | Build Lead |
| R-003 | Live app is deployed from another repository | High | High | SHA cannot be resolved | Deployment manifest and repo ownership | SRE |
| R-004 | Supabase schema drift | High | Critical | Fresh reset differs | Single migration source and CI reset | Platform |
| R-005 | Cross-tenant data exposure | Medium | Critical | RLS negative test fails | Default deny, RLS tests, pentest | Security |
| R-006 | Fail-open allows unsafe action during outage | Medium | Critical | Fault test | Approved per-operation failure policy | Product/Security |
| R-007 | Dependency vulnerabilities block procurement | High | High | SCA report | Upgrade/override/remove and exception process | Eng Lead |
| R-008 | CLI/SDK published package is unusable | High | High | Consumer test fails | Tarball contract gate | Build Lead |
| R-009 | False positives damage demo/customer trust | Medium | High | Fixture/user feedback | Golden benign corpus and tuning | Core Lead |
| R-010 | Detection bypass | Medium | Critical | Red-team/fuzz finding | Mutation/fuzz/manual review | Core/Security |
| R-011 | AIG target scanning creates SSRF/data risk | High | Critical | Security test | Target validation and network isolation | AIG/Security |
| R-012 | OAuth redirect/session failure in validation | Medium | High | Preflight fails | Dedicated OAuth config and smoke test | Platform |
| R-013 | Marketplace review delays connector distribution | Medium | Medium | Publication pending | Assisted VSIX/package install fallback | Product |
| R-014 | Billing paths conflict | High | High | State reconciliation fails | Assisted sale or single provider | Product/Platform |
| R-015 | Missing operational ownership | Medium | High | Alert unacknowledged | Named on-call and escalation test | SRE |
| R-016 | Licence/attribution issue | Medium | High | Legal review fails | Early counsel review and NOTICE audit | Legal |
| R-017 | Validation data leaks secrets | Medium | Critical | Redaction test fails | Synthetic data and log redaction | Security/QA |
| R-018 | Scope expands before stability | High | High | New GA claims | Change-control and feature freeze | Product |
| R-019 | Performance regression from remote checks | Medium | High | SLO fails | Async/cache/budgets and local-first path | Core |
| R-020 | Customer cannot reproduce internal result | Medium | High | External session mismatch | Versioned fixtures and immutable environment | QA |
| R-021 | Migration reset or tenancy ADR remains unresolved | High | Critical | Two-reset/N-1 or isolation matrix fails | Stop backend scope; repair authority/model before connector sale | Platform |
| R-022 | Release publishes from an untrusted branch or mutable action/input | High | Critical | Provenance/digest negative test fails | Protected RC promotion, pinned inputs, OIDC and least privilege | Build |
| R-023 | AIG scan reaches an unauthorized target or leaks a token/upload | High | Critical | SSRF/redaction/ROE test fails | Private broker, target authorization, egress sandbox, synthetic-only evaluation | AIG/Security |
| R-024 | Privacy/contract claims conflict with actual telemetry/AIG payloads | High | Critical | Payload-vs-notice assertion fails | Field-level data-flow registry, opt-in, DPA and outbound-domain gate | Privacy/Legal |
| R-025 | External pentest/design partner cannot be scheduled in the planned window | Medium | High | Provider/charter date unavailable | Reserve in Phase 0; publish P50/P90 with lead time | Security/Product |
| R-026 | Commercial SKU/price/provider/entitlement remains contradictory | High | High | Commercial Release Manifest or quote-to-offboard fails | Single provider/assisted sale, Finance/Legal sign-off | Commercial |
| R-027 | Customer-visible route/link or auth recovery is broken | High | Critical | Browser crawl finds 404/loop/console error | Wire/hide routes, deployed-RC crawl and preflight hard gate | Frontend/QA |
| R-028 | Built UI claim drifts from Claim Registry | High | High | Banned-copy scan finds unapproved string | Build-output claim scan and sales approval registry | Product/Marketing |
| R-029 | Enrollment/API secret or raw incident data appears in DOM/screen/log | Medium | Critical | Redaction canary or screen-share review fails | Masked reveal/copy, retention/redaction and support rules | Security/Frontend |
| R-030 | Customer cannot reach support or accessibility blocks evaluation | Medium | High | Ticket/axe/assistive-tech test fails | Visible support/status paths, WCAG/browser gate and documented limitations | Support/Frontend |

Risks are reviewed daily while Critical/High items remain open.

---

## 25. Quality metrics and business KPIs

### Engineering quality

- Required CI pass rate.
- Skipped tests: zero.
- Expected/discovered/executed mandatory suite parity.
- Critical-path coverage.
- Mutation score.
- Open defects by severity.
- Mean age of vulnerabilities.
- Reproducible-build hash match.
- Crash-free connector sessions.

### Product performance

- Install success rate.
- Median time to first protected agent.
- Enrollment completion rate.
- Benign fixture pass rate.
- Malicious fixture block rate.
- False-positive rate from validation corpus.
- Incident visibility latency.
- AIG task success and completion time.
- Capacity envelope utilization, queue age and error-budget burn.

### Commercial validation

- Customer test-case completion rate.
- Number of evaluator-blocking defects.
- Security questionnaire completion time.
- Procurement evidence turnaround.
- Design-partner acceptance.
- Conversion from technical validation to commercial next step.

Every engineering, product, commercial and investor metric must have a dictionary entry containing formula/denominator, source query, release/environment, sample size, observation period, owner/reviewer, target-versus-actual status and confidence interval or limitation. Historical/strategy figures are not product evidence until Finance/Product/Legal validate them.

Metrics must identify environment, release and fixture version.

---

## 26. Defect policy

### Severity

| Severity | Definition | Release rule |
|---|---|---|
| P0 | Security breach, cross-tenant access, data loss, bypass of mandatory protection, unrecoverable customer data, unusable primary path, unknown deployed revision or false evidence | Immediate, non-waivable NO-GO |
| P1 | Major supported feature broken, frequent crash, tenant/auth issue without demonstrated exploit | NO-GO |
| P2 | Workaround exists; limited supported behavior affected | Product/QA decision |
| P3 | Cosmetic, documentation or low-impact issue | May defer with owner |

### Defect record

Every defect includes:

- Release/environment.
- Reproduction steps.
- Expected/actual result.
- Logs, trace and correlation ID.
- Security/privacy impact.
- Affected customer claim.
- Regression test requirement.
- Owner and target date.
- Verification evidence.

No P0/P1 is closed without a regression test and independent verification.

---

## 27. Exception and waiver policy

Waivers are exceptional and may not be used to hide incomplete product scope. A waiver does not change a hard gate into a pass; it records a conditional decision only where the decision profile permits one.

A waiver must include:

- Gate and requirement.
- Business reason.
- Technical risk.
- Affected customers/claims.
- Compensating control.
- Detection/monitoring.
- Expiry date.
- Remediation owner.
- Product, Engineering and Security approval.
- Commercial/Sales, Legal, Privacy/DPO, Finance or Support approval when the affected requirement belongs to that domain.

Never waive:

- Any critical vulnerability.
- Cross-tenant access.
- Missing backup for production customer data.
- Unknown deployed source revision.
- Silent skip of mandatory tests.
- Missing AIG authentication if externally reachable.
- Unrecoverable customer data or falsified/placeholder evidence.

---

## 28. Final GO/NO-GO checklist

### Scope and claims

- [ ] GA/Beta/Experimental labels approved.
- [ ] Claim-to-evidence matrix complete.
- [ ] Known limitations published.
- [ ] Claim Registry and Commercial Release Manifest approved; no historical/unsupported claim is sales-approved.

### Build and artefacts

- [ ] Clean clone passes.
- [ ] Working tree unchanged after install/build.
- [ ] Lint/typecheck/build green.
- [ ] Package consumer tests green.
- [ ] Signed artefacts/SBOM/provenance archived.
- [ ] Release pipeline is protected, immutable-input and same-digest promote/rollback verified.

### Tests

- [ ] Unit/integration green.
- [ ] Required E2E green.
- [ ] Skipped count zero.
- [ ] Expected = discovered = executed mandatory suite/test counts; missing prerequisite is non-zero setup failure.
- [ ] Critical coverage/mutation thresholds green.
- [ ] Real host matrix green for every GA connector.

### AIG

- [ ] Reproducible source and containers.
- [ ] Compose/deployment green.
- [ ] API contract green.
- [ ] Four scan types green or unsupported types removed from claims.
- [ ] Non-zero signed data.
- [ ] Exact signed dataset hash is loaded by the installed consumer; capability readiness is honest.
- [ ] Positive/negative scans green.
- [ ] Result-to-incident path green.
- [ ] Security and outage tests green.
- [ ] Private broker, target authorization, egress/upload sandbox, tenant quota, cancellation and kill switch green.

### Backend/dashboard

- [ ] Fresh DB reset/migrations green.
- [ ] Two deterministic resets, N-1 migration and generated-type/schema diff green.
- [ ] Tenancy ADR and two-tenant all-store isolation matrix green.
- [ ] RLS and tenant isolation green.
- [ ] Auth/device flow green.
- [ ] Required Edge Functions present.
- [ ] Dashboard routes/actions green.
- [ ] Deployed-RC route/link crawl green for every customer-visible href, including pilot/pricing/footer/auth recovery.
- [ ] Onboarding expiry/retry/secret-presentation tests green.
- [ ] Browser console, axe/WCAG, keyboard/mobile and assistive-technology evidence green.
- [ ] DNS/TLS/version manifest green.

### Security/privacy

- [ ] Zero unwaived critical/high findings.
- [ ] Penetration-test closure.
- [ ] Secrets/redaction green.
- [ ] Secret-scan configuration is present/reproducible from clean checkout and full-history scan evidence is archived.
- [ ] Privacy/retention/export/deletion approved.
- [ ] Actual telemetry/AIG payloads match field-level privacy matrix and approved outbound domains.
- [ ] Sentry/OTLP/browser tracing redaction and retention/region/subprocessor evidence green.
- [ ] Audit append-only/erasure policy, local file ACLs and webhook/waitlist TTL/deletion evidence green.

### Reliability

- [ ] SLO report green.
- [ ] Load/soak green.
- [ ] Alert exercise green.
- [ ] Backup/restore green.
- [ ] Rollback green.
- [ ] Numeric per-data-class RPO/RTO, clean restore reconciliation and vendor-outage BCP green.

### Customer/commercial

- [ ] Test kit complete.
- [ ] Locked direct-GA all-connector scope is proven for Claude Code, Cursor, VS Code, OpenClaw and OpenCode on the supported host matrix.
- [ ] Hybrid deployment, EU/US/APAC placement and privacy/transfer controls are proven for the sold tenant mode.
- [ ] Enterprise invoice/private-registry provisioning, entitlement, revocation and offboarding rehearsal is green; self-service checkout is not advertised.
- [ ] 99.9% monthly managed control-plane/dashboard API SLA has an approved SLI, denominator, exclusions, observation window, service-credit schedule and incident evidence.
- [ ] Two dress rehearsals green.
- [ ] External validation completed.
- [ ] Support/on-call active.
- [ ] Customer-visible support/status/legal/docs links and ticket drill meet the approved support schedule.
- [ ] Legal/licensing/privacy terms approved.
- [ ] MSA/Order Form/DPA/SLA/Support Schedule/procurement data room ready; quote-to-offboarding rehearsal green.
- [ ] Evaluation Charter signed, guided + independent PoV complete, interventions/deviations reported and customer result/reservations signed.
- [ ] Data-room access, redaction, expiry and revocation test green.
- [ ] Final approvers signed.

Any unchecked mandatory item means NO-GO.

---

## 29. Sign-off record template

| Field | Value |
|---|---|
| Release Candidate | |
| Commit SHA | |
| Dashboard build | |
| Supabase migration | |
| AIG revision/data version | |
| Threat-rule version | |
| Evidence index URL/hash | |
| Known limitations version | |
| Rollback version | |
| Launch model | direct-GA |
| Connector matrix evidence | Claude Code / Cursor / VS Code / OpenClaw / OpenCode |
| Deployment model | hybrid edge/local + managed control plane |
| Tenant regions | EU / US / APAC |
| Billing provider-of-record | enterprise invoice / quote-based — **not held** |
| Private-registry manifest/hash | — **not held** |
| 99.9% SLA/SLI evidence | — **not held** |
| Tenancy ADR/version | |
| Commercial Release Manifest | |
| Privacy data-flow matrix | |
| Expected-test manifest | |

| Approver | Decision | Conditions | Date |
|---|---|---|---|
| Product Owner | | | |
| Engineering Lead | | | |
| QA Lead | | | |
| Security Lead | | | |
| Operations Owner | | | |
| Commercial/Sales Owner | | | |
| Legal reviewer | | | |
| Privacy/DPO reviewer | | | |
| Finance/Billing reviewer | | | |
| Support/Customer Success Owner | | | |

Final decision: GO / CONDITIONAL GO / NO-GO

Conditional GO is forbidden when a hard gate is red.

---

## 30. Execution cadence

### Daily

- 15-minute blocker review.
- P0/P1 defect triage.
- CI and environment health review.
- Evidence completeness check.
- Risk register update.

### Twice weekly

- End-to-end golden path demonstration.
- AIG positive/negative scan demonstration.
- Security finding review.
- Scope/claim drift review.

### Weekly

- Gate review with approvers.
- Customer documentation review.
- Timeline and staffing reforecast.
- Evidence archive integrity check.

### Release week

- Feature and schema freeze.
- Only release-blocking fixes.
- Two full dress rehearsals.
- Final backup/rollback verification.
- Signed GO/NO-GO meeting.

---

## 31. Immediate next 72 hours

### Day 1

1. Create the readiness board using IDs in this document.
2. Assign named owners.
3. Freeze first-sale scope and marketing claims.
4. Record the locked direct-GA enterprise-invoice/private-registry decision and assign its evidence owners.
5. Fix Biome and clean typecheck ordering.
6. Add no-skip enforcement.
7. Confirm the deployed landing/dashboard source repository and commit.

### Day 2

1. Repair CLI/SDK package outputs.
2. Add tarball consumer tests.
3. Restore/pin AIG source.
4. Correct Compose validation.
5. Produce a concrete AIG OpenAPI diff between TypeScript client and Python bridge.
6. Select authoritative Supabase schema.
7. Begin dependency critical/high remediation.

### Day 3

1. Stand up isolated integration Supabase.
2. Execute database reset and generate types.
3. Build the first Claude Code golden-path E2E.
4. Build AIG known-positive/known-negative fixtures.
5. Create environment manifest endpoint.
6. Create evidence directory and index.
7. Complete a 72-hour licence/IP/privacy/commercial triage: freeze SKU/price/provider, identify DPA/subprocessor/region gaps and label unsupported claims.
8. Draft the Evaluation Charter/Rules of Engagement, reserve the independent assessment and obtain a design-partner PoV window.
9. Hold the first formal Gate G0/G1 review with Product, Engineering, QA, Security, Operations, Commercial, Legal, Privacy, Finance and Support owners.

Expected outcome after 72 hours:

- Scope is frozen.
- CI failures are honest and visible.
- Critical path owners are named.
- AIG and backend unknowns are converted into measurable tasks.
- Commercial/privacy/support unknowns are converted into signed decisions or explicitly marked not held.
- No stakeholder is told the product is production-ready prematurely.

---

## 32. Templates

### 32.1 Test case

| Field | Content |
|---|---|
| Test ID | |
| Requirement/claim | |
| Release/environment | |
| Preconditions | |
| Fixture/version | |
| Steps | |
| Expected result | |
| Actual result | |
| Evidence ID | |
| Pass/fail | |
| Tester/reviewer | |

### 32.2 Evidence record

| Field | Content |
|---|---|
| Evidence ID | |
| Gate | |
| Release Candidate | |
| Command/procedure | |
| Tool version | |
| Start/end timestamp | |
| Result | |
| Artefact location | |
| SHA-256 | |
| Owner/reviewer | |

### 32.3 Customer validation summary

- Organization:
- Date:
- Release Candidate:
- Participants:
- Completed cases:
- Failed cases:
- P0/P1 findings:
- Performance observations:
- Security/privacy questions:
- Product feedback:
- Agreed follow-up:
- Acceptance decision:

### 32.4 Risk exception

- Exception ID:
- Gate/requirement:
- Reason:
- Risk and affected claims:
- Compensating controls:
- Monitoring:
- Owner:
- Expiry:
- Approvers:

### 32.5 Source Assurance Ledger row

| Field | Content |
|---|---|
| File path/hash | |
| Package/classification | active / generated / external / dead / experimental |
| Runtime entry/reverse dependency | |
| Customer claim/requirement | |
| Threat and decision paths | |
| Owner/reviewer | |
| Unit/property/fuzz/mutation/E2E IDs | |
| Coverage/manual review result | |
| Shipped artefact/digest | |
| Waiver/expiry | |

### 32.6 Claim Registry row

| Field | Content |
|---|---|
| Exact claim text | |
| Audience/channel | customer / investor / procurement / internal |
| Scope and maturity | |
| Release Candidate/valid-until | |
| Entry point and test IDs | |
| Evidence IDs/hash | |
| Owner/reviewer | |
| Sales Approved | yes/no |
| Known limitation/disclosure | |

### 32.7 Commercial Release Manifest

Use the locked, filled-out version in Appendix F.1; this row is the minimum schema and cannot override the direct-GA, hybrid, EU/US/APAC, enterprise-invoice, private-registry or 99.9% decisions.

| Field | Content |
|---|---|
| SKU/package and included GA/Beta capabilities | |
| Price/meter/currency/tax/minimum term | |
| Deployment model, region and data residency | |
| Retention, SLA, support tier and escalation | |
| Licence/customer usage rights and attribution | |
| Provider/source of truth for billing | |
| Entitlement/seat lifecycle and offboarding | |
| MSA/Order Form/DPA/SLA versions | |
| Product/Commercial/Finance/Legal approval | |

### 32.8 Evaluation Charter

| Field | Content |
|---|---|
| Organization and evaluator roles | |
| Objective and in/out of scope | |
| Release Candidate/environment/expiry | |
| Mandatory/optional test IDs and thresholds | |
| Permitted support and intervention logging | |
| Rules of Engagement/stop conditions | |
| Data, recording, DPA and retention rules | |
| Defect/retest/reset/deployment-change process | |
| Customer decision owner/signature | |

### 32.9 Gate registry row

| Field | Content |
|---|---|
| Gate/decision profile | |
| Requirement ID/class | hard / conditional / informational |
| Automated check and expected denominator | |
| Owner/approver | |
| Release Candidate/evidence | |
| Result and timestamp | |
| Waiver/expiry or non-waivable reason | |

### 32.10 Metric dictionary row

Use the investor and technical metric dictionary in Appendix F.5. Every number remains **Not held** until its formula, denominator, source, RC, window and reviewer are attached.

| Field | Content |
|---|---|
| Metric name/formula/denominator | |
| Source query and data owner | |
| Release/environment/fixture | |
| Sample size/observation window | |
| Target versus actual | |
| Confidence interval/limitation | |
| Reviewer/approval | |

---

## Appendix A — Current evidence references

- Root quality scripts: package.json
- Lint configuration: biome.json
- Coverage scope/exclusions: vitest.config.ts
- E2E configuration: vitest.e2e.config.ts
- AIG architecture: docs/architecture/aig-integration.md
- AIG Compose: docker-compose.aig.yml
- TypeScript AIG client: packages/core/src/aig-scan-client.ts
- AIG sync: packages/core/src/aig-sync.ts
- Python bridge: services/aig-bridge/app
- Dashboard router: packages/dashboard/src/main.tsx
- Supabase migrations: supabase/migrations
- Deployment runbook: docs/runbooks/deployment.md
- Alerting runbook: docs/runbooks/alerting.md
- Incident runbook: docs/runbooks/incident-response.md
- Secrets runbook: docs/runbooks/secrets-management.md
- Security audit: docs/audit/security-audit.md
- Product feature audit: docs/audit/product-feature-audit.md
- Feature truth map: FEATURE_MAP.md
- Device auth: docs/device-auth.md
- Control plane: docs/control-plane.md
- Billing notes: docs/billing.md
- Commercial/investor evidence registry: docs/production-readiness/commercial-go-evidence-registry.json
- Release-facing claim and license metadata check: docs/scripts/claim-check.mjs
- First-party commercial license: LICENSE
- Product notice and preserved third-party notices: NOTICE, THIRD_PARTY_NOTICES, threats/LICENSE
- Commercial Release Manifest template: docs/production-readiness/commercial-release-manifest-template.md
- Enterprise Order Form/entitlement template: docs/production-readiness/enterprise-order-entitlement-template.md
- Support/SLA template: docs/production-readiness/support-sla-template.md
- Privacy/legal review template: docs/production-readiness/privacy-legal-review-template.md
- Investor metric dictionary template: docs/production-readiness/investor-metric-dictionary-template.md

All historical audit claims must be revalidated against the target Release Candidate.

---

## Appendix B — Required automated commands

The final command names may change while the pipeline is repaired, but the capabilities are mandatory:

~~~text
install-clean
lint-all
typecheck-all
unit-all
coverage-all
mutation-critical
contracts-all
supabase-reset-and-test
aig-compose-validate
aig-contract-test
package-consumer-test
e2e-primary
e2e-platform-matrix
expected-suite-manifest-check
security-sca
security-sast
security-secrets
security-containers
sbom-and-provenance
source-assurance-ledger
claim-registry-check
node docs/scripts/claim-check.mjs --mode=gate
license-notice-package-metadata-check
commercial-go-evidence-registry-verify
privacy-payload-contract
tenant-isolation-all-stores
backup-restore-rto-rpo
performance-smoke
demo-preflight
release-evidence-index
~~~

One top-level release command must orchestrate them and fail on any mandatory failure or skip.

---

## Appendix C — Glossary

| Term | Meaning |
|---|---|
| AIDR | AI Agent Detection & Response |
| AIG | Tencent AI-Infra-Guard integration used for deep scanning |
| GA | Generally Available and fully supported |
| Release Candidate | Immutable candidate build evaluated by all gates |
| Golden path | Primary customer journey that must work end to end |
| RLS | Row Level Security |
| SCA | Software Composition Analysis |
| SAST/DAST | Static/Dynamic Application Security Testing |
| SBOM | Software Bill of Materials |
| SLO | Service Level Objective |
| RTO/RPO | Recovery Time/Recovery Point Objective |
| Evidence pack | Versioned artefacts proving a release claim |
| NO-GO | Release/sale must not proceed |
| Evaluation Charter | Bilateral scope, test, data, support and acceptance agreement for a customer PoV |
| Commercial Release Manifest | Single approved source for SKU, price, entitlements, legal/support terms and offboarding |
| Source Assurance Ledger | File/entry-point/claim/threat/test/evidence accountability record |
| Gate registry | Machine-readable hard/conditional/informational release requirements and results |
| SLI/SLO | Measured indicator and service objective; an SLO needs formula, window and error budget |
| RPO/RTO | Maximum measured data loss and recovery time by data class |

---

## Appendix D — Verified baseline evidence to re-run on every Release Candidate

These facts are the 2026-08-04 baseline, not proof of a future release. Re-run them and attach immutable logs to the evidence index:

- `pnpm quality:gate` and `pnpm lint` stop at the invalid Biome configuration.
- A clean-state `pnpm check` fails before dependent packages can resolve the built core declarations.
- `pnpm test` passes 111 files / 1,910 tests; this is positive unit/integration evidence only.
- Coverage reports 78.78% lines, 79.61% functions and 66.65% branches while instrumenting about 101 of 263 production files and excluding critical paths.
- `pnpm test:e2e` exits successfully while all 43 configured executions are skipped; the release manifest must prove collection and execution parity.
- `pnpm build:release` completes but CLI/SDK package consumer contracts still point at missing outputs; tarball tests are mandatory.
- `pnpm knip` reports 67 unused files plus unused exports/dependencies; every item must be classified before claims are made.
- Production dependency audit reports 99 findings (including one critical and 38 high at baseline); no unwaived critical/high is a sale gate pass.
- Historical baseline (before the Tencent source integration on 2026-08-04): AIG vendor content was absent, generated CVE/fingerprint counts were zero, Compose had a `container_name`/replicas conflict, TypeScript and Python request/route contracts disagreed, and bridge health could be falsely ready. The current working tree now pins/builds Tencent v4.5.1, compiles non-empty indexes, maps the v4 payload/result contract and verifies a benign bridge E2E; the remaining portability, authentication/HA, positive-fixture and incident-mapping gates are recorded above.
- The repository lacks a proven authoritative Supabase reset path: local configuration/schema ordering, duplicate migration prefixes, tenancy semantics and generated-type drift must be resolved and tested from zero plus N-1.
- The release workflow references a root `pnpm release` command that is not currently defined; branch-push publication, mutable CI inputs and source/lockfile mutation must be closed before promotion.
- Release conventions currently disagree on `main` versus `master`; artefact signing is optional/partial; dashboard deploy uses an unfrozen/direct path; plugin/marketplace and missing `landing` workspace provenance need an atomic consumer test; and the secret scan depends on a hidden `.gitleaks.toml` symlink.
- Extension rollback evidence must use a known-good re-release/pin or emergency disable; unpublishing a marketplace listing is not an automatic downgrade of already installed clients.
- Leak/source-map checks currently can skip missing artefact roots; all expected roots must fail closed. VSIX publishing tools are unpinned, and the private Claude package’s declared `health.cjs` bin needs an explicit internal-only or shipped/tested decision.
- The deployed dashboard router does not currently mount `/pilot` or `/pricing` although onboarding, verify, billing and landing UI link to them; onboarding polling has no bounded expiry/retry contract, and customer secrets/raw JSON can appear in DOM/screen-share paths.
- Browser evidence currently relies on MemoryRouter/manual mounts without a deployed-RC route crawl/axe/console gate; incident/schema fallbacks and missing support/status/legal footer paths must be made visible or closed before sale.
- Customer-facing privacy statements do not yet cover all managed telemetry and AIG payload flows; use synthetic data until the field-level matrix, opt-in, DPA and payload assertions pass.
- Baseline privacy review also finds raw URL/tool payload paths, configuration/runtime default disagreement, incomplete Sentry/OTLP/browser redaction, public wildcard-CORS AIG handling, unbounded webhook/waitlist/event JSON and an audit immutability versus admin-delete/CASCADE conflict; these require exact RC evidence, not a generic privacy checklist.

---

## Appendix E — Commercial/investor evidence runbook (current working tree)

This appendix is a short operational checklist for the customer/investor decision. It does not grant approval and must be re-run against the immutable Release Candidate.

### E.1 Generate the claim and licence inventory

```text
node docs/scripts/claim-check.mjs --mode=inventory --json > claim-check.inventory.json
```

Archive the JSON, the registry SHA-256 printed in it, every claim-facing and `artifactScans` SHA-256 value, the commit SHA, and the environment manifest. Review every `unapprovedHits`, `licenseCheck.errors`, `licenseCheck.warnings`, `missingRoots`, `missingArtifactRoots` and `emptyArtifactRoots`. Inventory mode is allowed to report open items; it must never be presented as a pass for sale.

### E.2 Enforce the commercial gate

```text
node docs/scripts/claim-check.mjs --mode=gate --json > claim-check.gate.json
```

The command must exit non-zero until all hard registry rows are closed, every release-facing claim is approved and unexpired, every scan root exists, and LICENSE/NOTICE/package metadata are reconciled. A zero exit code is necessary but not sufficient: legal, privacy, finance, support, independent security and customer acceptance records must still be attached to the evidence index.

### E.3 External evidence packet — required records, not placeholders

| Packet | Required record | Named approver | Current state |
|---|---|---|---|
| Commercial | Commercial Release Manifest, approved quote/order, provider-of-record and quote-to-offboarding rehearsal | Commercial/Sales + Finance/Billing | **Not held** |
| Legal/IP | Counsel-approved LICENSE/NOTICE/package matrix, attribution, vendor/source chain-of-title | Legal | **Not held; current machine check fails** |
| Privacy | Field-level payload/data-flow matrix, DPA/TOM/SCC, subprocessor/region/retention/deletion receipts | Privacy/DPO + Legal | **Not held** |
| Security | Independent pentest/equivalent assessment, remediation and RC-scoped retest | Security + assessor | **Not held** |
| Support | Support schedule/SLA, status/security/privacy links, reachable ticket and measured escalation drill | Support/Customer Success + Operations | **Not held** |
| Customer PoV | Signed Evaluation Charter, independent run, interventions/deviations, result/reservations | Customer + Product/QA | **Not held** |
| Investor | Metric dictionary and source records for every published technical/customer/compliance/financial metric | Product + Finance + Legal | **Not held** |

“Not held” means there is no acceptable evidence record in the current repository/evidence index; it does not mean the underlying control is false. No row may be changed to `closed` until the record is received, hashed, reviewed and linked to the same Release Candidate.

### E.4 Current legal metadata status

The mechanical metadata contradiction identified in the baseline has been addressed in the working tree:

- `LICENSE` now contains the proprietary AIDR draft terms.
- `NOTICE` now identifies first-party proprietary scope and points to preserved third-party notices.
- `THIRD_PARTY_NOTICES` records the direct dependency baseline and requires a lockfile-derived transitive SBOM/notice bundle for the Release Candidate.
- Every first-party workspace package now declares `"license": "Proprietary"`, including the dashboard package.
- The claim gate still reports stale first-party Apache/dual-license text in `README.md`, `CONTRIBUTING.md` and `packages/openclaw/README.md`; those files are outside this implementation scope and remain a legal/claims hard blocker until corrected and reviewed.

These are source changes, not legal approval. Counsel must still approve the actual terms, attribution, threat-rule interaction, third-party compatibility, package distribution rights and customer Order Form before the legal gate can close.
- Pricing, billing provider, licence and feature claims conflict across repository documents/code; only the approved Commercial Release Manifest is buyer-facing evidence.

---

## Appendix F — Locked commercial templates (approval required)

These templates encode the chosen direct-GA commercial shape. Empty fields are intentional: they identify evidence that Finance, Legal, Privacy/DPO, Operations, Support and the customer still need to provide. Do not replace an empty field with an assumption or a placeholder approval.

### F.1 Commercial Release Manifest

| Field | Locked decision / required value | Evidence / approval |
|---|---|---|
| Release Candidate | Immutable commit, package versions, image/plugin digests and registry manifest hash | Engineering + Release |
| Launch model | Direct GA | Product + Engineering + QA + Security |
| Connector scope | Claude Code, Cursor, VS Code, OpenClaw, OpenCode | Real-host support matrix and E2E reports for every connector |
| Deployment model | Hybrid: local/edge enforcement, managed control plane, private AIG bridge where enabled | Operations + Security architecture |
| Regions | EU, US, APAC tenant placement | Privacy/DPO + Legal region/subprocessor matrix |
| Billing | Enterprise invoice / quote-based order; no self-service checkout claim | Finance/Billing provider-of-record decision |
| Distribution | Authenticated private registry for CLI, SDK, connectors, plugins and signed artifacts | Release Engineering install/revoke/air-gap evidence |
| Metering unit | Connected protected-agent installation unless a signed Order Form specifies another unit | Finance + entitlement contract test |
| Price/currency/tax/minimum term | **Not held — Finance to complete** | Approved price book and quote |
| Included GA capabilities | All connector scope above only after each connector gate closes; AIG capabilities only when G3 is green | Product claim registry |
| Availability | 99.9% monthly managed control-plane/dashboard API target | Approved SLA, SLI denominator, exclusions and service-credit schedule |
| Support | Published tier, hours, channel, severity targets and escalation | Support/Operations sign-off and ticket drill |
| Data residency/retention | Tenant-selected EU/US/APAC placement; exact retention by data class | Privacy/DPO + Legal + deletion receipts |
| Licence and attribution | Proprietary AIDR first-party terms; third-party terms in LICENSE/NOTICE/THIRD_PARTY_NOTICES/threats/LICENSE | Legal approval |
| Renewal/cancellation/offboarding | Contractual notice, access revocation, artifact entitlement expiry, export and deletion receipt | Finance/Legal/Support rehearsal |
| Manifest status | **OPEN — not a sales approval** | Named approver and SHA-256 required |

### F.2 Enterprise Order Form and entitlement record

#### Order Form fields

| Field | Customer-completed value |
|---|---|
| Customer legal entity / billing address / tax ID | |
| Effective date / term / renewal / notice | |
| SKU and protected-agent quantity | |
| Connector scope and supported host versions | |
| Deployment mode and tenant region (EU / US / APAC) | |
| Private-registry organization, package scope and download identities | |
| Price, currency, tax, invoicing cadence, payment terms | |
| Availability SLA and approved exclusions | |
| Support tier, hours, channel, severity schedule, escalation | |
| Data categories, retention, deletion, export, subprocessor and transfer terms | |
| Licence rights, seats, internal-use/backup limits, attribution and prohibited resale | |
| Security review, DPA/TOM/SCC, MSA and policy versions | |
| Cancellation, suspension, revocation, export and deletion receipt process | |
| Customer security/procurement contacts and acceptance authority | |
| Customer signature / AIDR signature / Legal and Finance approval | |

#### Entitlement record (authoritative machine-facing shape)

```text
entitlement_id: <immutable id>
customer_id: <tenant/legal entity id>
order_form_id: <signed order id>
release_candidate: <commit + manifest hash>
status: pending | active | suspended | expired | revoked
regions: [EU | US | APAC]
connectors: [claude-code, cursor, vscode, openclaw, opencode]
protected_agent_limit: <integer from signed order>
registry_scopes: [cli, sdk, connector, plugin, dashboard]
features: <approved flags only; no hidden or experimental capability>
effective_at: <RFC3339>
expires_at: <RFC3339>
invoice_reference: <finance source-of-truth>
revocation_reason: <required for suspended/revoked>
audit_event_ids: [<provision>, <change>, <revoke>, <export>, <delete>]
```

Every entitlement transition must be idempotent, tenant-scoped, audited and correlated to the invoice/order. A dashboard screenshot is not entitlement evidence.

### F.3 Support and 99.9% SLA schedule

#### Availability definition

```text
monthly_availability = (eligible_service_minutes - unavailability_minutes)
                       / eligible_service_minutes * 100
target = 99.9%
scope = managed control plane and dashboard API
```

Before contract use, the schedule must define: eligible endpoints, synthetic probe locations, denominator, dependency treatment, approved maintenance windows, customer-caused exclusions, regional calculation, incident start/stop semantics, evidence retention, service credits, and dispute process. The target is locked; the contractual SLA is **not approved**.

#### Support schedule fields

| Field | Value / evidence required |
|---|---|
| Tier 1 channel and hours | **Not held — Support to approve** |
| Security incident channel and encryption | **Not held — Security/Support to approve** |
| Severity definitions (S1–S4) | Approved definitions and examples |
| Acknowledgement / update / workaround / resolution targets | **Not held — Support/Legal to approve** |
| Regional holidays and language coverage | **Not held** |
| On-call ownership and escalation | Named owner, rota and tested page |
| Status page and incident communication | Public/private status URL and drill evidence |
| Diagnostic consent and redaction | Consent record, redacted export and retention rule |
| SLA measurement and service credits | Finance/Legal-approved schedule |
| Ticket drill | Timestamped synthetic incident from open to closure |

### F.4 Privacy and legal review record

| Review item | Required decision/evidence | Status |
|---|---|---|
| First-party licensing | Proprietary AIDR terms in LICENSE; package metadata reconciled | **Draft changed; Legal approval open** |
| Third-party notices | THIRD_PARTY_NOTICES plus generated transitive SBOM/notice bundle | **Baseline present; generated RC bundle open** |
| Threat-rule licence | DRL 1.1 in threats/LICENSE and attribution propagation | **Evidence/review open** |
| Processing roles | Controller/processor/service-provider role by deployment mode | **Not held** |
| Data inventory | Commands, URLs, paths, prompts, events, incidents, AIG payloads, telemetry, traces, support artifacts | **Field-level matrix open** |
| Outbound domains | Exact destination, purpose, region, encryption, authentication | **Not held** |
| Retention/deletion/export | Numeric retention per data class, legal hold, backup expiry and deletion receipt | **Not held** |
| Tenant residency | EU/US/APAC placement and cross-region negative test | **Not held** |
| Subprocessors/transfers | Approved list, DPA, TOM, SCC/transfer mechanism and change notice | **Not held** |
| Security/privacy claims | Claim Registry wording matches actual mode and payload | **Open; claim gate required** |
| Customer/evaluator data | Synthetic-data default, consent, recording, support access and expiry | **Evaluation Charter open** |
| Counsel sign-off | Named Legal reviewer, date, version, scope and exceptions | **NOT HELD — cannot infer from repository** |

### F.5 Investor technical and commercial metric dictionary

No number is filled in below until the source, denominator, Release Candidate, observation window and reviewer are attached. “Not held” means no evidence has been supplied.

| Metric ID | Metric / formula | Source and denominator | RC / environment / window | Owner / reviewer | Status |
|---|---|---|---|---|---|
| INV-M001 | Protected-agent activation rate = activated enrolled agents / ordered agent entitlements | Entitlement ledger + device enrollment events | | Product + Finance | Not held |
| INV-M002 | Connector E2E pass rate = mandatory scenarios passed / mandatory scenarios discovered | Expected-suite manifest + real-host reports for all five connectors | | QA + Product | Not held |
| INV-M003 | Monthly managed availability = (eligible minutes − unavailability) / eligible minutes | SLI probe and incident timeline; denominator/exclusions must be signed | | Operations + Legal | Not held |
| INV-M004 | Enrollment completion rate = successful enrollment / valid authorization attempts | Device-start, verify, enrollment events; exclude malformed/abusive requests explicitly | | Product + Security | Not held |
| INV-M005 | Detection precision/recall by fixture class = TP/(TP+FP), TP/(TP+FN) | Versioned benign/malicious corpus and independent labels | | Security + QA | Not held |
| INV-M006 | Customer PoV completion = mandatory cases passed / mandatory cases agreed in Charter | Signed Charter, immutable run report and intervention log | | Customer Success + customer | Not held |
| INV-M007 | AIG dataset readiness = signed installed-consumer hash match and known-positive pass | Dataset manifest, packed artifact hash and fixture output | | Engineering + Security | Not held |
| INV-M008 | Support SLA attainment = tickets meeting acknowledgement/update target / eligible tickets | Ticket system export with severity, consent and time zone | | Support + Operations | Not held |
| INV-M009 | Net retention / revenue / pipeline metrics | Finance source of truth; formula, cohort, currency, period and audit trail required | | Finance + Legal | Not held |

Any investor deck, data-room answer, customer case study or sales script must reference a metric ID and its evidence hash. Unverified “customers”, “compliance”, “availability”, “coverage”, “CVE count”, “speed”, “savings” or “market” numbers remain excluded from external material.

## Final principle

The objective is not to make the demo look successful. The objective is to create an environment in which a customer can challenge the product, observe failures honestly, reproduce results, and still conclude that AIDR is technically credible, secure, operable and commercially supportable.

Until the mandatory gates in this document are green for one immutable Release Candidate, the correct status remains **NO-GO**.
