# AIDR first-customer sales and procurement packet v8

**Status:** Internal buyer-review draft; **NO-GO for a production sale or supported deployment**. Prepared 13 September 2026 for work package T41. No customer, approved quote, signed order, or customer acceptance is attached. This document is a fillable packet, not a Commercial Release Manifest, contract, security attestation, or authorization to make a claim.

The current engineering reference is the [v8 customer candidate](./2026-09-13-customer-candidate-v8.md), built from commit `07a4fc4ad3b0cad1c2ff84c93082e66a27bf3fa0` with a **dirty working tree**. Its local checks, loopback installation rehearsal and measured single-host resource profile do not identify a signed release and do not prove behaviour in a customer's AI host, network, region, or operations team. Refresh every evidence link and decision for the exact clean, signed candidate before external issue. The [commercial evidence registry](./commercial-go-evidence-registry.json) says `NO-GO`; its 13 hard gates remain open, and the [gate receipt file](./commercial-gate-receipts.json) records each one as `open` with the external input it still needs.

## Buyer overview and claim boundary

AIDR is an evaluation-stage control for selected AI coding-tool actions. A host connector passes an observed tool request to a shared policy/evaluation core, which returns a decision; configured local audit, managed telemetry, incident, and dashboard paths can make that decision reviewable. The [architecture description](../architecture.md), [feature inventory](../../FEATURE_INVENTORY.md), and [first-customer installation guide](../../deploy/FIRST_CUSTOMER.md) describe the implementation. A decision returned by a connector does **not** by itself show that the host prevented an external side effect.

The intended direct-sale profile is enterprise invoice, private distribution, Claude Code, Cursor, VS Code, OpenClaw, and OpenCode, with managed-cloud or customer-hosted control-plane options and EU/US/APAC placement. These are **commercial targets**, not approved support, regional residency, registry delivery, or availability claims. The source and local tests show an engineering candidate; customer-specific connector, deployment, privacy, security, finance, and support evidence is still required. Codex and the SDK exist as engineering surfaces and are recorded in the [native support matrix](../../deploy/native/support-matrix.json), but they are outside the five-connector direct-GA order template unless Product expressly adds and accepts them.

| Buyer statement for a controlled discussion | Current basis | Condition before it becomes a sold claim |
| --- | --- | --- |
| A synthetic, read-only `/demo` can show the decision and evidence workflow. | [Controlled demo runbook](./controlled-demo-runbook.md); local route/preflight checks in the [v8 candidate](./2026-09-13-customer-candidate-v8.md). | Disclose fixture status; verify the deployed URL, routes, browser console, and approved sales/support/legal links. A demo outcome is not detection effectiveness. |
| A portable installer and self-hosted preparation flow exist. | [First-customer guide](../../deploy/FIRST_CUSTOMER.md); v8 local kit (342 files) and loopback rehearsal. | Clean-source publisher signature, trusted verifier, customer TLS/ingress, network, backup, restore, monitoring, native-host, and operator acceptance. |
| Every Edge Function the dashboard calls has a machine-checked contract test. | [Edge function contract manifest](./edge-function-contract-manifest.json) enforced by `scripts/check-supabase-edge-contracts.mjs` (16/16). | This is a source-and-contract property. It is not a deployed-environment or customer acceptance result. |
| A subscription portal with a provider-of-record settlement state machine exists. | [Billing portal](../billing.md), `supabase/functions/billing-portal/`; contracts exercised against a local provider fixture. | Live provider keys, an approved SKU/price catalogue, finance reconciliation and accounting approval. A locally produced receipt is **not** an audited payment record. |
| Cloud preparation can target a customer-provided managed Supabase project. | [First-customer guide](../../deploy/FIRST_CUSTOMER.md). | Provision and test the actual project, region, identity, secrets, Edge functions, ingress, and retention. Local preparation is not a hosted deployment. |
| Tenant-scoped enterprise order **requests** can enter `pending_finance`. | [Invoice intake contract](./invoice-entitlement-v6.md). | Finance-approved quote/order, provider receipt, audited entitlement lifecycle, and customer-visible reconciliation. An intake record is not an invoice, payment, or seat grant. |

Do not put performance, recall, false-positive, return-on-investment, certification, compliance, 99.9% availability, complete-coverage, or customer-reference claims in a proposal unless the exact wording, release, workload, independent proof, and approvers are recorded in the [claim/evidence registry](./commercial-go-evidence-registry.json). No customer success story is available for this packet.

## Architecture, data, and deployment decision

The proposed control path is **AI host and connector → local evaluator/policy → host decision and local record**. When managed features are configured, a separate path sends scoped telemetry and policy/enrollment traffic to a tenant control plane and dashboard. Optional reputation, AIG bridge, browser diagnostics, SIEM, webhooks, exports, and support bundles add distinct destinations. The [data-flow and privacy register](./data-flow-privacy-v6.md) names source code, fields, triggers, and unverified destinations for each path. It is an engineering inventory, not a live packet capture, DPA, or data-residency attestation. Commands, URLs, paths, incident data, and optional scan targets can be sensitive; buyer review must identify which features and egress paths are enabled.

| Decision | Managed-cloud proposal | Customer-hosted proposal | Proof to attach before acceptance |
| --- | --- | --- | --- |
| Control plane | Customer-designated managed project; account, region, configuration, and service ownership pending. | Generated single-host Docker/Supabase baseline; customer owns host, TLS proxy, ingress, backup destination, and operations. | Exact topology, version/digest, DNS/TLS, routing, secret custody, tenant isolation, login, and recovery record. |
| Endpoint integration | Installed connector on every agreed host/OS/version. | Same requirement. | Signed artifact and private-delivery verification, install/rollback, host invocation, blocked side effect, benign twin, disabled/crashed/offline/restart cases. |
| Data movement | Field-level packet capture for chosen region, telemetry, optional providers, browser, backup, and export. | Same, including egress from local endpoints and customer-controlled processors. | Destination/region/subprocessor register, DPA/TOM/SCC as applicable, retention, deletion, backup-expiry and legal-hold receipts. |
| Availability and support | Proposed managed-control-plane target requires measured monthly SLI and approved exclusions/credits. | Customer and vendor responsibility split must be contracted; the single-host baseline has no proven HA. | Approved [support/SLA schedule](./support-sla-template.md), ticket drill, on-call owner, authenticated workload, failover and independent-host restore. |

Initial self-hosted sizing guidance is in [resource requirements](../../deploy/RESOURCE_REQUIREMENTS.md), [resource sizing v5](./resource-sizing-v5.md) and the current measured profile in [resource sizing v8](./resource-sizing-v8.md). The v8 measurement is a single Windows Docker Desktop development host with an isolated loopback fixture: 11 services at a median **1.501 MiB container memory** and **13,05% of one core** idle, with a 39,43 MiB connector payload and a hook process at roughly 0,8 s wall / 99 MiB peak RSS under diagnostics. Those are planning allocations and one idle data point, not measured fleet throughput or a commercial capacity guarantee. Record the customer's endpoints, peak tool actions, policy/ingest volume, retention, backup window, and concurrency, then run a representative load and recovery test before quoting a capacity or SLO.

## Host and feature support schedule to complete with the buyer

The table below is a **target-scope worksheet**. No row is approved as a supported host/version. The [native support matrix](../../deploy/native/support-matrix.json) now declares, per sold connector, the supported platforms, architectures, contexts, interception point, output interception point, tamper-resistance note, known bypasses and unobserved actions. `deploy/native/run-support-matrix.mjs` probes the local machine and reports **NO-GO** with `HOST_UNAVAILABLE` for every connector whose host is not installed; on this development host only OpenCode 1.18.30 and Codex CLI 0.141.0 were found, and no row has a named acceptance record.

| Proposed connector | Buyer OS / host build / installation owner | Required proof for each agreed build | Current support decision |
| --- | --- | --- | --- |
| Claude Code | To be named | Signed install; real host deny/allow and side-effect trace; offline, failure, restart, removal. | Open; host not present on the reference machine. |
| Cursor | To be named | Same, including extension/hook enablement and updates. | Open; host not present on the reference machine. |
| VS Code | To be named | Same, including extension/hook enablement and updates. | Open; host not present on the reference machine. |
| OpenClaw | To be named | Same, including after-tool/output-consumption boundary. | Open; host not present on the reference machine. |
| OpenCode | To be named | Same, including plugin/profile/model and provider prerequisites. | Open; version probed only (1.18.30). |
| Codex (not in the direct-GA template unless added) | To be named | Same; the host fails open on a crashing or untrusted hook, so the connector maps `ask` to an explicit deny and denies its own internal errors. | Open; version probed only (0.141.0). |

Explicit exclusions and warnings for the customer schedule: host actions outside an invoked hook cannot be promised as protected; PostToolUse/after-tool paths cannot reverse an action already performed; an observed deny string alone does not establish side-effect prevention; Codex has a documented host-owned fail-open boundary; and MCP gateway use still needs real client/server and direct-upstream-bypass acceptance. Endpoint isolation, fleet response, automatic rollback, full cross-agent forensic chain, and complete output-before-model inspection are not included in a first offer without separate evidence and approval. List any narrower approved scope and compensating controls in the signed order and PoV Charter, rather than leaving an ambiguity in marketing copy.

## Buyer environment and requirements worksheet

Sales Engineering and the customer platform/security owners complete this before a quote or PoV access is issued. Attach the customer's actual procurement questionnaire and replace every `TBD` with an owner, value, and evidence link.

| Required input | Customer answer / accountable owner | Why it changes the offer |
| --- | --- | --- |
| Legal entity, billing/tax jurisdiction, procurement and security contacts | TBD | Quote, DPA, invoicing, notices and acceptance authority. |
| Deployment mode, tenant region, controller/processor, subprocessors and transfer restrictions | TBD | Project placement, egress, backup and privacy terms. |
| AI hosts, exact versions, OS images, managed-device tools, admin rights and expected update cadence | TBD | Native support matrix, signed delivery and rollback. |
| Protected agent count, seat definition, peak concurrent actions and expected telemetry/retention | TBD | SKU, load test, quotas, sizing and commercial terms. |
| Network proxy, TLS/ingress owner, DNS, allowlisted destinations, air-gap requirement | TBD | Enrollment, optional reputation/AIG, managed policy and container delivery. |
| IdP/MFA/SCIM, tenant ownership, break-glass and service-account process | TBD | Identity setup and access-control tests. |
| Logging, SIEM, support-bundle consent, incident response and deletion/legal hold | TBD | Data-flow review, operator schedule and offboarding. |
| Permitted safe canaries, testing window, independent evaluator and stop contact | TBD | Authorized, repeatable PoV with benign negatives and side-effect proof. |

## Procurement and security questionnaire: draft answers

These are deliberately conditional answers. Each final response needs the buyer's question ID, exact release/configuration, artifact digest, evidence owner, reviewer, and expiry date. `Open` means the linked source does not yet support an affirmative procurement answer.

| Buyer question | Evidence-bounded draft answer | Source and owner | Remaining approval/evidence |
| --- | --- | --- | --- |
| What is the product's supported scope? | Six connectors are implemented; five are intended for direct-GA, subject to a versioned host/OS matrix that now exists as a manifest. | [Native support matrix](../../deploy/native/support-matrix.json), [COM-010](./commercial-go-evidence-registry.json); Product + QA + Support. | Open: signed artifacts, private install, real-host side effects, rollback and named support owner per row. |
| How is an action blocked? | A connector can request a local policy decision; enforcement depends on the host invoking and honoring that boundary. The matrix names each connector's interception point and known bypasses. | [Architecture](../architecture.md), [native support matrix](../../deploy/native/support-matrix.json); Endpoint Engineering + QA. | Open: independent benign/deny/failure traces on each buyer host. |
| Which functions can the dashboard call, and are they tested? | Sixteen Edge Functions are invoked from browser code; each has a declared contract test enforced by a repository gate. | [Edge function contract manifest](./edge-function-contract-manifest.json); Engineering. | Contract tests are source-level. Open: deployed-environment and browser acceptance. |
| What data is collected and where is it sent? | Local and configured managed/optional flows differ; the data register lists possible fields and destinations. | [Data-flow register](./data-flow-privacy-v6.md); Privacy/DPO + Security. | Open: exact-build wire capture, region/provider/retention/deletion map, DPA and buyer approval. |
| Is customer data tenant isolated? | Tenant authorization, server projection and local tests exist in the candidate. The billing portal additionally refuses a client-supplied tenant, customer or subscription identifier. | [V8 candidate](./2026-09-13-customer-candidate-v8.md), [first-customer guide](../../deploy/FIRST_CUSTOMER.md); Backend + Security. | Open: deployed cross-tenant negative tests and customer configuration review. |
| How are users enrolled and authenticated? | Bootstrap, recovery, enrollment and MFA-related controls have local coverage; provider delivery varies by deployment. | [First-customer guide](../../deploy/FIRST_CUSTOMER.md); Identity + Operations. | Open: customer IdP/SMTP/MFA, TLS ingress, actual browser-to-host pairing and lifecycle acceptance. |
| How are artifacts and updates trusted? | Hash/verification and signing tools exist; the current portable engineering envelope has no approved publisher signature (`publisher_authenticated=false`). | [First-customer guide](../../deploy/FIRST_CUSTOMER.md), [v8 candidate](./2026-09-13-customer-candidate-v8.md); Release Engineering. | Open: clean build, approved key custody, detached trust policy, signed private delivery, upgrade/rollback drill. |
| Are vulnerabilities independently assessed? | Local dependency checks (`pnpm audit:prod`: 0 advisories) and security tests are engineering evidence only. | [V8 candidate](./2026-09-13-customer-candidate-v8.md), [SEC-EXT-001](./commercial-go-evidence-registry.json); Security Lead. | Open: independent scoped report for sold candidate and critical/high remediation/retest. No certification claim. |
| How is detection effectiveness measured? | A benchmark protocol exists that separates a development set from a blind holdout, requires benign twins, keeps unsupported/timeout cases in the denominator, reports p50/p95/p99 and CPU/RAM (unmeasured when absent) and refuses `production_accepted` without an independent evaluator signature. | `scripts/benchmarks/evaluate.mjs`; Detection Research + QA. | **Open (T39):** no corpus, no customer benign workload, no independent evaluator. Do not quote a detection rate. |
| What availability, RPO/RTO and support are committed? | Templates and local recovery/load probes exist; one idle resource profile has now been measured on a single development host. No approved SLA, support rota, or customer failure-domain measurement is held. | [Support/SLA template](./support-sla-template.md), [resource sizing v8](./resource-sizing-v8.md); Operations + Support + Legal. | Open: contracted targets/exclusions, monthly SLI, ticket drill, independent-host restore and customer workload. |
| Can audit data be exported and deleted? | Tenant export and bounded live-data offboarding paths exist. | [First-customer guide](../../deploy/FIRST_CUSTOMER.md), [data-flow register](./data-flow-privacy-v6.md); Backend + Privacy. | Open: customer export custody, external backup expiry, retention/legal-hold and deletion receipt acceptance. |
| How does billing grant or revoke seats? | The dashboard records `pending_finance` order intake; a separate subscription portal implements a provider-of-record settlement state machine, seat projection and cancel/refund contracts. It does not mark payment by itself. | [Invoice intake v6](./invoice-entitlement-v6.md), [billing v6](./billing-v6.md), [V8 candidate](./2026-09-13-customer-candidate-v8.md); Finance + Billing Engineering. | Open: approved price/order, live provider keys, authenticated settlement, and provider-ledger reconciliation with accounting. |
| What legal terms and subprocessors apply? | Draft templates exist; counsel and Privacy have not approved customer-specific terms. | [Privacy/legal template](./privacy-legal-review-template.md), [commercial manifest template](./commercial-release-manifest-template.md); Legal + Privacy. | Open: MSA, licence/NOTICE, DPA/TOM/SCC, subprocessor/region and transfer review. |
| Where can we contact Sales, Support, Security and see service status? | URLs are configuration inputs, not proof that a deployed route reaches an owner. | [Controlled demo runbook](./controlled-demo-runbook.md); Sales Engineering + Support + Operations. | Open: approve URLs and email/contact ownership, then crawl deployed links and complete a timestamped ticket drill. The T41 static preflight did not establish a live sales CTA destination. |

## Quote and order schedule — fields requiring approval

Use the [Commercial Release Manifest template](./commercial-release-manifest-template.md) and [Enterprise Order Form](./enterprise-order-entitlement-template.md) as the signed source of truth. This packet supplies **no price, discount, term, tax treatment, entitlement, support level, legal warranty, or start date**. Finance and Legal must approve the complete row set for one customer and one clean, signed release; the buyer must sign the resulting order. The [gate receipt file](./commercial-gate-receipts.json) records, per gate, which external input is still missing.

| Binding field | Proposed value / evidence / approval |
| --- | --- |
| Customer legal entity, address, tax ID, contracting and technical acceptance authorities | TBD |
| Quote and Order Form IDs, issue/expiry/effective dates, term, renewal and cancellation notice | TBD |
| Exact release commit, artifact manifest digest, publisher signer and permitted update channel | TBD |
| SKU, included capabilities, five-connector host/OS/version schedule, explicit exclusions | TBD |
| Deployment mode, region, data flows, optional providers, customer/vendor responsibility split | TBD |
| Protected-agent quantity, metering unit, overage and seat change process | TBD |
| Currency, unit/total price, tax, invoice cadence, payment terms, provider of record | TBD |
| Entitlement issue/suspend/revoke/expiry process, registry download rights, offboarding | TBD |
| Support tier, hours/languages, severity, contacts, escalation, status page and diagnostic consent | TBD |
| SLA scope/SLI/exclusions/credits, recovery and maintenance commitments if offered | TBD |
| MSA, licence/NOTICE, DPA/TOM/SCC, subprocessor list, retention/deletion and breach terms | TBD |
| Pilot/PoV fees if any, success criteria, defect/remedy rules and production-conversion conditions | TBD |
| Finance, Product, Security, Support, Privacy, Legal and customer signatures with dates | TBD |

A customer-created `pending_finance` request is only an intake identifier. Do not quote it as an issued invoice, settled transaction, or active entitlement. The sold scope must equal the installed artifact, supported host schedule, configured features, support schedule and customer evidence; any difference requires a revised order and renewed acceptance.

## Repeatable demo and customer proof of value

**Orientation demo.** The operator follows the [12-minute controlled demo runbook](./controlled-demo-runbook.md): configure an isolated synthetic `/demo`, run the suspicious-command, package-integrity and MCP-request fixtures, inspect synthetic inventory/incident evidence, show invoice-only pricing and the subscription-portal state, and check support/status/privacy/security/terms links. Record the fixture version, evaluator, date, deployed build digest, route screenshots, preflight/route-smoke receipts and deviations. Stop if a real secret or customer datum appears. Static preflight is a structural check; a real hosted evaluation needs a dedicated account and tenant. The deployed sales CTA and support/legal links must be verified in a browser before the session.

**PoV Charter before access.** Customer Security, Platform, an end user, and AIDR Product/QA agree in writing on: exact signed candidate and configuration; host/OS/version and permitted network; mandatory and optional case IDs; safe canaries and Rules of Engagement; data class, recording consent, retention/deletion; support intervention counting; defect severity/retest rules; success/performance thresholds; and named technical and commercial signers. Use [the validation plan's Charter and independent-evaluation model](./customer-investor-validation-master-plan.md#183-evaluation-charter). The guided walkthrough is orientation; an independent customer-run sandbox/PoV and signed reservations are separate evidence.

| Mandatory PoV observation to agree in the Charter | Pass evidence and negative control | Current state |
| --- | --- | --- |
| Install, enroll, configure policy and roll it back for each quoted host/version. | Signed artifact/host version, tenant ID, policy revision, install/rollback logs and independent host action trace. | No buyer environment or signed artifact. |
| Block an authorized safe canary while allowing its benign twin. | Host tool-attempt trace plus connector receipt **and** independent observation that the blocked side effect did not occur; benign side effect does occur. | Local/synthetic tests only. |
| Exercise disabled hook, crash, timeout, offline interval and restart. | Explicit observed host behavior and gaps; do not convert missing attempt/receipt into a pass. | Native matrix open; scenario templates only. |
| Review policy, incident, audit/export and tenant isolation. | Correct-tenant record and export; cross-tenant read/write denied; redacted capture and discrepancy log. | Local control-plane evidence only. |
| Verify optional MCP, reputation, AIG, SIEM, billing and response features **only if sold**. | Each chosen feature's real boundary, failure mode and delivery/side-effect receipt; otherwise mark excluded. | Customer integration and live provider keys open. |
| Verify privacy and operations for chosen mode/region. | Wire destination/field capture, support ticket drill, backup/restore and deletion/retention plan, workload and failure test against pre-agreed thresholds. | Customer and legal acceptance open. |

For each case retain the attempt, result, environment, exact candidate hash, policy and host versions, timestamps, independent observer, deviations, support interventions, defects and retest outcome. Publish both passes and failures. The customer signs the result and reservations; a guided demonstration, synthetic fixture, version probe, or local loopback test cannot substitute for that record. Never invent a named customer, measured savings, detection rate or testimonial.

## Procurement handoff and release decision

| Deliverable to place in the buyer data room | Accountable owner | Current disposition |
| --- | --- | --- |
| Candidate-bound product/claim sheet, support matrix, architecture/data-flow, known limitations and signed artifact/provenance | Product + Release Engineering + QA | Draft/source, local evidence and an unsigned envelope only. |
| Completed buyer questionnaire with source, immutable artifact hash, reviewer and expiry for each answer | Sales Engineering + Security | Template above; customer questions not received. |
| Approved Commercial Release Manifest, itemized quote/order, finance-to-entitlement and revocation rehearsal | Sales + Finance + Product + Legal | Not held; `pending_finance` intake plus a fixture-tested settlement contract only. |
| MSA/licence/NOTICE, DPA/TOM/SCC, region/subprocessor/deletion review | Legal + Privacy/DPO | Not held. |
| Independent assessment/retest and operational evidence for availability, support, restore and incident response | Security + Operations + Support | Not held for the sold candidate and customer. |
| Demo trace, signed Charter, independent PoV case pack, assistance log and customer signed result/reservations | Sales Engineering + QA + customer evaluator | Not held. |

Before any external issuance, Sales Engineering checks the exact deployed website CTA and contact routes, the current registry, clean release digest, approved claim text and each evidence item's named owner/date/hash. Product, Finance, Legal, Privacy, Security, Operations and Support approve their respective terms and records. The final `GO` is a documented commercial release decision for the **same** candidate and order scope; this draft leaves T41 and production sale **open**.
