# Commercial Release Manifest — Direct-GA Template

Status: **DRAFT / NOT APPROVED**
Source inventory updated: **2026-10-06**. No accepted release candidate, price
book, production provider contract or signed order is supplied. Source facts
and proposals below are review inputs, not approved sale terms.
Registry: `commercial-go-evidence-registry.json`
Decision: direct GA, six direct-GA connectors including Codex CLI (Product decision 2026-10-11; Codex with its documented host limits: fail-open on a crashing or untrusted hook, no output-side interception, Bash and apply_patch matcher only), hybrid deployment, EU/US/APAC, online cloud sales plus enterprise invoice, private registry, 99.9% monthly managed control-plane/dashboard API target. All launch evidence remains open.

Complete this document for one immutable Release Candidate. Empty values are blockers, not defaults.

| Field | Value | Evidence / approver |
|---|---|---|
| Release Candidate commit/digest | **Not held**; source base `7f3ec0ad009abf5b032b8116b296d8604fee884e` plus uncommitted changes | Engineering + Release must freeze clean reviewed source and SHA-256 of `release-inventory.json` |
| Package/plugin/container digests | **Not held for a candidate** | Release Engineering must supply the signed customer-delivery envelope and inventory |
| Launch model | `direct-ga` | Product/Engineering/QA/Security |
| Connectors | Claude Code, Cursor, VS Code, OpenClaw, OpenCode, Codex CLI (with its documented host limits) | Real-host support matrix and E2E reports |
| Deployment | Hybrid edge/local enforcement + managed control plane + private AIG bridge where enabled | Architecture and outage evidence |
| Tenant regions | EU / US / APAC | Residency and transfer matrix |
| Billing | Online cloud payment plus enterprise/on-prem invoice; both disabled until provider settlement, finite entitlement, tax/legal, and Finance acceptance. Cloud trial: 14 days / 1 agent; paid cloud has no trial cap. | Finance provider-of-record and settlement/revocation receipts |
| Distribution | Authenticated private registry | Signed install, revoke and air-gap drill |
| Metering unit | Connected protected-agent installation | Entitlement contract test |
| Approved SKU IDs, included quantities and channel | **Not held** | Product + Finance price book bound to this Release Candidate |
| Price/currency/tax/minimum term | **Not held** | Finance price book and approved quote |
| Included GA capabilities/exclusions | Source: supported tool-call hooks, signed managed policies/entitlement, tenant event dashboard, optional discovery/AIG/SIEM/SSO. Every advertised host requires real-host acceptance. Output prevention depends on the host hook; private privacy-service protection covers explicitly routed text. Exclude unaccepted OS response adapters, unconfigured providers, managed SCIM and unqualified NER/model paths from a proposed order. | Claim Registry, native-host matrix, `PRODUCTION_SALES_GAPS.md`; accepted scope remains open |
| 99.9% availability scope | Managed control plane + dashboard API | Approved SLI/SLA and evidence window |
| Support tier/hours/severity | **Not held** | Support schedule and ticket drill |
| Data residency/retention/subprocessors | **Not held** | Privacy/DPO and Legal |
| Licence/attribution bundle | LICENSE, NOTICE, THIRD_PARTY_NOTICES, threats/LICENSE; official SHA-locked PyPI metadata in `services/aig-bridge/pypi-runtime-licenses.json` | Current local inventory: 204 libraries, 202 permissive declarations, 2 requiring review, 0 UNKNOWN declarations. Thirty exact wheel packages, 36 licence texts and a scoped built-image native notice archive are prepared in [the review pack](./bridge-notice-review-pack-2026-10-06.md). Candidate-bound delivery, native/full-image terms and counsel review remain open. |
| Renewal/cancellation/offboarding | **Not held** | Order/entitlement rehearsal |
| Rollback candidate | **Not held**; self-hosted recovery uses a verified backup into an isolated project after schema commit | Release Engineering; `deploy/UPGRADE.md` |
| Evidence index URL/hash | **Not held for current source** | QA/Security; rebind proof after freezing the candidate |
| Manifest status | **OPEN** | Product, Commercial, Finance, Legal signatures required |

## SKU and channel review input

Use one deployment path per order. Proposed identifiers below have no price or
entitlement authority until Product and Finance approve them and bind them to
the provider catalogue. They do not enable checkout.

| Proposed SKU | Unit and source behaviour | Approval inputs still required |
|---|---|---|
| `AIDR-MANAGED-AGENT` | One protected-agent installation; managed web app uses Clerk identity/organizations, Firestore and configured Polar recurring product. Multi-agent checkout requires a seat-based product; checkout grants no provider trial. | Actual product/price ID, approved quantity bounds, currency/tax, term, provider settlement/revocation and tenant-role acceptance |
| `AIDR-SELFHOSTED-AGENT` | One protected-agent installation in the selected Supabase deployment; invoice finance authority provisions a finite entitlement. | Authorized Finance operators, signed quantity/expiry, deployment/host matrix, registry/signer, renewal/cancellation terms, real invoice reconciliation |
| `AIDR-CLOUD-TRIAL` | Supabase cloud trial source is 14 days / 1 agent and requires legal-document acceptance; separate from Polar checkout. | Approved trial documents and live hashes, admission, expiry/revocation and deletion evidence |

EU/US/APAC and 99.9% describe product intent. Prove the selected actual region
and support scope before making an order commitment. Source billing boundaries:
`invoice-entitlement-v6.md`, `invoice-finance-authority.md`, `billing-v6.md`;
managed route: sibling repository `src/lib/billing/polar-client.ts` and
`entitlement-write.ts`.

## Approval record

| Role | Name | Decision/date | Evidence hash |
|---|---|---|---|
| Product | | | |
| Engineering | | | |
| QA | | | |
| Security | | | |
| Operations | | | |
| Commercial/Sales | | | |
| Finance/Billing | | | |
| Legal | | | |
| Privacy/DPO | | | |
| Support/Customer Success | | | |
