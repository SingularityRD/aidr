# Privacy, Licensing and Legal Review — Template

Status: **DRAFT / NOT APPROVED**
Source inventory updated: **2026-10-06**. This is a populated review draft,
not an executed DPA, a transfer assessment or Legal permission to distribute.
Release scope: proprietary first-party AIDR + preserved third-party/vendor notices.

## Licensing and notices

| Item | Evidence / status |
|---|---|
| First-party terms | LICENSE draft; counsel approval **not held** |
| Root/package metadata | Ten first-party package manifests declare `Proprietary`; the private privacy package declares `UNLICENSED`. The first-party root LICENSE and final package/delivery scope require counsel review. |
| Product notice | NOTICE references third-party bundle; counsel review **not held** |
| Third-party bundle | Local lockfile inventory: 204 libraries / 202 permissive declarations / 2 review / 0 UNKNOWN declarations. Thirty official SHA-locked PyPI wheels have metadata and 36 archived licence texts. [The review pack](./bridge-notice-review-pack-2026-10-06.md) supplies 17 system-libpq paths, the measured cryptography static-SSL record and exact upstream texts, plus all 110 installed dpkg package copyright records for the selected local image. Exact signed-candidate binding, selected non-dpkg/static/other-image obligations and counsel decision **not held**. |
| Threat rules | DRL 1.1 in `threats/LICENSE`; attribution propagation **not held** |
| AIG vendor | Vendor LICENSE/NOTICE and “Based on Tencent Zhuque Lab AI-Infra-Guard” attribution |
| Chain of title | Source/vendor/contributor records **not held** |

## Data-flow and privacy review

Use the 25 source-inventory rows in
[`privacy-data-flow-matrix.json`](./privacy-data-flow-matrix.json), not blank
copies of those rows. They record fields, triggers, source references,
destination configuration and implemented access/deletion boundaries. Actual
domains/regions, approved retention/basis/transfer and deployed payload or
erasure evidence remain explicit `unknown`; every flow is `inventory`.

| Enabled path | Processor/service review input | Actual contract, region, access and retention still required |
|---|---|---|
| Self-hosted Supabase | Customer-selected infrastructure; database/Auth/Storage; configured SMTP; optional AIG, diagnostics and webhooks | List the operated providers and legal entities. A self-hosted source option does not establish that the deployed path has no subprocessor. |
| Managed web application | Clerk authentication/organizations; Firebase/Firestore persistence; Polar if checkout enabled; selected server hosting | Separate contract/project IDs, processing and backup regions, administrator access, retention and export/deletion receipts for each provider |
| Contact and anti-abuse | Configured contact webhook recipient; Cloudflare Turnstile only if configured; shared rate-limit storage if enabled | Contact recipient, message retention and abuse/IP handling; bot-prevention terms and regional processing |
| Private privacy text route | One configured OpenAI Responses or Gemini generateContent provider, local approved NER, service account/session broker and vault | Actual provider account/model terms, approved model/data processing, fixed endpoint region, broker/vault custody and selected application's route/network acceptance |
| Optional reputation/AIG/MCP/diagnostics/SIEM | Source default reputation host, npm/PyPI metadata, configured AIG/scan model, configured upstream MCP servers, Sentry or customer SIEM | Enabled host list, provider identity, tenant-safe payload capture, credential custody, chosen retention and onward recipients. Disabled source routes are not accepted processor records. |

Legacy Stripe/Paddle/Lemon routes are included only if actually enabled for the
selected scope. Do not infer Polar region from a setting in the Supabase path
or Supabase SCIM capability from managed Clerk organization roles.

## DPA and security annex — reviewable draft inputs

The draft processing instruction is: operate the customer's selected AIDR
runtime/control-plane and enabled inspection, identity, billing, support and
export functions for its signed scope. Categories and subjects must follow the
enabled flow rows: user/organization/device identifiers; limited event and
incident data; possible tool text, URLs/paths and optional AIG/model content;
contact/account/payment metadata; exports/support summaries and backups. No
general promise that prompts never leave a host is supported by optional
reputation, AIG, MCP or model routes.

Before execution, the customer and Legal must fill the parties and signatory
authority, controller/processor roles, purpose and documented instructions,
duration, enabled functions and categories/subjects, handling of sensitive or
classified content, permitted administrators, incident assistance/notice route,
DSAR and export/deletion assistance, approved subprocessors/change notice,
audit arrangements, transfers, confidentiality, termination and surviving
record obligations. These are negotiation fields, not invented deadlines or
approved guarantees. Bind the executed terms and actual provider list to the
same Order Form and candidate.

Technical annex source facts: signed policy/entitlement and TLS transport;
tenant/role checks; scoped device credentials; consent-gated metadata support
bundle; encrypted backup tooling; retention/offboarding receipts and legal-hold
serialization. Actual deployment, operator/key custody, provider settings and
restore/erasure must be verified; the source inventory supplies no certificate.

For Turkish cross-border processing, Legal must select the applicable transfer
route and official instrument for the actual parties. The official
[KVKK standard-contract collection](https://www.kvkk.gov.tr/Icerik/7929/Standart-Sozlesmeler)
contains different party-role forms; an EU-labelled SCC does not itself resolve
this product's Turkish transfer review. Use the applicable official form and
[KVKK's contract guidance](https://www.kvkk.gov.tr/Icerik/8170/Yurt-Disina-Kisisel-Veri-Aktariminda-Kullanilacak-Standart-Sozlesmelerde-Dikkat-Edilmesi-Gereken-Hususlara-Iliskin-Kamuoyu-Duyurusu)
as Legal input; this repository does not execute or modify those forms.

## Retention and deletion — source input

`retention-holds.md` records current source defaults and bounds. New Supabase
tenants default to the existing `tenants.retention_days` (30); class-specific
policies and later owner-approved changes control actual eligibility. Public
waitlist rows without a tenant are deleted 365 days after sign-up, and an
operator DSAR routine exports or erases waitlist rows and pilot free-text notes
by e-mail (audit-log copies of pilot decision notes are retained;
`retention-holds.md`, "Public waitlist and pilot free text"). Commercial settlement/idempotency evidence is retained;
it is not silently erased as an event row.

Source export/offboarding deletion requires exact-path authorization, Storage
absence and ACK; legal holds and ambiguous requests stop the affected flow.
Database/Storage receipts prove application-level outcomes. Provider physical
erasure, replicas, backups, customer copies and external support/payment/Auth
records need separate retention/deletion evidence. Managed Firestore retention
requires its own approved policy and executed retention/deletion run; it is not
inherited from Supabase defaults.

## Legal approvals

- [ ] Controller/processor/service-provider role approved per deployment mode.
- [ ] EU/US/APAC placement and cross-border transfer mechanism approved.
- [ ] Subprocessor list, DPA/TOM/SCC and change-notice process approved.
- [ ] Numeric retention, deletion, export, backup expiry and legal-hold behavior approved.
- [ ] Privacy claims match payload assertions and Claim Registry.
- [ ] MSA, Order Form, SLA/support, vulnerability disclosure and acceptable-use terms approved.
- [ ] Counsel signs the exact Release Candidate/version and evidence hash.
