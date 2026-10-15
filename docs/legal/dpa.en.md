# Data Processing Agreement (DPA)

> **DRAFT — legal/business approval required.** Not approved by counsel, the
> data protection officer or the business owner; review before offering it for
> signature. The subprocessor list and hosting regions are candidates, not an
> approved residency statement ([data residency](../deployment/data-residency.md)).
> Turkish version: [dpa.tr.md](dpa.tr.md); for customers established in Turkey
> the Turkish version prevails. Version: draft 0.1, 14 October 2026.

## 1. Parties and roles

This Data Processing Agreement ("DPA") is between [Customer legal name]
("Controller") and SingularityRD [full legal name, MERSIS — Legal to complete]
("Processor"), under the Singularity AIDR End User License Agreement and Order
Form between them (the "Main Agreement").

Under Turkish Law No. 6698 on the Protection of Personal Data ("KVKK") the
Customer is the data controller (*veri sorumlusu*) and SingularityRD the data
processor (*veri işleyen*). Where the Customer is established in the EU or
serves EU data subjects, this DPA also meets Article 28 GDPR.

## 2. When this DPA applies

Singularity AIDR runs locally on endpoints by default and sends nothing. The
Processor processes personal data on the Customer's behalf only in these cases:

| Case | What the Processor processes | When |
|---|---|---|
| A. Hosted control plane | The categories in Annex 1, for the term of the hosted service | When the Customer chooses the hosted service |
| B. Support | The support bundle the Customer explicitly approves and information seen in support sessions | During a support case |
| C. Professional services | Information seen in the Customer environment during installation or a POC | During the service, under Customer supervision |

When the Customer operates the control plane itself (on-premises or
air-gapped), the Processor has no access to the Customer's telemetry; only B
and C apply.

## 3. Instructions

The Processor processes personal data only to perform the Main Agreement and
on the Customer's documented instructions. Product configuration (mode,
telemetry settings, `redact_mode`, retention, optional features) and written
approvals in a support case are instructions. The Processor informs the
Customer without delay if it believes an instruction infringes KVKK or GDPR.

## 4. Confidentiality

Staff and contractors with access to personal data are bound by written
confidentiality obligations, and access is limited to what their role needs.

## 5. Security

The Processor implements the technical and organisational measures in Annex 2
(KVKK Article 12, GDPR Article 32). Measures may evolve without lowering the
level of protection. Measures marked "planned" are not in place and are not
presented as if they were.

## 6. Subprocessors

The Customer gives general authorisation for the subprocessors in Annex 3. The
Processor gives at least 30 days' written notice before adding or replacing a
subprocessor; the Customer may object on reasonable grounds within that period
and, if the objection is not resolved, terminate the affected service with a
pro-rata refund. The Processor imposes equivalent obligations on its
subprocessors and remains liable for them.

## 7. International transfers

Personal data is transferred abroad only under KVKK Article 9 (and, where
applicable, GDPR Chapter V): an adequacy decision, the standard contract
published by the Turkish Data Protection Board (notified to the Board within
five business days of signature), binding corporate rules or Board
authorisation. Annex 3 names the mechanism per flow. Customers that want no
transfer abroad should run the control plane on their own infrastructure in
Turkey ([data residency](../deployment/data-residency.md)).

## 8. Data subject requests

The Processor forwards requests under KVKK Article 11 and the GDPR to the
Customer and does not answer them itself. It reasonably assists the Customer
with the product's export, deletion and tenant offboarding tools.

## 9. Personal data breach

The Processor notifies the Customer without undue delay and no later than
**[24] hours** after becoming aware of a breach affecting personal data, with
(as far as known) the nature of the breach, categories and approximate numbers
of data subjects and records, likely consequences, measures taken or proposed,
and a contact point. It assists the Customer with its notification to the Board
within 72 hours under KVKK and to data subjects. Notification is not an
admission of fault.

## 10. Audits

The Processor provides the information necessary to demonstrate compliance
(this DPA's annexes, the security whitepaper and any independent audit or
penetration test reports). As of today there is **no** independent audit
report, certification or completed penetration test. The Customer may audit, or
appoint an independent auditor, once a year on 30 days' written notice, during
business hours and under confidentiality, at its own cost unless the audit
finds a material breach.

## 11. Term, return and deletion

This DPA applies for the term of the Main Agreement and as long as the
Processor processes personal data for the Customer. When the hosted service
ends, the Processor, at the Customer's choice, returns the data through the
export tools within [30] days and then deletes it through tenant offboarding;
deletion from backups happens when those backups expire. Records that the law
requires to be kept, and records under a Customer legal hold, are kept until
the obligation ends. Support bundles are deleted within [30] days of case
closure and the deletion is recorded in the case.

## 12. Liability and precedence

Liability follows the limits of the Main Agreement, except where the law does
not allow a limit. On data protection matters this DPA prevails over the Main
Agreement.

---

## Annex 1: Details of processing

| Item | Hosted control plane (A) | Support (B) |
|---|---|---|
| Purpose | Central management of endpoints: enrollment, policy distribution, event and verdict visibility, approval workflow, audit trail, compliance report | Diagnosing and fixing an issue the Customer reported |
| Operations | Collection (from endpoints and the dashboard), storage, display, export, deletion | Receiving, reviewing and deleting the bundle the Customer approved |
| Data subjects | Customer's employees and contractors (developers, administrators, SOC analysts, approvers) | The same; the person who opened the case |
| Personal data | Identity/contact: e-mail, name, IdP user and group IDs. Security of processing: installation and device IDs, session and factor records, audit records. Usage: verdict events from AI tools (tool name, decision, matched rule, timestamp; tool summary and artefacts as SHA-256 digests in the default `hash` mode) and Browser Guard counts (site, action, count per type; no prompt text). | Allowlisted diagnostic summary in the support bundle (versions, health checks, rule digests); contact details in support correspondence |
| Special categories | Not intended. The product is not designed to collect them; the Customer keeps hashing on and does not use `redact_mode: none` | Not intended; the bundle is designed to exclude them |
| Not sent | Source code, file contents, full prompts, values Browser Guard masked ([privacy.md](../privacy.md)) | Environment files, logs, prompts, credentials ([support bundle](../runbooks/support-bundle.md)) |
| Retention | Tenant retention policy (7/90/365 days by edition or contractual); legal holds respected | [30] days after case closure |
| Duration | Term of the Main Agreement | Duration of the case |

## Annex 2: Technical and organisational measures (TOMs)

Status: **In place** = in the product source with tests in the repository;
**Customer** = the Customer implements it in its environment; **Planned** = not
in place yet. "In place" does not mean independently verified.

| # | Area | Measure | Status |
|---|---|---|---|
| 1 | Minimisation | Default local mode: detection runs on the endpoint without network access | In place |
| 2 | Minimisation | Mandatory credential scrub on events leaving the endpoint; default `redact_mode: hash` replaces tool summaries and artefacts with SHA-256 digests; server-side allowlist projection | In place |
| 3 | Minimisation | Browser Guard sends counts only; no prompt text, masked text, values or page URLs | In place |
| 4 | Access control | Row-level security on every tenant table; tenant membership and role checks | In place |
| 5 | Access control | Roles (owner, admin, member, viewer) with audited role changes | In place |
| 6 | Authentication | SAML / OIDC single sign-on, SCIM lifecycle, MFA and recovery codes for local accounts | In place (Customer IdP acceptance required) |
| 7 | Credential storage | Tenant API keys stored as hashes only; endpoint credential in the OS vault | In place |
| 8 | Integrity | Ed25519-signed release manifests, policy, detector bundles, rule/intel packs and offline licence; signing keys never distributed to endpoints | In place (generation and custody of production keys is a human step, open) |
| 9 | Integrity | Optional SHA-256-chained, Ed25519-signed endpoint audit log | In place (optional) |
| 10 | Transport | HTTPS/TLS to the control plane; on-prem services bind to loopback and TLS terminates at the Customer's ingress | In place / Customer |
| 11 | Storage | Disk encryption of the hosting environment | Hosted: provider (to be confirmed) / On-prem: Customer |
| 12 | Backup | Encrypted backups, offsite copy, restore-drill tooling | In place (tooling) / drill evidence by the operator |
| 13 | Retention and deletion | Per-tenant retention, legal holds, recorded deletion on offboarding | In place |
| 14 | Logging | Audit trail of administrative actions, enrollment, invitations, role and policy changes; audit export; SIEM delivery | In place |
| 15 | Continuity | Endpoints keep enforcing locally when the control plane is unreachable | In place |
| 16 | Separation | Cross-tenant negative tests on Postgres | In place (live two-tenant test open) |
| 17 | Secure development | Code review, automated tests, secret scanning, dependency audit | In place |
| 18 | Independent assessment | Penetration test ([scope/RFP](../security/pentest-scope-rfp.md)) | **Planned — not performed** |
| 19 | Personnel | Confidentiality undertakings, need-to-know access, access removal on exit | Planned (written policy required) |
| 20 | Incident management | Incident response runbook, on-call and notification process | Runbook exists; on-call rota planned ([support process](../runbooks/support-process.md)) |
| 21 | Support access | Customer-approved allowlisted support bundle; just-in-time, time-limited support access | In place (tooling) / process planned |
| 22 | Physical security | Data-centre provider's physical security for the hosted service | Provider (to be confirmed) |

## Annex 3: Subprocessors (candidates — not approved)

Applies to the hosted control plane (case A) only. On-premises, the Processor
has no subprocessors; providers the Customer chooses (SMTP, IdP, SIEM, backup
target) are the Customer's own processors.

| Subprocessor | Purpose | Location (known) | Transfer mechanism | Status |
|---|---|---|---|---|
| Supabase Inc. | Database, authentication, storage, server functions | Pilot project `eu-central-1` (Frankfurt); functions may run near the caller | [standard contract / Board notification — Legal] | Candidate |
| Cloudflare, Inc. | Request routing (pilot Worker on `workers.dev`) | Global; no regional restriction | [Legal] | Candidate (pilot) |
| Resend or another approved e-mail provider | Invitation, recovery and alert e-mail | United States (provider to confirm) | [Legal] | Candidate |
| Functional Software, Inc. (Sentry) | Error diagnostics | Only when explicitly enabled | [Legal] | Off by default |

The list becomes final when the hosted production cell is provisioned and its
region verified. The only known fact today is the pilot project's primary
region, `eu-central-1`.
