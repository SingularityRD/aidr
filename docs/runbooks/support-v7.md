# Support and security update operations (v7)

**Status: operating procedure draft; T40 field acceptance open.** This document tells Support, SRE, Security, and Release Engineering how to handle a case and what evidence must exist before a support or security-update promise can be made. It does not establish an active ticket channel, a staffed on-call rota, a contractual response time, or a supported end-of-life date. The current customer candidate is **NO-GO** for production and supported sale; see the [v7 candidate record](../production-readiness/2026-09-13-customer-candidate-v7.md) and [T40 gap](../../PRODUCTION_SALES_GAPS.md).

Use one opaque case ID to join the customer ticket, incident timeline, diagnostic consent, release/change record, and final acceptance. Record times in UTC and identify the exact source commit, release manifest digest, package/kit digest, deployment mode, and affected customer/host versions. Keep restricted customer and security records outside the release bundle.

## Activate support for a customer

Support/Customer Success and the customer must fill and approve this record for the *same* release candidate and Order Form before declaring support active. An empty value is a blocker, not a default.

| Required field | Responsible approver | Required evidence |
| --- | --- | --- |
| Reachable normal ticket route, test customer identity, and secure security-reporting route | Support + Security | Customer-visible URLs/addresses, access controls, successful open/acknowledge/close test |
| Named primary and backup for Support, SRE on-call, incident commander, PSIRT/security lead, Release Engineering, and customer decision maker | Support + SRE + Security | Rota, coverage hours/time zone/holidays, successful page and backup escalation |
| P0–P3 definitions and acknowledgement, update, workaround, and restoration targets | Support + Legal + customer | Approved [support/SLA schedule](../production-readiness/support-sla-template.md) and signed contract reference |
| Status/incident notice route, audience, encryption, notice deadline, and next-update cadence | Security + Support + Legal/Privacy | Delivered test notice, recipient acknowledgement, timestamped transcript without secrets |
| Supported connector/OS/host versions, update channel, rollback method, and maintenance owner | Product + QA + Release | [native-host matrix](../production-readiness/native-host-matrix-v6.md), signed release receipt, install/update/rollback drill |
| Diagnostics purpose, transfer method, access grant, retention/deletion schedule, and customer consent authority | Support + Privacy | Approved ticket terms, [support-bundle procedure](support-bundle.md), transfer/deletion receipts |
| Security maintenance and EOL policy by version and connector | Product + Security + Legal | Published dates, notification lead time, affected-customer list, migration path |

The [Commercial Release Manifest](../production-readiness/commercial-release-manifest-template.md) and support schedule currently say support hours and targets are **not held**. Do not copy the draft 99.9% target or any response clock into a quote, contract, status page, sales answer, or incident notice as an approved commitment. A passing local support-bundle test does not activate the routes above.

## Receive, triage, and escalate a case

1. Create or link the customer ticket; assign an opaque case ID. Record reported time, first human acknowledgement, severity decision and rationale, affected release/tenant/deployment/host versions, observed impact, customer contact, current owner, next update time, and all handoffs. Do not request credentials, raw prompts, customer files, or production logs in the initial ticket.
2. Check whether the report involves suspected exploitation, data exposure, tenant boundary failure, a compromised signer, or a protection bypass. If yes, restrict the record, page the named security lead and incident commander, preserve evidence, and follow the [incident response runbook](incident-response.md). Privacy/Legal decides notification obligations; Support sends only the approved customer message.
3. Otherwise reproduce on the recorded version with a benign fixture where possible. Check current health/alert receipts, deployment doctor output, relevant connector coverage, release signature receipt, and recent changes. Mark unknown or missing telemetry as **unknown**, never as clean or protected.
4. Give the customer a case ID, impact statement, current mitigation if proven, and the next agreed update time. Log delivery and acknowledgement. Escalate when a clock, owner, or dependency is at risk; a silent handoff does not stop a response clock.
5. Record mitigation and verification against the customer symptom, affected host, and exact release. Close only after customer confirmation or an explicitly documented closure rule; preserve unresolved risk and follow-up ownership.

Use this working severity guide for internal routing. The existing incident runbook lists security response guidance of **immediate / under 15 minutes** for SEV1, **under 4 hours** for SEV2, and **under 24 hours** for SEV3. Those figures are not a staffed customer SLA; use the approved customer schedule if one exists and record actual elapsed times in every drill.

| Working class | Example trigger | First route |
| --- | --- | --- |
| P0 / security SEV1 | Active exploit, confirmed breach, signer compromise, broad loss of a required protection or service | Page incident commander, Security/PSIRT, SRE, and customer owner immediately; start restricted incident timeline |
| P1 / security SEV2 | Credible vulnerability or suspicious activity; major supported function unavailable; potential tenant/auth issue | Security or SRE lead and Support; promote to P0 if exploitation or broad impact is confirmed |
| P2 / security SEV3 | Limited defect with an evidenced workaround, scanner finding, or dependency update needing review | Owning engineering team and Support; track patch decision |
| P3 | Question or low-impact request without demonstrated security or service impact | Support queue under the approved support hours |

Reclassify as evidence changes and preserve both the original and revised severity with timestamps. If there is no reachable route, named on-call owner, or agreed hours for a customer, report the support gate as open; do not imply 24×7 coverage.

## Security report, CVE, and incident communication

The named PSIRT/security lead owns the vulnerability record. On intake, preserve the reporter's confidentiality preference, affected versions and deployment modes, reproduction evidence, exploitability assessment, known exploitation status, and mitigations. Use a restricted tracker for sensitive details. Link dependency alerts and scanner output to the exact shipped artifact; a fresh `pnpm audit:prod` or other local scan is one point-in-time input, not proof that a deployed customer is unaffected.

Security, Product, and Release Engineering decide whether to issue a patch, rule update, temporary disablement, or customer workaround. Record which supported versions and host/OS combinations are affected and test both a malicious fixture and a benign twin on actual supported hosts. If a CVE is assigned, put its identifier and affected-version range in the advisory; do not invent an identifier or publish exploit details ahead of the approved disclosure plan. Legal/Privacy determines incident and data-subject notices, recipients, and deadlines. The incident commander timestamps decision, initial customer notice, subsequent updates, and closure; Support verifies that each intended recipient actually received the notice through the approved channel.

The customer bulletin must include the case/advisory ID, affected and unaffected versions, observable impact, immediate safe action, signed fixed-version identity, installation/verification instructions, rollback or recovery limits, and the next update time. State uncertainty explicitly. Never include secrets, unredacted diagnostic data, or an untested claim that a hook prevented a host side effect.

## Emergency security update

1. Open a restricted change linked to the incident and list affected customers, deployment modes, connectors, and versions. Freeze the candidate commit and exact artifact inventory. Record fix review, focused regressions, dependency/SBOM and license review, representative old-version upgrade rehearsal, and the supported-host side-effect tests. An emergency narrows the review window; it does not waive identity or signature verification.
2. Release Engineering builds from reviewed clean source, records digests and an increasing release sequence, and signs the **complete customer-delivery envelope** with the approved offline publisher key using [`release-sign.mjs`](../../scripts/release-sign.mjs). Keep the private key outside the bundle and customer system. An inner artifact signature or `SHA256SUMS` alone does not authenticate installer scripts; see [first-customer delivery](../../deploy/FIRST_CUSTOMER.md).
3. Before extraction or installation, the operator uses independently delivered verifier code, out-of-band signer policy, and persistent anti-rollback state to verify the signed envelope with [`release-verify.mjs`](../../scripts/release-verify.mjs). Record the verification receipt, signer fingerprint, expiry, sequence, manifest digest, and policy ID. Do not advance anti-rollback state at preflight; advance it only after successful installation and customer acceptance as described in the delivery and upgrade procedures. A failed, expired, revoked, mismatched, or unsigned bundle is held and escalated.
4. For **self-hosted** deployments, execute the exact-manifest backup, compatibility-contract, `preflight`, `apply`/`resume`, doctor, and recovery flow in [UPGRADE.md](../../deploy/UPGRADE.md). The upgrade tool requires a verified encrypted backup and append-only migration history. Drain traffic during the approved window. On failure after schema commit, keep traffic drained and recover into a **new isolated project**; never run an in-place down-migration or copy old application files over the changed schema. Record cutover, customer login, enrollment, deny-side-effect, audit export, and rollback outcomes separately from the tool receipt.
5. For **managed cloud**, use the cloud provider's reviewed deployment, migration, backup/PITR and rollback plan; the self-hosted upgrade script does not operate a cloud project. For each connector or marketplace package, prove install/update and known-good pin or emergency disable on the supported host matrix. Removing a listing does not downgrade installed clients. Release notes must state host-version exclusions and required operator actions.
6. Roll out to a named pilot/ring, inspect independent service and host receipts, then expand only after the change owner approves. Record delivery, customer acknowledgement, applied version, failed/offline devices, rollback decision, and remaining exposure per customer. Do not call distribution complete because an archive was uploaded or a hook returned `deny`.

If the **publisher signing key is lost, suspected exposed, or unusable**, stop signing and distributing with that key, preserve the key-custody and release audit trail, notify Security/Release/customer owners, and assess every artifact signed since the last trusted custody point. Security and Release Engineering must approve an out-of-band trust-policy update that revokes the old key and installs a separately generated replacement; test that old, forged, expired, and lower-sequence bundles are rejected before resuming delivery. Do not reset persistent anti-rollback state merely to make an emergency update pass. Record the key-rotation decision, independent policy distribution, customer verification receipts, and any affected-customer notice. Treat inability to establish a trusted signer as a release blocker, not as a reason to distribute an unsigned patch.

## End of security maintenance

Product, Security, Support, and Legal approve a versioned support policy before first sale: supported and security-only version ranges, EOL dates, minimum notice period, supported upgrade path, last compatible host/OS versions, and responsibility for offline customers. Publish the policy through the approved customer route, track delivery and acknowledgement for affected accounts, and keep a migration/rollback option tested before removing a version. After EOL, label the version unsupported in inventory and support responses; triage a newly reported serious vulnerability for customer safety without implying a contractual fix for an unapproved or unsupported version. No numeric EOL or notice promise is currently held.

## Diagnostics with customer consent

Collect only after the ticket records purpose-specific customer approval and an opaque consent reference. Use the allowlisted [support bundle](support-bundle.md); the example paths below are illustrative and must be replaced with the customer's approved deployment and restricted output locations:

```sh
node scripts/support-bundle.mjs --deployment /srv/aidr --output /secure/aidr-support-CASE-123456 --customer-consent --consent-reference CASE-123456 --consent-recorded-at 2026-09-13T10:01:00.000Z
node scripts/verify-support-bundle.mjs /secure/aidr-support-CASE-123456
```

Review the four generated files manually, record the verifier result and SHA-256 inventory in the ticket, then transfer only through the customer-approved secure route. The collector excludes environment files, logs, prompts/commands, identities, hostnames, paths, database and storage content; the verifier rejects extra files and common secret/identity patterns. `SHA256SUMS` detects changes but is **not** a publisher signature. Do not append screenshots, raw logs, config archives, tokens, or customer content. More data needs separate consent and a reviewed collection procedure. Grant any support access by MFA, just-in-time scope, named reason and auditable expiry; revoke it on closure. Delete local/exported copies under the approved retention rule and record the deletion receipt. Neither the collector nor local self-test proves transfer-system access or deletion.

## Evidence and acceptance gate

Before Support signs off on T40, run these drills on the **same immutable candidate and approved customer-like environment**. Keep raw sensitive records in a restricted evidence store and link only redacted receipts and hashes from the release evidence index.

| Drill | Required observable result |
| --- | --- |
| Real ticket lifecycle | Customer reaches the published route; named staff acknowledge, classify, escalate, update, resolve, close; timestamps prove each approved target or document the miss |
| Critical incident and customer notice | Synthetic SEV1 pages primary/backup; incident commander and PSIRT act; approved notice reaches the intended customer within the approved deadline; update cadence and closure are measured |
| Signing-key loss | Publishing halts; old key is removed from independent trust policy; replacement policy delivery and forged/old/expired/lower-sequence rejection are verified; customer receipts match new signer |
| Signed emergency patch and rollback | Clean candidate, signed envelope, independent verification, supported-host install, benign/malicious checks, applied-version receipts, self-hosted backup/preflight/isolated recovery or cloud-specific rollback, and customer cutover acceptance are all recorded |
| Diagnostic consent and deletion | Ticket consent predates collection; bundle verification and manual review find no secrets; approved transfer, access expiry, and deletion have receipts |
| EOL notice | Approved version policy, affected account list, customer notification/acknowledgement, and supported migration rehearsal are recorded |

The local support-bundle self-test can be run with `node scripts/verify-support-bundle.mjs --self-test`; it checks collection boundaries, not the customer ticket or support service. Attach candidate digests, UTC event times, owner names, reviewer decisions, customer acknowledgement, test outputs, and any failures or exceptions to the T40 acceptance record. Support, SRE, Security, Release Engineering, and the customer owner must sign the field result. Until the channels, rota, contracts, real drills, signed release, and customer acceptance exist, keep T40 `LOCAL_IMPLEMENTATION_FIELD_ACCEPTANCE_OPEN` and production/supported-sales status **NO-GO**.
