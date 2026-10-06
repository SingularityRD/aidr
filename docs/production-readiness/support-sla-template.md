# Support Schedule and Availability Target — Draft Template

Status: **DRAFT / NOT APPROVED**
Source inventory updated: **2026-10-06**. Severity definitions below are triage
guidance. Hours, response clocks, staffing and credits require actual owners.
Planning target only (not approved or a customer commitment): 99.9% monthly
availability for the managed control plane and dashboard API.

## Availability definition

```text
monthly_availability =
  (eligible_service_minutes - unavailability_minutes)
  / eligible_service_minutes * 100
target = 99.9%
scope = managed control plane and dashboard API
```

Before contract use, define endpoints, probe locations, denominator, dependency treatment, approved maintenance, customer-caused exclusions, regional calculation, incident start/stop, evidence retention, service credits and dispute handling.

| Item | Value / owner / evidence |
|---|---|
| Tier 1 support channel and hours | **Not held** |
| Security incident channel and encryption | **Not held** |
| EU/US/APAC holiday and language coverage | **Not held** |
| Customer severity definitions and mapping to internal P0–P3 / security SEV1–SEV3 | Draft: P0/SEV1 active exploit, confirmed exposure, signer compromise or broad required-protection loss; P1/SEV2 major supported function unavailable or credible tenant/auth issue; P2/SEV3 limited defect with evidenced workaround; P3 low-impact question/request. Customer mapping requires Support/Legal approval. |
| Acknowledgement/update/workaround/resolution targets | **Not held** |
| On-call rota and escalation owner | **Not held** |
| Status page and incident communication | **Not held** |
| Diagnostic consent, redaction and retention | Source: opaque case ID, purpose-specific customer consent, allowlisted deployment/doctor metadata, verify before transfer, approved recipient, deletion at agreed case retention. `docs/runbooks/support-bundle.md`; recipient/retention/operator acceptance open. |
| Maintenance windows and exclusions | **Not held** |
| SLI query, denominator and observation window | **Not held** |
| Service-credit schedule and approval | **Not held** |
| Ticket drill | Timestamped synthetic incident required |

## Customer-channel acceptance (same release candidate)

Record the deployed origin and candidate digest. In an unauthenticated browser, open
`/support`, `/status`, `/security`, `/privacy`, and `/terms`; a successful HTTP
response or SPA shell alone does **not** prove that the configured destinations
exist. Follow each rendered link to the operated service and record its final
URL, response, owner, and review time. Do not replace a missing channel with an
example address or a public source-code issue tracker.

From the customer-facing support route, submit one synthetic ticket without
secrets or customer content. Record ticket ID, submitted/acknowledged/escalated/
closed timestamps, named on-call owner, and the status-page update (or a
documented reason no update was required). Verify the security-disclosure route
and diagnostic-consent procedure separately. Attach redacted evidence and the
approved support schedule to the same candidate before marking COM-005 held.

Use the local receipt validator after the real drill:

```sh
node scripts/verify-support-ticket-drill.mjs /restricted/case/drill.json --candidate <release-inventory SHA-256>
node scripts/verify-support-ticket-drill.mjs --self-test
```

The JSON receipt uses `schema_version: 1`,
`kind: "aidr_support_ticket_drill_receipt"`, `environment: "operated"`,
`synthetic_ticket: true`, candidate digest, opaque `case_id`, P0–P3 severity,
distinct `primary_operator`/`backup_operator` and a named `reviewer`.
`events` contains submitted/acknowledged/escalated/updated/closed in that order,
each with `actor` and canonical UTC `at_utc` (`YYYY-MM-DDTHH:mm:ss.sssZ`).
`channels` contains one review per support/status/security/privacy/terms, with
`route`, credential/query-free HTTPS `final_url`, `owner`, `reached: true` and
`reviewed_at_utc`. Set `status_update` to published or not_required, with
`status_update_reference_or_reason`; set `diagnostics` to not_requested or
separate_consent_record with `diagnostic_reference_or_reason`. `evidence` lists
relative paths and SHA-256 hashes of redacted operated-system exports within
the receipt's restricted directory (at most 1 MiB per file).

Validation verifies input shape, time ordering, candidate and byte hashes. It
does not contact the service, authenticate people, prove delivery or approve a
clock/SLA. The self-test is local fixture evidence only. Support must compare
the receipt with the operated system and signed schedule before COM-005 closes.

## Monthly evidence record

| Month / region | Eligible minutes | Unavailability | Availability | Incidents | SLI hash | Reviewer |
|---|---:|---:|---:|---:|---|---|
| | | | | | | |

No 99.9% claim may appear in an Order Form, sales deck, data room or investor metric until this schedule, the SLI, the observation window and Legal/Operations approvals are attached to the same Release Candidate.
