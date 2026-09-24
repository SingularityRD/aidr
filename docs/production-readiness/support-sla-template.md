# Support Schedule and Availability Target — Draft Template

Status: **DRAFT / NOT APPROVED**
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
| Customer severity definitions and mapping to internal P0–P3 / security SEV1–SEV3 | **Not held** |
| Acknowledgement/update/workaround/resolution targets | **Not held** |
| On-call rota and escalation owner | **Not held** |
| Status page and incident communication | **Not held** |
| Diagnostic consent, redaction and retention | **Not held** |
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

## Monthly evidence record

| Month / region | Eligible minutes | Unavailability | Availability | Incidents | SLI hash | Reviewer |
|---|---:|---:|---:|---:|---|---|
| | | | | | | |

No 99.9% claim may appear in an Order Form, sales deck, data room or investor metric until this schedule, the SLI, the observation window and Legal/Operations approvals are attached to the same Release Candidate.
