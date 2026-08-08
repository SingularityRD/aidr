# Support Schedule and 99.9% SLA — Template

Status: **DRAFT / NOT APPROVED**
Locked target: 99.9% monthly availability for the managed control plane and dashboard API.

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
| S1–S4 severity definitions | **Not held** |
| Acknowledgement/update/workaround/resolution targets | **Not held** |
| On-call rota and escalation owner | **Not held** |
| Status page and incident communication | **Not held** |
| Diagnostic consent, redaction and retention | **Not held** |
| Maintenance windows and exclusions | **Not held** |
| SLI query, denominator and observation window | **Not held** |
| Service-credit schedule and approval | **Not held** |
| Ticket drill | Timestamped synthetic incident required |

## Monthly evidence record

| Month / region | Eligible minutes | Unavailability | Availability | Incidents | SLI hash | Reviewer |
|---|---:|---:|---:|---:|---|---|
| | | | | | | |

No 99.9% claim may appear in an Order Form, sales deck, data room or investor metric until this schedule, the SLI, the observation window and Legal/Operations approvals are attached to the same Release Candidate.
