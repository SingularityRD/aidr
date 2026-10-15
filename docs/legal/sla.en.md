# Support and service level schedule (SLA)

> **DRAFT — legal/business approval required.** No support hours, response
> times, staffing or service credits are approved or staffed today
> ([support schedule template](../production-readiness/support-sla-template.md)).
> Bracketed numbers are proposals for negotiation, not commitments; do not copy
> them into a quote, contract or status page until this schedule is approved
> and the on-call rota exists. Turkish version: [sla.tr.md](sla.tr.md).
> Version: draft 0.1, 14 October 2026.
>
> **No SLA is in force.** The 99.9% monthly availability figure in §4 is the
> commercial decision's draft target; its contract evidence is open (COM-013,
> CLAIM-014 in the
> [claim registry](../production-readiness/commercial-go-evidence-registry.json)),
> and no hosted service is live to measure it against. Sales material may describe
> it only as a draft target subject to contract.

## 1. Scope

This schedule is an annex to the Singularity AIDR End User License Agreement
and applies to the support level in the Order Form (`AIDR-SUP-STD`,
`AIDR-SUP-ADV` or `AIDR-SUP-CRT`). It covers the versions listed as supported
in the [supported versions policy](../security/supported-versions.md), on the
platforms and AI agent host versions in the
[compatibility matrix](../compatibility-matrix.md).

## 2. Severity levels

The customer proposes a severity when opening a case; SingularityRD confirms or
changes it with a written reason. Severity can change as evidence changes.

| Severity | Definition | Examples |
|---|---|---|
| **1 — Critical** | Production protection is lost or the control plane is down for most users, or a security incident involving the product is suspected, and there is no workaround | Every tool call is denied fleet-wide after an update; signed policy cannot be loaded and `remote_policy_required` blocks every enrolled agent; suspected compromise of a signing key; tenant data visible to another tenant |
| **2 — High** | A major function is unavailable or seriously degraded, with a workaround that is hard to sustain | Enrollment fails for new devices; approvals cannot be decided in the dashboard; SIEM delivery stopped |
| **3 — Medium** | A function behaves incorrectly with a reasonable workaround | A false positive on a common developer command; a dashboard report shows wrong counts |
| **4 — Low** | Question, documentation issue, feature request | How-to questions; wording in a message |

## 3. Response targets (proposals)

"Response" means a qualified engineer acknowledges the case and starts work,
not a resolution. Clocks run only during the coverage hours of the support
level, except Severity 1 under `CRT`.

| Severity | Standard (`STD`) | Advanced (`ADV`) | Critical (`CRT`) |
|---|---|---|---|
| 1 | [4] business hours | [2] hours, extended hours | [1] hour, 24×7 |
| 2 | [1] business day | [4] business hours | [4] business hours |
| 3 | [2] business days | [1] business day | [1] business day |
| 4 | [5] business days | [3] business days | [3] business days |

| Coverage | Standard | Advanced | Critical |
|---|---|---|---|
| Hours | Business days 09:00–18:00 Turkey time (TRT), excluding Turkish public holidays | Business days 08:00–20:00 TRT | Advanced + 24×7 for Severity 1 |
| Channels | Ticket portal, e-mail | + named support contact, phone during hours | + on-call phone for Severity 1 |
| Language | Turkish, English | Turkish, English | Turkish, English |
| Updates on open Severity 1 | Every [business day] | Every [4] hours | Every [2] hours |
| Reviews | — | Quarterly service review | Quarterly service review |

There are no resolution-time guarantees. For Severity 1 SingularityRD works
continuously (within coverage) until a fix, workaround or rollback restores
protection.

## 4. Availability (hosted service only)

On-premises and air-gapped deployments are operated by the customer; their
availability depends on the customer's infrastructure and is not covered by an
availability target. Endpoint detection keeps working when the control plane
is unavailable.

For the hosted control plane a monthly availability target of **[99.9]%** of
the dashboard and API is proposed, measured as
`(eligible minutes − unavailable minutes) / eligible minutes`, excluding
announced maintenance (at least [5] business days' notice, at most [8] hours a
month, outside business hours TRT) and causes outside SingularityRD's control.
Service credits: [10]% of the monthly fee below the target, [25]% below
[99.0]%, capped at [25]% per month, on written request within [30] days. The
hosted service is not accepted for customer use today
([SaaS deployment](../deployment/saas.md)), so this section applies only once
it is.

## 5. Customer responsibilities

- Name up to [3] (STD) / [5] (ADV, CRT) authorised contacts.
- Run supported versions and apply security updates within a reasonable time.
- Provide diagnostics through the consented support bundle
  ([support process](../runbooks/support-process.md)); never send credentials,
  prompts or customer data in a case.
- For on-premises deployments: keep backups, time synchronisation (NTP) and
  monitoring as described in the [on-prem runbook](../operations/onprem-runbook.md),
  and give remote or on-site access when agreed.

## 6. Exclusions

Unsupported versions or platforms; host versions not in the compatibility
matrix; changes the customer made to the product, the database or the
generated configuration; problems caused by third-party AI agent hosts or AI
providers; evaluation (POC) licences, which receive best-effort support only.

## 7. Escalation

If a case does not progress as expected, the customer may escalate to the
support manager, then to [the CTO / founder]. Contacts are listed in the Order
Form. Security incidents follow the incident runbook and the customer is told
who the incident commander is.
