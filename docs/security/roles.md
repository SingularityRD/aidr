# Control-plane roles

Every workspace (tenant) member holds exactly one role. Roles are enforced in the
database (row-level security and the `SECURITY DEFINER` functions behind every
write) and re-checked by each Edge function; the dashboard only hides links and
buttons the role cannot use. Hiding is never the control.

| Role | Purpose |
| --- | --- |
| `owner` | Owns the workspace. Everything an admin can do, plus owner-only settings (SSO, SCIM, retention and legal holds, ownership changes). |
| `admin` | Runs the workspace: members, policies, keys, integrations, approvals. |
| `member` | Day-to-day operator: edits policies, enrolls devices, creates own API keys. |
| `viewer` | Read-only view of the workspace's activity. |
| `auditor` | Read-only external or internal auditor: everything a viewer reads, plus both audit trails, their export, reports and compliance evidence. Cannot change anything. |
| `support_jit` | Time-boxed vendor support access; never granted from the dashboard. |

## Role matrix

`R` = read, `W` = change, `X` = export / generate, `-` = refused.

| Capability | owner | admin | member | viewer | auditor |
| --- | --- | --- | --- | --- | --- |
| Events, incidents and incident history | R | R | R | R | R |
| Incident triage (status, owner, notes) | W | W | - | - | - |
| Be assigned as an incident owner | yes | yes | yes | - | - |
| Team policy and runtime policy (read via `policy-management` / compliance report) | R W | R W | R W | R | R |
| Publish policy, rollouts, DLP / agent profiles | W | W | per policy | - | - |
| Tenant audit trail (`audit_logs`) | R X | R X | R | R | R X |
| Administrative audit trail (`admin_audit_logs`) | R X | R X | - | - | R X |
| Executive reports, team rollup, printable report | R | R | - | - | R |
| Scheduled report / governance digest settings | W | W | - | - | - |
| Governance scorecard | R | R | - | - | R |
| Compliance evidence report | X | X | - | - | X |
| Usage report | R | R | - | - | R |
| Member list with e-mail addresses (access review) | R | R | - | - | R |
| Invite, remove or change members | W | W | - | - | - |
| API keys, enrollment tokens, fleet keys | W | W | own keys | - | - |
| SSO, SCIM, identity policy, retention, legal holds | owner | some | - | - | - |
| SIEM destinations, notification channels | W | W | - | - | - |
| Approvals (decide) and approval settings | W | W | - | - | - |
| AI register, governance requests and exceptions | W | W | request | R | - |
| Billing and plan changes | W | W | - | - | - |

"Some" and "own keys" follow the existing per-feature rules in the feature
documentation; the auditor column is the point of this page.

## The `auditor` role

Introduced by `supabase/migrations/20261016000400_auditor_role.sql`.

- **Lateral, not a rung.** `auditor` is not part of the
  owner > admin > member > viewer ladder. `app.is_tenant_member_with_role` has a
  separate `auditor` level (owner, admin, auditor) used only by audit-reader
  gates; the `viewer` level (the read-only floor, used by no write policy) also
  admits an auditor. The `member`, `admin` and `owner` levels do not.
- **Fails closed on every write.** Every write path (RLS write policies, every
  service-role RPC that takes `p_tenant_id` and `p_actor_user_id`, every Edge
  write check) is a positive list of roles that does not name `auditor`.
  `scripts/auditor-role-postgres.test.mjs` sweeps all of those RPCs from the
  live catalog on real PostgreSQL and fails if any accepts an auditor actor or
  changes tenant state.
- **What it unlocks.** `list_tenant_admin_audit_logs`, the `audit-export`
  function for both trails, `compliance_report_evidence` (the report records
  `generated_by.role = "auditor"` and its receipt in the administrative trail),
  the `reports` function's read actions (`summary`, `rollup`, `document`),
  `governance_scorecard`, `tenant_usage_report` and
  `list_team_members_with_email`. Compliance reports still require AAL2.
- **Not included.** The AI register and governance request pages, approvals,
  device onboarding and installer downloads stay closed to an auditor; the
  dashboard hides those links. The team-policy editor is not shown; policy
  content is read through the compliance report's policy inventory or the
  `policy-management` `read` / `history` actions.
- **Granting it.** Only an owner or admin, from **Team** (invite with role
  *Auditor*, or change an existing member's role). The change is written to the
  administrative audit trail by the existing role-transition trigger. SCIM and
  OIDC group mappings cannot grant `auditor`: it is always a deliberate grant by a
  person. Give an external auditor a time-boxed membership and remove it when the
  engagement ends.

## Audit export date range

`POST /functions/v1/audit-export` accepts optional `from` and `to` (ISO 8601
date-times with an explicit zone, at most millisecond precision) and applies the
half-open range `[from, to)` to either trail (`source: "audit"` or `"admin"`).

```json
{ "team_id": "…", "format": "csv", "source": "admin",
  "from": "2026-09-01T00:00:00Z", "to": "2026-10-01T00:00:00Z" }
```

- Bounds are normalised to UTC and echoed in the response. `from` must not be
  after `to`, must be on or after 2000-01-01 and must not be in the future;
  `to` may be. Anything else is `400 invalid_export_range`, before any read.
- The range is signed into every `next_cursor`. Each later page must repeat the
  same `from` / `to`; a page that omits, widens or narrows them is refused with
  `400 invalid_or_expired_export_cursor`.
- In the dashboard (**Team → Team audit**) the *From* / *To* fields take UTC
  calendar days; *To* is inclusive (the request uses the next day's midnight).
