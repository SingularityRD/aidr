# Incidents (Dashboard)

The dashboard provides a lightweight **Incidents** view derived from telemetry stored in `public.events`.

## How incidents are derived (v0)

An event is treated as "incident-like" when:

- `type = "runtime_verdict"` and `payload.verdict` is `"deny"` or `"ask"`
- `type = "plugin_scan"` and `payload.findings_count > 0`
- `type = "incident"` (reserved for future explicit incident events)

This intentionally keeps the schema simple: the control plane stores raw events, and the dashboard derives an incidents list without requiring a separate incidents table.

## Correlation (v1)

Singularity AIDR also ships a local-first correlation engine that can turn raw events into explicit incident records.

- Inputs: `runtime_verdict`, `plugin_scan` findings, and explicit `incident` events
- Output: `incident_record` objects (correlated timeline + severity uplift)
- Example rule: repeated `deny` within a short window → escalate severity
- Example rule: `ask` + user override + network egress → escalate (approval-abuse shape)

### Persistence

When `incident.correlation_enabled` is enabled, core can also persist explicit correlated records:

- JSONL (default): appends `type="incident_record"` entries into the local audit log (`logging.path`).
- SQLite (optional): upserts incident snapshots into `~/.singularity-aidr/incidents.db` when available.

`incident_record` entries are ignored as inputs during correlation to avoid feedback loops.

## Requirements

- The agent must be configured to send telemetry to the control plane (see `docs/control-plane.md`).
- Your Supabase project must have the `public.events` table and RLS policy allowing the logged-in user to read their own events.

## Triage: status, owner, resolution note, snooze

Owners and admins handle each incident on **Security incidents** (`/incidents`) with
**Manage**. Every member, viewers included, sees the status, owner and audit trail.

| Field | Values and rules |
| --- | --- |
| Status | `open` (also every incident nobody has triaged yet) → `acknowledged` → `resolved` or `false_positive`; any status can be reopened. |
| Owner | An active owner, admin or member of the workspace (not a viewer). Checked again on every change. |
| Resolution note | Required to close (`resolved`, `false_positive`), at most 1000 characters. Shown on the page and in the triage history; never copied into the administrative audit log or any report. |
| Snooze | Hides an open or acknowledged incident from the default queue until a day at most 30 days ahead. Closing clears it. |

The default queue shows incidents still to handle (open and acknowledged, not snoozed);
the filter also shows snoozed, closed or all incidents, and *Only incidents assigned to
me*.

**Triage never changes enforcement.** Marking an incident a false positive does not
unblock anything. When the matched rule should stop firing for that agent, the page
offers **Create a detection exception…**, which opens the detection-exception form
filled in with the rule, the agent and the resolution note as the reason. The owner or
admin reviews and submits it there; the `detection-exceptions` function applies its own
checks (AAL2, at most 30 days, self-defense and canary rules refused). Canary and
self-defense incidents never get this link.

### How it is stored and checked

- Migration `supabase/migrations/20261014000100_incident_triage.sql`:
  `public.incident_triage` (current state, one row per incident event) and
  `public.incident_triage_history` (append-only). Neither table has a browser grant.
- Edge Function `supabase/functions/incidents/index.ts` (`list`, `history`, `update`):
  session → workspace sign-in policy (identity barrier) → active membership → tenant
  rate limit. `update` also needs owner/admin and an AAL2 session. There is no API-key
  path, so no agent can triage, close or hide an incident.
- `public.update_incident_triage` (service role only) re-checks the role, the event
  (same workspace, incident-like), the owner, the note and the snooze under a workspace
  lock, refuses a stale `expected_version` (`incident_triage_conflict`) and writes the
  history row and an `incident.triaged` audit row (no note text) in the same
  transaction. Closing an incident raised by one's own agent is allowed (one-admin
  workspaces) and recorded as `self_closure`.
- Retention: the triage state is deleted with its event by telemetry retention; the
  history is kept as security audit and removed by workspace offboarding (phases 60 and
  61).
- `public.incident_triage_summary` gives counts by triage status for the executive
  report and the scheduled governance summary (`docs/ai-governance-frameworks.md`).

Tests: `supabase/functions/__tests__/incidents-contract.test.ts`,
`packages/dashboard/src/__tests__/incident-triage-page.test.tsx` and, on a real
database with the full migration chain, `scripts/incident-triage-postgres.test.mjs`
(`AIDR_POSTGRES_TEST_URL=postgres://… node --test scripts/incident-triage-postgres.test.mjs`).
