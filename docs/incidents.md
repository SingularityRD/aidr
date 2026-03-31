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
