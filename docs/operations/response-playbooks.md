# Local response playbooks

`response-playbooks` currently exposes one built-in playbook, `agent_containment_v1`. It queues `agent_pause` first and queues `network_isolate` only after the existing fleet response worker records a verified success for the first step. The playbook API does not accept scripts, arbitrary commands, credential revocation, or external SOAR actions.

`incident_reference` is a UUID-shaped reference supplied by the operator. It is stored and bound consistently to the run, steps, and audit entry, but is not looked up or validated as an AIDR incident record: the current schema has no tenant-scoped incident-record table or foreign key. The similarly named `incident_events` view is event telemetry, not such a record.

Start a run with a Supabase access token from an active tenant owner or admin session at AAL2:

```json
{
  "action": "start",
  "tenant_id": "<tenant UUID>",
  "agent_id": "<enrolled agent UUID>",
  "incident_reference": "<operator-supplied UUID reference>",
  "playbook_id": "agent_containment_v1",
  "reason": "Contain the confirmed incident",
  "idempotency_key": "incident-2026-0001",
  "ttl_seconds": 300
}
```

The database stores the run and every typed step with the same tenant, operator, incident reference and agent bindings. Repeating the start request with the same idempotency key and the same request returns the existing run; reusing that key for different inputs conflicts. Each step has a derived idempotency key and expires no later than the run. The database queues only one step at a time through the existing tenant-bounded fleet command queue.

The existing enrolled agent consumer acknowledges a command, executes it through its explicit platform adapter, verifies the resulting host state, then reports the result. Only a persisted `succeeded` command result advances the run. A failed, expired, cancelled, or uncertain result stops the run; prior verified actions make the final run `partial`. Read a run using `{"action":"status","tenant_id":"<tenant UUID>","run_id":"<run UUID>"}` under the same owner/admin and AAL2 boundary.

This local implementation depends on deploying the additive playbook migration and on an installed endpoint worker with adapters that support the selected commands. It does not prove OS or hardware attestation, customer endpoint permissions, provider credential revocation, or external SOAR execution. Production acceptance still requires those endpoint and provider checks; an unsupported adapter action remains a failed or partial run rather than success.
