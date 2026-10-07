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

An authenticated alarm or SOAR caller can submit the same bounded playbook through `POST /functions/v1/response-playbooks` with `"action":"trigger"` and the additional required field `"trigger_source":"alarm"` or `"trigger_source":"soar"`. All other start fields above remain required, except the optional `ttl_seconds` (default 300, range 30–3600). This path requires the same active owner/admin Auth access token, current identity barriers and AAL2 assurance. An enrolled machine key or service-role key is not an operator session. A tenant header, when supplied, must match the body tenant.

The source tag and external UUID reference describe the operator's supplied event; they do not independently authenticate an alarm producer or validate an incident in another system. The human trigger uses a separate stable source-scoped idempotency key and adds one atomic `fleet.response.playbook_triggered` audit event alongside the existing run/start/queue records. Repeat the same trigger unchanged to recover the existing run; a changed actor, target, reference, reason or TTL conflicts. Success means the durable run was recorded and queued, not that containment already occurred.

For unattended alarm/SOAR calls, an active owner/admin first uses their current AAL2 Auth session to submit:

```json
{
  "action": "grant_automation",
  "tenant_id": "<tenant UUID>",
  "agent_id": "<enrolled target UUID>",
  "playbook_id": "agent_containment_v1",
  "trigger_source": "soar",
  "reason": "Authorize this incident containment integration",
  "max_ttl_seconds": 300,
  "grant_expires_in_seconds": 86400
}
```

The grant fixes the tenant, target enrollment identity, source, template and maximum command TTL. Command TTL ranges from 30 to 900 seconds. Grant expiry defaults to one day; an explicit owner/admin choice ranges from 60 seconds to 90 days. The response returns safe grant metadata and `automation_secret` once. The secret contains 32 random bytes; only its SHA-256 digest is stored in the existing hold/offboarding-aware delegated-grant table. Keep the returned secret in the integration's protected secret store. Do not store a human Auth JWT for the integration or include the secret in an incident, model input or log.

The integration sends that automation secret in the Bearer header and this exact body to the same endpoint:

```json
{
  "action": "trigger_automation",
  "tenant_id": "<tenant UUID>",
  "grant_id": "<issued grant UUID>",
  "incident_reference": "<external event UUID>",
  "reason": "Contain this confirmed incident",
  "ttl_seconds": 300
}
```

Target, template, source and actor come from the locked grant; supplying replacements in the body is rejected. A human JWT, ordinary delegated credential, enrollment key or service-role credential cannot substitute for the automation secret. Each call rechecks grant revocation/expiry, the creator's current owner/admin role, active tenant and target identity, and the creator's global revocation barrier. A new run's command TTL cannot exceed the grant's limit or remaining lifetime. The secret is matched against the grant before any quota is consumed, and authenticated calls are then rate limited on a dedicated `response-playbooks:automation` key (30/min per grant, 600/min per tenant), so unauthenticated callers cannot exhaust the operators' containment quota. The function is deployed with `verify_jwt = false` because the automation secret is not a Supabase JWT; operator actions verify their session in the handler. The grant UUID plus external event UUID form the stable idempotency namespace; unchanged retries return the existing run, while changed reason or TTL returns HTTP 409. The atomic audit includes the grant and source, without the secret or hash. The external UUID is a supplied reference, not proof that the event exists in another system.

An owner/admin with AAL2 can revoke the integration using `{"action":"revoke_automation","tenant_id":"<tenant UUID>","grant_id":"<grant UUID>","reason":"Disable this incident containment integration"}`. Revocation prevents later starts; an already delivered action still needs the existing operator rollback and native result checks. Reissue a new grant to rotate the automation secret. Existing general delegation APIs cannot add automation authority to an ordinary grant or change an issued automation grant's target, source, TTL or secret.

Command polls require the existing deployment Ed25519 key (`AIDR_REVOCATION_SIGNING_KEY_ID` and `AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64`). An unusable or absent signing key returns 503 before a command is leased. The response is `{"ok":true,"command_signed":null}` when idle, or a detached `{alg:"ed25519",key_id,sig_b64,payload}` envelope; there is no unsigned command fallback. The signature covers UTF-8 recursively key-sorted canonical JSON of `payload`:

```json
{
  "schema_version": 1,
  "purpose": "aidr.fleet-response.command",
  "key_id": "<installed trusted signing key ID>",
  "tenant_id": "<tenant UUID>",
  "agent_id": "<enrolled agent UUID>",
  "installation_id": "<registered installation ID>",
  "key_hash": "<SHA-256 of the presented API key>",
  "id": "<immutable command UUID>",
  "command_type": "agent_pause",
  "payload": {},
  "rollback_of": null,
  "created_at": "<original command timestamp>",
  "expires_at": "<original command deadline>",
  "attempt": 1
}
```

Only `agent_pause`, `agent_resume`, `network_isolate` and `network_release` are deliverable, with an empty action payload. Reverse actions require the immutable original command UUID in `rollback_of`. No bearer, private key, operator reason or arbitrary execution text is delivered. The locked database poll validates the tenant, agent, registered installation and presented key; the existing bounded renewal overlap remains allowed. Delivery/retry never extends the command deadline or changes its target/action/rollback binding. The worker must verify the installed key-ID-to-public-key map, exact device/hash binding, purpose, timestamps, action and persistent replay journal before acknowledgment or execution; keys supplied in a response are never trusted. Signing-key rotation requires updating that installed trust map through the approved signed deployment path.

The existing enrolled agent consumer acknowledges a command, executes it through its explicit platform adapter, verifies the resulting host state, then reports the result. Only a persisted `succeeded` command result advances the run. A failed, expired, cancelled, or uncertain result stops the run; prior verified actions make the final run `partial`. Read a run using `{"action":"status","tenant_id":"<tenant UUID>","run_id":"<run UUID>"}` under the same owner/admin and AAL2 boundary.

Local verification on 2026-10-06 passed 131 focused Edge tests, 101 signed-consumer tests and the frozen Deno check of 24 security-critical entrypoints. The consumer test uses the actual server payload producer, canonical JSON and Ed25519 signer through acknowledgment, execution, verification and result recording. The isolated PostgreSQL suite applied all 139 ordered migrations and passed 37 tests with no skips, including immutable device binding, credential rotation, grant mint/revoke/expiry, replay/provenance, observed authority lock waits, audit rollback and actual legal-hold/offboarding cleanup with neighboring tenant preservation. The signed-delivery PostgreSQL suite and response endpoint typecheck are blocking CI and release checks. These local fixtures do not establish real MFA, OS effects or customer integration acceptance.

This local implementation depends on deploying the additive playbook and signed-delivery migrations and on an installed endpoint worker with adapters that support the selected commands. It does not prove OS or hardware attestation, customer endpoint permissions, provider credential revocation, or external SOAR execution. Production acceptance still requires those endpoint and provider checks; an unsupported adapter action remains a failed or partial run rather than success.
