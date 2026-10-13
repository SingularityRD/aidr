# Contract: managed-mode dashboard approvals (fixed; G1a server side, G1b client side)
Purpose: in MANAGED mode, an `ask` verdict can be approved by a human admin in the dashboard (AAL2), out of band, instead of the same-OS-user CLI. Never agent-callable.
1. Request (connector -> control plane), sent when an ask verdict is issued in managed mode:
   POST {base}/functions/v1/approval-requests   Authorization: Bearer <tenant API key (scope tenant)>
   body: { iid, agent_runtime, action_id (string, ^[A-Za-z0-9._:-]{8,128}$), artifact_digest ("sha256:<64hex>" over the canonical artifacts JSON the core already digests for operator approvals), tool (string <=64), threat_ids (string[] <=16), summary (redacted, <=512 chars, control chars escaped), expires_at (ISO, <= now+30min) }
   -> 201 { request_id (uuid), status: "pending" } ; idempotent on (tenant, iid, action_id). A replay must repeat the whole subject (artifact_digest, tool, summary, threat_ids, agent_runtime); any difference is 409 approval_request_conflict, so a request pre-filed with other text never becomes the one the approver reads. summary, tool and iid carrying Unicode format or separator characters (bidi overrides/isolates, zero-width characters, BOM, tag characters, U+2028/2029) are refused (400); the connector sends such characters as visible escapes.
2. Approve/deny (dashboard, admin/owner, AAL2): POST {base}/functions/v1/approval-requests/{request_id}/decision body {decision: "approve"|"deny", reason}
   Separation of duties: when the tenant requires a different approver (`approval_require_distinct_approver`; default on for Business and Enterprise, off for Free and Team, changed by an owner/admin at AAL2 through `ai-governance { action: "update_approval_settings", require_distinct_approver: true|false|null }`), the user who owns the API key that filed the request cannot approve it: 403 `approval_self_approval_forbidden`, nothing is signed, the request stays pending and `approval.self_approval_refused` is audited. The requester may always deny. A permitted self-approval is audited as `approval.self_approved` (`self_approval: true`).
   -> server signs an approval token with the tenant approval signing key (Ed25519, key stored server-side, public key delivered in the signed runtime policy / entitlement as `approval_public_keys: [{key_id, public_key_spki_b64}]`).
   token payload (canonical JSON): { v:1, tenant_id, iid, action_id, artifact_digest, tool, decision, approver_id, issued_at, expires_at (<= issued_at+15min), nonce }
   token format: base64url(payload) + "." + base64url(signature) , key_id in separate field.
3. Poll (connector): GET {base}/functions/v1/approval-requests/{request_id} (API key) -> { status: pending|approved|denied|expired, token?: string, key_id?: string }
4. Client verification (core): signature valid with a key from the verified runtime policy; tenant_id/iid/action_id/artifact_digest/tool match the pending ask; not expired; nonce single-use (consumed set persisted locally; replay of a consumed nonce -> reject). Any failure -> stays blocked (fail closed). Approval releases exactly one identical retry, audited as source "dashboard_approval".
5. Audit: every request/decision/consumption audited server side (existing audit tables) and client side (audit-log).

## Server implementation notes (non-normative; the contract above is authoritative)

- Function: `supabase/functions/approval-requests/index.ts`; migrations
  `20260926000001_dashboard_approval_requests.sql` and
  `20260926000002_approval_retention_offboarding.sql`.
- Create answers `201 { request_id, status, created }` for both the first call and an
  idempotent replay (`created: false`, `status` is the current state). A replay with the
  same `(tenant, iid, action_id)` but a different `artifact_digest` or `tool` is refused
  with `409 approval_request_conflict`. Only `tenant`-scope API keys are accepted
  (`ingest:browser_guard` keys get `403 api_key_scope_denied`); an agent-bound key may
  file and poll only for its own installation. `expires_at` is clamped to `now + 30 min`
  when a client clock is up to 5 minutes ahead and refused beyond that.
- Token payload values: `decision` is `"approve"` or `"deny"` (the request-body values);
  `iid` is the installation id the connector sent when filing; `issued_at`/`expires_at`
  are ISO-8601 UTC with `expires_at = issued_at + 15 min`; `nonce` is 16 random bytes,
  base64url (22 chars); `v` is `1`. The signature is Ed25519 over the exact UTF-8 bytes of
  the canonical payload JSON (recursively sorted keys, no whitespace), i.e. over
  `base64url_decode(part[0])`.
- Deny decisions are signed too; a connector must treat anything but a valid
  `decision: "approve"` token as "stay blocked".
- `approval_public_keys` is added to the signed v2 entitlement snapshot (ingest) only once
  the tenant has an approval signing key (created on the first decision). It lists the
  active key and, for 20 minutes after a rotation, the retired key; revoked keys are never
  listed. An unreadable key table yields no keys (approvals then fail closed).
- Poll returns `404 approval_request_not_found` for another tenant's (or another bound
  agent's) request. Once decided it returns `{ request_id, status, token, key_id,
  token_expires_at }`.
- Dashboard decisions: `POST /approval-requests/{request_id}/decision` (contract form) or
  `POST /approval-requests { action: "decide", request_id, tenant_id, decision, reason }`
  (the dashboard's form, so the browser call site is statically checkable). `reason` is
  required (1–500 characters, no control characters). Key rotation:
  `POST /approval-requests { action: "rotate_key", tenant_id }` (owner/admin, AAL2).
- Server audit actions (`admin_audit_logs`, plus `audit_logs` for team tenants):
  `approval.requested`, `approval.approved`, `approval.self_approved`,
  `approval.self_approval_refused`, `approval.denied`, `approval.expired`,
  `approval.token_delivered` (first delivery of a token to the connector, the server-side
  view of consumption), `approval.signing_key_created`, `approval.signing_key_rotated`,
  `approval.offboarding_revoked`. The redacted summary is never copied into audit rows.
