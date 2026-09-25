# Control Plane (Auth, Dashboard, Licensing)

The control plane is the managed layer for:

- User authentication (dashboard login)
- Centralized agent inventory (installations)
- Telemetry-backed dashboards (verdict/event timeline)
- Incidents view derived from telemetry events (see `docs/incidents.md`)
- Agent-seat licensing (1 free agent, paid per additional agent)

Enforcement is **local by default**. `ConfigSchema.mode` defaults to `"local"`, so a fresh
install evaluates every tool call on the device with no account or network access. The
control plane is an opt-in `managed` layer: enrollment adds central policy, inventory,
telemetry and licensing, but it is never a precondition for detection. An un-enrolled or
unreachable managed install disables only the managed features and keeps enforcing locally.

## Enrollment (managed mode)

To join an installation to the control plane, the primary flow is **device authorization**.
Local enforcement is already active before these steps and stays active if they are never
completed:

1. Install the connector (Claude Code / Cursor / VS Code / OpenClaw / OpenCode).
2. Start the agent once.
3. Singularity AIDR prints a short verification code and a verification URL.
4. Open the URL, sign in, and approve.
5. Restart the agent (or rerun the enable-protection command).

See [Device Auth](device-auth.md).

## API keys (fallback)

For advanced or support scenarios, you can still use API keys:

1. Sign in to the dashboard.
2. Create an API key.
3. Set `auth.api_key` in `~/.singularity-aidr/config.json` and enable `control_plane.enabled`.

## Licensing model (recommended)

- **1 free agent per user**: first unique installation id (`iid`) that phones home under a given API key.
- **Paid per additional agent**: each additional unique `iid` requires an entitlement.

Enforcement is intended to be **server-side**:

- If the control plane sees a new `iid` over the entitlement limit, it should reject ingest (`402`/`403`) and optionally return a machine-readable error.
- The client keeps enforcing locally and disables only the managed features (telemetry upload,
  central policy, dashboard visibility) for that installation. Losing the control plane is
  never a reason to allow a tool call.

Failure handling is per layer, not a blanket "fail-open":

- **Managed features** degrade when the control plane is unavailable, over the seat limit or not
  enrolled; local detection and enforcement continue unchanged. A signed managed policy
  bundle that is installed but cannot be verified blocks tool calls rather than being
  silently dropped.
- **Connector entry points** (Claude Code, Cursor / VS Code, OpenClaw, OpenCode, Codex) fail
  **closed**: an internal error produces a deny or block, not a silent allow.
- **Detection internals** (an erroring rule, an optional reputation lookup, a cache or policy
  load) skip that signal and log it; a skipped signal is never reported as a clean result.
- **Security controls** on the control plane (authentication, tenant isolation, rate limits,
  webhook signatures, approvals) fail closed.

## Browser Privacy Guard (browser installs)

Singularity AIDR Browser Guard (`packages/browser-guard`) masks sensitive data
in prompts, pastes and files before they reach AI chat products. Detection and
masking run locally in the browser. Enrollment adds counts-only reporting to the
control plane; it is not a precondition for protection.

**Enroll browsers** (dashboard: **Browser Privacy**, route `/privacy-guard`):

1. Deploy the Browser Guard extension package from your AIDR release to Chrome,
   Edge or Firefox, per user or force-installed by browser management policy.
2. Create a tenant API key on the **API Keys** page (`/api-keys`). Keys are
   stored hash-only, so the key is shown once.
3. Push the managed policy the page generates, or enter the control-plane URL
   and key on the extension's options page. Managed values win over the user's
   settings:

   ```json
   {
     "mode": "auto",
     "enabledEntities": ["PERSON", "EMAIL", "PHONE", "TC_KIMLIK", "IBAN", "..."],
     "literals": [],
     "telemetry": {
       "controlPlaneUrl": "https://<your-project>.supabase.co",
       "apiKey": "<tenant API key>"
     }
   }
   ```

   `mode` is `auto` (mask), `confirm`, `block` or `monitor`. `literals` holds
   `{ "value": ..., "type": <entity type> }` rules for organization-specific
   terms. How the JSON is delivered depends on the management tool (for example,
   Chrome's extension policy for managed storage).

**Seats.** Each browser profile generates a stable install ID (`iid`) and
registers through `POST /functions/v1/ingest` with `agent_runtime:
"browser_guard"`. It is a protected agent seat counted by
`register_agent_for_ingest` exactly like any other connector, so an install over
the tenant's seat limit receives `402 agent_limit_exceeded` and its events are
not stored.

**Events.** The browser sends `privacy_scan` events following the fixed contract
in [`docs/contracts/privacy-telemetry.md`](contracts/privacy-telemetry.md). The
ingest projection (`supabase/functions/ingest/events.ts`) keeps only
`site`, `action`, `channel`, `entity_counts` (privacy entity types, integers
1–100000, at most 32 keys; unknown keys are dropped), `findings_count`, an
optional `policy_id` and the timestamp. Anything else in the event — prompt
text, masked text, matched values, URLs — is discarded. An unknown `site` is
stored as `other`; an unknown `action` or `channel` rejects the batch with
`400 invalid_event`. For generic views the server adds `decision`:
`masked`→`allow`, `warned`→`ask`, `blocked`→`deny`, `allowed`→`allow`.

Privacy scans are rows in `public.events` (`type = 'privacy_scan'`), so tenant
RLS, the event seat-admission guard, telemetry retention and tenant offboarding
apply unchanged. The dashboard reads aggregates through
`public.privacy_guard_summary(tenant, 7 | 30)`, a `SECURITY INVOKER` function
that keeps those RLS policies in force:

- **Prompts protected** — scans the guard masked, warned about or blocked.
- **Items masked** — detected items in masked sends (`findings_count`, or the
  sum of `entity_counts` when absent).
- **Blocked sends** — scans with `action = blocked`.
- **Active browser installs** — `browser_guard` agents seen within the window,
  shown against all enrolled browser installs.

The page also shows the entity-type and AI-site breakdowns, a daily (UTC)
series and the latest 25 scans (counts only). The audit export
(`audit-export`) covers the audit log only; privacy scans are not part of it.

## Dashboard approvals (managed mode)

In managed mode an `ask` verdict can be approved by a human in the dashboard
instead of only through the same-OS-user `aidr approve` CLI. The flow is
defined in [contracts/dashboard-approvals.md](contracts/dashboard-approvals.md)
and is never agent-callable:

1. The **connector** (not the agent) files a request with its tenant API key:
   `POST /functions/v1/approval-requests` with the installation id, `action_id`,
   artifact digest, tool, threat ids, a redacted summary and an expiry of at
   most 30 minutes. Filing is idempotent on (tenant, installation, action).
   Only `tenant`-scope keys are accepted; Browser Guard ingest-only keys are
   refused, and an agent-bound key can only file and poll for its own
   installation.
2. An **owner or admin** reviews it on the dashboard **Approvals** page
   (`/approvals`, with a pending-count badge in the navigation): tool, threat
   ids, redacted summary, agent and a live expiry countdown. Approve and deny
   both require a reason. The Edge Function re-checks the session, the tenant
   identity barrier, the owner/admin role and **AAL2** (an AAL1 session is sent
   through the MFA step-up flow), is rate limited, and writes the decision and
   its reason to the audit log in the same transaction.
3. The function signs an **Ed25519 approval token** that binds tenant,
   installation, `action_id`, artifact digest, tool, decision, approver, a
   15-minute lifetime and a single-use nonce. The connector collects it by
   polling `GET /functions/v1/approval-requests/{request_id}` and verifies it
   against `approval_public_keys` in its signed entitlement; any mismatch keeps
   the action blocked, and a valid approval releases exactly one identical
   retry.

**Key custody.** Each tenant has its own Ed25519 approval signing key, created
on the first decision. The private key is stored only as AES-256-GCM ciphertext
under a per-tenant key-encryption key derived with HKDF-SHA256 from the Edge
secret `AIDR_APPROVAL_SIGNING_WRAP_KEY_B64` (32 random bytes, base64), with the
tenant and key id bound as additional data; the table is service-role only and
no client role can read it. Without that secret the function answers
`server_misconfigured` and nothing can be approved (asks stay blocked). Owners
and admins can rotate the key from the Approvals page; the retired key stays
published for 20 minutes so tokens it already signed still verify, and closing a
workspace revokes the key. Changing the wrap secret makes existing keys
unusable (decisions fail closed with `approval_signing_unavailable`) until the
key is rotated.

**Data handling.** Members can read their tenant's requests through RLS, but the
token and nonce columns are never granted to the browser. Decided and expired
requests are deleted after the tenant's telemetry retention by the maintenance
worker (`prune_expired_approval_requests`, legal holds respected); offboarding
expires pending requests and revokes keys at request time and deletes both in
the telemetry and access-credential phases.

**Compatibility.** `approval_public_keys` is added to the signed entitlement only
once a tenant has a signing key. Connector builds that predate this field
re-canonicalize the entitlement without it and therefore reject the signature
of such an entitlement; upgrade every managed connector in a tenant before
deciding its first dashboard approval.
## Operator administration

Platform operators fix the deployment admission mode, record the approved
Terms and Privacy documents (URL and SHA-256), grant and revoke licensed tenant
admission, and review a minimal tenant directory and per-tenant usage through
the `operator-admin` Edge Function or its CLI wrapper `scripts/operator-admin.mjs`.
Every action requires an allowlisted, MFA-verified (AAL2) operator and writes
an actor-attributed audit receipt in the same transaction as the change. See
[operations/operator-admin.md](operations/operator-admin.md) for provisioning,
commands and error codes, and
[operations/admission-operators.md](operations/admission-operators.md) for the
tenant-scoped separation-of-duty rules that licensed grants still enforce.
