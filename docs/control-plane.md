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

## Single sign-on

Tenants can require SAML or OpenID Connect (Entra ID, Okta, generic) sign-in; see [OIDC SSO](production-readiness/oidc-sso-admin.md) and [SCIM directory setup](production-readiness/scim-directory-admin.md). Both are optional and off by default.

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

## Alert integrations (Slack, Teams, webhooks, e-mail)

Workspace owners and administrators configure real-time alert channels under
**Settings → Notifications**. The message formats, JSON schema, signature and
retry semantics are specified in
[`docs/contracts/notifications.md`](contracts/notifications.md).

**Channels.** `public.notification_channels` (migration
`20260926000020_notification_channels.sql`) stores one destination per row —
a Slack incoming webhook, a Microsoft Teams workflow webhook, a signed generic
HTTPS webhook (URL plus HMAC secret) or 1–10 e-mail recipients — and its
filters: new incidents at or above a minimum severity, critical runtime denies,
approval requests (`ask` verdicts; approval itself stays out-of-band) and
spikes of blocked Browser Guard prompts (threshold within a window). At most 20
channels per workspace.

**Write-only destinations.** The `notification-channels` Edge Function
validates a destination (https only, provider host allow-list for Slack/Teams,
no IP literals or private/internal names), encrypts it with AES-256-GCM using
`AIDR_NOTIFICATION_ENCRYPTION_KEYS` (`<key id>:<base64 32 bytes>[,…]`; the first
key encrypts, every listed key decrypts) with the tenant, channel and type as
associated data, and never returns it. Clients see a hint only
(`host · #<digest prefix>` or a masked recipient). RLS lets owners and
administrators read channel metadata; column grants exclude the ciphertext, and
no client role may write either table.

**API.** `GET` (header `X-AIDR-Tenant-ID`) lists channels and the last 25
deliveries for owners/admins. `POST {tenant_id, action}` with `create`, `update`,
`delete` or `test` requires owner/admin, the tenant identity barrier and AAL2,
is rate limited (20/min per user, 100/min per tenant; tests 5/min and 20/min)
and is audited in `admin_audit_logs` and `audit_logs` without names,
destinations or secrets. **Send test** enqueues a content-free row and delivers
it immediately through the dispatcher code path, returning the receiver's
status.

**Transactional outbox.** An `AFTER INSERT` trigger on `public.events`
(`20260926000021_notification_outbox.sql`) writes one
`notification_deliveries` row per matching enabled channel in the same
transaction as the telemetry row, with identifiers, severity, category and
counts only. Duplicates are suppressed per incident id (or event row) and per
spike window, and each channel is capped at 30 queued alerts per minute per
event kind (so a flood of one kind never suppresses another). An
enqueue fault is isolated and logged; it never loses the event.

**Dispatcher.** `notification-dispatch` is called with
`Authorization: Bearer <AIDR_NOTIFICATION_DISPATCH_TOKEN>` (never the
service-role key). Each run leases due rows (`FOR UPDATE SKIP LOCKED`, 120 s
lease), resolves every webhook host and refuses any private, link-local,
metadata or otherwise non-public address, posts with a 10 s timeout and no
redirects, and records the outcome with exponential backoff (8 attempts, 30 s
to 1 h). Generic webhooks carry `X-AIDR-Signature: t=<ts>,v1=<hmac-sha256>`
and `Idempotency-Key: <delivery id>`. Delivery is at-least-once. Terminal rows
are pruned after the tenant's `operational_ephemera` retention (≤ 7 days)
unless a legal hold is active.

Schedule the dispatcher once a minute:

- **Supabase Cloud** — store the token in Vault and schedule it with pg_cron
  and pg_net (run once as an operator; the token never goes into a migration):

  ```sql
  select vault.create_secret('<token>', 'aidr_notification_dispatch_token');
  select cron.schedule('aidr-notification-dispatch', '* * * * *', $$
    select net.http_post(
      url := 'https://<project-ref>.supabase.co/functions/v1/notification-dispatch',
      headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets
                                       where name = 'aidr_notification_dispatch_token')),
      body := '{}'::jsonb,
      timeout_milliseconds := 60000);
  $$);
  ```

- **Docker Compose on-prem** — `scripts/deployment-prepare.mjs` generates both
  keys in `.env.functions`; enable the timer with
  `sudo sh /srv/aidr/maintenance/install-systemd.sh --with-notifications`
  (see [deploy/maintenance](../deploy/maintenance/README.md)).
- **Kubernetes** — set `notifications.dispatcher.enabled=true`; the chart
  renders a minute CronJob that reads the token from the functions Secret
  (see [deploy/helm/aidr/README.md](../deploy/helm/aidr/README.md)).

Deliveries leave from the functions runtime, so its egress must reach Slack,
Teams, your webhook receivers and the mail provider (or an egress proxy).

**Offboarding.** When a workspace starts closing, its channels and deliveries
are deleted in the same transaction as the status change, and an offboarding
run cannot complete while any remain. Rotating the keyring: put the new key
first in the list and keep the old one; new and replaced destinations use the
new key while existing ones still decrypt. Remove the old key only after every
channel's destination has been re-entered (destinations are write-only, so
there is no automatic re-encryption).

**Not included.** `agent.offline` alerts, per-user notification preferences,
digest/batching, and mTLS to webhook receivers are not implemented.

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

## Signed runtime policy (Ed25519)

`GET /v1/policy` returns the tenant policy with a `policy_sha256` digest (SHA-256 of the
canonical `runtime_policy`) and, when the control plane has a policy signing key, a
`policy_signed` block:

```json
"policy_signed": {
  "alg": "ed25519",
  "key_id": "policy-2026-10",
  "sig_b64": "...",
  "envelope": {
    "schema_version": 1, "key_id": "policy-2026-10",
    "policy_version": "pol_20261005120000", "policy_sha256": "<hex>",
    "sequence": 1791201600000, "issued_at": "...Z", "expires_at": "...Z", "tenant_id": "..."
  }
}
```

The signature is Ed25519 over `canonicalJson(envelope)` (recursively key-sorted JSON, the same
form as signed entitlements). The legacy `policy_signature` HMAC field is an
operator-side value that connectors cannot verify and is ignored by them.

**Connector configuration.** Trust anchors are `control_plane.policy_public_keys_pem`
(Ed25519 public keys, PEM or base64 SPKI). If empty, `licensing.public_keys_pem` is used. If
neither is set, signature checking is off and only the digest over TLS applies.

When at least one key is configured, a policy is applied only if all of these hold:

- the signature verifies against one configured key (several keys may be listed for rotation);
- `key_id` (signed inside the envelope) is not in the signed revocation feed's `key_ids`
  (`licensing.revocations_cache_path`, the same feed that revokes entitlement and pack keys; the
  feed is used only when its signed `tenant_id` matches the tenant of the verified entitlement);
- the envelope's `policy_sha256` and `policy_version` equal the delivered ones, and the digest
  matches the delivered `runtime_policy`;
- `issued_at` is not in the future (5 minute skew) and `expires_at` has not passed;
- `sequence` is not lower than the highest accepted for this endpoint and token, and an equal
  sequence carries the same digest (rollback and replay protection, persisted in the policy cache).

Unsigned, tampered, wrong-signer, expired, revoked-key and rolled-back policies are rejected.
With `control_plane.remote_policy_required` the connector then fails closed (no policy applies
and the call is blocked); otherwise the response is ignored and local policy stays in force.
The last good signed policy is still cached and may be used inside the offline grace window, but
never beyond its signed `expires_at`, and it is re-verified on every load, so a tampered cache
file is rejected.

**Landing control plane.** Provision the signing key with `AIDR_POLICY_SIGNING_KEY_ID` and
`AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64` (Ed25519, PKCS#8 DER base64; set both or neither,
a half-configured pair returns 503 `policy_signing_unavailable`), validity with
`AIDR_POLICY_SIGNATURE_TTL_HOURS` (default 24, 1 to 720). A dedicated key is recommended; when
unset the entitlement signing key is reused (matching the connector's fallback to
`licensing.public_keys_pem`), and with neither the policy is served unsigned. The sequence is the
policy publish time in epoch milliseconds (or an explicit `runtime_policy_sequence`). Generate a key pair:

```bash
node -e "const c=require('crypto');const k=c.generateKeyPairSync('ed25519');console.log('AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64='+k.privateKey.export({type:'pkcs8',format:'der'}).toString('base64'));console.log('public (connector policy_public_keys_pem):\n'+k.publicKey.export({type:'spki',format:'pem'}))"
```

**Supabase Edge Function.** `supabase/functions/policy` emits the identical envelope (canonicalisation
copied into `_shared/policy-signature.ts`, held to `packages/core` by `policy-signature.test.ts`, which
runs the real `verifySignedPolicy` over the function output). It uses the same variables as the landing
control plane: `AIDR_POLICY_SIGNING_KEY_ID` + `AIDR_POLICY_SIGNING_PRIVATE_KEY_PKCS8_B64`
(both or neither), `AIDR_POLICY_SIGNATURE_TTL_HOURS` (default 24, 1 to 720), falling back to
`AIDR_ENTITLEMENT_SIGNING_KEY_ID` / `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64`. A half-configured
pair, an invalid TTL, an unusable key or a missing publish time answers 503 `policy_signing_unavailable`
(before authentication); with no key configured the policy is served unsigned, which connectors holding
policy public keys reject. The sequence is the publish time in epoch milliseconds
(`tenant_runtime_policies.updated_at`; for an agent-bound policy the later of the revision `created_at` and
the assignment `assigned_at`). Limitation: removing an agent's assignment so it returns to the tenant policy
can yield a lower sequence than the staged revision it left; connectors then refuse it as rollback until the
tenant policy is re-published (which advances the sequence).

Rotate by adding the new public key to connectors, switching the landing key id and private key,
then revoking the old `key_id` in the signed revocation feed.
