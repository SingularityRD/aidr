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
spike window, and each channel is capped at 30 queued alerts per minute. An
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
