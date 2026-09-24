# Control Plane (Auth, Dashboard, Licensing)

The control plane is the managed layer for:

- User authentication (dashboard login)
- Centralized agent inventory (installations)
- Telemetry-backed dashboards (verdict/event timeline)
- Incidents view derived from telemetry events (see `docs/incidents.md`)
- Agent-seat licensing (1 free agent, paid per additional agent)

For commercial builds, Singularity AIDR is **managed-first**: enrollment is required before protection is activated.

## Enrollment (recommended)

The primary onboarding flow is **device authorization**:

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
- The client should keep running local protections and simply disable cloud-only features (fail-open).

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
