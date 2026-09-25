# Alert notification contract (`aidr.notification.v1`)

Status: implemented. Producer: the control plane (`supabase/functions/notification-dispatch`,
shared code in `supabase/functions/_shared/notification-delivery.ts`). Consumers: Slack
incoming webhooks, Microsoft Teams workflow webhooks, customer HTTPS webhook receivers and
e-mail recipients configured under **Settings → Notifications**.

## Privacy rule

A notification says *that* something happened and *where to look*, never *what* the agent
did. Every channel receives only:

- identifiers: delivery id, tenant id, event row id, agent id, incident id;
- enums and categories: event type, severity, threat rule id (for example `T01`) or
  `privacy`;
- bounded counts: findings, blocked sends, spike window;
- a deep link into the AIDR console.

Prompts, masked or matched text, commands, file paths, URLs, tool inputs, reasons,
artifacts, user names and e-mail addresses are never included. The outbox row is built
in SQL from validated fields only (`app.enqueue_event_notifications`), and the dispatcher
re-validates each field against a fixed allow-list before it renders a message
(`buildNotification`). An unexpected key in the database cannot reach a receiver.

## Events

| `event` | Source (inserted into `public.events`) | Channel filter |
| --- | --- | --- |
| `incident.created` | `incident` / `incident_record` with `status` open (or absent) | `incident_created` and `severity >= incident_min_severity`; one alert per `incident_id` per channel |
| `runtime.deny_critical` | `runtime_verdict` with verdict/decision `deny` and severity `critical` | `runtime_deny_critical` |
| `approval.requested` | `runtime_verdict` with verdict/decision `ask` | `approval_requested` |
| `privacy.blocked_spike` | Browser Guard `privacy_scan` with action `blocked` | `privacy_blocked_spike` once `privacy_spike_threshold` blocked sends fall within `privacy_spike_window_minutes`; at most one alert per window bucket |
| `notification.test` | Console **Send test** | always (one attempt, no retries) |
| `agent.offline` | Scheduled scan: an enrolled agent (`public.agents`) whose `last_seen` is older than the channel's threshold | `agent_offline` with `agent_offline_minutes` (5–10080). One alert per agent per outage; only outages that begin after the filter was armed (created, enabled or switched on) alert |
| `agent.recovered` | Scheduled scan: the agent of an alerted outage reported again | `agent_offline`; `counts.offline_minutes` is the outage length |
| `governance.review_overdue` | Scheduled scan: AI register items (not retired) past `review_due_at` | `governance_review_overdue`; a count, at most once per channel per UTC day, only when the count is non-zero |
| `governance.intake_requested` | A new AI intake request (same transaction) | `governance_intake_requested`; `subject.request_id`, `category` = asset type |
| `governance.change_pending` | A new four-eyes policy change request (same transaction) | `governance_change_pending`; `subject.request_id`, `category` = change kind |
| `governance.exception_expiring` | Scheduled scan: approved governance exceptions expiring within `governance_exception_days` (1–90) | `governance_exception_expiring`; a count, at most once per channel per UTC day |
| `governance.digest` | The scheduled governance digest run (`governance-digest`), whatever the e-mail outcome | `governance_digest`; counts only, once per channel per digest period. Needs the tenant's digest schedule to be enabled |

The scheduled scan is `public.enqueue_scheduled_notifications`, called by every
`notification-dispatch` run (once a minute) before it drains the outbox; a failed scan is
logged and reported as `"scheduled": null` in the run summary, and never stops event
alerts from being delivered. Filters are sent as one object: the seven original keys are
required, the agent/governance keys are optional (absent = off on create, unchanged on
update), unknown keys are refused.

`approval.requested` is informational. Approval stays out-of-band in the AIDR console;
the alert carries no approval link, token or action id, so a forwarded message cannot
approve anything.

Each channel is capped at 30 queued alerts per minute per event kind; an event flood beyond
the cap is not turned into a message flood (the events themselves are still stored and
visible in the console), and a flood of one kind (for example `approval.requested`) never
suppresses another kind's alert (for example `runtime.deny_critical`).

The dispatcher claims fairly across tenants: each claim first takes up to five due alerts
of every tenant with something due (oldest first), then tops the batch up in due order, so
one tenant's backlog or slow receivers cannot delay other tenants' alerts.

## Generic webhook

`POST <your https URL>` with `Content-Type: application/json` and these headers:

| Header | Value |
| --- | --- |
| `X-AIDR-Event` | the `event` value |
| `X-AIDR-Delivery-ID` | the delivery UUID (same as `id` in the body) |
| `Idempotency-Key` | the delivery UUID; identical on every retry of the same alert |
| `X-AIDR-Signature` | `t=<unix seconds>,v1=<hex HMAC-SHA256(secret, "<t>.<raw body>")>` |
| `User-Agent` | `Singularity-AIDR-Notifications/1.0` |

Body (JSON Schema, draft 2020-12):

```json
{
  "$id": "https://schemas.singularityrd.com/aidr/notification/v1.json",
  "type": "object",
  "additionalProperties": false,
  "required": ["schema", "id", "event", "test", "occurred_at", "tenant_id", "severity",
    "category", "subject", "counts", "links"],
  "properties": {
    "schema": { "const": "aidr.notification.v1" },
    "id": { "type": "string", "format": "uuid" },
    "event": { "enum": ["incident.created", "runtime.deny_critical", "approval.requested",
      "privacy.blocked_spike", "notification.test"] },
    "test": { "type": "boolean" },
    "occurred_at": { "type": "string", "format": "date-time" },
    "tenant_id": { "type": "string", "format": "uuid" },
    "severity": { "enum": ["info", "warning", "high", "critical", null] },
    "category": { "type": ["string", "null"], "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" },
    "subject": {
      "type": "object",
      "additionalProperties": false,
      "required": ["event_id", "agent_id", "incident_id"],
      "properties": {
        "event_id": { "type": ["string", "null"], "pattern": "^[0-9]{1,19}$" },
        "agent_id": { "type": ["string", "null"], "format": "uuid" },
        "incident_id": { "type": ["string", "null"], "pattern": "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$" }
      }
    },
    "counts": {
      "type": "object",
      "additionalProperties": false,
      "required": ["findings", "blocked", "window_minutes"],
      "properties": {
        "findings": { "type": ["integer", "null"], "minimum": 0 },
        "blocked": { "type": ["integer", "null"], "minimum": 0 },
        "window_minutes": { "type": ["integer", "null"], "minimum": 5, "maximum": 1440 }
      }
    },
    "links": {
      "type": "object",
      "additionalProperties": false,
      "required": ["dashboard"],
      "properties": { "dashboard": { "type": ["string", "null"], "format": "uri" } }
    }
  }
}
```

### Agent and governance events (additive to v1)

The body of the original five events is exactly the schema above. `agent.*` and
`governance.*` events carry the same fields plus these (every value identifier-, enum- or
count-shaped; names, purposes, justifications, hostnames and user identities are never
included):

| Field | Type | Present on |
| --- | --- | --- |
| `subject.request_id` | UUID or null | `governance.intake_requested`, `governance.change_pending` |
| `counts.items` | integer ≥ 0 or null | `governance.review_overdue`, `governance.exception_expiring` |
| `counts.window_days` | integer 1–90 or null | `governance.exception_expiring` |
| `counts.offline_minutes` | integer ≥ 0 or null | `agent.offline` (threshold), `agent.recovered` (outage length) |
| `period` | `{ "from", "to" }` date-times or null | `governance.digest` |
| `digest` | object of integers or null | `governance.digest`: `agents_enrolled`, `agents_active`, `decisions_allow`, `decisions_ask`, `decisions_deny`, `approvals_requested`, `approvals_pending`, `incidents_reported`, `incidents_open`, `incidents_open_critical`, `browser_blocked`, `browser_masked`, `mcp_not_approved`, `reviews_overdue`, `intake_pending`, `policy_changes_pending` |

A receiver that validates strictly should add these event names and optional fields to
its copy of the schema before enabling the corresponding filters.

Example:

```json
{
  "schema": "aidr.notification.v1",
  "id": "7c1f0a52-3a8e-4b8e-9d6c-2f7b8a1e4c90",
  "event": "incident.created",
  "test": false,
  "occurred_at": "2026-09-25T09:59:57.000Z",
  "tenant_id": "1f6b1b0e-0c4f-4a53-9b7e-6d0f3f9a2c11",
  "severity": "critical",
  "category": "T01",
  "subject": { "event_id": "42", "agent_id": "6a4c…", "incident_id": "inc-1" },
  "counts": { "findings": 2, "blocked": null, "window_minutes": null },
  "links": { "dashboard": "https://aidr.example.com/incidents" }
}
```

### Verifying the signature

Verify against the **raw request bytes** before parsing JSON, reject timestamps more than
five minutes old, compare in constant time, and accept any `v1` entry (more than one may
appear during a secret rotation). Deduplicate on `X-AIDR-Delivery-ID`.

```js
import { createHmac, timingSafeEqual } from "node:crypto";

export function verifyAidrSignature(secret, header, rawBody, nowSeconds = Date.now() / 1000) {
  const parts = Object.groupBy((header ?? "").split(","), (p) => p.split("=")[0].trim());
  const t = Number(parts.t?.[0]?.split("=")[1]);
  if (!Number.isSafeInteger(t) || Math.abs(nowSeconds - t) > 300) return false;
  const expected = createHmac("sha256", secret).update(`${t}.${rawBody}`).digest();
  return (parts.v1 ?? []).some((entry) => {
    const candidate = Buffer.from(entry.split("=")[1] ?? "", "hex");
    return candidate.length === expected.length && timingSafeEqual(candidate, expected);
  });
}
```

```python
import hmac, hashlib, time

def verify_aidr_signature(secret: bytes, header: str, raw_body: bytes, tolerance=300) -> bool:
    fields = [item.split("=", 1) for item in header.split(",") if "=" in item]
    stamps = [v for k, v in fields if k.strip() == "t"]
    if not stamps or not stamps[0].isdigit() or abs(time.time() - int(stamps[0])) > tolerance:
        return False
    expected = hmac.new(secret, stamps[0].encode() + b"." + raw_body, hashlib.sha256).hexdigest()
    return any(hmac.compare_digest(v, expected) for k, v in fields if k.strip() == "v1")
```

The reference implementation is `verifySignature` in
`supabase/functions/_shared/notification-delivery.ts`; the contract suite checks it
against Node's `crypto.createHmac`.

## Slack (Block Kit)

`POST https://hooks.slack.com/services/…` (or `hooks.slack-gov.com`) with
`{ "text": <title>, "blocks": [header, section(fields), actions(button "Open in AIDR"),
context("Singularity AIDR · delivery <id>")] }`. Field values are escaped for Slack
`mrkdwn`. HTTP 2xx is delivered; 4xx other than 408/429 (for example `invalid_token`,
`channel_is_archived`) is a permanent failure.

## Microsoft Teams (Adaptive Card)

`POST` to a Teams **Workflows** webhook (`*.logic.azure.com`, `*.api.powerplatform.com`)
or a legacy Office 365 connector (`*.webhook.office.com`) with
`{ "type": "message", "attachments": [{ "contentType":
"application/vnd.microsoft.card.adaptive", "content": { "type": "AdaptiveCard",
"version": "1.4", "body": [TextBlock(title), FactSet(facts), TextBlock(delivery id)],
"actions": [Action.OpenUrl "Open in AIDR"] } }] }`. Workflows answer HTTP 202.

## E-mail

One message per recipient (1 to 10 recipients) through the deployment's mailer
(`AIDR_MAIL_PROVIDER` / Resend, see `supabase/functions/_shared/mailer.ts`), subject
`[AIDR] <title>`, text and HTML bodies listing the same facts plus the deep link. The
provider idempotency key is `aidr-notification:<delivery id>:<recipient index>`. With no
mailer configured, e-mail deliveries fail permanently with `mail_not_configured`.

## Delivery semantics

- **Transactional enqueue.** The outbox row is written by an `AFTER INSERT` trigger on
  `public.events` in the same transaction as the telemetry row. A failure inside the
  enqueue is isolated (logged as `notification_enqueue_failed`) and never loses the event.
- **At-least-once.** The dispatcher leases rows with `FOR UPDATE SKIP LOCKED`; a crash
  after the receiver accepted but before the outcome was recorded causes one retry with
  the same `Idempotency-Key` / delivery id.
- **Backoff.** Up to 8 attempts: 30 s, 60 s, 2 min, 4 min, 8 min, 16 min, 32 min (±20 %
  jitter, capped at 1 h). A receiver's `Retry-After` is honoured when longer.
- **Retry vs permanent.** Retry: timeouts, network errors, DNS failures, HTTP 408, 429,
  5xx, mail provider unavailable. Permanent (`dead`): HTTP 3xx (redirects are never
  followed), other 4xx, SSRF refusal, invalid or undecryptable destination, mail rejected
  or not configured, channel disabled, workspace not active.
- **Error codes** recorded on the delivery and shown in the console:
  `receiver_rejected`, `receiver_unavailable`, `receiver_rate_limited`, `redirect_refused`,
  `timeout`, `network_error`, `dns_unresolved`, `dns_unavailable`, `ssrf_blocked`,
  `target_invalid`, `decrypt_failed`, `mail_not_configured`, `mail_rejected`,
  `mail_unavailable`, `channel_disabled`, `channel_changed`, `tenant_inactive`,
  `lease_expired`, `delivery_error`.
- **Retention.** Delivered and dead rows are pruned after the tenant's
  `operational_ephemera` retention (at most 7 days) unless a legal hold is active.

## Destination security

- Destinations are **write-only**: stored as AES-256-GCM ciphertext
  (`AIDR_NOTIFICATION_ENCRYPTION_KEYS`, associated data = tenant, channel and type) and
  never returned by any API. The console shows `host · #<6 hex of SHA-256(url)>` or a
  masked first recipient.
- **SSRF protection.** `https` only; port 443 (8443 also for generic webhooks); no
  credentials in the URL; DNS host names only (no IP literals, single-label, `localhost`,
  `.local`, `.internal`, `.lan`, `.corp`, `.home`, `.arpa`). Slack must be
  `hooks.slack.com` / `hooks.slack-gov.com` under `/services/`; Teams must be a Workflows
  or Office 365 webhook host. Before **every** send the host is resolved and every A/AAAA
  answer must be public unicast: loopback, RFC 1918, CGNAT, link-local and the
  `169.254.169.254` metadata service, unique-local (including `fd00:ec2::254`), multicast,
  documentation, benchmarking, Teredo/6to4/NAT64 and IPv4-mapped forms of those are
  refused. Redirects are never followed. Residual risk: the check and the connection
  resolve separately, so a DNS-rebinding attacker with a very short TTL could race them;
  on-prem, pair this with the functions egress allow-list (`networkPolicy.functionsEgressCIDRs`
  on Kubernetes, host firewall or egress proxy on Compose).
- **Signing secrets** are 32 to 256 printable characters, supplied by the operator
  (the console's **Generate** button creates one in the browser) and never shown again.
