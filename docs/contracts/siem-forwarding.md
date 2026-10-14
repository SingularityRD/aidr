# Central SIEM forwarding contract (`aidr.siem.forwarded_event/v1`)

Status: implemented. Producer: the control plane. Destinations are configured on the
dashboard **SIEM** page (`siem-destinations` Edge Function); a scheduled forwarder
(`siem-forwarder`) delivers. Shared code: `supabase/functions/_shared/siem-config.ts`
(validation, encryption, network policy) and `supabase/functions/_shared/siem-forwarding.ts`
(envelope, formats, transports, forwarder loop). Schema:
`supabase/migrations/20261014000100_siem_forwarding.sql`.

This is the server-side path. The per-endpoint path (each host forwards its own incidents
from a durable local queue, `packages/core/src/siem-delivery.ts`, configured with
`SINGULARITY_AIDR_SIEM_CONFIG_PATH`) keeps working unchanged; use either or both.

## What is forwarded

| Destination filter | Source rows (`public.events`) | `kind` |
| --- | --- | --- |
| Incidents | `incident`, `incident_record` | `incident` |
| Decisions: blocked / held for approval / allowed | `runtime_verdict` with verdict `deny` / `ask` / `allow` | `decision` |
| Browser Guard | `privacy_scan` with action `blocked` or `warned`; `shadow_ai_usage` with action `blocked` | `browser` |
| (test send) | none, a fixed content-free event | `test` |

A minimum severity applies to incidents and decisions (an event without a severity counts as
`info`). Allowed decisions are high volume and off by default.

Telemetry is stored already sanitised (ingest projection). The outbox copies an allow-listed
projection only: identifiers (event row id, client event id, agent id, agent IID, connector,
session id, incident id, threat id, tool name, source, plugin key, policy id), enums
(decision, severity, status, Browser Guard site/action/channel, service id), bounded counts
(findings, count, entity-type counts) and the client-side SHA-256 digest of the tool input.
Prompts, commands, paths, URLs, reasons and matched values are never stored in telemetry and
never forwarded. The forwarder re-validates every field against the same allow-list before
it renders a message.

## Event body (JSON)

```json
{
  "schema_version": "aidr.siem.forwarded_event/v1",
  "event_id": "aidr_evt_4242",
  "observed_at": "2026-10-14T07:59:58.000Z",
  "source": { "vendor": "Singularity", "product": "AIDR", "component": "control_plane" },
  "tenant_id": "22222222-2222-4222-8222-222222222222",
  "kind": "decision",
  "event": {
    "type": "runtime_verdict",
    "occurred_at": "2026-10-14T07:59:58.000Z",
    "event_row_id": "4242",
    "source_event_id": "evt-1",
    "agent_id": "6a4c0000-0000-4000-8000-000000000001",
    "agent_iid": "laptop-17",
    "connector": "claude-code",
    "decision": "deny",
    "severity": "critical",
    "threat_id": "T01",
    "tool_name": "Bash",
    "session_id": "sess-9",
    "tool_input_digest": "sha256:…"
  }
}
```

`event_id` is stable for an event (`aidr_evt_<event row id>`; `aidr_test_<delivery id>` for
a test send): it is the de-duplication key on every transport. Optional fields are omitted
when absent. Field list: `type`, `occurred_at`, `event_row_id`, `client_timestamp`,
`source_event_id`, `agent_id`, `agent_iid`, `connector`, `decision`, `severity`, `status`,
`threat_id`, `incident_id`, `session_id`, `tool_name`, `source`, `plugin_key`, `policy_id`,
`findings_count`, `user_override`, `tool_input_digest`, `site`, `action`, `channel`,
`service_id`, `count`, `entity_counts`.

## Formats and transports

| Destination | Wire format | Acknowledgement |
| --- | --- | --- |
| Syslog TLS (`tls`, default 6514) | One message per event, RFC 6587 octet counting. `json`: RFC 5424 header, structured data `[aidr@32473 eventId kind severity decision tenant]`, BOM + JSON body. `cef` / `leef`: RFC 3164 header `<PRI>Mmm dd hh:mm:ss HOST APP: ` + the record | Delivered after every byte was written, the write side closed and the collector closed cleanly |
| Syslog TCP (`tcp`, 514) | Same, unencrypted; needs the explicit plaintext opt-in | Same |
| Syslog UDP (`udp`, 514) | One datagram per event (at most 8 KiB); unencrypted; plaintext opt-in | None: "handed to the network". If the server runtime offers no UDP sockets the delivery fails with `udp_unsupported` instead of being reported as sent |
| Splunk HEC | `POST /services/collector/event`, `Authorization: Splunk <token>`, newline-separated HEC events (`sourcetype` default `aidr:event`, optional `index`, `source`) | HTTP 2xx from HEC (accepted by HEC, not proof of indexing unless indexer acknowledgement is enabled in Splunk) |
| Elastic | `POST /_bulk`, `create` actions with `_id = event_id` (works with data streams), `ApiKey` or basic authentication | Judged per item: 2xx delivered, **409 delivered** (an earlier attempt already stored it), 429/5xx retry, other 4xx dead |
| Microsoft Sentinel | Logs Ingestion API: OAuth client credentials against Microsoft Entra (`https://monitor.azure.com//.default`; `.us` / `.cn` clouds follow the endpoint), then `POST {DCE}/dataCollectionRules/{DCR}/streams/{stream}?api-version=2023-01-01` with an array of records (`TimeGenerated`, `EventId`, `TenantId`, `Kind`, `Severity` + the event fields) | HTTP 204 |
| Signed webhook | `POST <url>` per event, JSON body; headers `X-AIDR-Event: siem.<kind>`, `X-AIDR-Delivery-ID` and `Idempotency-Key` = `event_id`, `X-AIDR-Signature` as in [notifications](notifications.md#verifying-the-signature) | HTTP 2xx |

CEF and LEEF use the conventions of the endpoint exporter (`packages/core/src/siem-export.ts`,
`exportToCEF` / `exportToLEEF`): vendor `Singularity`, product `AIDR`, the same 0-10 severity
scale (info 2, warning 5, high 8, critical 10) and the same escaping, so a value can never
start a second record.

- **CEF**: `CEF:0|Singularity|AIDR|1.0|AIDR/<severity>/<KIND>[/<DECISION or ACTION>]|<name>|<0-10>|rt=<epoch ms> externalId=<event_id> cat=<kind> act=<decision> cs1Label=threat_id cs1=<threat id> …event fields`.
- **LEEF 1.0**: `LEEF:1.0|Singularity|AIDR|1.0|AIDR-<SEVERITY>-<KIND>[-<DECISION>]|` then tab-separated
  `cat`, `sev`, `devTime` (epoch ms), `externalId`, `name` and the event fields.

The endpoint syslog adapter accepts the same choice (`payloadFormat: "cef" | "leef"`, JSON by
default): it sends `exportToCEF` / `exportToLEEF` records for the incident behind the same
RFC 3164 header. QRadar and Wazuh set-up: [QRadar](../integrations/qradar.md) ·
[Wazuh](../integrations/wazuh.md) (Turkish: [QRadar](../integrations/qradar.tr.md) ·
[Wazuh](../integrations/wazuh.tr.md)).

## Delivery semantics

- **Transactional enqueue.** An `AFTER INSERT` trigger on `public.events` writes one
  `siem_deliveries` row per matching, enabled destination in the same transaction as the
  telemetry row. A failure inside the enqueue is isolated (`siem_enqueue_failed` warning) and
  never loses the event.
- **Bounded backlog.** A destination holds at most 50 000 waiting rows. Events beyond that
  are not queued and are counted in `dropped_events`, shown on the SIEM page; they are never
  silently discarded.
- **At-least-once.** The forwarder leases rows with `FOR UPDATE SKIP LOCKED` per destination
  (oldest due work first, so one tenant's backlog cannot starve another). A crash after the
  collector accepted but before the outcome was recorded causes one more delivery with the
  same `event_id`. Ordering is best effort; use `observed_at`.
- **Backoff.** Up to 12 attempts: 30 s, 60 s, 2 min … capped at 1 h (±20 % jitter); a
  `Retry-After` from the collector is honoured when longer. Retry: timeouts, network and DNS
  failures, TLS verification failures (a certificate may be fixed), HTTP 408, 429, 5xx.
  Permanent: redirects (never followed), other 4xx, a destination refused by the network
  policy, an undecryptable configuration, UDP unsupported, a plan without `siem_export`.
- **Dead letters.** A row out of attempts becomes a dead letter: listed on the SIEM page
  (time, kind, decision/severity, last error and HTTP status) and re-queueable with
  **Resend dead letters** after the collector is fixed. Disabling a destination turns its
  waiting rows into dead letters.
- **Retention.** Delivered rows and dead letters are pruned after the tenant's
  `operational_ephemera` retention (at most 7 days), never during a legal hold. Offboarding
  a workspace deletes its destinations and outbox in the same transaction.

## Security

- Owners and administrators manage destinations with a verified second factor (AAL2), the
  BUSINESS `siem_export` entitlement and a tenant rate limit; every change is audited
  (`siem_destination.*`), without any name, address or secret in the audit detail.
- Connection settings are **write-only**: sealed with AES-256-GCM under
  `AIDR_NOTIFICATION_ENCRYPTION_KEYS`, associated data `tenant:destination:provider`, never
  returned. The page shows `provider route · host:port`.
- **Network policy.** HTTPS only for HTTP providers (no credentials or query in the URL);
  certificates are always verified, against the system roots or only the destination's
  private CA (PEM). Every DNS answer must be public unicast. On-prem operators may allow
  RFC 1918 / ULA / CGNAT collectors with `AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true` (Helm
  `siem.allowPrivateNetworks`); each destination must then opt in. Loopback, link-local
  (including `169.254.169.254` and `fd00:ec2::254`), multicast and reserved addresses are
  always refused. The forwarder dials the exact address it vetted, so a DNS answer cannot
  change between the check and the connection.
- Sentinel endpoints must be `*.ingest.monitor.azure.{com,us,cn}`; the Entra token is cached
  in memory only.

## Scheduling

`siem-forwarder` accepts `POST` with `Authorization: Bearer <AIDR_NOTIFICATION_DISPATCH_TOKEN>`
(the deployment's background-delivery token, shared with the alert dispatcher) and answers
`{ ok, claimed, delivered, retrying, dead, lease_lost, pruned }`.

- **Kubernetes**: `siem.forwarder.enabled=true` renders the `siem-forwarder` CronJob (every
  minute, `concurrencyPolicy: Forbid`). List collectors in `networkPolicy.siemEgress`.
- **Docker Compose on-prem**: preparation adds the `siem-forwarder` service (dashboard image,
  read-only, all capabilities dropped). It runs every `AIDR_SIEM_FORWARD_INTERVAL_SECONDS`
  (default 60) with the token from `.env` and reports unhealthy when runs fail. Open the
  host firewall from the `functions` container to the collectors.
- **Supabase Cloud**: schedule it with pg_cron + pg_net like the alert dispatcher:

  ```sql
  select cron.schedule('aidr-siem-forwarder', '* * * * *', $$
    select net.http_post(
      url := 'https://<project-ref>.supabase.co/functions/v1/siem-forwarder',
      headers := jsonb_build_object(
        'Content-Type', 'application/json',
        'Authorization', 'Bearer ' || (select decrypted_secret from vault.decrypted_secrets
                                       where name = 'aidr_notification_dispatch_token')),
      body := '{}'::jsonb,
      timeout_milliseconds := 60000);
  $$);
  ```

## Limits

- Not yet exercised against live QRadar, Wazuh, ArcSight, Splunk, Elastic or Sentinel
  installations: the transports are tested end to end against local TLS, TCP, UDP and HTTPS
  servers with a private CA, and the formats against the endpoint exporter.
- UDP depends on the Edge runtime offering datagram sockets; prefer TLS.
- A destination's connection settings cannot be edited in place; delete and re-add it.
