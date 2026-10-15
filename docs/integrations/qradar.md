# IBM QRadar integration (LEEF over syslog)

Türkçe: [qradar.tr.md](qradar.tr.md). Contract: [SIEM forwarding](../contracts/siem-forwarding.md).

AIDR sends QRadar one LEEF 1.0 record per incident, decision or Browser Guard event. There is
no IBM-published DSM for Singularity AIDR; QRadar's built-in **Universal LEEF** DSM parses the
records, and the DSM Editor maps them to QIDs and custom properties. This guide has not yet
been run against a live QRadar installation; treat the first set-up as a staging rehearsal.

## 1. Choose the sender

| Sender | When | Configure |
| --- | --- | --- |
| Central (recommended) | One stream from the AIDR server for every endpoint | SIEM page → **Central forwarding** → Add destination: type *Syslog*, format *LEEF (QRadar)*, transport *TLS*, collector = QRadar event collector, port 6514 |
| Per endpoint | Each host sends its own incidents (no server path, or segmented networks) | SIEM page → **Host forwarding**: message format *LEEF (QRadar)*; copy the generated `adapter` block (`"payloadFormat": "leef"`) to `SINGULARITY_AIDR_SIEM_CONFIG_PATH` on the host |

For a collector on a private address (10.x, 172.16-31.x, 192.168.x), the AIDR operator sets
`AIDR_SIEM_ALLOW_PRIVATE_NETWORKS=true` (Compose `.env.functions`) or
`siem.allowPrivateNetworks=true` (Helm) and you tick *Allow a private-network collector* on
the destination. On Kubernetes also list the collector in `networkPolicy.siemEgress`.

## 2. QRadar log source

1. **Admin → Log Source Management → New Log Source** (or **Admin → Log Sources** on older
   versions).
2. *Log Source Type*: **Universal LEEF**.
3. *Protocol*:
   - **TLS Syslog** (recommended): listen port `6514`. Give QRadar a server certificate issued
     by your internal CA, and paste that CA's PEM certificate into the AIDR destination
     (*Private CA certificate*). AIDR always verifies the certificate and its host name.
   - **Syslog** (TCP or UDP 514): unencrypted. AIDR requires the explicit plaintext
     confirmation; UDP has no acknowledgement.
4. *Log Source Identifier*: the syslog HOSTNAME AIDR sends. Central forwarding sends
   `aidr-control-plane` unless the destination sets another `hostname`; per-endpoint
   forwarding sends the configured `hostname` (default `aidr`).
5. Save and **Deploy Changes**.

## 3. Verify

On the SIEM page press **Send test**. QRadar's Log Activity shows an event with
`EventID = AIDR-INFO-TEST` from the log source. If it does not arrive, the page shows the
last error (`tls_verification_failed`, `destination_policy_rejected`, `network_error`, …).

## 4. Record layout

```
<PRI>Oct 14 07:59:58 aidr-control-plane aidr: LEEF:1.0|Singularity|AIDR|1.0|AIDR-CRITICAL-DECISION-DENY|cat=decision	sev=10	devTime=1791964798000	externalId=aidr_evt_4242	name=AIDR deny decision - T01	tenant_id=…	kind=decision	type=runtime_verdict	decision=deny	severity=critical	threat_id=T01	agent_iid=laptop-17	connector=claude-code	tool_name=Bash	…
```

| LEEF key | Meaning | QRadar use |
| --- | --- | --- |
| EventID (header) | `AIDR-<SEVERITY>-<KIND>[-<DECISION or ACTION>]`; endpoint incidents: `AIDR-<SEVERITY>` | QID mapping |
| `cat` | `incident`, `decision`, `browser`, `test` | Category / QID mapping |
| `sev` | 0-10 (info 2, warning 5, high 8, critical 10) | Severity |
| `devTime` | Event time, epoch milliseconds | Start time |
| `externalId` | Stable event id (`aidr_evt_<n>`); identical on a re-delivery | De-duplication, offense notes |
| `decision` | `allow`, `ask` (held for out-of-band approval), `deny` | Custom property |
| `threat_id` | AIDR rule id (for example `T01`) | Custom property |
| `agent_iid`, `connector`, `session_id`, `tool_name` | Which agent, which host connector, which tool | Custom properties |
| `incident_id`, `status`, `findings_count` | Incident correlation | Custom properties |
| `site`, `action`, `channel`, `entity_counts` | Browser Guard: AI site, blocked/warned, prompt/paste/file, entity-type counts | Custom properties |
| `tenant_id` | AIDR workspace | Multi-tenant filtering |

No prompt, command, path or URL is ever included (see the contract).

## 5. QID mapping (DSM Editor)

**Admin → DSM Editor → Universal LEEF**, then add event mappings for the EventIDs you need.
Suggested low-level categories (adapt to your taxonomy):

| EventID pattern | Suggested category |
| --- | --- |
| `AIDR-*-DECISION-DENY` | Policy Violation / Access Denied |
| `AIDR-*-DECISION-ASK` | Suspicious Activity (pending approval) |
| `AIDR-*-DECISION-ALLOW` | Information |
| `AIDR-*-INCIDENT`, `AIDR-<SEVERITY>` | Suspicious Activity / Malware (by `threat_id`) |
| `AIDR-*-BROWSER-BLOCKED` | Data Loss Prevention |
| `AIDR-INFO-TEST` | Information |

Add custom event properties for `decision`, `threat_id`, `agent_iid`, `tool_name` and
`incident_id` (Universal LEEF already extracts every `key=value`), then build rules, for
example *“3 or more AIDR deny decisions for the same agent_iid within 10 minutes”*.

Example AQL:

```sql
SELECT DATEFORMAT(devicetime, 'yyyy-MM-dd HH:mm') AS t, "decision", "threat_id", "agent_iid"
FROM events
WHERE LOGSOURCETYPENAME(devicetype) = 'Universal LEEF' AND "decision" = 'deny'
LAST 24 HOURS
```

## 6. CEF instead (ArcSight, or QRadar with CEF)

Choose *CEF (ArcSight)* as the format. Records follow
`CEF:0|Singularity|AIDR|1.0|AIDR/<severity>/<KIND>[/<DECISION>]|<name>|<0-10>|rt=… externalId=… cat=… act=<decision> cs1Label=threat_id cs1=<rule> …`.
In ArcSight use a Syslog SmartConnector (CEF is parsed natively); in QRadar use the
**Universal CEF** DSM.
