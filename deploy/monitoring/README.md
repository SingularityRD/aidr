# AIDR control-plane monitoring

The dashboard exposes three operational endpoints:

- `GET /livez` and the backward-compatible `GET /healthz` prove only that the
  dashboard process can answer HTTP. Container restart policy uses `/livez`.
- `GET /readyz` returns `200` only when every configured
  production dependency is ready. Any missing, stale, malformed, unreachable or
  over-threshold required check returns `503`.
- `GET /metrics` publishes fixed-name Prometheus readiness gauges plus bounded
  dashboard request counters and a duration histogram after Bearer-token
  authentication. It contains no URLs, file paths, tenant identifiers, key
  identifiers, exception text or secrets.

`/readyz` deliberately defaults to all seven checks: `database`, `storage`,
`functions`, `signing`, `backup`, `queue`, and `certificate`. Production and
commercial/final-release startup rejects every subset. A documented local
development profile may opt into a subset only with
`AIDR_DEVELOPMENT_MODE=true`; `NODE_ENV=production`,
`AIDR_RELEASE_MODE=commercial`, or `AIDR_FINAL_RELEASE=1` overrides that escape
hatch and still requires all seven exact checks.

## Dashboard environment

Configure the dashboard container with the following values. URLs must not carry
credentials, query parameters or fragments. `VITE_SUPABASE_ANON_KEY` is the
existing public project key and is used as the `apikey` header for the three
service probes.

The deployment preparer writes this environment contract, a random metrics
token, and a read-only dashboard mount for the health directory for generated
self-hosted and managed-cloud stacks. Use `compose.monitoring.yml.example` only
for hand-authored deployments, after replacing its required host values.

```text
AIDR_HEALTH_DATABASE_URL=http://api-gw:8000/rest/v1/rpc/aidr_readiness_probe
AIDR_HEALTH_STORAGE_URL=http://api-gw:8000/storage/v1/status
AIDR_HEALTH_FUNCTIONS_URL=http://api-gw:8000/functions/v1/packs-manifest
AIDR_SIGNING_HEALTH_FILE=/run/aidr-health/signing.json
AIDR_BACKUP_HEALTH_FILE=/run/aidr-health/backup.json
AIDR_QUEUE_HEALTH_FILE=/run/aidr-health/queue.json
AIDR_PUBLIC_HTTPS_URL=https://aidr.customer.example
AIDR_METRICS_TOKEN=<random monitoring-only bearer token>
AIDR_READINESS_REQUIRED_CHECKS=database,storage,functions,signing,backup,queue,certificate
AIDR_DEVELOPMENT_MODE=false
```

The functions probe sends a bounded `GET` to the exact `packs-manifest` route
with the public project key as both the gateway `apikey` and a negative-canary
Bearer credential. Readiness accepts only its exact JSON
`401 {"error":"invalid_api_key"}` response. This exercises the gateway,
deployed handler, handler configuration, service-role database access, and the
API-key lookup without mutation or returning customer data; an oversized or
different response fails closed. The database and storage probes require a
successful `2xx` response. Redirects and timeouts fail the check. The
certificate probe performs a validating TLS handshake and checks peer expiry.

Mount `/run/aidr-health` read-only in the dashboard container. Each producer must
write a complete JSON document to a sibling temporary file, `fsync` it, then
atomically rename it over the monitored path. Files must be owned by the producer
and must not be writable by the dashboard user. The documents are operational
attestations, so access to replace them is equivalent to access to falsify
readiness.

Signing producer document:

```json
{"schema_version":1,"status":"ok","last_success_at":"2026-09-12T09:00:00Z","active_key_expires_at":"2027-09-12T09:00:00Z"}
```

Write this only after generating and independently verifying a canary signature
with the active public key. The generated host worker verifies both the shared
entitlement/revocation key and the separate delegated-credential key, then uses
the earlier configured expiry. Never include a key, signature, payload or key
id. For managed cloud, this host-side canary proves the prepared key files, not
that the provider received the same secrets; a provider-side signed-response
check remains deployment acceptance evidence.

Backup verifier document:

```json
{"schema_version":2,"status":"ok","recovery_point_at":"2026-09-12T07:50:00Z","completed_at":"2026-09-12T08:00:00Z","verified_at":"2026-09-12T08:10:00Z"}
```

Write this only after authenticating the encrypted backup with the separately
held recovery key. `recovery_point_at` must come from the authenticated
backup manifest's start-of-snapshot timestamp, not the archive finish time;
readiness and `aidr_backup_age_seconds` use that older recovery point. Legacy
v1 success receipts fail closed. Copying or merely locating a backup is not
verification.

Queue producer document:

```json
{"schema_version":1,"status":"ok","checked_at":"2026-09-12T09:00:00Z","depth":0,"oldest_age_seconds":0,"failed_jobs":0}
```

The shipped producer aggregates bound `DurableTelemetryQueue` roots and the
configured SIEM delivery queue into the values above. If a bound source cannot
be read, it publishes `status: "failed"`; it never publishes a zero value for
an unknown source. Endpoint response-command journals are endpoint-local state,
not a dashboard-host delivery queue, and require authenticated fleet health
aggregation before they can be included in a customer-wide readiness policy.

The generated Linux deployment reuses `aidr-siem-delivery.timer` as the single
one-minute scheduler for signer canaries, telemetry queue inspection, optional
SIEM draining, and evidence publication. Run
`maintenance/install-systemd.sh` on the target host; telemetry sources must be
under `/var/lib/aidr-telemetry` and SIEM state under `/var/lib/aidr-siem` so the
hardened service can lock them. Production preparation requires an explicit
`--telemetry-queue-root`, and installation refuses to activate until the
external authenticated fleet aggregator has created a real 64-hex namespace.
An empty root or missing namespace stays red.
Workstation-local queues require authenticated fleet aggregation and are not
silently represented by an empty dashboard-host directory.

The defaults are a 3 second dependency timeout, 5 second result cache, signing
canary age of 5 minutes, signing-key remaining life of 7 days, verified backup
age of 25 hours, queue status age of 2 minutes, queue depth of 1000, oldest queue
item age of 5 minutes, zero failed jobs, and certificate remaining life of 14
days. Override them only from an approved SLO and capacity record:

```text
AIDR_READINESS_TIMEOUT_MS=3000
AIDR_READINESS_CACHE_MS=5000
AIDR_SIGNING_MAX_AGE_SECONDS=300
AIDR_SIGNING_KEY_MIN_REMAINING_SECONDS=604800
AIDR_BACKUP_MAX_AGE_SECONDS=90000
AIDR_QUEUE_STATUS_MAX_AGE_SECONDS=120
AIDR_QUEUE_MAX_DEPTH=1000
AIDR_QUEUE_MAX_OLDEST_AGE_SECONDS=300
AIDR_QUEUE_MAX_FAILED_JOBS=0
AIDR_CERT_MIN_REMAINING_SECONDS=1209600
```

## Prometheus and paging

Load [prometheus-alerts.yml](./prometheus-alerts.yml) into Prometheus and adapt
[prometheus-scrape.yml.example](./prometheus-scrape.yml.example) to the internal
dashboard address. Put the same random token in the dashboard's
`AIDR_METRICS_TOKEN` and Prometheus's protected
`/run/secrets/aidr_metrics_token` file; never commit it or place it inline in
the scrape configuration. Keep `/metrics` on a private monitoring network in
addition to token authentication. Never publish it through the customer-facing
ingress.

The scrape alerts distinguish a failed scrape (`up == 0`), a successful scrape
without `aidr_readiness`, a scraped instance missing any of the seven required
check metrics, and a job with no discovered targets. The first three retain the
affected `instance` label, so a healthy replica cannot hide a failed one.
Prometheus cannot infer that one expected target was removed from discovery
while other targets remain; compare the discovered target list with the approved
deployment inventory during rollout and on-call handoff.

`aidr_dashboard_http_requests_total` and
`aidr_dashboard_http_request_duration_seconds` cover completed customer-facing
dashboard requests. They deliberately exclude `/livez`, `/healthz`, `/readyz`
and `/metrics`, so probes and scrapes do not distort the signal. The counters are
process-local and reset when an instance restarts. `AIDRDashboardErrorBudgetBurn`
uses five-minute and one-hour server-error ratios, a 100-request minimum, and a
14.4x burn threshold against the repository's non-contractual 99.9% internal
reference. It is an early operational signal, not a measured monthly SLI, an
approved SLA, external-probe evidence, or service-credit evidence.

### Posture scanner bridge (optional)

When the AI Security Posture scanner is installed, the bridge
(`services/aig-bridge`) serves its own Bearer-protected `GET /metrics`. It is
disabled (`404`) until `BRIDGE_METRICS_TOKEN` is set, answers `401` to any other
credential, and refuses to enable when the token equals `BRIDGE_API_KEY`. Put a
separate random token in `BRIDGE_METRICS_TOKEN` and in Prometheus's
`/run/secrets/aidr_bridge_metrics_token`; the `aidr-posture-scanner-bridge`
job in the scrape example targets `aig-bridge:8099`. Series:
`aig_bridge_http_requests_total{method,route,status}` and
`aig_bridge_http_request_duration_seconds` (route templates only, excluding
`/api/v1/livez`, `/api/v1/readyz` and `/metrics`),
`aig_bridge_auth_rejections_total{status}` (401/403),
`aig_bridge_upstream_failures_total{outcome}` (`rejected`, `unavailable`,
`ambiguous` AIG calls), and `aig_bridge_active_tasks{state}` (reserved, queued,
running) with `aig_bridge_task_registry_up`, which is `0` and drops the depth
gauge when the registry cannot be read. Labels never carry task or tenant ids,
targets, URLs or error text. The counters are process-local. No alert rules ship
for these series yet.

Every alert must have a named primary owner, secondary owner, paging destination
and tested escalation. The supplied alert rules do not prove that a paging
integration is installed. Before production traffic, inject one failure for each
of DB, storage, functions, signing, backup, queue and certificate, record alert
delivery and resolution, and attach the results to the candidate acceptance
record.

Configure the load balancer or orchestrator readiness gate to call `/readyz`.
Do not use `/healthz` as a production traffic-admission signal; it remains a
process-health contract for existing installation tooling.

Run the focused contract tests with:

```sh
node --test deploy/monitoring/monitoring.test.mjs
cd deploy/monitoring && promtool check rules prometheus-alerts.yml && promtool test rules prometheus-alerts.test.yml
```
