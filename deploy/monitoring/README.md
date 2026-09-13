# AIDR control-plane monitoring

The dashboard exposes three operational endpoints:

- `GET /livez` and the backward-compatible `GET /healthz` prove only that the
  dashboard process can answer HTTP. Container restart policy uses `/livez`.
- `GET /readyz` returns `200` only when every configured
  production dependency is ready. Any missing, stale, malformed, unreachable or
  over-threshold required check returns `503`.
- `GET /metrics` publishes fixed-name Prometheus gauges. It contains no URLs,
  file paths, tenant identifiers, key identifiers, exception text or secrets.

`/readyz` deliberately defaults to all seven checks: `database`, `storage`,
`functions`, `signing`, `backup`, `queue`, and `certificate`. Do not remove a
check from `AIDR_READINESS_REQUIRED_CHECKS` to make a production rollout green.
An intentionally smaller list is suitable only for a documented development or
degraded-service profile.

## Dashboard environment

Configure the dashboard container with the following values. URLs must not carry
credentials, query parameters or fragments. `VITE_SUPABASE_ANON_KEY` is the
existing public project key and is used as the `apikey` header for the three
service probes.

For the generated self-hosted stack, apply
`compose.monitoring.yml.example` as an additional Compose file after replacing
the required host values. Managed cloud deployments use the same environment
contract and mount the evidence directory through their container platform.

```text
AIDR_HEALTH_DATABASE_URL=http://api-gw:8000/rest/v1/
AIDR_HEALTH_STORAGE_URL=http://api-gw:8000/storage/v1/status
AIDR_HEALTH_FUNCTIONS_URL=http://api-gw:8000/functions/v1/api-keys
AIDR_SIGNING_HEALTH_FILE=/run/aidr-health/signing.json
AIDR_BACKUP_HEALTH_FILE=/run/aidr-health/backup.json
AIDR_QUEUE_HEALTH_FILE=/run/aidr-health/queue.json
AIDR_PUBLIC_HTTPS_URL=https://aidr.customer.example
AIDR_READINESS_REQUIRED_CHECKS=database,storage,functions,signing,backup,queue,certificate
```

The functions probe sends `OPTIONS`; the canonical functions return a `200`
preflight without performing an authenticated operation. The database and
storage probes require a successful `2xx` response. Redirects and timeouts fail
the check. The certificate probe performs a validating TLS handshake and checks
the peer certificate expiry.

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
with the active public key. Never include the key, signature, payload or key id.

Backup verifier document:

```json
{"schema_version":1,"status":"ok","completed_at":"2026-09-12T08:00:00Z","verified_at":"2026-09-12T08:10:00Z"}
```

Write this only after authenticating the encrypted backup with the separately
held recovery key. Copying or merely locating a backup is not verification.

Queue producer document:

```json
{"schema_version":1,"status":"ok","checked_at":"2026-09-12T09:00:00Z","depth":0,"oldest_age_seconds":0,"failed_jobs":0}
```

Aggregate every durable delivery/retry queue into the values above. If a source
cannot be read, publish `status: "failed"` or let the previous document become
stale. Do not publish a zero value for an unknown source.

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
dashboard address. Keep `/metrics` on a private monitoring network or require
ingress authentication. Never publish it through the customer-facing ingress.

The scrape alerts distinguish a failed scrape (`up == 0`), a successful scrape
without `aidr_readiness`, and a job with no discovered targets. The first two
retain the affected `instance` label, so a healthy replica cannot hide a failed
one. Prometheus cannot infer that one expected target was removed from discovery
while other targets remain; compare the discovered target list with the approved
deployment inventory during rollout and on-call handoff.

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
