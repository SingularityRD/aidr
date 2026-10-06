# Availability, capacity and failover evidence

This directory supplies the in-repository foundation for DEP-07. It does not
turn the current single-host Compose baseline into a highly available system.
The two topology files are decision templates. They become deployment evidence
only after every placeholder is resolved for an exact release candidate and the
resulting infrastructure is independently exercised.

## Run the local harness check

Start the generated dashboard, then run:

```powershell
$env:AIDR_LOAD_BASE_URL = "http://127.0.0.1:8080"
node scripts/load-test.mjs --profile deploy/ha/workload.local.example.json --output .release-evidence/load-local.json
```

Loopback targets are allowed by default. A non-loopback staging target requires
an explicit `--allow-host api.staging.example` argument. Header and body secrets
are loaded only through named environment variables and are never written to the
result. The runner consumes response bodies with a configured byte limit and
counts unexpected status, transport failure and client-side load shedding.

For distinct telemetry events, use `"event_id": { "$request_id": true }` in
`body_json`; each request gets a new UUID. `$sequence` remains numeric and
`$timestamp` produces the current UTC timestamp. The runner observes the full
declared duration even when the final scheduled response finishes early.

The output conforms to [load-result.schema.json](load-result.schema.json). A
`passed: true` result means only that the declared thresholds passed for the
recorded target, workload and time window. The result always keeps
`production_accepted`, `production_sla_proven` and `ha_proven` false. Those
claims need candidate-bound field evidence and approval outside this runner.

## Required capacity program

Freeze the release candidate digest, host sizes, database/storage tiers, region,
agent count, event size distribution, policy polling interval and read/write mix.
Do not derive the workload from the 501-row pagination fixture; it tests keyset
pagination and performs no endpoint concurrency.

Execute the following independent runs against an isolated staging environment:

1. A stepped load run establishes the saturation point and reports p50, p95,
   p99, unexpected response ratio, transport errors and dropped requests.
2. An 8-hour minimum soak run at the agreed sustained load records memory,
   connection pools, queue depth, storage growth and latency drift. Extend the
   observation window to match the customer contract before making a sales claim.
3. A noisy-neighbor run uses independently enrolled baseline and high-volume
   tenants. Compare their per-cohort error and latency results and inspect tenant
   data isolation separately; similar latency alone is not isolation proof.
4. A failover run keeps traffic active while an approved operator injects one
   failure at a time: dashboard replica, edge gateway replica, database primary,
   storage dependency, failure domain, then planned maintenance. Record the exact
   mechanism and timestamps in the change/incident record.
5. Repeat recovery with delayed dependency responses and a network partition.
   Verify policy behavior, telemetry retry semantics and duplicate/lost event
   counts, not just HTTP health.

The failover profile declares an observation window. The runner deliberately
does not execute shell, cloud or orchestrator fault commands. It reports
`fault_not_observed` if no expected request fails in the window and requires a
configured run of consecutive successes before estimating recovery. Bind the
operator's infrastructure logs to the result SHA-256 before acceptance.

## Availability denominator

For a load result, `availability_ratio` is expected responses divided by all
scheduled requests, so generator shedding is not hidden. `error_ratio` is
unexpected and transport-failed requests divided by started requests;
`loss_ratio` is requests dropped before start divided by scheduled requests.
Every profile-level or scenario-level threshold set must constrain shedding
with `max_loss_ratio` or constrain end-to-end outcomes with
`min_availability_ratio`; an error-ratio threshold alone cannot detect requests
that the load generator never started. These are workload observations, not the
contractual monthly SLI.

The commercial SLI still needs an approved endpoint set, external probe
locations, time buckets, maintenance and customer-caused exclusions, dependency
treatment, minimum sample count, evidence retention, incident boundaries and
service-credit schedule. Monthly availability must be calculated from that
approved denominator over the entire observation period.

## Local monthly SLI report (non-contractual)

The repository includes a local, file-only report generator for an operator's
already-collected interval observations. It does not probe a service and it does
not convert a load-test result into monthly availability evidence:

```powershell
node scripts/monthly-sli-report.mjs --input observations.json --output monthly-sli.json
node scripts/monthly-sli-report.mjs validate --report monthly-sli.json
node scripts/verify-monthly-sli-report.mjs
```

The input and report contracts are
[`monthly-sli-observations.schema.json`](monthly-sli-observations.schema.json)
and [`monthly-sli-report.schema.json`](monthly-sli-report.schema.json). Every
endpoint/region interval is accounted for. Omitted intervals become
`NOT_RUN`; an explicitly ambiguous interval remains `unknown`. A monthly `PASS`
requires every scoped series to cover the full named UTC calendar month. A `FAIL`
may describe only the supplied measured window. Incomplete reports remain
`unknown` or `NOT_RUN` and do not publish an error-budget duration. The report's
claim flags are permanently false: a local result is not a contractual SLA or a
99.9% claim, and it does not close COM-013. Approved maintenance and
customer-caused exclusions require a named reference and explicit approval. The local CLI bounds an input file at
16 MiB and a report file at 64 MiB; the schemas and validator also cap endpoint
and region collections, observations, exclusions, incidents and intervals.
These are local tooling limits, not production capacity or SLA guarantees.

## Topology decision gates

Use exactly one starting template:

- `topology.self-hosted.reference.yaml` for a customer-owned deployment with an
  external HA Postgres and replicated object store.
- `topology.managed-cloud.reference.yaml` for the supplier-managed model.

Both require three failure domains, replicated stateless services, external
health probes, off-host restore-tested backups, controlled rolling maintenance
and named alert ownership. Provider capability documentation is input to the
design; only a candidate-bound failover drill is acceptance evidence.
