# Load, soak, noisy-neighbour and failover drill, 2026-10-11

**Label: LOCAL ENGINEERING DRILL.** It ran on one shared 4-vCPU Docker host. Every service had a single replica,
and the load generator ran on the same host. It is not HA, not a monthly SLA, not candidate-bound acceptance, and
not the 8-hour soak that the contract requires. AIDR-052 stays **BLOCKED_EXTERNAL**. The result keeps
`production_accepted`, `production_sla_proven` and `ha_proven` false.

**Evidence:** `docs/production-readiness/evidence/load-soak-2026-10-11/`

- `summary.json`: environment, the knee series, the control, soak summaries, a 10-minute latency/error series, a
  5-minute container CPU/RAM/DB-connection series, fault recovery, reconciliation, the lock A/B and findings.
- `soak-profile.json` and `quiet-control-profile.json`: the exact workload profiles.

The raw request ledger (216,000 lines, about 100 MB), the `docker stats` samples and the event-id export were not
kept. `summary.json` records their SHA-256 values.

## Result in brief

- **Knee.** The test used the 11-key ingest+policy mix: 2-event batches, 3 ingest calls to 1 policy poll. With
  another agent's containers active on the host, goodput tracked offered load up to **28 rps** and collapsed at
  34 rps. On the quiet host it tracked up to **48 rps**, with p95 at 1.8 s, and collapsed at 56 rps. Above the
  knee nothing sheds load, so goodput falls towards zero. It does not plateau (finding O1).
- **Soak.** The soak ran for **3 h (10,800 s) at 20 rps** offered, about 40% of the quiet-host knee, with two
  tenants. The noisy tenant ran at **10× the quiet tenant's rate** and exceeded its per-subject ingest quota:
  19.8% of its requests got HTTP 429.
  - The generator started all 216,000 scheduled requests and dropped none. Schedule lag was 0.44 ms at p95.
  - Outside the fault windows, quiet-tenant p50/p95/p99 were **60.7 / 98.3 / 401 ms**, with 1 error in 17,366
    requests and zero 429s. That is inside the isolation bound declared before the soak data was read: p95 at most
    269 ms, error ratio at most 0.1%, no 429s. The quiet tenant alone (control run) measured
    67 / 119 / 295 ms.
- **Faults injected under load:**

  | Fault | Requests failed | Recovery |
  | --- | --- | --- |
  | DB container restart | 28 quiet / 276 noisy, fast 503 | ≈15 s |
  | Edge-runtime restart | 0 quiet / 12 noisy, 502 | 1.3 s |
  | PostgREST restart | 4 quiet / 6 noisy, 503 | ≤ 2.4 s |
  | 30 s DB network partition (`docker network disconnect`) | 89 quiet / 887 noisy, all 10 s client timeouts | ~30 s after the network returned |

  Every component reconnected without operator action.
- **No loss, no duplication.** Clients acknowledged 122,168 ingest batches (1,221,680 event ids), and every one of
  those ids is in `public.events`, exactly once. None of the 388,430 rate-limited event ids was written.
  - 989 batches got 5xx or timeout responses. Before any retry, 77 of them (770 events) had in fact committed.
  - Re-sending all 989 batches once with the same ids, as a durable client queue does, was acknowledged and
    created no duplicates.
  - The final table holds 1,231,570 rows, all with distinct event ids. That is the acknowledged ids plus the
    replayed ones. The SHA-256 of the sorted acknowledged ids matches the same set read back from the database.
- **Defects fixed:**
  - The load runner's recovery estimate stretched across later faults (D1).
  - The read-only tenant admission check took an exclusive per-tenant lock (D2, partial fix; see below).

## Environment

| Item | Value |
| --- | --- |
| Host | 4 vCPU Intel Xeon 2.1 GHz (virtualised), 15.7 GiB RAM, kernel 6.18.44, Docker Engine 29.8.2, root disk had about 10 GB free |
| Co-tenancy | Another agent ran PostgreSQL/Supabase drill containers on this host during knee series A/B and the start of the soak. They had stopped before series C and the lock A/B. No CPU was reserved for this drill. |
| Load generator | `scripts/load-test.mjs` under Node 22.22 on the same host. It is not a separate, calibrated generator. |
| Source | `a327c4dc` at drill start, with this drill's tooling changes uncommitted. Other sessions committed to the same branch during the run. |

## Stack

The self-hosted Compose kit (`scripts/deployment-prepare.mjs`) is the target the load and noisy-neighbour
tooling is designed for. The full kit needs Studio, Envoy, Realtime, Storage, imgproxy, GoTrue and the dashboard
images, and the host lacked the disk for them. The drill therefore ran the subset that `/functions/v1/ingest`
and `/functions/v1/policy` actually use. All services shared one Docker bridge network, with one replica each:

| Service | Image | Notes |
| --- | --- | --- |
| `db` | `supabase/postgres:17.6.1.136` | The image available locally. **The kit now pins 17.11.0.004.** The 181 canonical migrations present at drill start were applied in order to a fresh database. The auth and storage schemas were stubbed the way the repository's PostgreSQL fixture tests stub them. |
| `rest` | `postgrest/postgrest:v14.17` | Kit default pool of 10 connections. |
| `functions` | `supabase/edge-runtime:v1.77.4` | The kit's pin. `supabase/functions` was copied in as `deployment-prepare` does, with the upstream self-hosted main router (150 MB and 60 s wall clock per worker). |
| `gw` | `node:24.21.0-alpine3.24` | A 30-line reverse proxy standing in for the kit's Envoy route table. |

Ed25519 entitlement and policy signing was configured, so every HTTP 200 carried a signed envelope. Both tenants
were pilot-admitted, with 50 seats and a published runtime policy each:

- **Quiet tenant:** 1 key.
- **Noisy tenant:** the owner plus 9 member keys.

## Method

1. **Knee.** Three stepped series, 60–90 s per step:
   - Series A: 11, 22, 44, 66, 88 and 110 rps, with 10 s between steps.
   - Series B: 15, 22, 28, 34 and 40 rps, with 45 s between steps.
   - Series C: 40, 48 and 56 rps on the quiet host, with 60 s between steps.

   Ingest batches carried 2 events, so the per-subject quota was never the limit. Request timeout was 10 s and
   `max_in_flight` was 400.
2. **Control.** The quiet tenant alone ran for 600 s at its soak rate (1.818 rps, 10-event batches).
3. **Isolation bound.** It was written to a file at 03:51:38 UTC, before any soak data existed. Quiet-tenant
   steady-state p95 must be at most max(2 × 119, 119 + 150) = 269 ms. The error ratio must be at most 0.1%, with
   no HTTP 429. Steady state means the whole soak minus each fault window, which runs from 5 s before injection to
   300 s after it ends.
4. **Soak.** 20 rps offered for 10,800 s.
   - Quiet tenant: 1.818 rps.
   - Noisy tenant: 18.18 rps, which is 10×. It used 5 keys, each at twice the quiet key's rate. With 10-event
     batches, that puts each noisy key above the 1,200 events/min per-subject ingest quota.
   - The runner wrote a per-request ledger (`--request-ledger`) and 30 s cohort buckets
     (`--timeseries-interval-seconds`).
   - `docker stats` and `pg_stat_activity` were sampled about every 5 s.
5. **Faults.** Each was injected by the operator script during the soak. The runner never executes faults.

   | Time into soak | Fault | Mechanism |
   | --- | --- | --- |
   | 2,400 s | DB restart | `docker restart` of the db container |
   | 4,500 s | Edge-runtime restart | `docker restart` of the functions container |
   | 6,600 s | PostgREST restart | `docker restart` of the rest container |
   | 8,700 s | DB network partition | `docker network disconnect` of the db container, 30 s, then reconnect |

   Recovery is measured from the ledger. It is the first request of a run of 20 consecutive successful requests
   in that cohort after the last failure.
6. **Reconciliation.** Every ingest request was classified:
   - **acked:** HTTP 200.
   - **rejected:** a 4xx response; it must not be written.
   - **ambiguous:** a 5xx response or a timeout; it may have committed.

   The ambiguous batches were re-sent once with the same event ids. Then every event id written since the soak
   started was exported and compared with the ledger by set and by SHA-256.
7. **Lock A/B.** The function under test was switched in place between the old (exclusive) and new (shared)
   definitions, with 60 s of cool-down before each run. The order was old, new, old, new. It ran at 34 rps and at
   52 rps with the knee profile.

## Results

### Knee (all tenants together, 2-event batches)

| Series | Offered (rps) | HTTP 200/s | Error ratio | p50 / p95 / p99 (ms) |
| --- | --- | --- | --- | --- |
| B, co-tenant | 15 | 15.0 | 0 | 85 / 254 / 896 |
| B, co-tenant | 22 | 22.0 | 0 | 65 / 263 / 1,064 |
| B, co-tenant | 28 | 28.0 | 0 | 64 / 464 / 1,313 |
| B, co-tenant | 34 | 20.1 | 34% | 2,531 / 10,006 / 10,025 |
| B, co-tenant | 40 | 2.4 | 93% | timeouts |
| A, 10 s gaps | 44 / 66 / 88 / 110 | 1.2 / 0 / 0 / 0 | 97–100% | timeouts; backlog carried over |
| C, quiet host | 40 | 40.0 | 0 | 58 / 289 / 776 |
| C, quiet host | 48 | 48.0 | 0 | 287 / 1,838 / 2,654 |
| C, quiet host | 56 | 41.3 | 13% | 7,614 / 10,001 / 10,003 |

Above the knee the two tenants degrade together. At 34 rps in series B the quiet tenant's error ratio was 33%,
against 34% for the noisy tenant. `pg_stat_activity` showed 6–9 of the 10 PostgREST connections waiting on
`Lock:advisory` inside ingest RPCs and in the event seat trigger. PostgREST logged `PGRST003` pool-acquisition
timeouts. One tenant's lock queue therefore occupies the pool that the other tenant needs.

### Soak (10,800 s, 20 rps offered, 216,000 requests, 0 dropped)

Steady state excludes the fault windows. Latencies are in ms.

| Cohort | Steady-state requests | Errors | p50 | p95 | p99 | HTTP 429 |
| --- | --- | --- | --- | --- | --- | --- |
| Quiet (1×) | 17,366 | 1 (503) | 60.7 | 98.3 | 401 | 0 |
| Noisy (10×) | 173,601 | 7 (5×503, 2×500) | 56.3 | 93.7 | 442 | 34,604 |

Over the whole run, quiet-tenant errors were 0.62% (33 × 503 and 89 timeouts). All of them fell inside fault
windows.

The 10-minute series in `summary.json` shows no drift in steady-state p95: it stays at 75–110 ms in every clean
bucket. The exception is one unexplained slowdown at t = 600–660 s (finding O5), when both tenants' p95 reached
about 5 s. No fault was injected then, offered load was constant, and the co-tenant containers were active.

### Resources and data

These are 5-minute buckets in `summary.json`. CPU is a percentage of one core.

| Container | Average CPU | Memory |
| --- | --- | --- |
| db | about 30% | 213 MiB → 500 MiB |
| PostgREST | about 19% | — |
| edge runtime | about 40% | 651 MiB → 1.12 GiB; plateaued after about 1 h; 0.85 GiB after its restart |
| gateway | about 13% | — |

- PostgreSQL had 12 client connections in total throughout. The most PostgREST connections busy at once in
  steady state was 5.
- `public.events` reached 1.28 M rows and 601 MB, including indexes.
- Ingest and policy p50 stayed at 55–65 ms. Edge workers recycle on their 60 s wall-clock limit, which produces
  periodic p99 spikes of 0.3–1 s.

### Faults

Recovery is measured from injection; the last column measures from the moment the fault cleared.

| Fault | Duration | Quiet: failed / class | Noisy: failed / class | Recovered after (quiet / noisy) | After fault cleared |
| --- | --- | --- | --- | --- | --- |
| DB restart | 0.5 s command | 28 / 503 | 276 / 503 | 15.7 s / 15.3 s | 15.1 s / 14.8 s |
| Edge-runtime restart | 0.5 s command | 0 | 12 / 502 | — / 1.3 s | — / 0.7 s |
| PostgREST restart | 0.4 s command | 4 / 503 | 6 / 503 | 2.4 s / 0.6 s | 2.1 s / 0.2 s |
| DB network partition | 30.3 s | 89 / timeout | 887 / timeout | 60.0 s / 60.6 s | 29.7 s / 30.3 s |

During a DB restart, the edge functions fail fast and closed with HTTP 503, and PostgREST reconnects by itself. During the partition, requests hang until the client's 10 s timeout instead
of failing fast. Success resumes about 30 s after the network returns (finding O2).

### Reconciliation

| Quantity | Value |
| --- | --- |
| Event ids generated in ingest requests | 1,620,000. The generator produced no duplicate ids. |
| Acknowledged (HTTP 200) | 122,168 batches, 1,221,680 ids. **Missing from the DB: 0.** |
| Rejected (HTTP 429) | 38,843 batches, 388,430 ids. **Present in the DB: 0.** |
| Ambiguous (5xx or timeout) | 989 batches, 9,890 ids. 77 batches (770 ids) had committed before any retry. |
| Replay of the ambiguous batches, same ids | 989 of 989 acknowledged. **Ambiguous ids missing afterwards: 0.** |
| Rows in DB / distinct `(tenant_id, event_id)` | 1,231,570 / 1,231,570. **Duplicates: 0.** Foreign ids: 0. |
| SHA-256 of the sorted acknowledged ids | `5c7e8b48…cc56842`. The same set read back from the DB gives the same hash. |

## Defects

**D1. Fixed: the load runner stretched an earlier fault window's RTO across later faults.**
`faultObservations()` looked for the last failure over the whole rest of the run. In a soak with several
windows, the first window therefore absorbed every later fault: the runner reported 6,675 s for a DB restart that
recovered in 15 s. The last failure is now taken from inside the window. The confirming successes may still
complete after the window ends, but a failure that interrupts them leaves the window `not_recovered`. The new test in `scripts/load-test.test.mjs` ("a later
fault does not stretch the recovery time…") failed before the fix (1,703 ms against a 1,100 ms bound) and passes
after it. The `fault_observations` in this soak's raw result predate the fix, which is why `summary.json` marks
the ledger-derived `fault_recovery` as authoritative.

**D2. Partially fixed: per-tenant exclusive lock in a read-only path.**

- **Before.** Each ingest request took the tenant's exclusive advisory lock three times: in
  `register_agent_for_ingest`, in the `get_tenant_admission` → `tenant_admission_capacity` read, and in the
  event seat-admission trigger.
- **Change.** Migration `20261011000400_tenant_admission_capacity_shared_read_lock.sql` makes the capacity read
  take the lock in **shared** mode.
- **Why the semantics hold.**
  - Every allocating caller still takes the exclusive lock first. That covers registration, Browser Guard
    registration, the event trigger, device enrollment, trials and licence grant/revoke. A session that holds
    the exclusive lock can then take the shared one.
  - A shared lock still waits for, and blocks, every exclusive holder.
  - The row-level `FOR SHARE` locks are unchanged.
- **Test.** `scripts/tenant-ga-admission-concurrency-postgres.test.mjs` gains a concurrent-reader phase. A
  second reader must not wait, while `register_agent_for_ingest` and the raw exclusive lock must still time out.
  Against the drill database, that phase failed before the migration with a lock timeout in
  `tenant_admission_capacity` and passed after it.
- **A/B results.**
  - At 34 rps on the quiet host, below the knee, there was no difference.
  - At **52 rps**, in overload, goodput rose from **33.0 / 31.3** to **42.5 / 37.8** HTTP 200/s. The error ratio
    fell from **24–28%** to **9–16%**.
  - That is two runs per arm. The quiet tenant still failed 7.5–15.9% in overload, so this narrows the problem
    but does not close it.
- **Left unchanged.** The registration and event-trigger locks stay exclusive. They protect seat allocation and
  event-id ownership, and loosening them is a security decision.

**Open, not changed here:**

- **O1. Congestion collapse above the knee.** There is no per-tenant in-flight cap and no `lock_timeout`-based
  shedding. Abandoned requests keep holding edge workers and pool connections after the client's 10 s timeout. A
  fix means choosing which tenant's work gets shed and with what retry contract. That is a product decision.
  **Partly addressed:** the product owner chose fair share per tenant; see the two fair-share addenda below.
  Collapse is gone in both re-runs, but the pre-declared quiet-tenant bound was missed in both, including after
  the admission state moved into the database.
- **O2. Partition behaviour.** Requests hang for 10 s and success resumes about 30 s after the network heals,
  because the PostgREST pool is stuck on dead connections. Dead-peer detection (libpq keepalives or
  `tcp_user_timeout` on the PostgREST DB URI) and a request deadline would bound this. No target was agreed, and
  the instruction was not to tune timeouts just to pass. **Partly addressed:** see the addendum below. The kit now
  sets libpq dead-peer detection on PostgREST's URI, and a re-run on a minimal db+rest pair shortened recovery but
  did not remove the tail.
- **O3. Edge-runtime memory.** RSS grew from 0.65 to about 1.1 GiB and then plateaued over 3 h. That says nothing
  about multi-day behaviour.
- **O4. Fixed-window quota bursts.** Noisy keys exhaust their per-minute ingest quota about 40 s into each
  window, which causes 429 bursts. The quiet tenant was unaffected.
- **O5. Unexplained slowdown.** One 60 s slowdown at t = 600 s could not be attributed. It happened while the
  co-tenant was active.

## Tooling added

`scripts/load-test.mjs` gains two options. Both are opt-in and do not change the result for existing callers.

- `--timeseries-interval-seconds N` adds per-cohort buckets to the result: count, outcome classes, p50/p95/p99,
  status counts. `deploy/ha/load-result.schema.json` gains the optional `timeseries` property.
- `--request-ledger FILE` writes one JSONL line per finished or dropped request. Each line carries the generated
  `$request_id` values, the status and the outcome. That is enough to reconcile ingested rows for loss and
  duplication. Header and `$env` values are never written, and a test asserts this.

`node --test scripts/load-test.test.mjs` passes 11 of 11 tests. `pnpm verify:load` passes.

## Limits

- **One host.** One shared 4-vCPU VM, with the load generator on the same VM and another agent's containers
  active for part of the run.
  - The knee moved from 28 to 48 rps with co-tenancy alone, so these are not capacity numbers for any sold
    topology.
  - There was one replica of every service: no failover target, no failure domains, no HA.
- **Not the full kit.**
  - The images are a subset of the kit. The stand-in gateway replaced Envoy, and there was no GoTrue, Storage,
    dashboard, TLS or backups.
  - The DB image is 17.6.1.136, not the current 17.11.0.004 pin.
  - The auth schema was stubbed.
- **Workload.** Synthetic: two tenants, 11 keys, `runtime_verdict` events of one shape, and only the ingest and
  policy endpoints. There was no dashboard query load, no SIEM delivery, no URL or file reputation, and no
  realistic event-size distribution.
- **Soak length.** The soak lasted 3 h, not the 8 h minimum in the capacity program. It is not a monthly SLI and
  says nothing about 99.9% availability.
- **Faults.** One fault of each kind, injected once. There was no repetition, no slow-dependency fault and no
  storage fault.
- **Not candidate-bound.** The run had no `candidate_id` and the worktree was dirty.
- **Measurement noise.** In the lock A/B, two runs per arm on a host whose capacity visibly changed during the
  day is indicative, not conclusive.

## Reproduce

1. Bring up `db`, `rest`, `functions` and `gw` with the configuration and images in `summary.json`. Apply the
   canonical migrations.
2. Seed two pilot-admitted tenants with keys, and export the keys as `DRILL_AUTH_QUIET`, `DRILL_AUTH_NOISY` and
   `DRILL_AUTH_NOISY_1`…`DRILL_AUTH_NOISY_4` (`Bearer …`).
3. Run:

   ```bash
   AIDR_LOAD_BASE_URL=http://127.0.0.1:58000 node scripts/load-test.mjs \
     --profile docs/production-readiness/evidence/load-soak-2026-10-11/soak-profile.json \
     --output soak.json --timeseries-interval-seconds 30 --request-ledger soak-ledger.jsonl
   ```

4. Inject the four faults at the times in the profile's `fault_windows`.
5. Re-send ambiguous batches with their ledger ids, export `(tenant_id, event_id)` for rows written since the
   start, and compare.

The drill stack, its volumes and the pulled edge-runtime image were removed after the run.

## Addendum, 2026-10-11: PostgREST dead-peer detection (finding O2)

**Label: LOCAL ENGINEERING DRILL.** This was a minimal two-container re-run on the same host, not a re-run of the soak.
It changes no acceptance flag.

**Evidence:** `docs/production-readiness/evidence/load-soak-2026-10-11/partition-keepalive-2026-10-11.json` holds
the per-run analysis. The per-request ledgers and container logs were not kept.

### Change

The kit now appends libpq parameters to PostgREST's `PGRST_DB_URI`:

```text
keepalives=1&keepalives_idle=30&keepalives_interval=10&keepalives_count=3&tcp_user_timeout=20000
```

- **Compose:** `scripts/deployment-prepare.mjs` appends it. Operators can replace the whole string with
  `AIDR_POSTGREST_DB_URI_PARAMS` in `.env` (`docs/operations/onprem-config-reference.md`).
- **Helm:** `rest.dbConnectionParams` is appended after `sslmode`. Set it to `""` to drop the parameters.
- **Keepalives:** probe idle connections. The first probe goes out after 30 s idle, then one every 10 s, and the
  connection is dropped after 3 misses.
- **`tcp_user_timeout` (20 s):** drops a connection whose sent data stays unacknowledged for 20 s. This is the
  setting that matters for a connection that was mid-query when the path died, because keepalives never probe a
  connection that has data in flight.
- **What it does not limit:** neither setting bounds query or request duration. A long query whose packets are
  acknowledged is unaffected.
- **Pool settings unchanged:** `db-pool-acquisition-timeout` stays at 10 s, `db-pool-max-idletime` at 30 s and
  `db-pool-max-lifetime` at the PostgREST default. A test asserts the kit does not set them.

PostgREST v14 passes the URI's query parameters to libpq. The measurement below confirms that the parameters take
effect: connections were dropped with `no connection to the server` partway through the partition.

### Method

- **Stack:** `postgres:17-alpine` (PostgreSQL 17.11) and `postgrest/postgrest:v14.17` on one user-defined bridge
  network, with PostgREST's default pool of 10.
- **Load:** Node `fetch` from the host at a fixed rate, with a 10 s client timeout, for 150 s per run.
  - **Slow:** `GET /rpc/slow`, which runs `pg_sleep(0.4)`, at 20 rps. That keeps about 8 statements in flight, so
    pooled connections are mid-query when the partition starts. This is the soak's situation.
  - **Light:** `GET /items?id=eq.7` at 10 rps, where connections are mostly idle.
- **Fault:** `docker network disconnect` of `db` 30 s into the run, then `docker network connect` 30 s later.
  `db` kept the same IP.
- **Recovery:** the start of the first run of 20 consecutive HTTP 200 responses after the last failure, measured
  from the reconnect. This is the soak's rule.
- **Cleanup:** the containers and network were removed after every run.

### Results

| `PGRST_DB_URI` parameters | Workload | Runs | Recovery after reconnect (s) | Failed requests started after reconnect |
| --- | --- | --- | --- | --- |
| none (before) | light | 1 | 1.3 | 12 |
| **none (before)** | slow | 3 | **26.5 / 30.7 / 31.6** | 358 / 442 / 371 |
| keepalives 10/5/3 only | slow | 1 | 24.2 | 72 |
| keepalives 10/5/3, `tcp_user_timeout` 25 s | slow | 2 | 0.3 / 0 | 1 / 0 |
| keepalives 10/5/3, `tcp_user_timeout` 10 s | slow | 1 | 0.6 | 1 |
| keepalives 30/10/3, `tcp_user_timeout` 25 s | slow | 2 | 11.8 / 31.5 | 63 / 377 |
| keepalives 30/10/3, `tcp_user_timeout` 25 s | light | 1 | 1.2 | 11 |
| **kit default: keepalives 30/10/3, `tcp_user_timeout` 20 s (after)** | slow | 3 | **11.3 / 24.4 / 23.2** | 59 / 281 / 271 |

Keepalive figures are idle / interval / count in seconds.

### Reading

- **The light workload does not reproduce O2.** With idle connections, PostgREST fails fast with 503 during the
  partition and recovers about 1 s after the reconnect, with or without the parameters.
- **The slow workload reproduces O2.** Without the parameters, recovery came 26.5–31.6 s after the reconnect,
  which matches the soak's ~30 s.
  - In one baseline run every request in the window hung until the 10 s client timeout, and PostgREST never
    entered its reconnect loop.
  - The cause was connections stuck in kernel TCP retransmission backoff, which resumed only on a late
    retransmit.
- **Keepalives alone do not help (24.2 s).** The stuck connections have data in flight, and keepalives do not probe
  them.
- **`tcp_user_timeout` removes the retransmission component.** With the kit default, recovery was 11.3–24.4 s
  (mean 19.6 s, against 29.6 s), and requests that failed after the reconnect fell from about 390 to about 200 per
  run.
- **The rest of the tail is PostgREST's own reconnect backoff.** PostgREST logs "Attempting to reconnect to the
  database in 1, 2, 4, 8, 16 seconds". If its reconnect loop starts early in a 30 s partition, the next attempt
  lands well after the network returns.
  - The two near-zero results with `tcp_user_timeout` 25 s are partly a coincidence of timing: connections died
    about 5 s before the reconnect, so the backoff was still short when the network returned. They are not a
    reason to tune the value to the partition length.
  - We found no PostgREST v14 setting for this backoff.
- **Why these values.** The kit keeps conservative values (30/10/3 and 20 s) rather than the faster ones measured
  here.
  - 20 s of unacknowledged data on a LAN path is a dead peer, not congestion.
  - The value is twice the 10 s pool-acquisition timeout, so it never preempts a request that is still waiting
    normally.

### What stays open in O2

- Requests still hang until the 10 s client timeout while connections are pinned. Bounding that needs a request
  deadline or fail-fast admission, which is O1's product decision.
- PostgREST's reconnect backoff can add up to about 16 s after a long partition.
- n = 3 per arm on a shared host is indicative, not conclusive. The soak stack (edge runtime, gateway, 11-key mix)
  was not re-run with the change.

## Addendum, 2026-10-11: PostgREST reconnect backoff (finding O2, remaining tail)

**Label: SOURCE RESEARCH, NO RUN.** No kit change and no new measurement. This addendum records why the reconnect
backoff tail measured above (recovery 11.3–24.4 s with the kit default) cannot be shortened by configuration.

### Finding: the backoff is hard-coded in every released PostgREST

The reconnect loop is `retryingSchemaCacheLoad`. It flushes the pool, queries the server version and reloads the
schema cache, and retries with a fixed policy:

```haskell
retryPolicy =
  let delayMicroseconds = 32 * oneSecondInUs {-32 seconds-}
  in  capDelay delayMicroseconds $ exponentialBackoff oneSecondInUs
```

That is 1, 2, 4, 8, 16, 32, 32, … seconds. The policy is a constant: no configuration key, environment variable
or in-database setting reaches it. The same code is in every source checked:

| Source (fetched 2026-10-11) | File | Policy |
| --- | --- | --- |
| `v14.18` (kit pin `v14.17`; 14.18 only fixes JWT time and log time) | `src/PostgREST/AppState.hs` | 1 s doubling, cap 32 s |
| `v16.4` (latest release, 2026-09-24) | `src/library/PostgREST/AppState/Reload.hs` | same |
| `main` (unreleased) | `src/library/PostgREST/AppState/Reload.hs` | same |

The `CHANGELOG.md` for 14.0 through 16.4 and the Unreleased section has no entry that changes reconnect timing.
Moving to v16 would bring the same backoff plus the v16 migration items (`jwt-role-claim-key` syntax, PostgreSQL 13
dropped), so it is not a fix for O2.

### Options checked and rejected

- **`db-pool-automatic-recovery = false` (`PGRST_DB_POOL_AUTOMATIC_RECOVERY`).** This does not shorten the
  backoff. It makes PostgREST exit on the first failed version query, so recovery moves to the container
  restart policy:
  - Docker's restart delay also doubles, from 100 ms.
  - Kubernetes `CrashLoopBackOff` starts at 10 s and grows to 5 min.
  - In-flight requests are dropped at every exit, and during a partition each restarted process fails its
    startup connection and exits again.
  - The expected tail is equal or worse, so this is unsafe as a default. It was not measured.
- **`SIGUSR1` or `NOTIFY pgrst, 'reload schema'` as a nudge.** Both go through the same debounced loader. While
  the retry loop sleeps, the loader is still running, so a new trigger queues behind the sleep instead of
  cutting it short.
- **Admin `/ready` as a fast signal.** `/ready` reports the state honestly (503 while pending, 200 once the
  schema cache reloads). It is a probe, not a trigger, and cannot speed up reconnection.
- **`db-pool-*` timeouts.** `db-pool-acquisition-timeout`, `db-pool-max-idletime` and `db-pool-max-lifetime`
  govern pooled connections, not the reconnect schedule. The kit keeps them at their defaults, as recorded
  above.
- **Shorter request or client timeouts.** These are deliberately not used to make the drill pass, per the
  readiness brief.

### Upstream

- No upstream issue asks for a configurable reconnect delay or cap. Related history:
  - [#742](https://github.com/PostgREST/postgrest/issues/742): the original recovery design, which discusses
    capped and cyclic backoff.
  - [#1878](https://github.com/PostgREST/postgrest/issues/1878): adds `Retry-After` during recovery.
  - [#1932](https://github.com/PostgREST/postgrest/issues/1932): "Connection worker delay is not being
    respected", still open.
- The upstream change would be a `db-pool-retry-max-delay`-style key read by `retryPolicy`. Opening that
  request is an owner action. This environment has no write access to the PostgREST repository.

### What stays open in O2 (unchanged)

- The reconnect tail of up to about 16 s after a 30 s partition is accepted as an upstream limit. The kit's
  dead-peer detection, from the previous addendum, still removes the TCP-retransmission part.
- Bounding the hang during the partition still needs a request deadline or fail-fast admission. That is
  O1's product decision.

## Addendum, 2026-10-11: fair-share admission (finding O1)

**Label: LOCAL ENGINEERING DRILL.** Overload A/B on a minimal stack on the same shared 4-vCPU host, with the load
generator on that host. It changes no acceptance flag, and AIDR-052 stays **BLOCKED_EXTERNAL**.

**Evidence:**

- `docs/production-readiness/evidence/load-soak-2026-10-11/fair-share-bound-declaration.json`: the bound, written
  at 16:07:10 UTC before any A/B data existed.
- `docs/production-readiness/evidence/load-soak-2026-10-11/fair-share-ab-2026-10-11.json`: every run, the control,
  the isolate-churn observation and the lease-cost measurement.

Raw load-test outputs and container logs were not kept.

### Decision and change

The product owner chose **fair share per tenant**. Under overload the heaviest tenant's excess requests are
rejected with a retryable answer, and quiet tenants keep being served.

`supabase/functions/_shared/tenant-concurrency.ts` adds per-tenant in-flight admission to `ingest` and `policy`.

- **What a slot covers.** A slot is taken **before** the API-key lookup and released when the handler settles,
  whether it returns, throws or rejects. A lease timer reclaims and logs a slot whose work never settles. The slot
  therefore covers every PostgREST call the request makes, including the four inside authentication.
- **Admission rules.** Let *n* be the tenant's slots, *total* all slots, and *active* the tenants holding a slot.
  1. If *total* ≥ capacity, the request gets 503 `service_overloaded`.
  2. If *n* ≥ the per-tenant max, it gets 429 `tenant_overloaded`.
  3. Under pressure (*total* ≥ the per-tenant max), if *n* ≥ max(floor, ⌊capacity ÷ active⌋), it gets 429
     `tenant_overloaded`.
  4. Otherwise it is admitted.
- **Why the per-tenant max sits below capacity.** One tenant alone can never take the last slots, so a quiet
  tenant's request is admitted while a noisy tenant holds everything it may. The noisy tenant is then shed until
  it falls below its fair share.
- **Admission before authentication.** The tenant is known only after authentication. A request is therefore
  charged to the tenant its key (by SHA-256) last authenticated as in this isolate.
  - A key not yet seen is charged to one shared `unresolved` bucket, so a flood of unknown or invalid keys is
    capped at one share. Under pressure, each unresolved key may have one request in flight.
  - After authentication the slot moves to the real tenant. The move is refused (429) if that tenant is already
    at its cap or share.
  - The key-to-tenant hint never reaches authorization, and a 401 or 403 forgets it.
- **Answers.** Rejections carry `{"error": "tenant_overloaded" | "service_overloaded", "retryable": true}` and
  `Retry-After`. Connectors already treat 429 and 5xx as retryable: the telemetry queue keeps the batch, and policy
  is served from cache.
- **Failure policy.** A rate limit is a security control, so the limiter fails closed.
  - A malformed `AIDR_TENANT_INFLIGHT_*` value refuses every request with 503 `tenant_limiter_unavailable` and is
    logged once per isolate.
  - An internal limiter error refuses only that request and is logged.
  - Sheds are logged as `tenant_inflight_shed`, at most once per tenant and reason every 10 s.
- **Configuration.** The defaults are capacity 10 (the kit's PostgREST pool), per-tenant max 75% of capacity
  (7), floor 2 and `Retry-After` 1 s.
  - Compose: set them in `.env.functions`; see `docs/operations/onprem-config-reference.md`.
  - Helm: `functions.tenantInflight`.
- **Tests.** `supabase/functions/__tests__/tenant-concurrency.test.ts` covers:
  - fairness, the cap, the floor and capacity;
  - release on success, throw and rejection, and lease expiry;
  - no leaks under a concurrent burst;
  - unresolved-key flooding;
  - fail-closed configuration;
  - ingest and policy handler shedding.

### Why this layer

- **Envoy cannot do it.** The gateway sees only the bearer value. The tenant comes from a hashed-key lookup in the
  database. Envoy's local rate limit bounds rate, not concurrency, and its circuit breakers are per cluster, not
  per tenant.
- **The function is where pool use starts.** Every PostgREST call the request makes, including authentication,
  runs inside the slot.
- **A database-backed lease was measured and not chosen.**
  - One extra service-role RPC round trip through PostgREST cost 3.5 / 5.8 ms (p50 / p95) sequentially, and
    6.5 / 12.9 ms at concurrency 8.
  - A lease adds two such round trips to the roughly 12 an ingest request already makes, on the same 10-connection
    pool it is meant to protect.
  - It also needs a TTL so that a killed isolate cannot leak its lease.

### Multi-instance and isolate behaviour

- **The bound is per isolate.** It is not per runtime instance, not shared by `ingest` and `policy`, and not
  shared across replicas.
- **Isolates churn under overload.** In one 95 s on-arm run the edge runtime logged 33 "CPU time soft limit
  reached", 49 "early termination" and 16 wall-clock events. A function's isolate was replaced every few seconds.
  - Each fresh isolate starts with zero counts and no key-to-tenant hints.
  - The retiring isolate keeps draining the requests it admitted.
  - Effective concurrency per instance can therefore exceed capacity.
- **Replicas multiply the bound.** With *R* replicas and two functions, the pool can face up to 2 × *R* ×
  capacity admitted requests, plus the overlap from retiring isolates.
- **What would make the bound per instance.** Admission in the runtime's long-lived main router, with the worker
  reporting the tenant back. The main router is the reviewed upstream file, and changing it was not part of this
  change.

### Method

- **Stack.** The same minimal subset as the soak:
  - `supabase/postgres:17.11.0.004` (the kit pin), with all 184 canonical migrations;
  - `postgrest/postgrest:v14.17` with pool 10 and the kit's libpq parameters;
  - `supabase/edge-runtime:v1.77.4` (the kit pin) with the upstream main router and signing configured;
  - the stand-in Node gateway.
- **Tenants.** Two pilot-admitted tenants with 50 seats each: quiet with 1 key, noisy with 10 keys.
- **Workload.** The 11-key knee profile: 2-event ingest batches, ingest : policy = 3 : 1, equal per-key rate,
  so noisy = 10×. Each run lasted 90 s at 56 and at 52 rps, with a 10 s timeout and `max_in_flight` 400.
- **Arms and order.**
  - The **off** arm set capacity and per-tenant max to 10,000, so the limiter is present but never binds. The
    **on** arm used the defaults.
  - Per rate, the order was off, on, off, on, with 60 s of cool-down. The arms were switched by restarting the
    edge runtime.
- **Pre-declared bound** (quiet tenant, every on-arm run, the whole 90 s):
  - error ratio ≤ 0.1%;
  - zero 429 or 503;
  - p95 ≤ max(2 × control p95, control p95 + 150 ms).
  The control was the quiet tenant alone at 5.09 rps for 90 s: p50 / p95 / p99 of 61.2 / 91.2 / 431 ms, 459 of 459
  succeeded. That gives a p95 bound of **241 ms**.
- **Iterations.** The first iteration missed the bound. The design was changed twice, and each version ran the
  full A/B against the same bound. All three are reported.
  - **v1:** slot after authentication; capacity 16, max 12.
  - **v2:** slot before authentication with key hints; capacity 10, max 7.
  - **v3:** v2 plus the refused move after authentication and one unresolved request per key under pressure.
    v3 is the committed code.
  - One unanalysed 90 s smoke run confirmed the v3 deployment before its A/B.

### Results

Quiet columns cover the quiet tenant only. Goodput is HTTP 200 per second across both tenants.

| Iteration, rate | Arm | Goodput (200/s) | Quiet error ratio | Quiet non-200 | Quiet p50 / p95 (ms) | Noisy 429 / 503 |
| --- | --- | --- | --- | --- | --- | --- |
| v1, 56 | off | 11.0 / 25.6 | 81.3% / 57.4% | timeouts | 10,001 / 10,004; 9,864 / 10,003 | 0 / 0 |
| v1, 56 | on | 50.2 / 48.1 | 0 / 0.87% | 4 × 503 | 1,439 / 2,452; 1,578 / 2,774 | 520 / 2; 695 / 14 |
| v1, 52 | off | 40.5 / 18.7 | 21.3% / 61.9% | timeouts | 4,108 / 10,002; 10,001 / 10,003 | 0 / 8; 0 / 0 |
| v1, 52 | on | 47.0 / 51.6 | 0 / 0 | none | 1,470 / 2,920; 530 / 1,681 | 453 / 1; 33 / 0 |
| v2, 56 | off | 25.8 / 20.5 | 53.7% / 62.8% | timeouts | 9,366 / 10,003; 10,001 / 10,003 | 0 / 0 |
| v2, 56 | on | 53.4 / 52.1 | 1.30% / 1.09% | 1 × 429 + 5 × 503; 2 × 429 + 3 × 503 | 79 / 899; 367 / 998 | 190 / 35; 300 / 44 |
| v2, 52 | off | 26.3 / 35.4 | 46.0% / 32.7% | timeouts | 8,390 / 10,002; 6,979 / 10,002 | 0 / 0 |
| v2, 52 | on | 49.9 / 51.3 | 1.17% / 0.93% | 3 × 429 + 2 × 503; 3 × 429 + 1 × 503 | 62 / 853; 57 / 476 | 158 / 25; 58 / 6 |
| v3, 56 | off | 24.8 / 19.8 | 53.9% / 63.5% | timeouts | 9,291 / 10,003; 10,001 / 10,003 | 0 / 0 |
| v3, 56 | on | 51.7 / 53.8 | 0.65% / 0.87% | 2 × 429 + 1 × 503; 4 × 429 | 319 / 868; 95 / 630 | 367 / 16; 187 / 3 |
| v3, 52 | off | 52.0 / 51.9 | 0 / 0.23% | 1 × 503 | 69 / 1,082; 506 / 1,590 | 0 / 7 |
| v3, 52 | on | 50.5 / 50.2 | 0.93% / 0.93% | 4 × 429; 3 × 429 + 1 × 500 | 61 / 928; 79 / 999 | 124 / 9; 154 / 1 |

Two figures per cell are the two runs of that arm, in order. "Timeouts" means 10 s client timeouts plus requests
the generator dropped at `max_in_flight`. Noisy 500s (0–6 per run) occurred in both arms.

### Reading

- **Collapse is gone.** At 56 rps every off-arm run collapsed: goodput 11.0–25.8 HTTP 200/s, quiet errors
  54–81%, timeouts and drops. Every on-arm run in every iteration held 48–54 HTTP 200/s, with no timeouts or
  drops. The noisy tenant received 33–695 `tenant_overloaded` answers per run, all with `Retry-After: 1`.
- **The pre-declared bound was missed in every on-arm run of every iteration.**
  - Quiet error ratios were 0.65–1.30% in v2 and v3, against ≤ 0.1%.
  - All quiet failures were retryable 429 or 503 answers (plus one 500), never timeouts. That is better than the
    21–81% timeouts off-arm, but it breaks the zero-429/503 condition.
  - Quiet p95 was 0.48–1.0 s against 241 ms.
- **Why the bound was missed.**
  - In v3, quiet sheds were charged to the shared `unresolved` bucket. The quiet key's first request in each
    fresh isolate competes there with the noisy tenant's ten keys, and under overload isolates are replaced every
    few seconds.
  - The latency comes from admitted work from several overlapping isolates and both functions. That work queues on
    one 10-connection pool and one host CPU, which fair-share admission does not schedule.
- **52 rps in the v3 window was not overload.** The off arm did not collapse there: 52.0 / 51.9 HTTP 200/s, with
  quiet errors of 0 and 0.23%. Host capacity had moved between windows. In that window the limiter cost the quiet
  tenant 0.93% retryable 429s, while its p95 stayed similar to the off arm (0.93 and 1.0 s, against 1.08 and
  1.59 s).
- **Measurement noise.** Two runs per arm on a shared host whose capacity moved during the session. The result is
  indicative, not conclusive.

### What stays open in O1

- **The isolation bound above the knee is not met.** Meeting it needs admission state that outlives an isolate:
  - instance-wide admission in the main router; or
  - a database-backed lease, measured above at 2 extra pool round trips per request; or
  - fewer isolate retirements under load.

  These are not set by the defaults here. Lower capacity or lower CPU limits were not tried, so that the bound
  would not be tuned to this host.
- **Sizing guidance is per isolate.** Operators should size `AIDR_TENANT_INFLIGHT_CAPACITY` × functions ×
  replicas against the PostgREST pool. With the defaults, one instance can admit about 20 requests (more during
  isolate overlap) onto a 10-connection pool. *(Superseded by the shared-lease addendum below: the capacity is
  now deployment-wide.)*
- **No HA, no 8 h soak, not candidate-bound.** AIDR-052 stays **BLOCKED_EXTERNAL**.

## Addendum, 2026-10-11: shared-lease fair-share admission (finding O1, second iteration)

**Label: LOCAL ENGINEERING DRILL.** The same overload A/B as the previous addendum, re-run after moving the
admission state out of the edge worker. It changes no acceptance flag, and AIDR-052 stays **BLOCKED_EXTERNAL**.

**Evidence:**

- `docs/production-readiness/evidence/load-soak-2026-10-11/fair-share-shared-lease-bound-declaration.json`: the
  bound, written at 17:31:21 UTC before any shared-lease data existed.
- `docs/production-readiness/evidence/load-soak-2026-10-11/fair-share-shared-lease-ab-2026-10-11.json`: every run,
  the control, the lease-cost measurement, edge-runtime and limiter log counts, and the SHA-256 of each raw
  load-test output. The raw outputs and container logs were not kept in the repository.

### Bound

The bound is unchanged from the previous addendum: quiet error ratio ≤ 0.1%, zero quiet 429 or 503, quiet p95 over
the whole 90 s run. The p95 limit is min(241.2 ms, the old formula applied to a fresh control). The control was
re-measured on the new stack, with the lease RPCs included, but the bound could only get stricter, never looser.
The fresh control gave p50 / p95 / p99 of 67.5 / 91.8 / 338 ms, with 459 of 459 requests succeeding. The formula
gives 241.8 ms, so the bound stayed at **241.2 ms**.

### Design chosen

The design combines option (a), a database lease counter, with option (b), resolving key to tenant in the same
call. Option (b) on its own would only have fixed the charging problem, not the per-worker counts, so it was not
measured separately.

`supabase/migrations/20261016000100_tenant_inflight_shared_leases.sql` adds two `SECURITY DEFINER` RPCs. Only
`service_role` may execute them.

- **`acquire_tenant_inflight_lease(scope, key_hash, capacity, per_tenant_max, floor, lease_seconds)`.** One call per
  request.
  - It resolves the tenant from the presented key's SHA-256 with the same lookup as authentication: the active
    hash, then a retired hash inside its overlap window. A revoked key resolves to no tenant.
  - It applies the existing fair-share rules to the live leases in the scope.
  - If the request is admitted, it writes a lease that expires after 60 s.
  - The resolved tenant only decides whose share a request counts against. The handler still authenticates the
    key in full.
- **`release_tenant_inflight_lease(scope, slot, lease_id)`.** One call when the handler settles. It frees exactly
  that lease. A late release, after the lease expired and its slot was reused, changes nothing.
- **No leaked slots.** An expired lease stops counting, and the next acquire reuses its slot row and logs
  `tenant_inflight_lease_expired`. A worker the runtime kills before it releases therefore holds its slot for at
  most 60 s. That is the main router's per-worker wall clock, so no live request outlives its lease.
- **Serialisation.** Decisions in a scope are serialised by a row lock that the acquire's own short transaction
  takes on the scope row. There is no advisory lock and nothing is held across requests.
- **Storage.**
  - Slot rows are updated in place, and no indexed column changes, so the churn stays in HOT updates on a table no
    larger than the peak number of leases.
  - The tables are `UNLOGGED` in schema `app`. A crash or failover loses only leases that would have expired
    anyway.
  - `service_role` cannot read the tables directly.
- **Edge side.** `supabase/functions/_shared/tenant-concurrency.ts` now only parses the configuration, calls the two
  RPCs and maps the answers.
  - The per-worker counts and key hints are removed.
  - `ingest` and `policy` share one scope (`machine-api`).
- **Unchanged.** The stable codes and fail-closed behaviour stay the same:
  - 429 `tenant_overloaded` and 503 `service_overloaded`, both with `Retry-After`;
  - a malformed `AIDR_TENANT_INFLIGHT_*` value answers 503 `tenant_limiter_unavailable` before any database call;
  - a failed or unreadable acquire answers the same 503, and is logged;
  - a failed release is logged, and the lease then frees itself at expiry.
- **Configuration.** No new variables. The capacity changes meaning: it is now **deployment-wide** (both functions,
  every worker and replica) instead of per isolate. Size it to the total PostgREST pool. The config reference and
  the Helm values comment are updated.

### Latency cost

Measured through the stand-in gateway and PostgREST while the functions were idle, 2,000 acquire+release pairs per
row:

| Concurrency | Acquire p50 / p95 (ms) | Release p50 / p95 (ms) | Pair p50 / p95 / p99 (ms) |
| --- | --- | --- | --- |
| 1 | 3.4 / 5.0 | 3.0 / 4.5 | 6.4 / 9.4 / 12.6 |
| 8 | 6.5 / 13.9 | 4.3 / 9.7 | 11.2 / 20.9 / 31.1 |

Both round trips use the same 10-connection pool that the admission protects. The release is awaited before the
response is returned.

### Method

The method was identical to the previous addendum:

- **Stack:** `supabase/postgres:17.11.0.004` with 185 canonical migrations, `postgrest/postgrest:v14.17` (pool 10,
  kit libpq parameters), `supabase/edge-runtime:v1.77.4` (kit digest) with the upstream main router, and the
  stand-in gateway.
- **Workload:** the 11-key knee profile, 90 s runs at 56 and 52 rps.
- **Arms:** off then on, twice per rate, with 60 s of cool-down. The off arm sets capacity and max to 10,000. It
  still makes both lease RPCs, but the limit never binds.

There was one design iteration. It was not changed after the data, and it was not re-run.

### Results

| Rate | Arm | Goodput (200/s) | Quiet error ratio | Quiet non-200 | Quiet p50 / p95 (ms) | Noisy 429 / 503 | Bound |
| --- | --- | --- | --- | --- | --- | --- | --- |
| 56 | off | 17.9 / 15.5 | 66.5% / 74.8% | timeouts and drops | 10,001 / 10,003; 10,001 / 10,003 | 0 / 0 | n/a |
| 56 | on | 52.4 / 50.6 | 1.09% / 1.74% | 5 × 503; 8 × 503 | 79 / 328; 109 / 460 | 294 / 21; 381 / 101 | **missed / missed** |
| 52 | off | 11.2 / 8.2 | 78.5% / 83.9% | timeouts and drops | 10,001 / 10,003; 10,001 / 10,003 | 0 / 0 | n/a |
| 52 | on | 47.0 / 46.3 | 1.64% / 1.40% | 7 × 503; 2 × 429 + 4 × 503 | 99 / 504; 117 / 496 | 325 / 116; 433 / 76 | **missed / missed** |

Two figures per cell are the two runs of that arm, in order. Every on-arm run missed all three conditions. There
were no on-arm timeouts or drops.

### Reading

- **The isolate problem is fixed.**
  - In all four on-arm runs the quiet tenant was never charged to the `unresolved` bucket. No `unresolved` shed was
    logged, and the quiet key was charged to its own tenant from the first request of every new worker.
  - The cap held across workers and both functions. Two seconds after each on-arm run no live lease was left.
- **Quiet latency improved but still missed.** Quiet p95 fell from 0.63–1.00 s (v3, per isolate) to 0.33–0.50 s,
  against a bound of 241 ms.
- **Quiet errors did not improve.** Quiet error ratios were 1.09–1.74%, against 0.65–0.93% in v3. The
  deployment-wide capacity of 10 is half of what two per-isolate limiters admitted.
- **Why the bound was still missed.** Every quiet refusal came while the deployment was at capacity 10 and the
  quiet tenant already held **3 to 5 leases of its own**. Its fair share is 5.
  - Two refusals were `fair_share` at exactly 5. The rest were `capacity`.
  - At about 5 quiet requests per second, holding 3–5 leases means individual quiet requests took roughly
    0.6–1 s. They were stalled while holding a lease, not refused admission because of other tenants' leases.
  - The edge runtime still retired workers 43–49 times per on-arm run on its CPU-time soft limit.
  - Concurrency admission bounds requests in flight, not CPU time or worker restarts on a saturated 4-vCPU host.
    The noisy tenant was still served at about 42–47 HTTP 200/s on the same CPUs.
- **The off arm changed too.** It collapsed in all four runs, with goodput of 8.2–17.9 HTTP 200/s. At 52 rps that
  is lower than the previous off arm's 52.0 / 51.9, so host capacity moved again between windows. The off arm now
  also pays the two lease RPCs.
  - Under collapse the lease RPCs themselves failed. `tenant_limiter_error` and `tenant_inflight_release_failed`
    were logged, and expired leases were reclaimed. A collapsed deployment fails closed with 503
    `tenant_limiter_unavailable` rather than admitting unbounded work.
- **Measurement noise.** Two runs per arm on a shared host whose capacity moved during the day. The result is
  indicative, not conclusive.

### What stays open in O1

- **The quiet-tenant isolation bound above the knee is still not met.** The remaining cause is that the quiet
  tenant's own admitted requests stall under CPU saturation and worker retirement. Admission state is no longer
  the cause.
- **Options not tried.** Each of these would set the result on this host rather than in the design, so none was
  tried:
  - a lower capacity;
  - lower CPU limits;
  - preempting leases granted before a tenant became active;
  - a CPU-aware or rate-based limit for the noisy tenant.
- **Sizing guidance is now deployment-wide.** Set `AIDR_TENANT_INFLIGHT_CAPACITY` (Helm
  `functions.tenantInflight.capacity`) to the total PostgREST pool that `ingest` and `policy` share.
- **No HA, no 8 h soak, not candidate-bound.** AIDR-052 stays **BLOCKED_EXTERNAL**.
