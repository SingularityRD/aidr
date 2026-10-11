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
- **O2. Partition behaviour.** Requests hang for 10 s and success resumes about 30 s after the network heals,
  because the PostgREST pool is stuck on dead connections. Dead-peer detection (libpq keepalives or
  `tcp_user_timeout` on the PostgREST DB URI) and a request deadline would bound this. No target was agreed, and
  the instruction was not to tune timeouts just to pass.
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
