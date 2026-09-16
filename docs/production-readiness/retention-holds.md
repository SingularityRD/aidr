# Retention, offboarding and legal holds

Migration `20260916000004_retention_legal_holds.sql` is append-only. It replaces the billing pruning RPC and legal-hold protection function, and extends the existing `scripts/deployment-maintenance.mjs` reaper. It does not change finance approval, runtime policy, source audit retention, settlement evidence, or the original migration files.

## Serialization contract

All routine retention and legal-hold placement/release use the existing tenant advisory transaction lock:

```sql
pg_advisory_xact_lock(hashtextextended(tenant_id::text, 2606))
```

Transactions must use **READ COMMITTED**; other isolation levels are refused to prevent stale snapshots after waiting for a lock. Retention uses nonblocking acquisition and a fresh hold check under the lock. Busy tenants are reported for a subsequent scheduled run; one held or busy tenant does not prevent unrelated tenants from pruning. Held records are excluded from retention completion, not counted as deleted.

Billing request/webhook rows are counted/deleted under that same lock, with the original per-table batch budget (1–1000). Expired held rows remain, then become eligible after release. Future rows and the append-only settlement ledger remain untouched. Legacy webhooks with `tenant_id IS NULL` cannot safely be matched to a hold: they remain with an explicit `unattributed_webhooks_retained` count and incomplete status until an operator repairs attribution. They do not stop other tenants from pruning.

## External Storage authorization (not an HTTP-spanning SQL transaction)

1. `prepare_expired_audit_exports` checks expiry and holds under the tenant lock. Apply mode persists one random authorization per selected export **before** returning its path/token. A database-clock clamp prevents an ahead-of-server client from selecting future objects. Dry run creates no authorization and makes no Storage call.
2. While any authorization exists for a tenant, a new legal-hold INSERT waits for any current lock holder and then **fails** with `legal_hold_refused_pending_export_deletion` (SQLSTATE `55000`). This refusal is **not an active hold**; operators must surface it as an urgent unresolved hold request, never success. Authorizations cover both pending and in-flight HTTP deletion.
3. Only the worker receiving the new authorization sends Storage DELETE. A second worker receives neither that token nor that tenant's pending paths. The authorization has **no automatic expiry, takeover, replay, or cancellation**. Even a 30-second client HTTP timeout does not bound how long Storage may execute the request.
4. The worker requires a successful Storage response containing each exact authorized path once before calling `ack_expired_audit_export`. A missing/mismatched/duplicate path, non-success response or timeout retains authorization and ledger for reconciliation. ACK takes the same tenant lock and atomically removes authorization and ledger; the FK prevents other code from deleting an authorized ledger row first. Service-role direct ledger DELETE is revoked.
5. ACK trusts the privileged worker's Storage observation. It is **not** cryptographic/provider-independent proof of erasure. Maintenance evidence explicitly acknowledges this scope and excludes replicas, caches and backups. Sending a DELETE, acquiring authorization, a timeout, or an empty HTTP success response never produces a deletion count. Before any side effect the script replaces previous success evidence with `status: incomplete`; an interrupted/failed run cannot leave that earlier success as its current artifact.

### Crash and ambiguous-result recovery

A crash after authorization (including a lost prepare response), an ambiguous Storage result, or a lost ACK response requires operator investigation. When authorization remains, later runs report it and exit 2, but still process unrelated tenants/billing. If ACK committed before its response was lost, later runs may finish normally; they do not invent a receipt for the earlier run. The service API intentionally exposes no cancellation or takeover RPC.

Before modifying pending authorization state:

- Fence/terminate the original worker and prevent it from resuming or sending more requests. Merely waiting for its client timeout is insufficient.
- Establish that every dispatched Storage request has settled and cannot execute later. If that cannot be established, leave authorization intact; the requested hold remains refused and requires escalation.
- Inspect the exact path in Storage and the ledger; retain incident/change evidence. If deletion completed, a trusted operator can ACK the token, recording that this acknowledges observed deletion rather than independently certified erasure.
- If bytes remain and no request can execute later, an authorized DBA may, under the same tenant lock, remove the abandoned authorization **without removing the ledger**, then place the hold in the same transaction. That manual cancellation must be supported by worker/request fencing evidence. Do not grant table DELETE to maintenance or automate this step.
- If ACK already committed but its response was lost, the token and ledger are absent; inspect Storage rather than inventing a repeat ACK receipt.

This deliberately sacrifices availability for the **affected tenant only** after an uncertain external side effect. It does not block retention or hold placement without a tenant-specific reason.

## Mandatory rollout boundary and limits

Stop/fence old maintenance schedulers and workers, and drain/resolve their outstanding Storage DELETE requests **before** deploying this migration/new reaper and accepting holds under this protocol. An old worker may already have selected a held path; revoking SQL ledger DELETE cannot prevent its service credential from deleting Storage bytes. Update every shipped/customer-kit reaper and restart scheduling only after the migration is installed. Quiesce maintenance during the upgrade; there is no mixed-version safety claim.

The service credential remains privileged and can bypass this protocol by calling Storage directly. SQL cannot constrain arbitrary external use of that credential. Hold administrators and maintenance operators are trusted; ordinary authenticated/anonymous users cannot call these RPCs or mutate authorization state.

Migration `20260916000007_offboarding_storage_authorizations.sql` extends this **same authorization table and tenant lock** to tenant offboarding. `run_tenant_offboarding_batch` now commits a run-bound token for every selected path; pending maintenance OR offboarding authorization stops further phase dispatch with `reconcile_storage_authorizations`, never reissues tokens, and leaves completion false. The driver requires exact Storage response names, verifies absence, then ACKs the entire batch with exact path/token pairs. Old paths-only ACK is disabled; maintenance ACK cannot consume offboarding tokens. Phase completion, run completion and tenant closure refuse pending authorization; export phase/final closure also refuse ledger residue. A shared-lock ledger INSERT guard rechecks active status at insertion, preventing a registration that waited on the older quota lock from adding exports after offboarding starts. Fleet/cache41/DLP42–43/billing90+ dispatch remains intact.

**Fence old offboarding workers as well as maintenance workers before installing 00007.** Drain/resolve requests and invalidate any saved legacy paths-only work. Revoking an old ACK cannot stop an old process with a service credential from sending Storage DELETE. Deploy the new CLI everywhere before resuming; mixed-version deletion is unsupported. On ambiguity or crash the CLI replaces prior success evidence with incomplete state, makes no blind Storage retry, and later invocations stop for reconciliation. The recovery/fencing procedure above applies to offboarding too; a trusted operator uses the run-bound whole-batch ACK only after verifying every exact path absent and that all original requests have settled.

Remaining limits: provider physical erasure, versions/replicas, external caches, customer-managed copies and backups require separate provider/customer evidence. A fixture Storage response plus absence observation is not certification of physical deletion. Privileged direct Storage access remains outside the protocol. No customer rollout/acceptance, external erasure, or general source-audit/backup completion is claimed.

## Verification

- `node --test scripts/deployment-maintenance.test.mjs`: actual CLI against a loopback HTTP fixture; held/unheld/current exports and billing, release-then-prune, dry run/idempotency, no Storage request for held paths, malformed authorization, failed/partial/wrong-path Storage responses, failed ACK, durable non-replay and stale-evidence replacement.
- `node --test scripts/retention-holds-postgres.test.mjs`: creates its **own** network-isolated Docker container using cached `supabase/postgres:17.6.1.136` (`--pull never`), applies the full canonical migration chain, and removes that container. Never targets an existing deployment. The Storage schema and missing `auth.jwt()` helper are minimal database fixtures; no live Storage provider erasure is claimed. Real PostgreSQL multi-connection tests prove hold-first tenant isolation, authorization-first blocking/refusal, and billing-first commit/hold ordering. They also verify release-then-prune, held/unheld/current rows, dry run, batch bounds, immutable settlement bytes, original hold-history/single-release assertions, RPC permissions, and unsupported isolation refusal.

Neither suite skips unavailable prerequisites: the PostgreSQL suite fails if Docker/the cached image is unavailable. These tests do not claim customer deployment acceptance, external Storage deletion verification, backup erasure, or a full repository test pass.

### Offboarding extension validation on the 4c53b490 baseline

- CLI/offboarding-migration/maintenance regressions: **47/47 passed**. Original assertions remain, with legacy paths-only fixtures strictly strengthened to exact path/token/Storage receipts. Invalid tokens, partial/wrong/duplicate results, pending non-replay and stale-evidence replacement are exercised without widening timeouts or skips.
- Real PostgreSQL integrated suite: **16/16 passed** against the complete **46-migration** chain in its own cached, no-network container. The new helper `scripts/offboarding-storage-postgres-fixture.mjs` drives the actual CLI through a loopback transport into real RPCs, with fixture Storage bytes. It proves held/unheld deletion, release then prune, both concurrent hold/authorization orders, whole-batch exact ACK and replay denial, abandoned authorization, lost HTTP response, maintenance/offboarding mutual fencing, pending/residue closure denial, late registration refusal, and successful cache41/DLP42–43/billing90–91 dispatch.
- **Separately confirmed preexisting limitation:** a tenant with nonempty `billing_settlements` cannot finish commercial offboarding: the append-only settlement guard rejects the existing purge with `billing_settlement_is_append_only`. This extension does not weaken financial immutability. A dedicated regression asserts preserved settlement data and incomplete run; the successful full-chain case has an empty settlement ledger, deletes billing requests/webhooks and records billing phase receipts. This is not a claim that arbitrary billed customers can already complete offboarding.
- Tests use Node built-ins; no dependency installation, external database, shared dependency links, live-provider credentials or customer data were needed. Fixture evidence is retained under the worktree's ignored `.tmp-test/` directory. Migration ordering and `git diff --check` pass.

### Isolated validation on the f80762d1 baseline

- Own `pnpm install --offline --ignore-scripts`: passed; no shared `node_modules`.
- `pnpm verify:retention`: **17/17 passed**, including real PostgreSQL 17.6 multi-session races and the full 40-migration chain.
- Existing `billing-portal.test.ts` via root Vitest: **38/38 passed**, assertions unchanged.
- Existing offboarding/hold migration suites: **14/15 passed**. The unchanged doctor test at `scripts/deployment-offboarding.test.mjs:270` searches `String(label)` for a timer name, while the unchanged doctor emits `unverified` objects `{check, reason}`; it reports zero matching verdicts on Windows. This unrelated baseline mismatch was not hidden by changing assertions or editing the doctor.
- Migration ordering/unique-version check, JavaScript syntax checks and `git diff --check`: passed. Repository Biome excludes these `.mjs` paths, so this is not a claim that Biome linted them.

No skips, widened existing timeouts, allowlist changes, original assertion changes, finance approval changes or policy changes were made. New concurrency tests add bounded SQL/child deadlines so a blocking-lock regression fails rather than hanging.
