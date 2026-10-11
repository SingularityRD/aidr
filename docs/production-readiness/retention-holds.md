# Retention, offboarding and legal holds

Migration `20260916000004_retention_legal_holds.sql` established the shared legal-hold lock. Later billing consistency changes made settlement request keys permanent and replaced the billing pruning RPC; `20260923000024_billing_webhook_retention_guard.sql` restores hold-aware pruning for completed webhooks. These migrations leave the historical files intact.

## Serialization contract

All routine retention and legal-hold placement/release use the existing tenant advisory transaction lock:

```sql
pg_advisory_xact_lock(hashtextextended(tenant_id::text, 2606))
```

Transactions must use **READ COMMITTED**; other isolation levels are refused to prevent stale snapshots after waiting for a lock. Retention uses nonblocking acquisition and a fresh hold check under the lock. Busy tenants are reported for a subsequent scheduled run; one held or busy tenant does not prevent unrelated tenants from pruning. Held records are excluded from retention completion, not counted as deleted.

Routine pruning retains every billing settlement request key as durable financial idempotency evidence. It deletes only expired webhook rows with `processing_status = 'completed'`, for active tenants without a legal hold, under the tenant lock and a global batch budget (1–1000). Processing and failed claims, inactive tenants, held tenants, future rows and the append-only settlement ledger remain untouched. Held completed webhooks become eligible after release when the tenant is active. Legacy webhooks with `tenant_id IS NULL` cannot safely be matched to a hold: they remain with an explicit `unattributed_webhooks_retained` count and incomplete status until an operator repairs attribution. They do not stop other tenants from pruning.

## External Storage authorization (not an HTTP-spanning SQL transaction)

1. `prepare_expired_audit_exports` checks expiry and holds under the tenant lock. Apply mode persists one random authorization per selected export **before** returning its path/token. A database-clock clamp prevents an ahead-of-server client from selecting future objects. Dry run creates no authorization and makes no Storage call.
2. While any authorization exists for a tenant, a new legal-hold INSERT waits for any current lock holder and then **fails** with `legal_hold_refused_pending_export_deletion` (SQLSTATE `55000`). This refusal is **not an active hold**; operators must surface it as an urgent unresolved hold request, never success. Authorizations cover both pending and in-flight HTTP deletion.
3. Only the worker receiving the new authorization sends Storage DELETE. A second worker receives neither that token nor that tenant's pending paths. The authorization has **no automatic expiry, takeover, replay, or cancellation**. Even a 30-second client HTTP timeout does not bound how long Storage may execute the request.
4. The worker requires a successful Storage DELETE response containing only distinct authorized paths, then checks each exact path with Storage object info. A `404` permits ACK even when an upload failed before creating the object; a present object, mismatched/duplicate response path, unavailable info endpoint, non-success DELETE or timeout retains authorization and ledger for reconciliation. ACK takes the same tenant lock and atomically removes authorization and ledger; the FK prevents other code from deleting an authorized ledger row first. Service-role direct ledger DELETE is revoked.
5. ACK trusts the privileged worker's Storage absence observation. It is **not** cryptographic/provider-independent proof of erasure. Maintenance evidence explicitly acknowledges this scope and excludes replicas, caches and backups. Sending a DELETE, acquiring authorization, a timeout, or an empty HTTP success response alone never produces a deletion count. Before any side effect the script replaces previous success evidence with `status: incomplete`; an interrupted/failed run cannot leave that earlier success as its current artifact.

## Audit export publication and failed uploads

Migration `20260923000020_audit_export_publication.sql` checks for a legal hold at ledger insertion and again when the export is published. Both checks share hold placement's tenant lock. The Edge route may return a signed URL only after upload/sign and a successful final publication RPC; a hold placed during Storage HTTP prevents that publication. Failed signing or publication after a confirmed upload marks the ledger row due for retention immediately. An ambiguous upload failure keeps the normal one-day expiry so a delayed Storage completion cannot race an immediate deletion. The ledger and its quota remain until the authorized reaper confirms the exact Storage path absent and ACKs it. A failed abandonment RPC also falls back to normal expiry. A hold blocks deletion until release.

The publication RPC, Edge route and maintenance worker must ship together after the migration. These checks are local contract evidence until the PostgreSQL and live Storage acceptance runs complete.

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

## Tenant-specific premium pack objects

Migrations `20260924000013`–`20260924000015` create the private `aidr-packs` bucket, protect tenant-prefixed objects and metadata from legal-hold/closure races, and add pack deletion authorization and receipt tables. At the existing `pack_versions` retention phase, the offboarding RPC selects a bounded batch of tenant-prefixed Storage objects, including orphans, under the shared tenant lock. It refuses legacy out-of-prefix or shared metadata paths. Each object gets a run-bound, exact-path token. The CLI deletes only from `aidr-packs`, requires an exact Storage response and an independent absence lookup for every path, then calls the pack-specific ACK. The ACK checks the whole path/token batch and PostgreSQL Storage absence, writes application-level receipts, and removes pending authorization. A later batch removes metadata; phase completion and tenant closure refuse residue. Late metadata writes, late Storage uploads and held metadata mutations fail closed.

If Storage times out, returns partial/inexact results, or the worker crashes, **do not retry DELETE or mint another token**. Pending pack authorization blocks legal-hold placement and phase progression until the same fenced-request reconciliation procedure above is completed by a trusted operator. The worker's receipt is an observation of live Storage absence, not proof of provider physical erasure or backup deletion. In the local self-hosted Storage API, a missing object returns HTTP 400 with `statusCode: "404"`, `error: "not_found"`, and `code: "NoSuchKey"`; the driver accepts only that exact absence form or HTTP 404, never a general 400. Before deploying this upgrade, fence every old offboarding worker and drain its in-flight Storage requests; mixed-version deletion is unsupported. Isolated PostgreSQL/HTTP fixtures and a synthetic self-hosted offboarding run exercised real Storage DELETE, exact response, absence, ACK, metadata removal and a retained receipt; the run correctly stopped at `waiting_retention` for other data classes. This is not a signed release candidate or a completed tenant-erasure claim. Live cloud/provider acceptance, backup expiry/key-destruction evidence, and independent release authorization remain open. Do not represent local test success as a customer erasure certificate.

## Expired, unaccepted team invitations

Migration `20260924000007_expired_invitation_retention.sql` adds a bounded, service-role-only routine and a partial index for pending invitations. The maintenance worker calls `prune_expired_team_invitations` in dry-run or apply mode. It removes only rows where `accepted_at IS NULL`, `expires_at <= database clock`, and `created_at + identity_membership.retention_days <= database clock`, for an active tenant whose existing `identity_membership` retention policy is present and which has no active legal hold. It takes the same tenant advisory lock as hold placement/offboarding, rechecks tenant status, policy and hold after locking, uses deterministic `(created_at, id)` batches, and refuses non-READ-COMMITTED transactions. The retention period is existing tenant policy; this change invents no new interval.

Deleting an eligible row removes its invitation recipient email and token hash along with the other row fields. Accepted invitations, unexpired or not-yet-old-enough invitations, held-tenant rows and inactive-tenant rows are retained. Active tenants with expired pending invitations but no `identity_membership` policy are retained and make the maintenance receipt incomplete, with bounded counts; contention and a hold appearing during the operation also prevent a clean completion receipt. A release or policy repair makes the corresponding rows eligible on a later run. The evidence reports application-level database row deletion, not physical erasure from backups, replicas, logs or exports. The migration and updated worker must be deployed together; this routine must not be run against a live deployment until the migration is installed.

This does not implement a person-wide DSAR export/deletion workflow. Public waitlist rows with `tenant_id IS NULL` remain outside tenant offboarding, and their retention/erasure policy is still unresolved. Pilot free-text notes and their audit-log duplication are unchanged pending an explicit business/legal evidence-retention decision.

## Legal-hold management API and dashboard (migrations `20261005101002` and `20261005101003`)

For an active tenant, hold placement/release and retention-period changes use the API. Once offboarding changes the tenant to `closing`, tenant administration stays disabled; releasing a blocking hold requires the approved legal-operator procedure below.

**Who.** The `retention-admin` Edge Function (`GET`/`POST`, `verify_jwt = true`, identity barrier, per-tenant/subject rate limit) allows an **active tenant owner or admin to read** and an **active tenant owner only to write**. Each write RPC (`admin_place_tenant_legal_hold`, `admin_release_tenant_legal_hold`, `admin_set_tenant_retention`) re-verifies the active owner inside the database, is granted to `service_role` only, validates input, takes the shared tenant lock (seed 2606) and writes its `admin_audit_logs` row (`legal_hold.placed`, `legal_hold.released`, `retention.policy.changed`) in the same transaction. The dashboard page is `/retention` ("Legal holds & retention"); admins see it read-only.

**Holds.** A hold carries `case_id`, `hold_owner`, `reason` and a reference (defaults to the case id). One active hold per tenant (unchanged unique index); history is immutable and the new columns are frozen by the existing single-release trigger. Legacy holds keep `NULL` case/owner. A placement **refused** because a Storage deletion authorization is pending returns `409 hold_refused_pending_deletion` with `hold_active: false`; the UI states plainly that the tenant is not protected. Treat it as an urgent unresolved request (see the recovery procedure above), never as success.

**Honouring holds.** Routine retention (telemetry, audit-export ledger/Storage reaper, billing, invitations, rate limits), audit-export publication and offboarding already check the hold under the tenant lock; `scripts/legal-hold-admin-postgres.test.mjs` additionally proves end to end that a hold placed through the API stops the telemetry reaper and that release makes the data eligible again.

**Per-tenant retention periods.** `tenant_data_retention_policies` (already the source for the telemetry reaper and offboarding eligibility) is now tunable per tenant within platform bounds in `public.retention_policy_bounds`: telemetry 7–3650, endpoint identity 30–3650, security intelligence 7–3650, policy configuration 30–3650, membership 30–3650, commercial records 2555–3650, security audit 365–3650 days. `temporary_exports`, `access_credentials` and `operational_ephemera` are platform-controlled. **Defaults are unchanged**: no existing row is modified and new tenants are still seeded from `tenants.retention_days` (30 by default). Old/new values and the reason are audited; setting the current value is a no-op without an audit row; changes are refused during offboarding. Shortening a period lets the next scheduled run delete data already older than the new period unless a hold is active; backups follow their separate retention.

**Rollout.** Apply both migrations before deploying `retention-admin` and the dashboard. No worker change is needed. Operators must still run the maintenance reaper on its normal schedule. Not covered: dual-control (second approver) for release, hold-owner notification, and backup/replica retention.

### Releasing a hold after offboarding starts

`blocked_legal_hold` is a protective stop, not deletion completion. The dashboard and `admin_release_tenant_legal_hold` deliberately require an active tenant, so they cannot release a hold after the tenant becomes `closing`. Do not reopen the tenant or remove the hold row to bypass this boundary. Before offering an offboarding service, assign a named legal operator and database operator who can perform this procedure; their availability and approval are deployment acceptance prerequisites.

Obtain written release approval from the tenant owner and the person responsible for the hold. Record the case, exact tenant/hold IDs, a current owner Auth user ID, the release reason, change reference, approval reference and the named operator. Fence the offboarding worker while reviewing the request. An authorized database operator then substitutes every placeholder below and runs this single transaction through an approved privileged database session. The current-owner check, closing-state check, immutable single release and append-only audit write either all commit or all roll back. The service role is used only inside this transaction; do not expose this procedure through an ordinary tenant API.

```sql
begin isolation level read committed;
set local role service_role;
do $release_offboarding_hold$
declare
  v_tenant uuid := '<tenant UUID>';
  v_hold uuid := '<hold UUID>';
  v_owner uuid := '<current owner Auth UUID>';
  v_reason text := '<approved release reason>';
  v_change text := '<change reference>';
  v_approval text := '<written approval reference>';
  v_operator text := '<named legal/database operator>';
  v_released public.tenant_legal_holds;
begin
  if length(btrim(v_reason)) not between 1 and 2000
     or length(btrim(v_change)) not between 1 and 200
     or length(btrim(v_approval)) not between 1 and 200
     or length(btrim(v_operator)) not between 1 and 200 then
    raise exception 'approved hold-release details are required';
  end if;
  perform pg_advisory_xact_lock(hashtextextended(v_tenant::text, 2606));
  perform 1 from public.tenants t join public.tenant_members m on m.tenant_id = t.id
   where t.id = v_tenant and t.status = 'closing' and m.user_id = v_owner
     and m.role = 'owner' and (m.expires_at is null or m.expires_at > clock_timestamp())
   for share of t, m;
  if not found then raise exception 'closing tenant and current owner required'; end if;
  if not exists (select 1 from public.tenant_offboarding_runs
                 where tenant_id = v_tenant and status <> 'completed') then
    raise exception 'incomplete offboarding run required';
  end if;
  update public.tenant_legal_holds
     set released_at = clock_timestamp(), released_by = v_owner, release_reason = v_reason
   where tenant_id = v_tenant and id = v_hold and released_at is null
   returning * into v_released;
  if not found then raise exception 'active hold not found'; end if;
  insert into public.admin_audit_logs(actor_user_id, tenant_id, action, detail)
    values (v_owner, v_tenant, 'legal_hold.released', jsonb_build_object(
      'hold_id', v_released.id, 'case_id', v_released.case_id,
      'hold_owner', v_released.hold_owner, 'placed_at', v_released.placed_at,
      'release_reason', v_reason, 'change_reference', v_change,
      'approval_reference', v_approval, 'operator', v_operator,
      'method', 'trusted_operator_offboarding'));
end;
$release_offboarding_hold$;
commit;
```

Verify the exact hold now has its release timestamp and reason, and one matching `legal_hold.released` audit event containing the approval/operator references. Preserve the approved change record. Resume the existing offboarding command for the same run; it rechecks holds, retention clocks and outstanding Storage authorizations. Do not manually mark receipts or the run completed. This transaction records a legally authorized application-level release; it does not establish backup expiry, physical erasure or customer acceptance.

## Verification

- `node --test scripts/legal-hold-admin-postgres.test.mjs` (Docker, cached image, offline): owner-only/tenant-scoped placement and release, validation, audit rows, one-active-hold, immutability including the new columns, refusal while an export deletion is pending, retention bounds/non-configurable classes/unchanged defaults/audited old-new values/offboarding refusal, and the reaper honouring hold, release and the configured period. `supabase/functions/__tests__/retention-admin-contract.test.ts` and `packages/dashboard/src/__tests__/retention-page.test.tsx` cover the Edge and UI contracts.

- `node --test scripts/deployment-maintenance.test.mjs`: actual CLI against a loopback HTTP fixture; held/unheld/current exports and billing, release-then-prune, dry run/idempotency, no Storage request for held paths, malformed authorization, failed/partial/wrong-path Storage responses, failed ACK, durable non-replay and stale-evidence replacement.
- `node --test scripts/team-invitation-retention-postgres.test.mjs`: applies only the additive invitation-retention migration inside its isolated, network-disabled PostgreSQL fixture; checks tenant policy duration, active status, accepted/young/future exclusions, holds, missing-policy fail-closed behavior, lock contention, batch determinism and service-only grants. `scripts/deployment-maintenance.test.mjs` also verifies its dry-run/apply integration and rejects malformed deletion receipts.
- `node --test scripts/retention-holds-postgres.test.mjs`: creates its **own** network-isolated Docker container using cached `supabase/postgres:17.11.0.004` (`--pull never`), applies the full canonical migration chain, and removes that container. Never targets an existing deployment. The Storage schema and missing `auth.jwt()` helper are minimal database fixtures; no live Storage provider erasure is claimed. Real PostgreSQL multi-connection tests prove hold-first tenant isolation, authorization-first blocking/refusal, and billing-first commit/hold ordering. They also verify release-then-prune, held/unheld/current rows, dry run, batch bounds, immutable settlement bytes, original hold-history/single-release assertions, RPC permissions, and unsupported isolation refusal.

Neither suite skips unavailable prerequisites: the PostgreSQL suite fails if Docker/the cached image is unavailable. These tests do not claim customer deployment acceptance, external Storage deletion verification, backup erasure, or a full repository test pass.

Local verification (2026-09-23): `pnpm verify:retention` passed **38/38** and `pnpm verify:offboarding` passed **49/49** against the migration chain through version 52 in isolated PostgreSQL 17.6 containers. This includes real concurrency, webhook status, inactive-tenant and permanent request-key cases; bounded rate-limit pruning; retained settlement and provider-payment evidence; fail-closed admission before fixture-only pilot configuration; admission/operator revocation under legal hold and deletion at their own offboarding retention phases; and the absence of recreated audit rows after membership cleanup. The rollback-only offboarding inventory also verified all 52 phase receipts. The baseline results below are historical.

### Offboarding extension validation on the 4c53b490 baseline

- CLI/offboarding-migration/maintenance regressions: **47/47 passed**. Original assertions remain, with legacy paths-only fixtures strictly strengthened to exact path/token/Storage receipts. Malformed credentials; partial/wrong/duplicate results, pending non-replay and stale-evidence replacement are exercised without widening timeouts or skips.
- Real PostgreSQL integrated suite: **16/16 passed** against the complete **46-migration** chain in its own cached, no-network container. The new helper `scripts/offboarding-storage-postgres-fixture.mjs` drives the actual CLI through a loopback transport into real RPCs, with fixture Storage bytes. It proves held/unheld deletion, release then prune, both concurrent hold/authorization orders, whole-batch exact ACK and replay denial, abandoned authorization, lost HTTP response, maintenance/offboarding mutual fencing, pending/residue closure denial, late registration refusal, and successful cache41/DLP42–43/billing90–91 dispatch.
- **Limitation at that historical baseline:** a tenant with nonempty `billing_settlements` could not finish commercial offboarding because the old purge conflicted with the append-only guard. Migration `20260916000008_billing_settlement_offboarding_retention.sql` superseded that purge with a retained-evidence receipt. The current real PostgreSQL test verifies the settlement remains immutable and the receipt is bound to its tenant and run.
- Tests use Node built-ins; no dependency installation, external database, shared dependency links, live-provider credentials or customer data were needed. Fixture evidence is retained under the worktree's ignored `.tmp-test/` directory. Migration ordering and `git diff --check` pass.

### Isolated validation on the f80762d1 baseline

- Own `pnpm install --offline --ignore-scripts`: passed; no shared `node_modules`.
- `pnpm verify:retention`: **17/17 passed**, including real PostgreSQL 17.6 multi-session races and the full 40-migration chain.
- Existing `billing-portal.test.ts` via root Vitest: **38/38 passed**, assertions unchanged.
- Existing offboarding/hold migration suites: **14/15 passed**. The unchanged doctor test at `scripts/deployment-offboarding.test.mjs:270` searches `String(label)` for a timer name, while the unchanged doctor emits `unverified` objects `{check, reason}`; it reports zero matching verdicts on Windows. This unrelated baseline mismatch was not hidden by changing assertions or editing the doctor.
- Migration ordering/unique-version check, JavaScript syntax checks and `git diff --check`: passed. Repository Biome excludes these `.mjs` paths, so this is not a claim that Biome linted them.

No skips, widened existing timeouts, allowlist changes, original assertion changes, finance approval changes or policy changes were made. New concurrency tests add bounded SQL/child deadlines so a blocking-lock regression fails rather than hanging.
