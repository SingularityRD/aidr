# PostgreSQL 17.6.1.136 → 17.11.0.004 backup/restore and upgrade drill, 2026-10-11

**Label: local engineering drill. Not production acceptance.** All of it ran on one Docker host with synthetic
data. It is not a separate failure domain, nothing went offsite, the recovery key had no independent custody,
and no customer RPO/RTO target was approved. AIDR-044 stays **BLOCKED_EXTERNAL**.

The drill gates the stateful image change that `upstream-image-triage-2026-10-11.md` left open. Moving
`supabase/postgres` from `17.6.1.136` to `17.11.0.004` drops the image's Trivy findings from 0 CRITICAL / 48 HIGH
to 0 / 23. That record would not change the pin until a migration, backup and restore drill had run.

**Result.** 17.11.0.004 passed:

- A cold encrypted backup of a 17.6.1.136 deployment, made with the shipped backup tool, restored onto 17.11.0.004.
- All 181 canonical migrations were present after the restore, and none was re-applied.
- Every table count and content hash matched the source.
- RLS behaviour, policies, functions and grants were identical.
- Storage bytes and Storage API reads matched.
- The repository's 18-table/object recovery comparison passed.
- Every suite that can target an existing database passed on 17.11 with the same results as on 17.6.
- The blocking `postgres-gates` step passed with the pin moved (see below).

The pin was moved. The drill also found a **backup-tool gap that has nothing to do with the image**. The cold
backup does not include the `db-config` volume, which holds the pgsodium/Vault root key. A restored Vault secret
therefore cannot be decrypted, on 17.6 as much as on 17.11.

**Evidence:** `docs/production-readiness/evidence/postgres-upgrade-restore-drill-2026-10-11/`. It holds
`summary.json`, the restore script, `verify.sql`, the per-run timelines, the verification outputs for the source
baseline, both restores and the in-place and rollback runs, and the storage inventories. The drill containers,
volumes, backup ciphertext and key were deleted after the run.

## Images (resolved through `mirror.gcr.io`, cross-checked with the `hub.docker.com` tag API)

| Role | Reference | Index digest | Notes |
|---|---|---|---|
| Source (current pin) | `supabase/postgres:17.6.1.136` | `sha256:f371b5f3f2ac0a05703f33d6e6134515fb2498cab708fb948a0aeb7481467c00` | PostgreSQL 17.6, built 2026-06-15 |
| Candidate | `supabase/postgres:17.11.0.004` | `sha256:06ddc7962e11ab0f4f0334fd05671e97c30ea202f6e6a7113800bd3d6e416108` (hub tag API: same; last pushed 2026-10-05) | PostgreSQL 17.11; amd64 manifest `sha256:4b438c22395a9a2bd19ee0522742cc9a1ff91db4732ff0c1b08fc07e9c767c22`, arm64 `sha256:2638e94e8e712b2926a2763c37ecfaee4b7abde2cd804a01ac55bba031e52a00` |
| Storage | `supabase/storage-api:v1.80.2@sha256:95b217a9…d7d2` | | kit pin |
| Auth | `supabase/gotrue:v2.197.0@sha256:1736a630…2c6b` | | kit pin (it creates the `auth` schema the migrations need) |
| Backup helper | built by `scripts/lib/node-helper-image.mjs` from `node:24.21.0-alpine3.24` | image `sha256:59a1812ddb1d9e2e048af874d04d6057300161b5d1e1f8319d5f56ce757a1140` | `--network none` |

Compatibility facts checked on this host:

- Both images report `pg_control version 1700` and catalog version `202406281` on the restored data directory.
- Both run `postgres` as uid/gid `100:101`.
- Both carry 78 extension control files.
- The image init migrations differ by exactly one file:
  `20260730000000_revoke_trigger_on_cron_tables_from_postgres.sql`. It revokes `TRIGGER` on `cron.job_run_details`
  and redefines `extensions.grant_pg_cron_access()`.

This is an in-major move, so neither `pg_upgrade` nor a dump/restore is needed. Upstream's only upgrade script,
`deploy/upstream/docker/utils/upgrade-pg17.sh`, covers 15 → 17. The drill applied its step-9 pattern for an
in-major move: the new image migration, `ALTER EXTENSION … UPDATE` for every installed extension, and
`REFRESH COLLATION VERSION`.

## Source deployment and data set

- **Source tree:** a clean clone of `315ab50fadb45139cfa98e57d197b96091886836`. The deployment manifest records
  `source_has_changes: false`. The main tree has other agents' edits, and the backup tool refuses a dirty source.
  `node_modules` was symlinked in and the built `packages/core/dist` and `packages/dashboard/dist` were copied in.
  Both are ignored by git.
- **Kit:** `deployment-prepare.mjs --mode self-hosted --development --upstream-dir deploy/upstream --region drill-local`,
  using a drill-only region manifest. Services run: `db`, `auth`, `rest`, `imgproxy`, `storage`. Studio, realtime,
  meta, functions and the dashboard were not started.
- **Migrations:** `deployment-migrate.mjs` applied all **181** canonical migrations atomically in 2.6 s.
  The last one is `20261010000200_browser_guard_native_ner_setting.sql`. The set hash over name and sha256 is
  `2428893365c7d3a00d2e5d41bce7b72e`.
- **Seed (synthetic):**
  - 40 `auth.users`. Triggers provisioned 80 tenants, 40 teams, 40 entitlements and 800 retention-policy rows.
  - 39 extra cross-team memberships (119 `tenant_members`, 79 `team_members`).
  - 40 `team_policies`.
  - 100,040 `audit_logs`, about 200 B of verdict JSON each, and 440 `admin_audit_logs`.
  - One Vault secret.
  - A 5,000-row `public.drill_sentinel` table with RLS enabled.
  - A private bucket `drill-objects` holding 60 objects uploaded through the Storage API with the service-role key:
    6 of 1 MiB and 54 of about 16 KiB. This produced 60 `storage.objects` rows.
  - Not seeded: agents, API keys, runtime policy revisions and policy assignments. Those tables were empty, and
    were compared as empty.
- **Size:**
  - Data: 157 tables in `public`, `app`, `auth`, `storage`, `vault` and `supabase_functions`, with 107,138 rows
    (107,139 after the final pre-backup write).
  - Database: `pg_database_size` summed over all databases is 109,471,272 B, and PGDATA on disk is 264,863,047 B
    including WAL.
  - Objects: 60 files totalling 7,464,532 B.
  - Encrypted backup: 54,773,353 B. That is `database.tar.gz.enc` 46,058,851, `storage.tar.gz.enc` 7,187,158 and
    `installation.tar.gz.enc` 1,527,344.

## Commands (paths shortened; `$D` is the drill directory, outside the repository)

```sh
node $D/kit-src/backup/deployment-backup.mjs keygen --key-file $D/keys/recovery.key
psql … "insert into public.drill_sentinel(payload) values ('last-write-before-backup')"   # id 5001
node $D/kit-src/backup/deployment-backup.mjs backup --deployment $D/kit-src --output $D/backups/b1 \
  --key-file $D/keys/recovery.key --recovery-journal $D/state/recovery-journal.json --maintenance
# 10 further sentinel writes (ids 5002–5011) after services restarted, then "incident" declared
$D/restore-run.sh 17.11.0.004 run-1711b      # candidate
$D/restore-run.sh 17.6.1.136  run-1706b      # same-image control
node scripts/verify-deployment-recovery.mjs --source $D/run-1706b --recovered $D/run-1711b
```

`restore-run.sh` and `verify.sql` are kept in the evidence directory. `restore-run.sh` runs these steps:

1. `deployment-backup.mjs verify`.
2. `deployment-backup.mjs recover --runtime <separately prepared reviewed kit>`. This creates a new
   `aidr-recovery-<hex>` project with new `aidr-db` and `aidr-storage` volumes.
3. A single `sed` that changes only the `db` image line of the recovered `compose.yml`.
4. `up --wait db`.
5. The post-change SQL. The image migration is skipped for the control.
6. `up --wait auth storage`.
7. `deployment-migrate.mjs`.
8. `verify.sql`. It covers the per-table count and an md5 of the sorted row hashes for all 157 tables, the
   migration set hash, the RLS-enabled set, the `pg_policies`, `public`/`app` function and grant hashes, anon
   SELECT privileges, a tenant-scoped `authenticated` JWT read, extension versions, collation versions and the
   Vault decrypt.
9. The storage-volume sha256 inventory, using a `--network none` helper.
10. A read of all 60 objects through the Storage API inside the recovered Compose network.

## Backup

| Item | Value |
|---|---|
| Command wall time | 22.9 s (03:05:01.256Z → 03:05:24.113Z), including stop, `pg_controldata` clean-shutdown check, archive, restart |
| Manifest `started_at` / `completed_at` | 2026-10-11T03:05:04.875Z / 03:05:15.053Z |
| `backup.json` sha256 | `8583c9f17a98f3e23c81bd2fdfb653b45a221bf3451d3436f6316cd0a333e4fd` |
| Source commit / installation runtime sha256 | `315ab50f…6836` / `e854eb3213950d5fd5239d96caccf3fb9e003a100ff0862eb430ca8a94ef265f` |

## RPO and RTO (measured, same host)

**RPO.**

- The last write captured is sentinel id 5001 at `03:04:57.143Z`. The restored sentinel rows match the source's
  rows with id ≤ 5001 exactly: 5,001 rows, md5 `55a2d33063cb12c757ac7a0715ee27cd` on both sides.
- Services were stopped from `03:05:04.875Z` until the restart, so no write could fall between the last capture
  and the snapshot.
- After the restart, 10 rows (ids 5002–5011) were written. The last was at `03:05:48.265Z`. None of them is in
  the backup, so they are lost on recovery. The **measured data-loss window is 51.1 s (10 rows)**.
- The backup's recovery-point age at the declared incident (T0 of the candidate run) was 195.9 s for `run-1711`.
- In production, RPO is set by the backup schedule. This drill measures only the mechanics.

**RTO.** The clock runs from the incident (T0) to verified healthy (T1). T1 is when every verification below has
completed. Traffic cutover is excluded.

| Run | Image | T0 → T1 | verify | recover | db healthy | post-SQL | auth/storage healthy | migrate check | verification |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| `run-1711` | 17.11.0.004 | **57.2 s** | 2.4 | 13.4 | 7.1 | 1.5 | 12.3 | 1.0 | 19.4 |
| `run-1711b` | 17.11.0.004 | **50.7 s** | 1.6 | 11.0 | 7.1 | 1.4 | 12.1 | 0.7 | 16.8 |
| `run-1706-control` | 17.6.1.136 | 70.4 s | 1.8 | 12.2 | 6.2 | 1.3 | 14.0 | 1.5 | 33.3 |
| `run-1706b` | 17.6.1.136 | 51.6 s | 1.6 | 9.6 | 6.2 | 1.0 | 12.4 | 1.0 | 19.9 |

The candidate's restore time is the same as the same-image control. An earlier candidate attempt stopped at its
first verification. The script ran with `set -e`, and the Vault check raised an error (see below). Its timings are
not counted. After that, the Vault check was made to report the error instead of aborting.

## Results on the restored 17.11.0.004 database

| Check | Result |
|---|---|
| Server | `PostgreSQL 17.11` started on the restored 17.6 data directory without `pg_upgrade` |
| Canonical migrations | 181 present and identical by set hash. `deployment-migrate.mjs` reported every migration as already applied by matching hash and applied none |
| 157 tables, count + content hash | identical to the source baseline. The only difference is `drill_sentinel`, which has 5,001 rows against 5,000, and that difference is the final pre-backup write described under RPO |
| RLS | 110 of 111 `public` tables have RLS enabled. The exception is `aidr_schema_migrations`, which `anon` cannot SELECT. `anon` has SELECT only on the drill table, which has RLS on and no policy. 183 `pg_policies` with an identical definition hash |
| Functions / grants | 419 `public`/`app` functions with an identical definition and `SECURITY DEFINER` hash. The table-grant hash is identical |
| Tenant isolation | An `authenticated` JWT for drill user 1 sees 3 tenants, 2 teams and 5,002 audit rows, with **0** rows from tenants it is not a member of, and 0 storage objects. These numbers are identical on the source |
| Storage | 60 files with an identical sha256 inventory `89f4d17a…9db1` and identical ownership. All 60 objects read back through the Storage API with an identical aggregate digest `42f5c33b…e9d8`. An unauthenticated read returns 400 |
| Extensions | `ALTER EXTENSION … UPDATE` moved `pg_net` from 0.20.3 to 0.20.4, and nothing else changed. No extension is behind its default. No collation-version mismatch |
| `scripts/verify-deployment-recovery.mjs` | **18/18** comparisons pass between the same-image 17.6 restore and the 17.11 restore of the same backup. These cover 16 table fingerprints, the policy contents and every object path/digest |
| Existing-DB suites (`AIDR_RLS_TEST_DB_CONTAINER`) | **18/18 pass on the restored 17.11 container and 18/18 on the 17.6 source**, with the same results: `tenant-lifecycle-rls --installed`, `team-invitation-acceptance --installed`, `database-boundary-hardening`, `device-revocation-concurrency`, `billing-channel-intent`, `events-seat-admission`, `member-api-key-revocation`, `member-authorization-race`, `member-removal-audit`, `member-role-audit`, `owner-role-audit`, `pilot-application-atomic-audit`, `pilot-approval-seat`, `scim-canonical-membership`, `scim-saml-identity`, `team-invitation-atomic-audit`, `team-member-email-projection`, `team-resource-read-rls`. Nine suites only accept a `supabase_db_*` container name, so the drill containers were renamed for those runs |
| Blocking `postgres-gates` (`ci-local --only postgres-gates`, pin moved to 17.11.0.004) | Every PostgreSQL suite passed on `supabase/postgres:17.11.0.004` (and `postgres:17-alpine`): identity, reputation, OIDC, workspace retention, Browser Guard, SAML admin and outage, discovery, fleet, delegated session, and offboarding (64/65). The one failure is `deployment-offboarding.test.mjs` "IPv6 offboarding…", which fails with `listen EAFNOSUPPORT ::1`. This host has no IPv6, and the test does not touch the database. That failure stopped the `set -e` step, so `pnpm verify:retention` (53/53) and `tenant-rate-limit-postgres` (1/1) were run separately and passed. The runner's `guard-tree-unchanged` also failed, because this drill and other agents were editing the tree while it ran |

### Finding: the backup omits the pgsodium/Vault root key (tool gap, not an image regression)

The Vault secret written before the backup fails to decrypt after **every** restore. Both 17.11 runs and both
17.6 control runs fail with `pgsodium_crypto_aead_det_decrypt_by_id: invalid ciphertext`. The cause:

- `vault.getkey_script` and `pgsodium.getkey_script` read `/etc/postgresql-custom/pgsodium_root.key`.
- That file lives on the Compose `db-config` named volume.
- `deployment-backup.mjs` archives only `aidr-db`, `aidr-storage` and the installation tree.
- A recovered project therefore gets an empty `db-config`, and `pgsodium_getkey.sh` generates a new random key on
  first start.

Copying the source key into the recovered `db-config` volume (owner `100:101`, mode `0640`) and restarting `db`
fixes it. `vault.decrypted_secrets` then returned the original value.

AIDR's canonical schema does not use Supabase Vault (no migration or Edge Function calls `vault.*`), so no AIDR
row was lost. Operator- or Studio-created Vault secrets and pgsodium-encrypted values would be lost. The interim
operator step is to save the key into recovery-key custody with every backup. That step is documented in
`deploy/backup/README.md`. Changing the backup format so it also captures the key is a follow-up and was not done
in this drill.

## In-place path and rollback (on the source volume)

- **In-place 17.6 → 17.11.** This needs no dump and no `pg_upgrade`. The steps: stop the project, swap only the
  `db` image line, `up --wait db`, run the post-change SQL, then `up --wait auth storage`. That took **25.6 s**.
  After it:
  - all 157 table hashes were identical to the pre-change snapshot;
  - the Vault secret decrypted, because the `db-config` volume was kept;
  - `pg_net` was at 0.20.4.
- **Rollback by image swap back to 17.6.1.136, after the post-change SQL.** The database starts and the data is
  intact. `pg_net` still works: `net.http_get` queued a request. The catalog, however, records `pg_net` 0.20.4
  against the 0.20.3 library. No downgrade script exists for that, so the state is unsupported. The documented
  rollback is therefore:
  - before the post-change SQL: swap the image back;
  - after it: recover the pre-upgrade backup into a new project on 17.6.1.136 and restore the saved pgsodium key.

## Repository changes

- **Compose kit:** `scripts/deployment-prepare.mjs` pins
  `compose.services.db.image = "supabase/postgres:17.11.0.004@sha256:06ddc796…6108"`. The `deploy/upstream`
  submodule stays at 17.6.1.136. `scripts/deployment-prepare.test.mjs` asserts the new pin and records that the
  reviewed upstream pin is still 17.6.1.136.
- **Helm:** `deploy/helm/aidr/values.yaml` `postgresql.image.tag: 17.11.0.004`. It stays tag-only, per the chart's
  air-gap convention. Matching updates went into `deploy/helm/chart.test.mjs`, `deploy/helm/aidr/README.md`,
  `docs/operations/kubernetes.md` and the comment in `deploy/helm/images/migrations.Dockerfile`. The 17.6 client
  is still valid for a 17.x server.
- **CI and tests:** `.github/workflows/ci.yml` and `release-rc.yml` now pull and pin `17.11.0.004`, and so does
  every `scripts/*-postgres*.test.mjs` that starts its own container.
  `scripts/database-workflow-gates.test.mjs` and `docs/production-readiness/retention-holds.md` were updated to
  match.
- **Air-gap lists:** these are derived from the rendered Compose/Helm images (`scripts/build-airgap-images.mjs`),
  so they follow the pin. No list file changed.
- **Operator procedure:** `deploy/backup/README.md`, section "PostgreSQL image upgrade". It covers the backup
  plus pgsodium key custody, the candidate restore drill, the in-place swap, the post-change SQL and rollback.

## Limits

- Everything ran on one host and one Docker daemon. There was no separate failure domain, no offsite target, no
  independent key custodian, no alerting, and no traffic cutover or DNS/TLS. The restore read the backup from local
  disk; `deployment-restore-drill.mjs`, which needs an offsite target and a signed candidate inventory, was not
  run.
- The data set is small: about 104 MiB of databases and 7.1 MiB of objects. RTO grows with volume size, so these
  timings say nothing about a customer-scale database.
- Studio, realtime, postgres-meta, edge functions and the dashboard were not started, so no end-to-end login or
  agent decision ran on 17.11.
- The PostgreSQL server version is still not inventoried by Trivy, and the PostgreSQL advisory list was not
  fetched from this host. This record does not claim which CVEs 17.11 fixes.
- The Helm chart change is render-verified only. No Kubernetes install was done.
