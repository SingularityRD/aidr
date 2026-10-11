# AIDR offsite backup operation

`deployment-backup.mjs` creates a cold, encrypted and authenticated backup.
`deployment-backup-offsite.mjs` transfers that backup to a separately
administered filesystem or S3-compatible target, downloads it again, verifies
every digest and authenticated encryption tag, and only then writes the
dashboard readiness contract.

The offsite target never receives the recovery key. `--key-reference` is a
non-secret identifier for the separately held key, such as a vault or HSM
reference. Give target credentials permission only for the configured prefix.
Keep recovery-key custody and target administration with separate principals.
For S3-compatible targets, grant scoped `ListBucket` on the configured prefix
so upload can distinguish an absent commit marker from a failed lookup. A lookup
failure stops publication.

## pgsodium/Vault root key

Supabase Vault secrets and pgsodium-encrypted values are encrypted with
`/etc/postgresql-custom/pgsodium_root.key`. That file lives on the Compose
`db-config` volume, not in the database volume. When it is missing, the image's
`pgsodium_getkey.sh` silently generates a new random key on first start, and
every restored Vault secret then fails with `invalid ciphertext`.

`deployment-backup.mjs backup` therefore reads the key from the stopped
source's `db-config` volume through the network-isolated helper, after the
clean-shutdown check. It never writes the key to host disk. The key is sealed
with AES-256-GCM under its own HKDF subkey of the recovery key
(`pgsodium-root-key`) and stored as the `pgsodium_root_key` record in the
HMAC-authenticated `backup.json` manifest, together with the SHA-256 of the
plaintext key file. No new backup file is created, so the offsite inventory,
commit marker and readiness contract are unchanged. A key file that is not a
32-byte hex key, or that is a symbolic link, rejects the snapshot and restarts
the source services. A source that never generated a key is recorded as
`absent_at_source`.

The key is sealed under the existing recovery key, not wrapped under a second
key, for these reasons:

- The backup ciphertext alone is already insufficient. Every archive and the
  key record need the recovery key, which this tool keeps outside the
  installation, the backup and the offsite target.
- The installation archive sealed under the same key already holds equally
  powerful material: the database password, JWT secret and service-role key.
  Whoever holds the recovery key and the backup can start the database and read
  `vault.decrypted_secrets` as `postgres` once the key is present. A second key
  would add no confidentiality against that holder.
- A second custodian is a second single point of failure. Losing it reproduces
  the defect this record fixes: a recovery whose Vault secrets cannot be read.

`verify` decrypts and authenticates the key record and checks its SHA-256. It
prints `pgsodium/Vault root key: captured and authenticated (sha256 …)`. A
tampered or malformed record fails verification.

`recover` writes the key into the new project's `db-config` volume after
`docker compose create`, so Docker has already copied the image's default
configuration (`supautils.conf`, `conf.d`, …) into it, and before the database
first starts. The file is owned by the restored PGDATA owner (uid:gid 100:101
on the pinned images) with mode `0600`. The tool refuses to overwrite an
existing key, checks the written file's SHA-256 against the manifest, and
records `vault_root_key: "restored"` and `vault_root_key_sha256` in
`recovery-receipt.json`. The restore drill also counts `vault.secrets` and
fails when any recovered secret does not decrypt.

Only the key is captured. Other operator changes on `db-config`, such as files
added under `conf.d`, are not part of the backup; the recovered project gets
the reviewed image's defaults.

**Backups made before this change** carry no key record. `verify` still passes
and `recover` still completes, but both print `VAULT_KEY_MISSING` on stderr, and
the receipt records `vault_root_key: "VAULT_KEY_MISSING"`. AIDR's canonical
schema does not use Vault, so no AIDR row is affected. If operators created
Vault secrets, restore the key that was saved into recovery-key custody for
that backup (see step 5 of the PostgreSQL image upgrade below). Keep the
manually custodied copies until every backup older than this change has aged
out of retention.

## One backup

Filesystem targets must be absolute, mounted from another failure domain and
must not contain the deployment, source backup or recovery key:

```sh
node scripts/deployment-backup-offsite.mjs upload \
  --backup /var/lib/aidr-backup/2026-09-12 \
  --target /mnt/aidr-offsite/production \
  --key-file /run/credentials/aidr-recovery.key \
  --key-reference vault://security/aidr-production-recovery \
  --retention-days 35 \
  --health-file /srv/aidr/health/backup.json
```

S3-compatible targets require AWS CLI v2 and a non-root prefix. Use an instance
role, workload identity or credential process; do not put S3 secrets in the
service environment file. `--s3-endpoint` is optional for AWS S3 and required
for another compatible provider.

```sh
node scripts/deployment-backup-offsite.mjs upload \
  --backup /var/lib/aidr-backup/2026-09-12 \
  --target s3://company-backups/aidr/production \
  --s3-region eu-central-1 \
  --key-file /run/credentials/aidr-recovery.key \
  --key-reference hsm://security/aidr-production-recovery \
  --retention-days 35 \
  --object-lock-mode COMPLIANCE \
  --health-file /srv/aidr/health/backup.json
```

Each object is uploaded under a random staging prefix, checked by size and
SHA-256 metadata, copied to the immutable backup identifier and downloaded for
an independent byte digest check. `COMMITTED.json` is copied last, so an
interrupted transfer is never treated as complete. Repeating upload for the
same authenticated manifest is idempotent. A conflicting object inventory,
key reference or retention policy is rejected. Readiness uses the completion time from the
authenticated backup manifest and rejects a conflicting commit timestamp.

`GOVERNANCE` and `COMPLIANCE` ask the S3 provider to apply native Object Lock to
the final objects. The bucket must already have Object Lock enabled. Without an
object-lock mode, the commit still records the retention deadline as metadata,
but the provider does not enforce WORM storage. A filesystem target likewise
needs storage-level immutability and access separation outside this tool.

## Download and retention

There are two separate kinds of hold. S3 Object Lock/legal hold protects an
individual backup object version. AIDR's `tenant_legal_holds` protects tenant
records and is **not** consulted by the offsite prune command. An S3 object-level
hold therefore does not prove that a tenant legal hold's data remains in
offsite backups. Until a hold-aware backup retention workflow is accepted, do
not apply offsite pruning while any tenant hold is active or under review.
Coordinate hold placement/release and backup deletion under an operator change
freeze; the current tooling cannot make those separate systems' state changes
atomic. Preserve any explicitly authorized hold copies outside the routine
backup prefix and verify their retention with the data custodian. The ordinary
backup retention period is not a legal-hold policy.

Use the manifest SHA-256 printed as `backup_id` by upload:

```sh
node scripts/deployment-backup-offsite.mjs verify \
  --backup-id BACKUP_ID \
  --target s3://company-backups/aidr/production \
  --s3-region eu-central-1 \
  --key-file /run/credentials/aidr-recovery.key \
  --health-file /srv/aidr/health/backup.json

node scripts/deployment-backup-offsite.mjs download \
  --backup-id BACKUP_ID \
  --target s3://company-backups/aidr/production \
  --s3-region eu-central-1 \
  --key-file /run/credentials/aidr-recovery.key \
  --output /srv/aidr-disaster-download
```

`download` requires a new directory and authenticates the downloaded backup.
Pass it to `deployment-backup.mjs recover` with `--runtime` pointing to a
separately reviewed, clean deployment for the same source commit. Recovery
validates the archived installation tree against the authenticated manifest
and reviewed inventories before restoring its exact configuration.
On a handled error after creating its new project, manual `recover` removes only
that invocation's containers, volumes and plaintext output. A cleanup error
names the project and output; inspect their Compose-labeled resources before
manual removal. Never run a broad Docker prune or delete an existing deployment
to clear a failed recovery. An uncatchable host/process crash may still leave
the generated `aidr-recovery-*` project or `.aidr-installation-*` staging path;
verify ownership and remove those exact resources before retrying.

Retention is a dry run unless `--apply` is explicit. It only considers
64-character backup directories or prefixes containing a valid commit marker;
foreign data, staging data and incomplete transfers are outside deletion scope.
For S3, pruning enumerates object versions and delete markers, checks each data
version's Object Lock deadline and legal hold, and deletes only eligible version
IDs. It refuses any object version absent from the committed inventory. Its
result distinguishes fully removed backups from retained ones; a
current-version tombstone is never reported as deletion of retained bytes.
The worker verifies payload versions are absent before deleting the commit
marker, then lists versions again and fails rather than reporting
`fully_removed` if any version remains. This verifies the provider's
listing response, not physical erasure, replicas, or independently retained copies.

```sh
node scripts/deployment-backup-offsite.mjs prune \
  --target s3://company-backups/aidr/production \
  --s3-region eu-central-1 \
  --retention-days 35

node scripts/deployment-backup-offsite.mjs prune \
  --target s3://company-backups/aidr/production \
  --s3-region eu-central-1 \
  --retention-days 35 \
  --apply
```

## Scheduled cycle

Install `aidr-backup-offsite.service`, its timer, and
`aidr-backup-health-failed.service` from this directory, copy
`aidr-backup-offsite.env.example` to `/etc/aidr/backup-offsite.env`, and store
the recovery key at `/etc/aidr/aidr-recovery.key` as a root-owned, regular,
non-symlink file with mode `0600`. systemd passes a read-only credential copy to
the worker, which also verifies the source file's custody properties. If
credential loading fails before the worker can start, the unit's `OnFailure`
service atomically replaces any stale success receipt with failed readiness.
The service creates a cold backup during its maintenance window, transfers and
re-verifies it, and writes `/srv/aidr/health/backup.json` for the generated
dashboard's read-only health mount. Scheduled cycles do **not** delete old
backups; standalone pruning requires explicit `prune --apply`, and cycle-based
pruning requires explicit `cycle --apply-retention`; neither is enabled by the
systemd unit or an environment variable. Cycle spool
directories are transient: the current copy is removed on success or handled failure, and exact tool-owned leftovers older
than 24 hours are reclaimed by the next cycle only when their matching
`.aidr-owned` sidecar is present. Similar-looking operator directories and
older unmarked leftovers require manual review; they are not deleted by name
alone. The timer does not replay a
missed cold-backup window at boot; backup freshness monitoring must alert on
the missed run instead of causing an unscheduled service stop.

Before enabling the timer, run one cycle manually, inject a failed target
connection, confirm the backup readiness alert, and recover on a different
host using only the offsite target plus the separately held key. Record measured
data loss and recovery time against the customer's approved RPO/RTO. The local
tests and templates do not establish provider durability, key-custodian access,
schedule activation, alert delivery or customer RPO/RTO acceptance.

For filesystem mode, mount the target out of band and create its target
directory before running any backup command. Set
`AIDR_BACKUP_FILESYSTEM_MOUNT_IDENTITY` to the exact `UUID=<uuid>` or
`SOURCE=<source>` reported by `findmnt` for that target. It must differ from
the host-root filesystem. A missing target, missing identity, unavailable
`findmnt`, identity mismatch, or storage shared with the root filesystem fails
closed before publication or pruning.

`install-systemd.sh --with-backup` installs the recovery unit but deliberately
leaves the backup timer disabled. After the manual cycle and failure-alert check
pass, enable the schedule explicitly with `systemctl enable --now
aidr-backup-offsite.timer`.

## Scheduled restore drill

Install `aidr-restore-drill.service` and `.timer`, then copy
`aidr-restore-drill.env.example` to `/etc/aidr/restore-drill.env`. Replace every
placeholder with the absolute path to a clean reviewed runtime, its signed
release candidate inventory and signer policy, an evidence-retention period,
and approved numeric RPO/RTO targets. The timer dynamically selects the newest
fresh authenticated backup whose source commit matches the signed candidate.
The canonical release verifier validates the inventory, artifact bytes,
metadata, manifest and signature. Recovery also verifies the authenticated
installation archive's complete runtime-tree digest and requires its migration
and artifact inventories to match that reviewed runtime before restoring the
exact original environment, Compose and agent configuration. This preserves
the database/JWT/S3/signing key identities paired with the recovered data. The
pgsodium/Vault root key is preserved only for backups that carry it (see
"pgsodium/Vault root key"); the drill fails if recovered Vault secrets do not
decrypt. systemd supplies a read-only credential copy
and creates a unique owner-only directory below `/var/lib/aidr-restore-drill`
for every run.

Run `systemctl start aidr-restore-drill.service` and inspect its new
`restore-drill-evidence.json` before enabling the timer. The evidence includes
candidate/runtime digests and explicit RPO/RTO targets and results. Recovered
containers, volumes, downloaded ciphertext and plaintext runtime material are
removed after every run and on unit stop; evidence is retained for the configured
period. The timer is a weekly reference schedule, not proof that it was enabled
or monitored.

Real offsite provider access, independent key custody, alert delivery, and a
restore executed on a second failure-domain host remain **BLOCKED_EXTERNAL**.
Do not replace these with repository fixtures, placeholder credentials or a
same-host receipt.

## First-customer rehearsal without customer data

Before approaching the first customer, use two company-controlled hosts in
separate failure domains and synthetic tenant, policy, audit and object data.
Configure a real offsite target with provider-enforced retention, a recovery
key held by a different operator, and a reviewed signed candidate. On the
primary host, manually run and verify one scheduled backup cycle, then enable
the timer and confirm its health alert fires when a deliberately failed target
connection prevents the next cycle. Record the newest authenticated backup ID
and its completion time.

Treat the primary host as lost: the recovery operator must use only the
offsite target, separately held key and clean reviewed runtime on the second
host. Run the restore drill there, preserve its evidence receipt, then verify
login, policy decisions, database rows and object contents before a synthetic
traffic cutover. Measure data-loss age from the last authenticated backup and
measure end-to-end recovery from declared incident start through that cutover;
the script's `technical_restore_seconds` explicitly excludes cutover. Record
both measured values against *internally approved* first-customer targets,
along with host identities, candidate digest, alert receipt, key-custodian
sign-off and any failed steps. A passing same-host test or an unmeasured drill
must not be called disaster-recovery acceptance.

## PostgreSQL image upgrade (supabase/postgres 17.6.1.136 → 17.11.0.004)

New kits from `deployment-prepare.mjs` pin
`supabase/postgres:17.11.0.004@sha256:06ddc7962e11ab0f4f0334fd05671e97c30ea202f6e6a7113800bd3d6e416108`.
An existing installation on `17.6.1.136` keeps its image until an operator
changes it. Both images are PostgreSQL 17 (catalog version `202406281`, same
`postgres` uid 100:101), so the data directory is used as it is. `pg_upgrade`
and a dump/restore are not needed. The change is still a stateful platform
change and is not an application upgrade, so do it in a maintenance window, in
this order. The local engineering drill behind these steps is recorded in
`docs/production-readiness/postgres-upgrade-restore-drill-2026-10-11.md`.

1. **Back up first.** Take a cold encrypted backup with `deployment-backup.mjs
   backup --maintenance`, publish it with `deployment-backup-offsite.mjs`, and
   check it with `verify`. `verify` must report `pgsodium/Vault root key:
   captured and authenticated`. The backup then carries the pgsodium/Vault root
   key (`/etc/postgresql-custom/pgsodium_root.key`), and `recover` restores it.
   If `verify` reports `VAULT_KEY_MISSING`, the backup tool in the installation
   predates key capture. Update it, or copy the key into recovery-key custody
   (`umask 077`), outside the deployment and the backup target. The manual copy
   is also acceptable as defense in depth:

   ```sh
   docker run --rm --network none --entrypoint cat \
     --mount type=volume,src=<project>_db-config,dst=/c,readonly \
     supabase/postgres:17.6.1.136 /c/pgsodium_root.key > /protected/aidr-pgsodium-root.key
   ```

2. **Run a restore drill on the candidate before production.** On a separate
   recovery host, or at least in a new project, run `deployment-backup.mjs recover`
   with a reviewed runtime. In the recovered `compose.yml`, change only the `db`
   image to the candidate. Start `db`, run the post-change SQL from step 4, start
   `auth` and `storage`, and run `deployment-migrate.mjs` on the recovered
   directory. It must report the full migration set as already applied. Then
   compare the recovered data with a same-image recovery of the same backup by
   running `scripts/verify-deployment-recovery.mjs --source <17.6 recovery>
   --recovered <17.11 recovery>`. Record the timeline (RTO) and the backup point
   (RPO). Remove the recovered projects with `docker compose ... down --volumes`.

3. **Change the image in place.** Stop the project with `docker compose
   --project-directory /srv/aidr -f /srv/aidr/compose.yml stop --timeout 60`. In
   `compose.yml`, set the `db` image to the pinned candidate reference above.
   Change no other line. Then run `docker compose ... up -d --wait db`.

4. **Apply the in-major post-change steps.** These follow the pattern of
   upstream `docker/utils/upgrade-pg17.sh` step 9, run as `supabase_admin`:
   - the one image migration added after 17.6.1.136:
     `psql -U supabase_admin -d postgres -v ON_ERROR_STOP=1 -f /docker-entrypoint-initdb.d/migrations/20260730000000_revoke_trigger_on_cron_tables_from_postgres.sql`
     (it revokes `TRIGGER` on `cron.job_run_details`, if `pg_cron` is installed)
   - `ALTER EXTENSION … UPDATE` for every installed extension. In the drill
     only `pg_net` moved (0.20.3 → 0.20.4).
   - `ALTER DATABASE <db> REFRESH COLLATION VERSION` for `postgres`, `template1`
     and `_supabase`. In the drill there was no collation mismatch.

   Then run `docker compose ... up -d --wait` and `node scripts/deployment-migrate.mjs
   /srv/aidr`. The migrate step must skip every migration and apply none. Finish
   with the readiness and smoke checks before you end the maintenance window.

5. **Rollback.** Until step 4 runs, you can roll back by setting the `db` image
   back to `17.6.1.136` and starting the project again. After `ALTER EXTENSION …
   UPDATE`, an image swap back still starts, but it leaves extension catalog
   versions ahead of the older libraries. The drill saw `pg_net` 0.20.4 registered
   against the 0.20.3 library. That state is unsupported, so do not use the image
   swap after step 4. Instead, recover the step 1 backup into a new project with
   `deployment-backup.mjs recover` on `17.6.1.136`, then start it and cut over.
   `recover` restores the pgsodium key from the backup. Only a backup whose
   receipt records `vault_root_key: "VAULT_KEY_MISSING"` needs the manual step.
   `recover` leaves services stopped, so before the first start write the saved
   `pgsodium_root.key` into that project's `db-config` volume (owner `100:101`,
   mode `0600`). If the database was already started, the image generated a new
   key: stop `db`, replace the file and start it again. The old deployment's volumes are not modified by recovery.

The drill was a same-host engineering rehearsal. It is not a separate failure
domain, an offsite restore or customer RPO/RTO acceptance (see AIDR-044).
