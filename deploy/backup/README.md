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
the database/JWT/Vault/S3/signing key identities paired with the recovered
data. systemd supplies a read-only credential copy
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
