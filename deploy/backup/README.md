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
  --target /mnt/offsite/aidr/production \
  --key-file /run/credentials/aidr-recovery.key \
  --key-reference vault://security/aidr-production-recovery \
  --retention-days 35 \
  --health-file /run/aidr-health/backup.json
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
  --health-file /run/aidr-health/backup.json
```

Each object is uploaded under a random staging prefix, checked by size and
SHA-256 metadata, copied to the immutable backup identifier and downloaded for
an independent byte digest check. `COMMITTED.json` is copied last, so an
interrupted transfer is never treated as complete. Repeating upload for the
same authenticated manifest is idempotent. A conflicting object inventory or
key reference is rejected. Readiness uses the completion time from the
authenticated backup manifest and rejects a conflicting commit timestamp.

`GOVERNANCE` and `COMPLIANCE` ask the S3 provider to apply native Object Lock to
the final objects. The bucket must already have Object Lock enabled. Without an
object-lock mode, the commit still records the retention deadline as metadata,
but the provider does not enforce WORM storage. A filesystem target likewise
needs storage-level immutability and access separation outside this tool.

## Download and retention

Use the manifest SHA-256 printed as `backup_id` by upload:

```sh
node scripts/deployment-backup-offsite.mjs verify \
  --backup-id BACKUP_ID \
  --target s3://company-backups/aidr/production \
  --s3-region eu-central-1 \
  --key-file /run/credentials/aidr-recovery.key \
  --health-file /run/aidr-health/backup.json

node scripts/deployment-backup-offsite.mjs download \
  --backup-id BACKUP_ID \
  --target s3://company-backups/aidr/production \
  --s3-region eu-central-1 \
  --key-file /run/credentials/aidr-recovery.key \
  --output /srv/aidr-disaster-download
```

`download` requires a new directory and authenticates the downloaded backup.
Pass it to `deployment-backup.mjs recover` to create an independent deployment.

Retention is a dry run unless `--apply` is explicit. It only considers
64-character backup directories or prefixes containing a valid commit marker;
foreign data, staging data and incomplete transfers are outside deletion scope.
Native Object Lock may correctly reject deletion until its retention deadline.

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

Install the service and timer from this directory, copy
`aidr-backup-offsite.env.example` to `/etc/aidr/backup-offsite.env`, and store
the recovery key at `/etc/aidr/aidr-recovery.key` with root-only permissions.
The service creates a cold backup during its maintenance window, transfers and
re-verifies it, writes `/run/aidr-health/backup.json`, then applies scoped
offsite retention. Successful cycles keep the local encrypted spool copy for
operator-controlled capacity and retention management.

Before enabling the timer, run one cycle manually, inject a failed target
connection, confirm the backup readiness alert, and recover on a different
host using only the offsite target plus the separately held key. Record measured
data loss and recovery time against the customer's approved RPO/RTO. The local
tests and templates do not establish provider durability, key-custodian access,
schedule activation, alert delivery or customer RPO/RTO acceptance.
