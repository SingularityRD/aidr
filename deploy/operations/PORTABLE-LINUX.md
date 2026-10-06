# Portable Linux operations

This pack prepares a customer installation. It does not grant production GO.
No staging environment is assumed. These commands run on the eventual approved
Linux host or on an explicitly isolated recovery host after the operator reviews
the target. The eight-hour load run and operated support drill remain unexecuted
until that host and the responsible people exist.

Use the signed customer kit without a repository checkout or package build.
Before extracting it, follow the independent verifier, pinned publisher policy
and anti-rollback procedure in [portable release signing](../../docs/runbooks/portable-release-signing.md).
Then follow [first customer installation](../FIRST_CUSTOMER.md) for deployment
preparation, database migration, SMTP, first administrator, device enrollment
and policy publication. Node 24, Docker Engine with Compose v2, `tar`, systemd,
and the approved TLS proxy/ACME tooling must already exist on the Linux host;
S3 backup also requires an approved AWS CLI/provider integration. For disconnected
installation, transfer and verify the exact Compose images and the backup helper's
pinned base `node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1`
through the customer's approved image process. The supplied helper Dockerfile
removes unused package managers. Backup and recovery build that public-only
context from the cached base with pulling and build networking disabled, then
run its immutable image ID; no installation files or live configuration enter
the build context. Load the pinned base before scheduling maintenance.
On the approved connected build host, include the exact helper base alongside
the prepared Compose images using the existing air-gap assembler:

```sh
node scripts/build-airgap-images.mjs --compose /srv/aidr/compose.yml \
  --images node:24.21.0-alpine3.24@sha256:ebfe2f90462722a7a4de65e91990e97fe0d401c70e0e762c5b53302f905ec1c1 \
  --output /approved-transfer/aidr-images
```

Verify that bundle with the same `--compose` and `--images` references before
loading it through the customer's approved Docker image process.
This pack does not download or approve host prerequisites for you.

## Paths and private configuration

The supplied units use `/opt/aidr-kit` for the verified kit and `/srv/aidr` for
the prepared runtime. Keep the kit read-only and the runtime's private `.env*`
files owner-only. Review unit paths if either location changes; the maintenance
installer requires `/srv/aidr`. The kit, runtime, backup spool, recovery work
directory and recovery key must be separate. Never put the recovery key or live
configuration in the portable archive.

```sh
sudo install -d -m 0700 /etc/aidr /var/lib/aidr-operations /var/lib/aidr-restore-drill
sudo install -m 0600 /opt/aidr-kit/deploy/operations/operations.env.example /etc/aidr/operations.env
```

Replace the public example paths/origins in that file before using it. It contains
no credentials and does not replace `/srv/aidr/.env.readiness`, private
`/etc/aidr/backup-offsite.env`, `/etc/aidr/restore-drill.env` or
`/etc/aidr/tls-renew.env`. Prepare those from the existing
[readiness](../maintenance/aidr-readiness-evidence.env.example),
[backup](../backup/aidr-backup-offsite.env.example),
[restore](../backup/aidr-restore-drill.env.example) and
[TLS](../ingress/README.md) instructions. Use real approved key expiry dates,
SMTP/OAuth settings, DNS/certificate names and backup target identity. Do not
replace missing provider checks with locally written green health files.

Load the reviewed path references in a root operator shell:

```sh
set -a
. /etc/aidr/operations.env
set +a
cd "$AIDR_KIT_ROOT"
CANDIDATE_DIGEST=$(sha256sum "$AIDR_CANDIDATE_INVENTORY" | cut -d ' ' -f 1)
```

Keep command logs and receipts below `$AIDR_OPERATIONS_EVIDENCE`, mode 0700.
That inventory digest must match the independently verified delivery. A digest
alone does not approve a publisher.

## Real readiness and scheduled maintenance

Configure the actual authenticated fleet queue aggregator or protected SIEM
source before installing the readiness timer. `--telemetry-queue-root` names
a real source; creating an empty folder or synthetic namespace is not deployment
readiness. The worker verifies the exact self-hosted function signing keys and
queue state, and replaces stale success evidence with failures.

```sh
sudo sh /srv/aidr/maintenance/install-systemd.sh --with-backup
sudo install -m 0644 deploy/maintenance/aidr-export-retention.service /etc/systemd/system/
sudo install -m 0644 deploy/maintenance/aidr-export-retention.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start aidr-export-retention.service
sudo systemctl enable --now aidr-export-retention.timer
node scripts/deployment-doctor.mjs --deployment "$AIDR_DEPLOYMENT_DIR" --online
```

The first command requires the protected backup environment and key to exist;
omit `--with-backup` until they do. It runs readiness before enabling the SIEM
timer, installs backup units and enables boot recovery, but leaves the backup
timer disabled. Complete TLS ingress and renewal timer setup separately using
the ingress guide. Doctor must exit successfully and its actual
`doctor-evidence.json` must have `passed: true`, no `failures` and no
`unverified` checks. `/healthz` or a local engineering test runner returning zero
does not substitute for `/readyz` or production receipt review. Check the real
signing, queue, backup and certificate-renewal evidence plus alert delivery in
the customer's monitoring system.

## Encrypted offsite backup and isolated restore

Follow [backup custody and recovery](../backup/README.md) before starting a
backup. A cycle briefly stops only this deployment's running services; schedule
that maintenance window. The recovery key is generated with the existing
`deployment-backup.mjs keygen` tool or securely supplied by its custodian, kept
outside installation/backups, and escrowed separately. S3 must have the requested
Object Lock support; filesystem offsite storage must be a preexisting distinct
mount with the configured UUID/source identity. A directory on the host's root
filesystem is refused.

```sh
sudo systemctl start aidr-backup-offsite.service
sudo systemctl status aidr-backup-offsite.service --no-pager
```

Review `/srv/aidr/health/backup.json`, the remote committed inventory/readback
and the actual failure-alert route. Only after one successful real cycle and a
controlled failure-alert acceptance enable the daily timer:

```sh
sudo systemctl enable --now aidr-backup-offsite.timer
```

Run restoration on a distinct recovery host/failure domain, with its own approved
Docker engine and separately delivered key. Copy the exact independently
verified candidate, signer policy and reviewed prepared runtime there, keep them
separate from the restore work root, and configure the reviewed
`/etc/aidr/restore-drill.env`. Choose actual approved positive RPO minutes and RTO
seconds; the example deliberately has no default acceptance values. This command
selects an authenticated recent backup for that exact candidate, creates a new
Compose project and volumes, validates restored database/object contents, and
cleans up only its recovery resources and plaintext:

```sh
set -a
. /etc/aidr/restore-drill.env
set +a
node --env-file=/etc/aidr/backup-offsite.env --env-file=/etc/aidr/restore-drill.env \
  scripts/deployment-restore-drill.mjs \
  --target "$AIDR_RESTORE_TARGET" --key-file "$AIDR_RECOVERY_KEY_FILE" \
  --runtime "$AIDR_RESTORE_RUNTIME" \
  --candidate-inventory "$AIDR_CANDIDATE_INVENTORY" --candidate-policy "$AIDR_CANDIDATE_POLICY" \
  --work-root "$AIDR_RESTORE_WORK_ROOT" --evidence-retention-days 90 \
  --rpo-target-minutes "$AIDR_RESTORE_RPO_TARGET_MINUTES" \
  --rto-target-seconds "$AIDR_RESTORE_RTO_TARGET_SECONDS"
```

The first three lines load the reviewed nonsecret restore references before
shell argument expansion; `--env-file` alone populates only the child process.
Store each actual `restore-drill-evidence.json`. Require `passed: true`, matching
candidate/source/runtime hashes, measured passing RPO/RTO and
`sensitive_material_removed: true`. This proves technical restoration;
customer traffic cutover, login/enforcement and independent-host approval need
their own witnessed acceptance. Never apply backup pruning while unresolved
legal holds require a longer period; scheduled pruning is off by default.

## Eight-hour workload preparation

Copy `workload.soak-8h.example.json` into the private evidence directory. It is a
valid low-rate liveness/readiness template with no result, SLA or capacity claim.
Set its `candidate_id` to the verified inventory digest, replace the environment
label and approve realistic rates/thresholds and the required authenticated
login/policy/ingest/export scenarios. The existing runner supports environment
references for secret headers/body fields; keep those secrets outside profiles
and results. See [load and HA instructions](../ha/README.md).

```sh
node scripts/load-test.mjs --profile "$AIDR_OPERATIONS_EVIDENCE/workload.soak-8h.json" \
  --output "$AIDR_OPERATIONS_EVIDENCE/load8h-result.json" \
  --allow-host "$AIDR_LOAD_ALLOWED_HOST" --dry-run
```

After host/workload approval, remove only `--dry-run` to run the eight-hour test.
Capture host memory, connections, queue age/depth/loss and storage metrics over
the same window. Require passing recorded thresholds and those external metrics;
the runner always leaves production/HA acceptance false. No eight-hour run has
been performed merely by preparing this package.

## Operated support drill and consent-bound diagnostics

Copy `support-ticket.receipt.example.json` into a restricted evidence directory.
It starts `not_run` and is intentionally rejected by the existing verifier.
Once support owners are assigned, open a benign synthetic case in the actual
operated ticket system. Record submission, acknowledgement, escalation, update
and closure with distinct primary/backup operators and a reviewer. Actually
review the five published customer routes and their owners, attach redacted
operated-system evidence and its SHA-256, and bind the candidate digest.

```sh
node scripts/verify-support-ticket-drill.mjs \
  "$AIDR_OPERATIONS_EVIDENCE/support-drill/receipt.json" --candidate "$CANDIDATE_DIGEST"
```

This checks structure and evidence bytes; the reviewer must verify human
authenticity, route reachability, acknowledgement/escalation timings and approval.
If diagnostics are requested, obtain separate customer consent first, then use
the existing `support-bundle.mjs --deployment ... --output ... --customer-consent
--consent-reference ... --consent-recorded-at ... --collected-at ...` command.
Use canonical UTC timestamps with milliseconds and the actual consent reference.
Review `inventory.json` before a separately approved transfer; do not send raw
configuration, database rows, keys or customer payloads. This pack sends no
ticket, email or support message.
