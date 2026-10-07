# AIDR self-hosted upgrade and recovery runbook

This runbook applies to the generated single-host, self-hosted deployment. A
managed cloud project uses the cloud provider's database migration, backup,
point-in-time recovery and deployment workflow; do not point this tool at it.

An upgrade is accepted only for one exact current manifest and one exact target
manifest. The target must use the same reviewed Supabase baseline and public
origins, preserve every existing migration name and checksum in the same order,
add migrations only at the end, and be prepared from a reviewed commit-bound
source tree or a verified signed customer kit. A container-baseline change is a
separate platform migration.

Before preparing a target from a customer kit, verify its signed outer envelope
with the independently delivered verifier, signer policy and persistent
anti-rollback state as described in the [first-customer guide](FIRST_CUSTOMER.md). Extract the exact verified
tar artefact, run `scripts/customer-kit-verify.mjs`, and prepare the target in a
new directory from that extracted kit. A checksum-only or merely present inner
release signature is insufficient to authenticate the installation scripts.
Do not advance the anti-rollback state during preflight; repeat verification
and record the accepted target sequence only after the upgrade and customer
acceptance checks succeed. Preserve the old deployment, its encrypted backup,
the old signed bundle and the last accepted state for recovery planning.

## Required release evidence

Prepare the target in a new directory. Never run `deployment-prepare` over the
customer installation. The release owner must produce a compatibility contract
and at least one evidence file from an upgrade rehearsal using representative old
data. Keep these beside each other in a restricted release-evidence directory.

The contract format is:

```json
{
  "schema_version": 1,
  "current_manifest_sha256": "64 lowercase hex characters",
  "target_manifest_sha256": "64 lowercase hex characters",
  "current_migration_set_sha256": "64 lowercase hex characters",
  "target_migration_set_sha256": "64 lowercase hex characters",
  "current_app_compatible_with_current_schema": true,
  "target_app_compatible_with_target_schema": true,
  "target_schema_accepts_existing_data": true,
  "migrations_transactional": true,
  "required_env_keys": ["ANON_KEY", "SERVICE_ROLE_KEY"],
  "required_function_env_keys": [
    "AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64",
    "AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64",
    "AIDR_PACK_DOWNLOAD_GRANT_SECRET"
  ],
  "required_ingress_env_keys": ["AIDR_DEVICE_START_INGRESS_SECRET"],
  "current_support_files": [
    { "path": "agent-config.json", "sha256": "64 lowercase hex characters" },
    { "path": "compose.yml", "sha256": "64 lowercase hex characters" }
  ],
  "target_support_files": [
    { "path": "agent-config.json", "sha256": "64 lowercase hex characters" },
    { "path": "compose.yml", "sha256": "64 lowercase hex characters" }
  ],
  "approved_by": "Release owner identity",
  "approved_at": "2026-09-12T12:00:00.000Z",
  "acceptance_evidence": [
    {
      "path": "upgrade-rehearsal.json",
      "sha256": "64 lowercase hex characters"
    }
  ]
}
```

`current_manifest_sha256` and `target_manifest_sha256` are SHA-256 values of the
exact `deployment.json` bytes. A migration-set hash is SHA-256 over the ordered
UTF-8 sequence `name`, a zero byte, the migration SHA-256, and a newline for each
manifest entry. Release automation should generate these values and the evidence
digest; the approver must review the rehearsal result and configuration key lists
before setting the four compatibility declarations to `true`. This contract is
an auditable assertion, not proof created by the upgrade tool itself.

The support-file arrays bind the current and target `compose.yml` and
`agent-config.json`, which are operational inputs outside the application artifact
inventory. The upgrade rejects extra dashboard, function or migration files that
were added after preparation.

A deployment prepared before the region manifest existed carries no `region`,
`tenant_region` or `regions` fields, so the online doctor cannot confirm that the
tenant and deployment regions match and fails closed. Record the region the
customer agreed on in the current `deployment.json` (`region` and `tenant_region`
plus the matching entry from `deploy/regions.manifest.json` in `regions`, or the
default `unassigned` declaration), and prepare the target with the same
`--region` and `--tenant-region`, before running the upgrade. An upgrade must not
change the declared region of an existing installation.

The GA admission cutover at migration `20260923000041` removes the old two-argument
trial activation RPC. Stage the matching `pilot-status` Edge Function and
dashboard consent UI in the same release as migrations `34`–`42`; rehearse the
exact migration/function/UI combination before promotion. An old function
against the new schema fails closed, but trial activation is unavailable until
the new function is live. Do not set `AIDR_SIGNUP_MODE=cloud` merely because
the UI exists: Supabase Auth registration, cloud admission mode, approved
published Terms/Privacy documents, and a verified operator legal configuration
are independent gates. Self-hosted deployments keep signup closed and use the
finite-term licensed bootstrap instead.

The rehearsal must cover existing customer-shaped rows and objects, the target
application on the final target schema, authorization boundaries, login,
enrollment, policy enforcement and audit export. If a new environment or function
secret is required, provision it in the current private environment files before
preflight and name it in the contract. The tool preserves those private files.

## Backup and preflight

Create and verify a fresh encrypted cold backup in the approved maintenance
preparation window. Store the key separately from both installation and backup.

```sh
node scripts/deployment-backup.mjs backup --deployment /srv/aidr --output /backups/aidr-pre-upgrade --key-file /secure/aidr-recovery.key --recovery-journal /var/lib/aidr-backup/recovery-journal.json --maintenance
node scripts/deployment-backup.mjs verify --backup /backups/aidr-pre-upgrade --key-file /secure/aidr-recovery.key
```

The backup command requires a deployment-bound recovery journal at `/var/lib/aidr-backup/recovery-journal.json`. If the process or host stops unexpectedly after the Compose stop, the boot recovery unit starts only services recorded as running before the backup. Verify the journal is cleared and service health is restored before retrying or upgrading.

Run preflight while the current database is online:

```sh
node scripts/deployment-upgrade.mjs preflight \
  --current /srv/aidr \
  --target /srv/aidr-target \
  --backup /backups/aidr-pre-upgrade \
  --key-file /secure/aidr-recovery.key \
  --contract /secure/aidr-upgrade/upgrade-compatibility.json \
  --recovery-output /srv/aidr-recovery
```

Preflight verifies every inventoried current and target artifact, exact manifest
and compatibility-evidence hashes, append-only migration history, unchanged
container baseline and origins, required configuration keys, and the encrypted
backup through `deployment-backup.mjs verify`. The authenticated backup must match
the current Compose project and source commit and defaults to a maximum age of 24
hours. Use `--max-backup-age-hours N` only when the approved change record defines
a different window; the maximum accepted value is 168 hours.

The preflight does not execute migration SQL against the live database. It writes
private state under `/srv/aidr/.aidr-upgrade/` and changes no application artifact
or schema. After maintenance begins, the tool stops application writers, runs all
candidate migration SQL inside a transaction while holding the production advisory
lock, verifies the ledger, rejects unknown entries and rolls the dry-run back before
the real atomic migration starts.
Monitoring can consume `.aidr-upgrade/monitoring/backup.json`, which is atomically
published with `schema_version`, `status`, `completed_at` and `verified_at` plus
the verified backup digest and source binding.

## Apply and resume

Start the approved maintenance window, drain external traffic, and run:

```sh
node scripts/deployment-upgrade.mjs apply \
  --current /srv/aidr \
  --target /srv/aidr-target \
  --backup /backups/aidr-pre-upgrade \
  --key-file /secure/aidr-recovery.key \
  --contract /secure/aidr-upgrade/upgrade-compatibility.json \
  --recovery-output /srv/aidr-recovery \
  --maintenance
```

The tool stops the current non-database services, delegates atomic schema
application to `deployment-migrate.mjs`, installs hash-bound application files,
preserves `.env`, `.env.functions`, `.env.ingress`, public origins and the Compose project identity,
starts the target services, and requires the online deployment doctor to pass.
The successful receipt is `.aidr-upgrade/upgrade-receipt.json`.

If the process is interrupted, run the same command with `resume` instead of
`apply`. State is recorded after each completed phase and after each installed
component. Resume rechecks the immutable target, contract and backup bindings,
recognizes components already at their target hash, and never reapplies an already
recorded migration. A completed resume is a no-op. Do not edit the state, payload,
previous-component or receipt files.

On `SIGINT` or `SIGTERM` the tool stops at the next safe point instead of dying
mid-step. Read-only and rollback-only steps (backup verification, the migration
dry-run, the online doctor) are cut short; writer stop/start, the atomic migration
and recovery run to completion so their outcome is known. Before the schema commit
it restarts exactly the services that were running before maintenance; after the
commit it keeps target services drained. It then records `interrupted_by` and the
resumable phase in the state file and exits with 130 (`SIGINT`) or 143 (`SIGTERM`).
Send the signal once and wait for the process to exit; do not `SIGKILL` it.

## Failure and recovery

Every failed apply writes `.aidr-upgrade/rollback-plan.json`. A failure before the
database migration completes leaves the source files unchanged. Once the target
schema is committed, do not attempt an in-place down-migration or copy old app
files over it. Keep traffic drained and recover the authenticated backup into a
new isolated project:

```sh
node scripts/deployment-upgrade.mjs recover \
  --current /srv/aidr \
  --target /srv/aidr-target \
  --backup /backups/aidr-pre-upgrade \
  --key-file /secure/aidr-recovery.key \
  --contract /secure/aidr-upgrade/upgrade-compatibility.json \
  --recovery-runtime /srv/aidr-reviewed-current \
  --recovery-output /srv/aidr-recovery \
  --maintenance
```

This delegates to `deployment-backup.mjs recover`, which refuses archived runtime
configuration and an existing destination. `--recovery-runtime` must be a separate,
clean prepared deployment whose manifest inventory and source commit match the
authenticated backup. Recovery creates new volumes and a distinct Compose project;
services stay stopped. Resolve port and hostname conflicts, start it in isolation, run the
online doctor, compare database/object evidence, and repeat administrator login,
agent enrollment, policy deny and audit-export acceptance. Change traffic only
after those checks pass. Retain the failed project and logs for investigation and
retain the former environment until the change record's rollback window closes.

The local orchestration receipt does not establish customer traffic cutover,
native-agent effectiveness, high availability, RPO/RTO, or production acceptance.
Record those results in the customer change and acceptance records.
