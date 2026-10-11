# Backup and restore drill (v6)

The self-hosted backup command creates encrypted, authenticated cold snapshots of the PostgreSQL, object-storage, and installation volumes. `deployment-backup-offsite.mjs` publishes a committed copy to a scoped filesystem or S3-compatible target, then downloads and verifies every object with the separately held recovery key. Filesystem retention is metadata only; native Object Lock must be enabled and verified on an S3-compatible target when immutability is required.

`scripts/deployment-restore-drill.mjs` adds the missing read test. It downloads a committed backup into a **new** work directory, verifies ciphertext hashes and AES-GCM tags, validates the archived installation's complete runtime-tree digest against the authenticated backup manifest, and requires its migration and artifact inventories to match the signed reviewed runtime. Recovery then uses that exact authenticated installation configuration, preserving the database, JWT, service-role, Vault, S3, signing, delegation and pack-key identities that belong to the restored data. It refuses recovered containers that publish host ports or have foreign project labels, starts only the recovered database, reads critical AIDR tables and migration count, fingerprints the restored object volume, then stops that database. Before downloading on Windows, it removes inherited access with `icacls`, grants the current SID inheritable full access, and verifies that the DACL has exactly that explicit allow rule; ACL failure stops the drill before secret files are written. POSIX mode must exclude group and world access. The Windows operation follows [Microsoft's `icacls` syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls).

The drill is fail-closed unless the reviewed runtime is clean, the canonical release verifier validates the candidate inventory, metadata, artifact bytes, manifest and signature, and the authenticated backup carries the same source commit. Evidence schema v2 records the SHA-256 of the signed candidate controls and complete reviewed runtime tree. It also requires explicit RPO minutes and RTO seconds, records the selected-backup age from its authenticated `started_at` (before source shutdown, conservatively earlier than the data snapshot), and technical recovery time; it passes only when both targets are met. The offsite health receipt uses schema v2 `recovery_point_at` for age monitoring; an older completion-only success receipt is not accepted as ready. It never addresses or stops the source project. Recovered containers, volumes, downloaded ciphertext and plaintext runtime files are removed automatically after every run; only the evidence receipt remains for the configured retention period.

Example, run from the repository root on an isolated recovery machine with Docker and the pinned images already available:

```text
node scripts/deployment-restore-drill.mjs \
  --target s3://company-backups/aidr/production \
  --key-file /protected/recovery.key \
  --runtime /srv/aidr-reviewed-runtime \
  --candidate-inventory /srv/aidr-release-candidate/release-inventory.json \
  --candidate-policy /etc/aidr/release-signer-policy.json \
  --work-root /protected/restore-drills \
  --evidence-retention-days 90 \
  --rpo-target-minutes <approved RPO minutes> \
  --rto-target-seconds <approved technical RTO seconds>
```

For a private S3-compatible endpoint, add `--s3-endpoint`, `--s3-region`, and the same AWS CLI configuration used to publish the backup. The work directory must not exist and must be outside both key custody and any filesystem backup target. The source deployment is not required on the recovery machine. Never put the recovery key in the backup target or the work directory.

The repository includes `deploy/backup/aidr-restore-drill.service`, `deploy/backup/aidr-restore-drill.timer`, and `deploy/backup/aidr-restore-drill.env.example`. The weekly schedule is only a native template: configure the reviewed runtime, signed candidate inventory and signer policy, retention and approved objectives, run the service manually once, then enable the timer. Each run dynamically selects the newest eligible authenticated backup for that signed source commit and receives a unique owner-only state directory. A stale or mismatched inventory fails closed instead of silently recycling old success evidence.

This drill measures technical recovery, not application traffic cutover. It does not verify customer login, policy enforcement, object downloads through the API, DNS/TLS routing, or customer acceptance. Offsite provider durability, independent recovery-key custody, schedule/alert activation, and a restore on a second failure-domain host remain **BLOCKED_EXTERNAL** until named operators execute and approve them. No local template, same-host run or placeholder credential closes AIDR-044.

## Managed cloud recovery contract

The self-hosted volume tool does not back up the Cloudflare/Supabase deployment. For that mode, inventory four separately recoverable parts: PostgreSQL data (including Auth and Vault records), Storage object bytes and bucket configuration, the signed dashboard/Worker and Edge Function release, and the Auth settings, API keys, secrets, routes, DNS/TLS and scheduled jobs needed to run it. [Supabase database backups exclude Storage object bytes](https://supabase.com/docs/guides/platform/backups); its [restore to a new project](https://supabase.com/docs/guides/platform/clone-project) is a database copy that requires manual reconfiguration of Storage, Edge Functions, Auth settings/API keys and Realtime. A restored database may immediately resume external jobs, so isolate or disable those jobs before connecting the recovery project to live providers. [Cloudflare Worker rollback](https://developers.cloudflare.com/workers/versions-and-deployments/rollbacks/) changes application code but does not roll back bound data resources; the selected release must remain compatible with the restored schema.

Before declaring managed cloud recovery ready, execute a synthetic-data drill in a separately administered recovery project. Record the provider backup/PITR point, an independently retained Storage-object inventory and byte checks, signed release digest, configuration and secret re-provisioning record, operator identities, and the actual restore timeline. Verify login, tenant isolation, policy enforcement, audit events, object reads and a synthetic end-to-end agent decision on the recovered endpoint. Measure data loss from the last recoverable transaction/object state and recovery time through DNS/TLS traffic cutover against approved targets. Retain a failure alert receipt and a deletion/retention receipt for both database and object backups. Until this drill is completed, provider backup availability and local tests are only preparation, not a cloud RPO/RTO claim.

Local execution on 2026-09-13 used an older 2026-09-12 archived snapshot copied to a separate filesystem target. The ACL-protected drill passed in 35 seconds: PostgreSQL opened and returned 18 migration records, 65 tenant rows, 13 policy rows, 4,037 audit rows and 25 storage metadata rows; the recovered object volume contained 25 readable files and produced a SHA-256 inventory fingerprint. That legacy receipt carried no source commit, candidate digest or approved recovery objectives and ran on the same host. It is historical mechanics evidence only and cannot pass the current schema-v2 verifier or satisfy independent-host acceptance. Raw local receipt: `.release-evidence/restore-drill-v6-acl/restore-drill-evidence.json`.

## Addendum 2026-10-11: the pgsodium/Vault root key was not preserved

The statement above that recovery preserves the "Vault … identities" was wrong
for every backup made before this date. The installation archive restores the
environment and Compose configuration, but Supabase Vault secrets are encrypted
with `/etc/postgresql-custom/pgsodium_root.key`, which lives on the Compose
`db-config` volume. `deployment-backup.mjs` archived only `aidr-db`,
`aidr-storage` and the installation tree. A recovered project therefore started
with an empty `db-config` volume, the image generated a new key, and every
restored Vault secret failed with `invalid ciphertext`. The PostgreSQL upgrade
drill found this
(`docs/production-readiness/postgres-upgrade-restore-drill-2026-10-11.md`).
AIDR's canonical schema does not use Vault, so no AIDR table was affected.

**Fix.** Backups now seal the key under a dedicated HKDF subkey of the recovery
key and store it, with the SHA-256 of the key file, in the HMAC-authenticated
`backup.json` manifest. No new backup file is added, so the offsite inventory is
unchanged. `verify` authenticates the key record. `recover` writes the key into
the new `db-config` volume before the database first starts and records
`vault_root_key: "restored"` in the receipt. The restore drill now fails when
recovered Vault secrets do not decrypt. Backups made before the fix still verify
and recover, but report `VAULT_KEY_MISSING`. For those backups the manually
custodied key is still needed. Design, rationale and operator steps:
`deploy/backup/README.md`, section "pgsodium/Vault root key".

**Evidence.** This is a local same-host Docker drill on
`supabase/postgres:17.11.0.004`, run with
`AIDR_BACKUP_DOCKER_DRILL=1 node --test scripts/deployment-backup-vault-key-docker.test.mjs`
against the shipped tool:

- A Vault secret was created.
- The deployment was backed up, verified and recovered into a new project with new volumes.
- `vault.decrypted_secrets` returned the original value.
- The key file matched the source by SHA-256 and was `100:101` mode `0600`.
- The image's default `db-config` files were present.
- The same backup with the key record removed reported `VAULT_KEY_MISSING`
  and failed with `invalid ciphertext`.

Summary: `docs/production-readiness/evidence/backup-vault-root-key-2026-10-11.json`.
The external gates of AIDR-044 are unchanged.
