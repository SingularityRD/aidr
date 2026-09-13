# Backup and restore drill (v6)

The self-hosted backup command creates encrypted, authenticated cold snapshots of the PostgreSQL, object-storage, and installation volumes. `deployment-backup-offsite.mjs` publishes a committed copy to a scoped filesystem or S3-compatible target, then downloads and verifies every object with the separately held recovery key. Filesystem retention is metadata only; native Object Lock must be enabled and verified on an S3-compatible target when immutability is required.

`scripts/deployment-restore-drill.mjs` adds the missing read test. It downloads a committed backup into a **new** work directory, verifies ciphertext hashes and AES-GCM tags, recovers into a randomly named Compose project with new volumes, refuses recovered containers that publish host ports or have foreign project labels, starts only the recovered database, reads critical AIDR tables and migration count, fingerprints the restored object volume, then stops that database. Before downloading on Windows, it removes inherited access with `icacls`, grants the current SID inheritable full access, and verifies that the DACL has exactly that explicit allow rule; ACL failure stops the drill before secret files are written. POSIX mode must exclude group and world access. The Windows operation follows [Microsoft's `icacls` syntax](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/icacls). It writes `restore-drill-evidence.json` with an explicit `passed` field, backup identity and age, source commit if present, aggregate row counts, object inventory fingerprint, and measured technical restore time. It never addresses or stops the source project. The recovered project and plaintext installation configuration remain on disk for audit; protect the work directory and remove it and its isolated volumes under the normal data-handling procedure after evidence review.

Example, run from the repository root on an isolated recovery machine with Docker and the pinned images already available:

```text
node scripts/deployment-restore-drill.mjs \
  --target s3://company-backups/aidr/production \
  --backup-id <64-character manifest digest> \
  --key-file /protected/recovery.key \
  --work-dir /protected/new-restore-drill \
  --expected-source-commit <release commit> \
  --max-backup-age-minutes <contract RPO minutes>
```

For a private S3-compatible endpoint, add `--s3-endpoint`, `--s3-region`, and the same AWS CLI configuration used to publish the backup. The work directory must not exist and must be outside both key custody and any filesystem backup target. The source deployment is not required on the recovery machine. Never put the recovery key in the backup target or the work directory.

This drill is a technical recovery check, not an application cutover or an RTO guarantee. It does not verify customer login, policy enforcement, object downloads through the API, DNS/TLS routing, or the freshness of a running production backup schedule. Numeric RPO/RTO and customer acceptance still require a named off-host target and key custodian, scheduled backup history, an **independent host**, a candidate-bound restore with the release commit, full application smoke and reconciliation, measured cutover time, and the customer's approval. A same-machine filesystem copy does not close AIDR-044.

Local execution on 2026-09-13 used an older 2026-09-12 archived snapshot copied to a separate filesystem target. The ACL-protected drill passed in 35 seconds: PostgreSQL opened and returned 18 migration records, 65 tenant rows, 13 policy rows, 4,037 audit rows and 25 storage metadata rows; the recovered object volume contained 25 readable files and produced a SHA-256 inventory fingerprint. `icacls` showed only the current user on the work directory, recovered directory and recovered `.env`; the new database was stopped afterward. The backup carried no `source_commit`, the target and recovery ran on the same host, and no application cutover was attempted. This evidence proves the new command's local mechanics only; it does not bind to v6 or satisfy independent-host acceptance. Raw local receipt: `.release-evidence/restore-drill-v6-acl/restore-drill-evidence.json`.
