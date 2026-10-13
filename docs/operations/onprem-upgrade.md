# Upgrading an on-prem installation

[Türkçe](onprem-upgrade.tr.md)

This guide is for the operator of a self-hosted Singularity AIDR control plane. It
covers the one-command upgrade of a Docker Compose installation, the three-command
Helm upgrade, the single signed bundle for disconnected (air-gapped) hosts, and what to
do when an upgrade stops. The detailed contracts behind each step stay in
[the upgrade runbook](../../deploy/UPGRADE.md) and
[the on-prem installation guide](../../deploy/onprem/README.md).

Endpoint protection does not depend on this: connectors keep enforcing locally while
the control plane is being upgraded.

## Docker Compose: one command

You need three things before you start:

1. **The new release, prepared in its own directory.** Never prepare over the live
   installation. From the verified kit of the new release:

   ```sh
   node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr-target ...
   ```

   Use the same `--dashboard-url`, `--supabase-url`, `--region` and `--tenant-region` as
   the live installation.
2. **The compatibility contract** from the release owner, by default at
   `/secure/aidr-upgrade/upgrade-compatibility.json` next to its rehearsal evidence
   ([format](../../deploy/UPGRADE.md#required-release-evidence)).
3. **The backup key**, by default `/secure/aidr-recovery.key`, kept away from the
   installation and the backups.

Then, in an approved maintenance window, from the new release's kit:

```sh
pnpm onprem:upgrade --to /srv/aidr-target --dry-run   # shows the plan, changes nothing
pnpm onprem:upgrade --to /srv/aidr-target             # runs it
```

Without pnpm, use `node scripts/onprem-upgrade.mjs` with the same options. The
installation is `/srv/aidr` unless you pass `--current` (or set `AIDR_DEPLOYMENT_DIR`).
Messages are in Turkish when the system language is Turkish, or with `--lang tr`.

The command runs these steps and stops at the first one that fails:

| Step | What happens | Tool it runs |
|---|---|---|
| 1. Check | The new release fits this installation: same platform baseline and addresses, database changes only added at the end, contract signed off for exactly these two versions, signing keys unchanged. Read-only. | `deployment-upgrade.mjs check` |
| 2. Backup | Encrypted cold backup into `/backups/aidr-pre-upgrade-<time>` (`--backup-root` to change). The services stop for the snapshot and start again. | `deployment-backup.mjs backup` |
| 3. Verify | The backup decrypts and is complete. | `deployment-backup.mjs verify` |
| 4. Preflight | Every file of both versions matches its recorded hash, the backup belongs to this installation and is fresh. | `deployment-upgrade.mjs preflight` |
| 5. Apply | Writers stop, the database changes are rehearsed and then applied in one transaction, the new files are installed. | `deployment-upgrade.mjs apply` |
| 6. Restart | The new version starts (part of step 5). | |
| 7. Doctor | The online health check passes (run inside step 5 and again here). | `deployment-doctor.mjs --online` |
| 8. Post-upgrade checks | The installed release matches the upgrade receipt, the health record is from this run and passed, the dashboard answers. | read-only |

It refuses to start when `--to` is the live directory (or inside it), when the target
was already used as a running installation, or when the contract, backup key or backup
folder is missing. A previous upgrade that did not finish is never overwritten: the
command tells you to continue it with `--resume`. A finished one is moved to
`/srv/aidr/.aidr-upgrade/history/`.

To reuse a backup you took and verified yourself, pass `--backup <dir>` (it must be
younger than 24 hours, or `--max-backup-age-hours`, at most 168).

Each run writes `/srv/aidr/.aidr-upgrade/onprem-upgrade-receipt.json` with every
step's result and time; the upgrade tool's own receipt is
`/srv/aidr/.aidr-upgrade/upgrade-receipt.json`. Neither is customer acceptance: after a
successful run, sign in as an administrator, enroll a test device, check that a blocked
action is blocked and export the audit log.

If the installation runs the AI Security Posture scanner or the privacy gateway, copy
their prepared directories as described in
[the on-prem guide](../../deploy/onprem/README.md#upgrade) before the run.

## If the upgrade fails

The command prints which step stopped, why, what state the installation is in and the
exact command to run next. In short:

| Stopped at | Your installation | What to do |
|---|---|---|
| 1. Check, 3. Verify, 4. Preflight | Unchanged; the current version keeps running. | Fix the reason and run the same command again. After a failed preflight it offers `--backup <dir>` to reuse the backup it just verified. |
| 2. Backup | Unchanged. The backup tool restarts the services it stopped. | If some stay stopped: `node scripts/deployment-backup.mjs recover-services --deployment /srv/aidr --recovery-journal /var/lib/aidr-backup/recovery-journal.json`, then run again. |
| 5. Apply, before the database change | The database is unchanged and the previous version was started again. | Fix the reason, then `pnpm onprem:upgrade --to /srv/aidr-target --resume`. |
| 5–7, after the database change | The database is already on the new version. Keep users away. | Check `docker compose ... logs`, fix the cause and continue with `--resume`. If it cannot be fixed, restore (below). |
| 8. Post-upgrade checks | The new version is installed and running. | Fix the failing check, rerun `node scripts/deployment-doctor.mjs --deployment /srv/aidr --online`, then `--resume` to confirm. |
| Stopped by Ctrl+C or a stop signal | Stopped at a safe point. | Continue with `--resume`. |

**No automatic restore is attempted.** Before the database change the upgrade tool
already puts the previous version back by itself. After it, going back means restoring
the verified backup into a new, separate installation, which needs your decision before
users are moved:

```sh
node scripts/deployment-upgrade.mjs recover \
  --current /srv/aidr --target /srv/aidr-target \
  --backup /backups/aidr-pre-upgrade-<time> --key-file /secure/aidr-recovery.key \
  --contract /secure/aidr-upgrade/upgrade-compatibility.json \
  --recovery-runtime /srv/aidr-reviewed-current --maintenance
```

`--recovery-runtime` is a clean directory prepared from the **current** (old) release.
The plan with the exact command is also written to
`/srv/aidr/.aidr-upgrade/rollback-plan.json`. Start the restored installation on its
own, run the doctor there, check sign-in, enrollment, a blocked action and the audit
export, and only then move users. Details:
[Failure and recovery](../../deploy/UPGRADE.md#failure-and-recovery).

## Kubernetes (Helm): three commands

With backups on, the chart backs up, migrates and rolls out by itself, and stops before
the database changes if the backup fails. Start from
[`values.example.yaml`](../../deploy/helm/aidr/values.example.yaml) and follow
[Upgrade in 3 commands](../../deploy/helm/aidr/README.md#upgrade-in-3-commands):

```bash
node deploy/helm/build-images.mjs --output .aidr-images-<version> --registry <registry> --build --push
helm upgrade aidr deploy/helm/aidr -n aidr -f my-values.yaml --wait --timeout 30m
kubectl -n aidr wait --for=condition=Available deployment -l app.kubernetes.io/instance=aidr --timeout=10m
```

## Disconnected (air-gapped) hosts: one bundle

On a connected staging host with the same release, build one signed bundle with
everything the disconnected site needs:

```sh
node scripts/onprem-offline-bundle.mjs build --output /media/aidr-offline-0.6.1 \
  --signing-key /secure/offline-bundle-signing.pem --key-id site-operator-2026 \
  --compose .aidr-deploy/compose.yml --platform linux/amd64 \
  --intel-pack /releases/intel/aidr-intel-2.0.0 --intel-trusted-keys /secure/intel-trusted-keys.json \
  --installers /releases/installers-staged --installer-catalog-public-key /secure/installer-catalog.pub.pem \
  --browser-guard-feed /releases/browser-guard-feed \
  --tar
```

Pass `--images <dir>` instead of `--compose` to reuse an image bundle already made with
`scripts/build-airgap-images.mjs`. Each part is optional, but at least one is required.
The result is one directory (and with `--tar` one `.tar` file) holding:

| Part | Contents | Checked before it is bundled and again before import |
|---|---|---|
| `images/` | Every container image the stack needs, as `docker save` tarballs | Size and SHA-256 of every tarball |
| `intel-packs/` | The signed threat-intelligence packs | Ed25519 signature from a trusted key, expiry, every file digest |
| `installers/` | Desktop installers and their signed catalog | Catalog and pointer signatures, every installer digest |
| `browser-guard/` | Browser Guard update files, if given | Every `.crx` has a signed CRX3 header and every `.xpi` a Mozilla signature |
| `aidr-offline-bundle.manifest.json` (+ `.sig`) | What is inside, with every file's SHA-256 | Signed with your bundle key |
| `SHA256SUMS` | SHA-256 of every file | |

The bundle is refused, and nothing is written, when the signing key is missing, an
intel pack or installer catalog signature does not verify, a trusted key or catalog key
is missing, or a Browser Guard package is unsigned.

On the disconnected host, with the bundle public key delivered separately (not inside
the bundle):

```sh
node scripts/onprem-offline-bundle.mjs verify --bundle /media/aidr-offline-0.6.1.tar \
  --public-key /secure/offline-bundle-signing.pub.pem \
  --intel-trusted-keys /secure/intel-trusted-keys.json --installer-catalog-public-key /secure/installer-catalog.pub.pem

node scripts/onprem-offline-bundle.mjs import --bundle /media/aidr-offline-0.6.1.tar \
  --public-key /secure/offline-bundle-signing.pub.pem \
  --intel-trusted-keys /secure/intel-trusted-keys.json --installer-catalog-public-key /secure/installer-catalog.pub.pem \
  --load-images --intel-target storage --deployment /srv/aidr \
  --installers-out /srv/aidr-downloads/0.6.1 --browser-guard-out /srv/aidr-browser-guard
```

`import` verifies everything again first and imports nothing if any check fails. It
loads the images with `docker load`, installs the intel packs with
`scripts/import-offline-pack.mjs` (`--intel-target local --packs-dir <dir>` for an
endpoint packs folder), and copies the installers and the Browser Guard files into new
directories for your internal download portal and update address. Then prepare the new
release and run the one-command upgrade above.

The image tarballs are protected by the bundle signature and their digests, not by a
publisher signature: verify vendor images with `cosign` as in
[the Kubernetes guide](kubernetes.md#vendor-built-signed-images-and-chart) before you
bundle them.

## What this does not cover

- Customer acceptance, traffic cutover, high availability and recovery-time targets are
  recorded in your change and acceptance records.
- A change of the platform baseline (the bundled Supabase release) or of the public
  addresses is a separate platform migration; step 1 refuses it.
