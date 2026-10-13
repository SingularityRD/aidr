# Singularity AIDR Helm chart

Self-hosted AIDR control plane for Kubernetes 1.25+. It runs the same stack as the
Compose installation prepared by `scripts/deployment-prepare.mjs`, reduced to the
services AIDR uses:

| Component | Image | Notes |
|---|---|---|
| `dashboard` | `aidr/dashboard` (built here) | Web console, `/livez`, `/readyz`, `/metrics` |
| `api-gw` | `envoyproxy/envoy:v1.39.2` | Routes `/auth/v1`, `/rest/v1`, `/storage/v1`, `/functions/v1`; everything else is 404 |
| `auth` | `supabase/gotrue:v2.197.0` | Invite-only (sign-up disabled) |
| `rest` | `postgrest/postgrest:v14.17` | |
| `storage` | `supabase/storage-api:v1.80.2` | PVC (`file`) or S3-compatible backend |
| `functions` | `aidr/edge-functions` (built here) | `supabase/edge-runtime:v1.77.4` (digest-pinned) + AIDR functions |
| `db` | `supabase/postgres:17.11.0.004` | Optional single instance; use `externalDatabase` in production |
| `migrations` | `aidr/migrations` (built here) | Helm hook Job |
| `backup` | `aidr/migrations` | Optional `pg_dump` CronJob |
| `posture-scanner-*` | `aidr/posture-scanner-server`, `aidr/posture-scanner-agent`, `aidr/posture-scanner-bridge` (built here) | Optional AI Security Posture scanner (`postureScanner.enabled`) |

Supabase Studio, pg-meta, Realtime, imgproxy, analytics and the pooler are **not**
deployed. The gateway answers 404 for their routes.

Full operating guide: [`docs/operations/kubernetes.md`](../../../docs/operations/kubernetes.md).

## Install

```bash
# 1. Build and push the AIDR images (dashboard dist must be built first).
pnpm -C packages/dashboard build
git submodule update --init deploy/upstream        # reviewed Supabase release, for the functions router
node deploy/helm/build-images.mjs --output .aidr-images \
  --registry registry.example.internal --build --push

# 2. Generate the installation's credentials ONCE and keep the directory in your vault.
node deploy/helm/generate-secrets.mjs --output ~/aidr-credentials --namespace aidr \
  --dashboard-url https://aidr.example.com --api-url https://api.aidr.example.com \
  --artifact-verification-public-key-file release-signing.pub.pem
kubectl create namespace aidr
kubectl apply -f ~/aidr-credentials/platform-secret.yaml -f ~/aidr-credentials/functions-secret.yaml

# 3. Install.
helm install aidr deploy/helm/aidr --namespace aidr -f my-values.yaml

# 4. Create the first tenant owner through the public API.
node scripts/deployment-bootstrap.mjs --deployment ~/aidr-credentials --email owner@example.com \
  --name "Example Corp" --seats 250 --license-expires-at 2027-09-30T00:00:00Z --license-reference "PO-1234"
```

Minimal `my-values.yaml` (see `ci/default-values.yaml`; `ci/prod-values.yaml` shows a
production shape):

```yaml
global:
  imageRegistry: registry.example.internal
publicUrls:
  dashboard: https://aidr.example.com
  api: https://api.aidr.example.com
secrets:
  existingSecret: aidr-platform
  functionsExistingSecret: aidr-functions
ingress:
  className: nginx
  tlsSecretName: aidr-tls        # or certManager.enabled + clusterIssuer
```

## What the chart refuses to do

Rendering fails, rather than producing a weaker install, when:

- `secrets.existingSecret` / `secrets.functionsExistingSecret` are unset. The chart never
  generates a password, JWT secret or signing key and never renders a `Secret`.
- `publicUrls.*` are not `https://` origins, or `ingress.tlsSecretName` is unset (TLS is
  mandatory; cert-manager can fill the Secret).
- An image tag is `latest`, or an AIDR-built image has no registry.
- `postgresql.enabled=false` with `networkPolicy.enabled` and no
  `externalDatabase.networkPolicyCIDRs`.
- `storage.replicaCount > 1` on a `ReadWriteOnce` file volume.
- `backup.enabled` with `storage.backend=file` but neither `backup.storage.enabled`
  nor `backup.storage.acknowledgeNotBackedUp` (the backups would silently miss every
  stored object); `backup.storage.enabled` with `storage.backend=s3` or a
  `ReadWriteOncePod` storage volume. See [Backups](#backups).
- `helm upgrade` while the pre-upgrade migration would run without a fresh backup
  (`backup.enabled` + `backup.preUpgrade.enabled`) and `migrations.allowWithoutBackup`
  is not `true`.
- `backup.enabled` without `backup.encryption.ageRecipients` (unless the dev-only
  `backup.encryption.allowPlaintext`), or `backup.offsite.enabled` without encryption,
  an `https://` endpoint, bucket, region, credentials Secret or (with NetworkPolicy)
  `backup.offsite.egressCIDRs`.
- `postureScanner.enabled` without its Secret, signing key, data ConfigMap, trust anchors or egress proxy.
- `postureScanner.bridge.authMode` other than `broker`: the bridge's `api_key` mode takes the
  tenant from a caller-supplied header, so any holder of the shared key could act for every tenant.
- Any value under the former `aig` key; see [AI Security Posture scanner](#ai-security-posture-scanner).
- `privacyGateway.enabled` with `privacyGateway.mtls.enabled=false`, without its mTLS
  Secret, gateway Secret, trust ConfigMap, model PVC or egress allow-list, with a default
  route or link-local egress CIDR, or with weak or placeholder `serviceConfig`; see
  [Privacy gateway](#privacy-gateway).

## Secrets

`secrets.existingSecret` keys: `postgres-password` (URL-safe; it is embedded in the
Postgres connection URLs), `jwt-secret`, `anon-key`, `service-role-key` (HS256 JWTs signed
with `jwt-secret`), `metrics-token`. Optional: the key named by `auth.smtp.passwordKey`.

`secrets.functionsExistingSecret` is exported verbatim into the functions runtime:
`AIDR_ENTITLEMENT_SIGNING_KEY_ID`, `AIDR_ENTITLEMENT_SIGNING_PRIVATE_KEY_PKCS8_B64`,
`AIDR_REVOCATION_SIGNING_KEY_ID`, `AIDR_REVOCATION_SIGNING_PRIVATE_KEY_PKCS8_B64`,
`AIDR_DELEGATION_SIGNING_KEY_ID`, `AIDR_DELEGATION_SIGNING_PRIVATE_KEY_PKCS8_B64`,
`AIDR_DELEGATION_SIGNING_PUBLIC_KEY_SPKI_B64`, `AIDR_PACK_MASTER_KEY_B64`,
`AIDR_PACK_DOWNLOAD_GRANT_SECRET`, `AIDR_DEVICE_START_INGRESS_SECRET`,
`AIDR_NOTIFICATION_ENCRYPTION_KEYS`, `AIDR_NOTIFICATION_DISPATCH_TOKEN`, and optionally
`AIDR_SHARED_PACK_KEYS` (keys of shared/vendor premium intel packs; see `supabase/README.md`).

## Retention maintenance

The `maintenance` CronJob (on by default, `maintenance.schedule` hourly) runs
`scripts/deployment-maintenance.mjs --from-env --apply`, shipped in a ConfigMap from
`files/deployment-maintenance.mjs` (a byte-identical copy, checked by the chart tests). It
deletes data past each tenant's retention (telemetry, approval requests, expired
invitations, billing webhooks, AI governance records), GA trial subjects, public waitlist
sign-ups after 365 days, expired temporary audit-export objects and rate-limit counters,
honouring legal holds, then dispatches due governance digests. It reaches only the API
gateway Service (its own NetworkPolicy) with `service-role-key` from
`secrets.existingSecret`, read from the environment. The evidence JSON is the pod log;
exit code 2 means the run was incomplete (for example a legal hold or a tenant without a
retention policy), 1 means it failed. Alert when no run has succeeded for two hours.
`maintenance.apply=false` makes it a dry run. Disabling it keeps personal data
indefinitely, whatever retention the workspace owners configure.

## Alert notifications

Settings → Notifications lets workspace owners and administrators send alerts to Slack,
Microsoft Teams, signed HTTPS webhooks or e-mail. Set `notifications.dispatcher.enabled=true`
to render the `notification-dispatch` CronJob (every minute, `concurrencyPolicy: Forbid`),
which calls the functions Service with `AIDR_NOTIFICATION_DISPATCH_TOKEN` from the functions
Secret. Both notification keys must exist in that Secret first (`generate-secrets.mjs` writes
them; for an older Secret add `AIDR_NOTIFICATION_ENCRYPTION_KEYS=k1:<base64 32 bytes>` and a
random 32+ character `AIDR_NOTIFICATION_DISPATCH_TOKEN`). Deliveries leave from the functions
pods, so add the receivers' CIDRs (or an egress proxy) to `networkPolicy.functionsEgressCIDRs`;
that list opens port 443 only, so a generic webhook on 8443 also needs its own egress rule.

`deploy/helm/generate-secrets.mjs` writes both Secrets plus the operator record used by
`scripts/deployment-bootstrap.mjs` and the `agent-config.json` enrolled agents need. You
may instead source the same keys from an external secret manager (External Secrets,
Vault, sealed-secrets) as long as the Secret names match.

## Key values

| Value | Default | Purpose |
|---|---|---|
| `global.imageRegistry` | `""` | Prefix for **every** image (air-gapped mirror) |
| `resourcesPreset` | `small` | `small` / `medium` (x2) / `large` (x4) requests and limits for every component without explicit `resources` |
| `<component>.resources` | `{}` | Explicit override for one component |
| `<component>.replicaCount`, `.pdb`, `.autoscaling` | | Replicas, PodDisruptionBudget, HPA (dashboard, apiGateway, functions) |
| `postgresql.enabled` | `true` | In-cluster single Postgres; set `false` + `externalDatabase.*` in production |
| `externalDatabase.sslMode` | `require` | `require`, `verify-ca` or `verify-full` |
| `storage.backend` | `file` | `file` (PVC, one replica) or `s3` |
| `migrations.enabled` | `true` | Schema hook Job |
| `migrations.allowWithoutBackup` | `false` | Let `helm upgrade` migrate without the pre-upgrade backup (only after your own backup) |
| `maintenance.enabled` | `true` | Hourly retention/erasure/digest CronJob (see [Retention maintenance](#retention-maintenance)) |
| `backup.enabled` | `false` | Nightly encrypted `pg_dump` CronJob to a PVC (off by default: needs your age recipients) |
| `backup.encryption.ageRecipients` | `[]` | Required with backups: age public keys every artifact is sealed to |
| `backup.offsite.enabled` | `false` | Also upload each encrypted artifact to an S3-compatible bucket off the cluster |
| `backup.preUpgrade.enabled` | `true` | Backup hook Job that must succeed before the pre-upgrade migration |
| `backup.storage.enabled` | `false` | Also archive the `storage.backend=file` volume (tar.gz + SHA-256) |
| `backup.storage.acknowledgeNotBackedUp` | `false` | Dev only: accept database-only backups with `storage.backend=file` |
| `notifications.dispatcher.enabled` | `false` | Minute CronJob draining the alert outbox (needs the notification keys in the functions Secret) |
| `ingress.certManager.*` | disabled | Adds the cert-manager issuer annotation |
| `networkPolicy.enabled` | `true` | Default-deny plus per-component allows |
| `networkPolicy.*EgressCIDRs` | `[]` | Opt-in egress: functions (npm mirror/IdP/billing), SMTP, dashboard certificate probe, S3 |
| `functions.npmRegistry` | `""` | npm mirror for the functions' `npm:` imports |
| `postureScanner.enabled` | `false` | AI Security Posture scanner |
| `privacyGateway.enabled` | `false` | Optional privacy gateway (explicit mTLS egress API) |

`values.schema.json` validates types, enums and patterns at install time.

## AI Security Posture scanner

`postureScanner.enabled=true` adds the `posture-scanner-server`, `posture-scanner-agent`
and `posture-scanner-bridge` Deployments, their Services, PersistentVolumeClaims and
NetworkPolicies. The bridge is reachable only from pods carrying
`postureScanner.bridge.clientPodLabel` (default `aidr.singularity/posture-scanner-client: "true"`).

Chart versions before the rename used the values key `aig`. Rendering now stops with
``values key `aig` was renamed to `postureScanner` `` whenever that key is present:
move every `aig.*` setting under `postureScanner.*` (for example `aig.enabled` becomes
`postureScanner.enabled`), rebuild the images under their new repository names
(`node deploy/helm/build-images.mjs --only posture-scanner-server,posture-scanner-agent,posture-scanner-bridge`)
and relabel bridge clients with the new pod label. The Kubernetes objects are renamed
too, so an upgrade creates new `posture-scanner-*` PersistentVolumeClaims; the old
`*-aig-*` claims are kept (`helm.sh/resource-policy: keep`) and can be copied or
deleted once the scanner is verified.

## Privacy gateway

`privacyGateway.enabled=true` adds `aidr-privacy-service` (packages/privacy) as one
`privacy-gateway` Deployment with its ConfigMap, state PVC, Service and NetworkPolicy.
It is an explicit egress API: clients call `POST /v1/egress` over mutual TLS and the
gateway sends policy-checked text to one approved provider with a credential only it
holds. It is **not a transparent proxy** and inspects nothing that is not addressed to
it, so remove the clients' direct provider routes as well (NetworkPolicy, egress
firewall, MDM).

Create `privacyGateway.mtls.existingSecret` (`tls.crt`, `tls.key`, `ca.crt`),
`privacyGateway.existingSecret` (one key per `*Ref`), `privacyGateway.trustConfigMap`
and the model PVC `privacyGateway.models.existingClaim` first, set `serviceConfig` and
`egress.cidrs` (see `ci/privacy-gateway-values.yaml`), and build the image with
`node deploy/helm/build-images.mjs --only privacy-gateway`. The pod meets the
`restricted` Pod Security Standard, reads secrets as files only, and its NetworkPolicy
(ingress 8443 from `clientPodLabel` pods and `clientCIDRs`, egress DNS plus TCP 443 to
`egress.cidrs`) renders even when `networkPolicy.enabled=false`. Details:
[deploy/privacy-gateway/README.md](../../privacy-gateway/README.md).

## Security posture

Every pod runs with `runAsNonRoot`, a numeric non-root UID, `seccompProfile:
RuntimeDefault`, no service-account token, and every container drops all capabilities
with `allowPrivilegeEscalation: false` and a read-only root filesystem (writable
`emptyDir` mounts only where a process needs scratch space). The in-cluster Postgres
container is the single exception to the read-only root filesystem.

The API gateway keeps the upstream Supabase key checks: protected `/auth/v1` and
`/rest/v1` routes need the anon or service-role key, the PostgREST OpenAPI document
needs the service-role key, CORS is pinned to `publicUrls.dashboard`, and API keys are
substituted from the Secret at container start into an in-memory volume, never into the
ConfigMap.

## Upgrade

```bash
node deploy/helm/build-images.mjs --output .aidr-images-0.6.1 --registry registry.example.internal --build --push
helm upgrade aidr deploy/helm/aidr --namespace aidr -f my-values.yaml
```

The migrations Job runs as a `pre-upgrade` hook: the schema moves (atomically, with
checksum verification) before any new pod rolls out, and a failed migration aborts the
upgrade with the old pods still serving.

With `backup.enabled` the chart takes that backup for you: a `pre-upgrade` hook Job
(`<release>-backup-pre-upgrade`, `helm.sh/hook-weight: "-10"`) runs the same backup as the
CronJob before the migrations Job (weight `"0"`). Helm runs hooks in ascending weight and
waits for each Job, so a failed or timed-out backup aborts the upgrade before the schema
changes; the artifacts are `aidr-<stamp>-pre-upgrade.*` on the backup volume. Without it
(`backup.enabled=false` or `backup.preUpgrade.enabled=false`) `helm upgrade` refuses to
render unless `migrations.allowWithoutBackup=true`; set that only after taking your own
backup (for example a managed-database snapshot). Fresh installs are unaffected: the
post-install migration has no existing data to lose.

The backup hook mounts the existing backup volume. On the upgrade that **first** enables
`backup.enabled`, that claim does not exist yet, so pass
`--set backup.preUpgrade.enabled=false --set migrations.allowWithoutBackup=true` once (or
pre-create a claim and set `backup.persistence.existingClaim`).

## Air-gapped installs

1. On a connected host: build the AIDR images, then bundle them with every upstream
   image the chart renders for your values:
   ```bash
   helm template aidr deploy/helm/aidr -f my-values.yaml --set global.imageRegistry=docker.io \
     | awk '$1=="image:"{print $2}' | grep -v '/aidr/' | sort -u > upstream-images.txt
   args=$( (cat upstream-images.txt; jq -r '.images[].ref' .aidr-images/images.json) | sed 's/^/--images /')
   node scripts/build-airgap-images.mjs --output aidr-images-bundle $args
   ```
   The bundle manifest records every reference with its size and SHA-256.
2. Transfer the bundle, verify it (`node scripts/build-airgap-images.mjs --verify --output aidr-images-bundle`),
   `docker load` the tarballs, retag `docker.io/<repo>:<tag>` as
   `<internal-registry>/<repo>:<tag>` and push everything to the internal registry.
3. Install with `global.imageRegistry: <internal-registry>` and, for the functions' npm
   imports, `functions.npmRegistry: <internal npm mirror>`.

## Backups

Backups are **off by default** (`backup.enabled=false`): turning them on needs two
decisions the chart cannot make for you, where the decryption identity is kept and
(recommended) which bucket holds the off-cluster copy. With `externalDatabase`, prefer
the provider's PITR and keep the CronJob as a second, logical copy.

`backup.enabled=true` adds a CronJob (and the pre-upgrade hook, see [Upgrade](#upgrade))
that streams the custom-format `pg_dump` through [age](https://age-encryption.org) to
every recipient in `backup.encryption.ageRecipients` and writes `aidr-<UTC stamp>.dump.age`,
its `.sha256` and an `aidr-<stamp>.manifest` to a PVC, pruning files older than
`backup.retentionDays`. No plaintext dump touches the volume, and the cluster only holds
public recipients: create the identity off the cluster (`age-keygen -o backup-identity.txt`)
and keep it in your vault or key escrow (list two recipients to split custody). Rendering
fails without a recipient; `backup.encryption.allowPlaintext=true` (dev only) restores the
old plaintext `.dump`. The default `aidr/migrations` image ships `age` and `curl`; a custom
`backup.image` without them fails the run instead of writing plaintext.

**Off-cluster copy.** A PVC on the same cluster is not a disaster-recovery copy.
`backup.offsite.enabled=true` uploads every finished artifact (`.age`, `.sha256`,
`.manifest`) to `backup.offsite.endpoint`/`bucket`/`prefix` over HTTPS with SigV4
(path-style; AWS S3, MinIO, Ceph RGW and similar), with write-only credentials from
`backup.offsite.existingSecret` (`access-key-id`, `secret-access-key`) passed to curl on
stdin. A failed upload fails the run (and, for the pre-upgrade hook, the upgrade). Use a
bucket with versioning/object lock and a lifecycle rule; `retentionDays` prunes only the
PVC. With NetworkPolicy, `backup.offsite.egressCIDRs` opens TCP 443 to the store.

What is and is not backed up:

| Data | Backed up by the chart |
|---|---|
| Database (all schemas, including `storage.objects` metadata) | Yes, `pg_dump` |
| Stored objects, `storage.backend=file` | Only with `backup.storage.enabled=true` |
| Stored objects, `storage.backend=s3` | **No**: use bucket versioning, replication or provider backups |
| Secrets (`secrets.existingSecret`, functions Secret, S3 credentials) | **No**: keep the `generate-secrets.mjs` credential directory safe |
| pgsodium / Vault root key of the in-cluster Postgres (`pgsodium_root.key` on the `config-<release>-db-0` PVC) | **No**: export it once, see [Key material](#key-material) |
| The age identity that decrypts the backups | **No**: it must never be on the cluster; escrow it |
| The backup volume itself | Only with `backup.offsite.enabled=true`; otherwise replicate it off-cluster |

### Key material

A restore needs, besides the dump: the age identity, the platform and functions Secrets
(the `generate-secrets.mjs` directory, which also holds the pack master key and signing
keys), and, for the in-cluster Postgres, its pgsodium root key. Any value encrypted with
pgsodium or Supabase Vault is unreadable after a restore without that key (AIDR's own
schema does not use them today, but extensions and operators may). Export it once after
install, sealed to the same recipients, and store it with the identity escrow:

```bash
kubectl -n aidr exec aidr-db-0 -c postgres -- cat /etc/postgresql-custom/pgsodium_root.key \
  | age -r age1... -r age1... > pgsodium_root.key.age
```

The key does not change after the first start; re-export only after you replace it. With
`externalDatabase`, follow the provider's key backup instead.

With `storage.backend=file` and `backup.enabled=true`, rendering fails until you choose:
`backup.storage.enabled=true`, `storage.backend=s3`, or (dev only)
`backup.storage.acknowledgeNotBackedUp=true`, which accepts that a restore loses every
stored object.

`backup.storage.enabled=true` mounts the storage volume **read-only** in the backup pod
and, after the dump, writes `aidr-<stamp>.storage.tar.gz`, its `.sha256` and an
`aidr-<stamp>.manifest` naming the dump and archive of that run. Limits:

- **Volume access mode.** A `ReadWriteOnce` volume is mounted only on the node that
  runs the storage pod, so the backup pod gets a required `podAffinity` to it: the storage
  pod must be running, and the backup volume must be attachable on that node (same
  zone). `ReadWriteMany` needs no affinity. `ReadWriteOncePod` is refused at render time;
  use a CSI `VolumeSnapshot` instead.
- **Consistency.** The archive is taken while Storage serves traffic. The dump runs
  first, so an upload racing the backup leaves an orphan file rather than a database row
  without its object. GNU tar fails the run when a file changes while it is read (retry);
  busybox tar does not detect it. For an exactly consistent pair, scale Storage to zero
  or snapshot both volumes.
- **Extended attributes.** storage-api keeps an object's content type and cache control
  in `user.*` xattrs. They are archived only when the backup image has GNU tar; the
  default `aidr/migrations` image has busybox tar, and the manifest then records
  `storage_xattrs=not-preserved` (the bytes and the database metadata are intact).

Restore (off the cluster or in a restore pod, with the identity): stop Storage, verify
the checksums (`sha256sum -c aidr-<stamp>.dump.age.sha256` and
`aidr-<stamp>.storage.tar.gz.age.sha256`), decrypt and restore the dump
(`age -d -i backup-identity.txt aidr-<stamp>.dump.age | pg_restore --clean --if-exists -d <db>`),
then decrypt and extract the archive into an empty storage volume as the storage user
(`age -d -i backup-identity.txt aidr-<stamp>.storage.tar.gz.age | tar -xzf - -C <volume>`,
adding `--xattrs` with GNU tar) and start Storage again. For the in-cluster Postgres,
put the exported `pgsodium_root.key` back on the new `config` volume before the first
start. Rehearse this on a scratch namespace after every chart upgrade; the chart does not
yet ship a restore-drill Job (the Compose path has `scripts/deployment-restore-drill.mjs`).
