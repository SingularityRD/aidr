# Running AIDR on Kubernetes

The Helm chart in `deploy/helm/aidr` installs the self-hosted AIDR control plane. It is
the Kubernetes counterpart of the Compose installation from
`scripts/deployment-prepare.mjs` and uses the same pinned upstream Supabase release
(self-hosted v0.8.1, commit `8c7a4d9d`). The chart README lists every value; this page
covers operation.

## Architecture

```
            Ingress (TLS)                        cluster-internal only
  aidr.example.com ──► dashboard :8080 ──────────┐ (health probes)
  api.aidr.example.com ─► api-gw (Envoy) :8000 ◄─┘
                             │ /auth/v1   ─► auth (GoTrue) :9999 ─┐
                             │ /rest/v1   ─► rest (PostgREST) :3000 ─┤
                             │ /storage/v1─► storage :5000 ──────────┼─► Postgres :5432
                             │ /functions/v1 ─► functions (edge-runtime) :9000 ─┘
                             └ anything else: 404
```

- One Helm release per installation and namespace. The chart creates no cluster-scoped
  resources.
- `migrations` is a Helm hook Job; `maintenance` is an hourly CronJob; `backup` is an optional, encrypted CronJob.
- `postureScanner.enabled` adds the AI Security Posture scanner (`posture-scanner-server`,
  `posture-scanner-agent` and `posture-scanner-bridge`, the
  `docker-compose.posture-scanner.yml` stack) with the bridge reachable only from
  labelled pods. The former `aig` values key is refused with a pointer to
  `postureScanner`; see the chart README for the upgrade steps.

## Prerequisites

- Kubernetes 1.25+, a CNI that enforces NetworkPolicy (Calico, Cilium, ...), an ingress
  controller, and a default StorageClass (or `global.storageClass`).
- A container registry the cluster can pull from.
- For production: a Supabase-compatible Postgres 15+ (see below) with backups/PITR, and
  optionally an S3-compatible bucket for storage.
- A workstation with Node 22+ and this repository to generate credentials, plus Docker when
  building the images from source instead of using the signed release images.

## Images

Upstream images are used unchanged. Three AIDR images are built from this repository by
`deploy/helm/build-images.mjs`:

| Image | Built from |
|---|---|
| `aidr/dashboard` | `deploy/dashboard/Dockerfile` + `packages/dashboard/dist` + `supabase/templates` |
| `aidr/edge-functions` | `deploy/helm/images/edge-functions.Dockerfile`: `supabase/edge-runtime:v1.77.4` (digest-pinned), the reviewed upstream router `docker/volumes/functions/main` (from `deploy/upstream` at the pinned commit; the `hello` sample is dropped) and `supabase/functions` |
| `aidr/migrations` | `deploy/helm/images/migrations.Dockerfile`: `postgres:17.11-alpine3.24` client (digest-pinned, matching the 17.11 server), `migrate.sql` and `aidr-migrate.sh` |

### Vendor-built, signed images and chart

`.github/workflows/release-images.yml` builds the three images above plus
`aidr/privacy-gateway` and the three posture scanner images from a protected, signed
`vX.Y.Z-rc.N` tag, pushes them to `ghcr.io/singularityrd/aidr/<name>:<X.Y.Z-rc.N>`,
scans each digest with Trivy (a CRITICAL finding with a fix fails the run), signs it
keyless with cosign, attaches a CycloneDX SBOM attestation and a GitHub build-provenance
attestation, and pushes the chart as `oci://ghcr.io/singularityrd/charts/aidr` with every
AIDR image already pinned to `tag@sha256:digest` in its default values. The run's
`release-images-<run id>` artifact holds `release-images.json` (every digest), the scan
summary, the SBOMs and the packaged chart. Until GitHub Actions is enabled for the
repository (OPS-1) and a candidate tag has gone through it, no such images exist; build
from source as below.

Verify before installing (replace the tag and digest with the release values):

```bash
identity='https://github.com/SingularityRD/aidr/.github/workflows/release-images.yml@refs/tags/v0.6.0-rc.0'
cosign verify --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/singularityrd/aidr/dashboard@sha256:<digest>
cosign verify-attestation --type cyclonedx --certificate-identity "$identity" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  ghcr.io/singularityrd/aidr/dashboard@sha256:<digest>
gh attestation verify oci://ghcr.io/singularityrd/aidr/dashboard@sha256:<digest> --repo SingularityRD/aidr
helm pull oci://ghcr.io/singularityrd/charts/aidr --version 0.6.0-rc.0
```

When `global.imageRegistry` points at an internal mirror, the pinned digests still apply,
so a mirrored image that differs from the signed one does not start.

### Building from source

```bash
pnpm -C packages/dashboard build
git submodule update --init deploy/upstream
node deploy/helm/build-images.mjs --output .aidr-images --registry registry.example.internal --build --push
# optional AI Security Posture scanner:
node deploy/helm/build-images.mjs --output .aidr-images-posture-scanner --only posture-scanner-server,posture-scanner-agent,posture-scanner-bridge \
  --registry registry.example.internal --build --push
```

Without `--build` the script only stages the contexts and prints the `docker build`
commands. It refuses a `latest` tag, an existing output directory and an upstream
checkout that is not the reviewed commit. `images.json` lists each reference and the
SHA-256 inventory of every staged context.

`migrate.sql` is produced by `buildAtomicMigrationSql` in
`scripts/lib/migration-contract.mjs`, the same function `scripts/deployment-migrate.mjs`
uses for Compose: one transaction, `pg_advisory_xact_lock`, a refusal when the database
holds a migration absent from the plan or a changed checksum, and a ledger in
`public.aidr_schema_migrations`. `aidr-migrate.sh` refuses to run if `migrate.sql` does
not match the `plan_sha256` recorded in the image.

## Credentials

The chart never creates or generates secrets. Generate them once per installation:

```bash
node deploy/helm/generate-secrets.mjs --output ~/aidr-credentials --namespace aidr \
  --dashboard-url https://aidr.example.com --api-url https://api.aidr.example.com \
  --artifact-verification-public-key-file release-signing.pub.pem
kubectl apply -f ~/aidr-credentials/platform-secret.yaml -f ~/aidr-credentials/functions-secret.yaml
```

The directory (0700; files 0600; nothing printed) also holds `deployment.json` + `.env`
for `scripts/deployment-bootstrap.mjs`, the managed `agent-config.json` (control-plane
endpoint, entitlement verification key, artifact verification key) and `readiness.env`
(signing-key expiry dates). Store it in your vault. Generating again produces a
different installation identity: never apply a second set to an existing database.

The Supabase anon and service-role keys expire after 365 days, as in the Compose
installation. Rotate them (new `jwt-secret` and keys, rolling restart) before
`deployment.json`'s `prepared_at` plus one year.

## External database (recommended for production)

Set `postgresql.enabled=false` and `externalDatabase.{host,port,database,sslMode}`. The
database must provide what `supabase/postgres` provides: the roles `authenticator`,
`anon`, `authenticated`, `service_role`, `supabase_auth_admin`,
`supabase_storage_admin` and `postgres`, all using the `postgres-password` from the
platform Secret, and the database settings `app.settings.jwt_secret` /
`app.settings.jwt_exp`. The simplest compliant option is an operator-managed cluster
running the `supabase/postgres:17.11.0.004` image (for example with a CloudNativePG or
Patroni-based operator) with synchronous standbys, as `deploy/ha/topology.self-hosted.reference.yaml`
describes. Set `externalDatabase.networkPolicyCIDRs` to the database addresses.

The in-cluster `postgresql` StatefulSet is a single instance without failover. Use it
for evaluation and small non-critical installs only.

## Install, verify, bootstrap

```bash
helm install aidr deploy/helm/aidr -n aidr -f my-values.yaml
kubectl -n aidr get pods -w
kubectl -n aidr logs job/aidr-migrations
```

The migrations Job is a `post-install` hook on first install (the Supabase roles and the
`storage.buckets` table it depends on are created by the stack's first boot; the Job
waits up to `migrations.storageWaitSeconds` for them) and a `pre-upgrade` hook
afterwards. `helm install --wait` therefore returns once the application pods are Ready
and the schema is applied.

Then create the first owner:

```bash
node scripts/deployment-bootstrap.mjs --deployment ~/aidr-credentials --email owner@example.com \
  --name "Example Corp" --seats 250 --license-expires-at 2027-09-30T00:00:00Z --license-reference "PO-1234"
```

## Readiness and monitoring

- Kubernetes probes use `/livez` for the dashboard (`dashboard.readinessProbePath`) and
  the services' own health endpoints.
- `GET /readyz` on the dashboard reports all seven operator checks (database, storage,
  functions, signing, backup, queue, certificate). The signing, backup and queue checks
  read evidence files from `/run/aidr-health`, written by
  `scripts/readiness-evidence-worker.mjs`. The chart mounts an empty directory there
  unless `dashboard.healthEvidence.existingClaim` names a PVC that the evidence worker
  writes, so `/readyz` reports those checks as failed until you run the worker. The
  certificate check needs `networkPolicy.dashboardEgressCIDRs` to reach the public
  ingress address.
- `GET /metrics` on the dashboard (Bearer `metrics-token`) exposes Prometheus metrics;
  `deploy/monitoring` has the rules.

## Network policy

With `networkPolicy.enabled=true` (default) every AIDR pod is default-deny for ingress
and egress, with only these allows: DNS to kube-dns; ingress controller to dashboard and
gateway; dashboard, functions to gateway; gateway to auth, rest, storage, functions;
auth to dashboard (recovery e-mail template); storage to rest; auth, rest, storage,
functions, migrations, backup to Postgres. Internet egress is opt-in per purpose via
`networkPolicy.functionsEgressCIDRs` (npm mirror, IdP, billing provider),
`smtpEgressCIDRs`, `dashboardEgressCIDRs` and `storageEgressCIDRs`. Adjust
`ingressControllerNamespaceSelector` and `dnsNamespaceSelector`/`dnsPodSelector` to
your cluster.

## Upgrade and rollback

```bash
node deploy/helm/build-images.mjs --output .aidr-images-<version> --registry <registry> --build --push
helm upgrade aidr deploy/helm/aidr -n aidr -f my-values.yaml
```

Back up first. The `pre-upgrade` migration applies the new schema atomically before
new pods roll out; if it fails nothing is applied and the old release keeps serving.
`helm rollback` restores the previous manifests but not the schema: migrations are
forward-only, so a rollback across a migration needs a database restore.

## Backup and restore

Backups are off by default. `backup.enabled=true` (with the required
`backup.encryption.ageRecipients`) schedules `pg_dump --format=custom` streamed through
age into a PVC (`aidr-<stamp>.dump.age` plus `.sha256`) with `backup.retentionDays`
pruning; `backup.offsite.enabled=true` also uploads every encrypted artifact to an
S3-compatible bucket off the cluster. Keep the age identity, the credential directory and
the exported pgsodium root key off the cluster (chart README, "Backups" and "Key
material"), and rehearse restores regularly:

```bash
kubectl -n aidr run restore --rm -it --image <registry>/aidr/migrations:<tag> --command -- sh
sha256sum -c aidr-<stamp>.dump.age.sha256
age -d -i backup-identity.txt aidr-<stamp>.dump.age | pg_restore --clean --if-exists --no-owner -d "$DATABASE_URL"
```

Copy the identity into the restore pod only for the restore (for example with
`kubectl cp`) and delete the pod afterwards.

## Retention maintenance

The chart's `maintenance` CronJob (on by default, hourly) runs the same retention,
erasure and governance-digest worker as the Compose timer; see the chart README,
"Retention maintenance", and [control-plane.md](../control-plane.md#retention-maintenance).

The Compose tools `scripts/deployment-backup*.mjs` and `deployment-restore-drill.mjs`
operate on a Compose deployment directory and do not apply to the chart.

## Air-gapped installs

Build the AIDR images and bundle every upstream image the chart renders with
`scripts/build-airgap-images.mjs` (see the chart README). In the isolated environment,
push them to the internal registry and set `global.imageRegistry`. The edge functions
import `npm:` packages at first use; point `functions.npmRegistry` at an internal npm
mirror (`NPM_CONFIG_REGISTRY`) and allow it with `networkPolicy.functionsEgressCIDRs`.

## Validating the chart

```bash
pnpm verify:helm
```

runs `deploy/helm/chart.test.mjs` and `deploy/helm/tools.test.mjs` with `node --test`.
Static checks always run. The rendered checks (`helm lint --strict` and `helm template`
for `ci/default-values.yaml`, `ci/prod-values.yaml` and `ci/posture-scanner-values.yaml`) need Helm 3
on `PATH` or in `HELM_BIN`; without it they are reported as skipped. They assert that
every container has CPU/memory requests and limits, runs non-root with all capabilities
dropped and no privilege escalation, uses a pinned non-`latest` image, takes credentials
only from Secrets, that a default-deny NetworkPolicy and a per-component allow-list
exist, and that rendering fails on missing secrets, non-HTTPS URLs, `latest` tags,
missing TLS, incomplete posture scanner inputs and the retired `aig` values key. With `kubeconform` on `PATH` or in
`KUBECONFORM_BIN`, the rendered manifests are also validated against the Kubernetes
1.25 and 1.30 OpenAPI schemas.

## Known limitations

- Not yet exercised on a live cluster. The rendered manifests are validated by Helm,
  the tests above and kubeconform, and the gateway configuration was checked with
  `envoy --mode validate` and request probes against envoy 1.39.1 during development.
  Treat the first install as a staging rehearsal.
- The device-code bootstrap route `/functions/v1/device-start` needs the trusted
  ingress signer (`deploy/ingress/device-start.mjs`) in front of it. The chart does not
  deploy the signer; without it the function rejects requests (fails closed) and agents
  must enroll with enrollment tokens instead.
- The readiness evidence worker, SIEM delivery and export-retention timers
  (`deploy/maintenance`) are not yet shipped as CronJobs.
- Storage with the `file` backend is a single replica on a `ReadWriteOnce` volume; use
  `storage.backend=s3` for more replicas.
- The storage-api and edge-runtime images run as root upstream; the chart runs them as
  UID 1000 with a read-only root filesystem and `/tmp` scratch space.
