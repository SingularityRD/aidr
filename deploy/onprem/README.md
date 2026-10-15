# AIDR on-prem installation

This is the entry point for running the AIDR control plane on a customer-owned
Linux host with Docker Compose. It covers one host. It does not provide
Kubernetes manifests, multi-host high availability or an availability SLA.
The detailed contracts it builds on are in [the installation guide](../README.md),
[the first-customer guide](../FIRST_CUSTOMER.md), [the upgrade runbook](../UPGRADE.md)
and [the backup runbook](../backup/README.md).

Endpoint protection works without this stack: connectors enforce locally by
default. The control plane adds identities, signed enrollment, remote policy,
telemetry and the dashboard.

## Requirements

- A 64-bit Linux host (x86_64 or arm64) with systemd.
- Docker Engine with the Compose plugin. Preparation output is validated with
  `docker compose config`; the reference check used Docker 29 with Compose v5.
- Node 24 on the host (the doctor, migration, backup and TLS tools run there).
- A verified customer kit or a built repository checkout (`pnpm build`).
- The artifact-verification public key from the independent release-signer channel.
- HTTPS origins for the dashboard and API, a TLS reverse proxy, SMTP settings
  and a backup target, as described in [the installation guide](../README.md).
- Optional AI Security Posture scanner: the scanner release data-signing RSA
  public key and its key id, plus the scanner sources in the release checkout.

## Sizing

Pick a resource profile with `--profile`. Each profile sets per-service CPU,
memory and PID limits and reservations from
[`resource-profile.json`](resource-profile.json). The figures are starting
budgets, not a capacity promise; size and validate the host with
[`RESOURCE_REQUIREMENTS.md`](../RESOURCE_REQUIREMENTS.md) and your own load
and soak runs.

| Profile | Intended use | Host starting point | Add for `--with-posture-scanner` |
| --- | --- | --- | --- |
| `small` (default) | Pilot, up to roughly 100 endpoints | 4 vCPU, 8 GiB RAM, 100 GiB SSD | 4 vCPU, 6 GiB, 40 GiB |
| `medium` | Load-test start for roughly 1,000 endpoints | 8 vCPU, 16 GiB RAM, 250 GiB SSD | 6 vCPU, 8 GiB, 60 GiB |
| `large` | Dedicated host for multi-thousand endpoint tests | 16 vCPU, 32 GiB RAM, 500 GiB SSD | 8 vCPU, 12 GiB, 100 GiB |

The profile is fixed when the installation is prepared. To change it later,
edit the `deploy.resources` blocks in `compose.yml` during a maintenance
window, or prepare the target in a new directory during an upgrade.

## Install

Run from the verified kit or built repository root on the deployment host:

```sh
node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr --profile small --region self-hosted --tenant-region self-hosted --dashboard-url https://aidr.customer.example --supabase-url https://api.aidr.customer.example --artifact-verification-public-key-file /secure-delivery/aidr-artifact-signing-public.pem --telemetry-queue-root /var/lib/aidr-telemetry --offline-policy keep_enforcing_local
docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml config --quiet
docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d --build
node scripts/deployment-migrate.mjs /srv/aidr
node scripts/deployment-doctor.mjs --deployment /srv/aidr --online
```

The doctor fails until the TLS ingress, the device-start signer, the evidence
and backup timers and the first account are in place. Complete those steps from
[the installation guide](../README.md) and [the first-customer guide](../FIRST_CUSTOMER.md),
then rerun the doctor. A running container is not acceptance.

Preparation writes, into a private `0700` directory:

- `compose.yml`: the pinned Supabase baseline plus the dashboard
  (`image: aidr-dashboard:<version>`, built from `dashboard/`), merged with
  [`compose.onprem.overlay.yml`](compose.onprem.overlay.yml) (restart policy,
  compressed log rotation, extra health checks and stop grace periods) and the
  selected resource profile.
- `.env`, `.env.functions`, `.env.readiness`, `.env.ingress` (mode `0600`):
  every variable is described in the
  [configuration reference](../../docs/operations/onprem-config-reference.md);
  [`.env.onprem.example`](.env.onprem.example) is the secret-free annotated
  version. Regenerate both with `pnpm onprem:config-reference`; CI-style drift
  checking is `pnpm verify:onprem-config-reference`.
- `deployment.json`: the prepared manifest, including `resource_profile`,
  `dashboard_image` and the `posture_scanner` block.

### Supabase Studio (operator-only)

Supabase Studio is a database administration tool, not part of the API, so it is
not reachable from the public API host. Preparation moves the Studio routes off
the gateway listener that the ingress proxies (`127.0.0.1:8000`, which now ends
in a `404`) onto a separate gateway listener published on loopback only:
`127.0.0.1:8001` (with `--development`, the API port plus one). Studio keeps its
HTTP basic-auth prompt there (`DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` in
`.env`) and its MCP endpoints stay denied. The reference ingress configs proxy
only the API prefixes and never port `8001`; do not add an ingress or firewall
rule for it.

Reach Studio from an administrator workstation through an SSH tunnel to the
host, then open `http://127.0.0.1:8001` locally:

```sh
ssh -N -L 8001:127.0.0.1:8001 admin@aidr-host.customer.example
```

Close the tunnel when finished. Studio holds the database superuser
credentials, so treat a tunnel to it like database console access. The Helm
chart does not deploy Studio at all.

### Optional AI Security Posture scanner

Add these options to the preparation command:

```sh
--with-posture-scanner --posture-scanner-signing-public-key-file /secure-delivery/posture-scanner-release-public.pem --posture-scanner-signing-key-id <release-key-id>
```

This merges `docker-compose.posture-scanner.yml` into `compose.yml` under the
`posture-scanner` Compose profile (enabled by `COMPOSE_PROFILES=posture-scanner`
in `.env`), stages the build contexts under `posture-scanner/`, generates the
worker secret and bridge API key, and pins the data-signing key fingerprint,
bundle id and source commit as `POSTURE_SCANNER_*` settings. Single-host
defaults apply: a durable SQLite task registry with HA not required, and the
bridge published on `127.0.0.1:8099` only. The scanner's Compose services
(`aig-server`, `aig-agent`, `aig-bridge`, `aig-egress`) and volumes keep their
names across releases so scan state survives upgrades.

Remote scan traffic leaves only through the `aig-egress` service, a pinned
Ubuntu Squid gateway that denies everything by default. Add the domains the
customer has authorized for scanning to
`/srv/aidr/posture-scanner/egress/allowlist.txt`, then run
`docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml restart aig-egress`.
Destinations that resolve to loopback, link-local, private, CGNAT, multicast
or reserved addresses are refused even when listed. The scanner server and
worker sit on an internal network with no route out.

We ship the gateway rather than asking the operator to supply one because an
unconfigured proxy setting either blocks every scan or tempts a direct route
out. The shipped gateway keeps the default closed (empty allowlist) while
giving operators a reviewed, single-file way to open specific destinations.

The committed scanner data manifest is unsigned. The bridge therefore reports
not-ready, and the doctor fails its signature check, until a release-signed
manifest and matching public key are deployed. For multi-replica HA, switch to
the PostgreSQL registry as described in `.env.posture-scanner.example`.

Installations prepared by earlier releases keep working: their `.env`
settings are still read as fallbacks, and the doctor still checks their
staging directory and Compose profile.

### Optional privacy gateway

`--with-privacy-gateway` adds `aidr-privacy-service` as the `privacy-gateway`
Compose service under the `privacy-gateway` profile. It is an explicit egress
API (`POST /v1/egress` over mutual TLS), **not a transparent proxy**: it protects
only the clients configured to call it, so direct provider access must be
blocked separately. Preparation refuses it without mutual TLS material, the
operator's service configuration, secret and trust files, an approved NER model
whose manifest matches its digest, and an IPv4 egress allow-list; it generates
no gateway credential. The service is not started by `docker compose up`, runs
non-root on a read-only root filesystem on its own bridge network, reads its
secrets as Compose secret files, and gets the `privacy-gateway` budget of the
selected resource profile (add 2 vCPU/4 GiB on `small`, 4 vCPU/6 GiB on
`medium`, 8 vCPU/8 GiB on `large`). Docker does not filter container egress:
apply the prepared `privacy-gateway/egress-firewall.sh` before starting it. See
[the privacy gateway guide](../privacy-gateway/README.md) for the inputs,
the start commands and what the gateway does and does not do.

### Optional single sign-on with an internal identity provider

Tenant owners connect Keycloak, ADFS or another OIDC provider in the dashboard;
users can be created at first sign-in (just-in-time provisioning) without SCIM,
and Active Directory is connected through Keycloak user federation. When the
identity provider uses an internal CA or a private address, prepare with
`--idp-ca-file <pem>` (the CA is added to the public roots of the functions
runtime and mounted read-only) and `--oidc-internal-idp-hosts host[:port],...`
(only those exact names may resolve to private addresses). `--with-saml` turns
on SAML in GoTrue and generates its signing key on this host. Set
`AIDR_OIDC_SSO=true` in `.env` to show the SSO form on the sign-in page. See
[the on-prem SSO runbook](../../docs/operations/onprem-sso.md)
([Türkçe](../../docs/operations/onprem-sso.tr.md)) for the Keycloak, ADFS and
LDAP steps.

## Upgrade

Prepare the new release in a new directory (never over `/srv/aidr`), then run one
command from the new release's kit:

```sh
pnpm onprem:upgrade --to /srv/aidr-target --dry-run   # the plan; changes nothing
pnpm onprem:upgrade --to /srv/aidr-target
```

It checks that the release fits, takes and verifies an encrypted backup, runs the
preflight, applies the database changes in one transaction, starts the new version,
runs the doctor and the post-upgrade checks, and stops at the first failure with the
exact next step. It reads the compatibility contract from
`/secure/aidr-upgrade/upgrade-compatibility.json` and the backup key from
`/secure/aidr-recovery.key` unless you pass `--contract` and `--key-file`. Step by
step, what to do when it stops, and the Turkish version:
[docs/operations/onprem-upgrade.md](../../docs/operations/onprem-upgrade.md). The
contracts behind each step are in [the upgrade runbook](../UPGRADE.md).

The upgrade tool does not carry the posture scanner's staged build contexts.
When the current installation runs the scanner and the target was prepared
with `--with-posture-scanner`, copy the target's `posture-scanner/` directory
into `/srv/aidr` and set `COMPOSE_PROFILES=posture-scanner` in `/srv/aidr/.env`
before restarting; the doctor's profile check fails until you do. The same
applies to the privacy gateway: copy the target's `privacy-gateway/` directory
(image context, configuration, trust and secret files) into `/srv/aidr` and
rebuild with `--profile privacy-gateway`. Its state volume
(`<project>_aidr-privacy-state`) is not part of the AIDR backup either.

## Backup

Use `scripts/deployment-backup.mjs` and the offsite timer from
[the backup runbook](../backup/README.md). It covers the database and storage
volumes, and a restore drill must pass before customer data is accepted.
Posture scanner state (`<project>_aig-db`, `<project>_aig-bridge-state`,
`<project>_aig-uploads`) is not part of that backup. Snapshot those volumes
separately while the scanner is stopped if scan history must survive a host loss.

## Air-gapped hosts

For one signed transfer that carries the images, the latest signed intel packs,
the desktop installers with their signed catalog and the Browser Guard update
files, use `scripts/onprem-offline-bundle.mjs` (`build` on the connected staging
host, `verify` and `import` on the disconnected one); see
[the air-gap section of the upgrade guide](../../docs/operations/onprem-upgrade.md#disconnected-air-gapped-hosts-one-bundle).
The images alone can still be bundled directly as below.

On a connected staging host with the same release, prepare the installation,
build the local images, then bundle every image the stack needs:

```sh
docker compose --project-directory .aidr-deploy -f .aidr-deploy/compose.yml build
node scripts/build-airgap-images.mjs --compose .aidr-deploy/compose.yml --output .aidr-airgap --platform linux/amd64
```

The bundle contains the registry images, the locally built
`aidr-dashboard` (and, with the posture scanner, `aidr-aig-*`) images, and the Dockerfile
`FROM` base images of every `build:` service, so the disconnected host can
run or rebuild offline. Verify, load and start it as described in the
[air-gap section](../README.md#disconnected-air-gapped-installation). Use the
containerd image store on the disconnected host so digest-pinned base images
keep their digests after `docker load`.

## Uninstall

1. Take and verify a final encrypted backup, and complete tenant offboarding if
   data must be deleted (`scripts/deployment-offboarding.mjs`).
2. Disable the host units: `systemctl disable --now aidr-siem-delivery.timer aidr-backup-offsite.timer aidr-restore-drill.timer aidr-export-retention.timer aidr-tls-renew.timer`,
   and the device-start signer service if you installed it from `ingress/aidr-device-start.service.reference`.
3. Stop the stack: `docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml down`.
4. Delete data only after the retention decision is recorded:
   `docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml down --volumes`,
   then securely remove `/srv/aidr`, which holds the private key material.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `docker compose config` fails with `required variable ... is missing` | Run commands with `--project-directory /srv/aidr` so Compose reads `/srv/aidr/.env`. |
| A container restarts with exit code 137 | It hit its memory limit. Move to a larger `--profile` or raise that service's `deploy.resources.limits.memory`. |
| Dashboard stays `unhealthy` | Production health is `/readyz`. It stays unhealthy until the signing, queue, backup and TLS evidence exists (`/srv/aidr/health`). |
| `meta` is `unhealthy` | The overlay probes TCP 8080 inside the container; check `docker compose logs meta` and the database health. |
| `aig-bridge` is `unhealthy` | The public `/api/v1/readyz` only answers ready/not-ready. The authenticated `curl -s -H "Authorization: Bearer $AIG_BRIDGE_API_KEY" http://127.0.0.1:8099/api/v1/health` names the failing gate: dataset signature, worker, registry or egress. |
| Remote posture scans fail | The destination is missing from `posture-scanner/egress/allowlist.txt` or resolves to a non-public address; check `docker compose logs aig-egress`. |
| Doctor reports `UNVERIFIED` | The host scheduler or Docker could not be inspected from that shell; UNVERIFIED is never a pass. |
| Logs fill the disk | Each container keeps at most 5 compressed 20 MiB files; check other writers under `/var/lib/docker`. |
