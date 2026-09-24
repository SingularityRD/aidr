# Install and verify AIDR

This repository prepares both a customer-owned self-hosted control plane and a
cloud deployment using a managed Supabase project. Local protection runs at the
agent hook boundary. The dashboard/control plane supplies identities, telemetry,
signed enrollment and runtime policy. Preparation is not production acceptance.

## Prerequisites

- Node 24, pnpm 10.29.3 and Git on the build machine.
- Docker Compose v2 with sufficient memory/disk for the Supabase stack for self-hosting.
- The reviewed upstream Docker baseline is Supabase `self-hosted/v0.8.1`, commit
  `8c7a4d9dbbaf8b552893822e89d7bf06f33f9220`.
- Production requires dashboard/API HTTPS origins, a TLS reverse proxy, approved
  SMTP/identity-provider settings, signing-key custody and backup/restore procedures.
  Ports are bound to loopback so a customer ingress is configured explicitly.

The current Docker baseline is a single host. Multi-region placement and an
availability SLA require additional infrastructure and evidence. Follow the
[upstream self-hosting guidance](https://supabase.com/docs/guides/self-hosting/docker)
alongside the generated, pinned configuration.

## Self-hosted installation

The [on-prem guide](onprem/README.md) is the short entry point for a customer
host: sizing profiles (`--profile small|medium|large`), the optional AIG
scanning sidecar (`--with-aig`), upgrade, backup, uninstall and troubleshooting.

Build from the repository root on the release machine (skip this step when
using an already built, independently verified customer kit):

```powershell
pnpm install --frozen-lockfile
pnpm build
```

On the Linux deployment host, run the following from the reviewed kit or built
repository root. The prepared systemd units use `/srv/aidr`, so do not
substitute a different production output path without updating those units and
their environment files:

```sh
node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr --region self-hosted --tenant-region self-hosted --dashboard-url https://aidr.customer.example --supabase-url https://api.aidr.customer.example --artifact-verification-public-key-file /secure-delivery/aidr-artifact-signing-public.pem --telemetry-queue-root /var/lib/aidr-telemetry
docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml config --quiet
docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d --build
node scripts/deployment-migrate.mjs /srv/aidr
```

Do not use `docker compose up --wait` during first boot. The dashboard's
production health check is `/readyz`, which must remain unhealthy until the
signing, durable queue, offsite backup and TLS evidence workers are configured
and have run. Install those workers and the ingress as described below and in
the [first-customer guide](FIRST_CUSTOMER.md), then run `node scripts/deployment-doctor.mjs --deployment
/srv/aidr --online` and require a successful `/readyz` response. A running
container or a passing `/livez` response is not deployment acceptance.

`--telemetry-queue-root` must be a real target-host queue root populated by the
authenticated fleet aggregator, not a directory created to satisfy the gate.
The systemd installer requires at least one 64-hex queue namespace and runs the
evidence worker successfully before it enables the timer.

The generator refuses an existing destination. Preserve that directory and its
secrets for restarts; rerunning preparation is not an upgrade. Migrations check
SHA-256 against the manifest, acquire an advisory lock and apply atomically.
Repeated application skips only identical migrations. Do not change an already
applied migration; add a new migration. Customer upgrades need a tested backup
and restore before applying a new candidate.

The output includes `compose.yml`, private `.env` and `.env.functions`, built
dashboard assets, Edge Functions, migrations, `agent-config.json` and
`deployment.json`. The browser receives only the public URL and anonymous key.
Keep service-role, JWT, signing and database secrets out of browser builds and
source control. On Windows, enforce private directory ACLs through deployment
tooling; POSIX file-mode arguments alone do not set Windows ACLs.
The artifact verification public key must arrive through the independent release
signer channel. Preparation validates and copies only that public key into
`agent-config.json`; it never generates one or reuses the entitlement key.

Configure SMTP and approved OAuth providers, provision the first account and
its tenant/entitlement, configure the invoice sales destination and perform
onboarding before inviting customers. Signup is disabled in the generated
self-hosted baseline. Team invitations create manually shared, expiring links;
the application does not claim to send invitation emails.

The first account is provisioned with the vendor-signed license:
`node scripts/deployment-bootstrap.mjs --deployment /srv/aidr --email
owner@customer.example --license-file /secure-delivery/aidr-license.json`
(password on stdin). Seats, admission end and contract reference come from the
signed license, which is verified against `deploy/onprem/license-public-keys.json`
before any API call; the shipped registry is empty and refuses every license
until the vendor-published registry is installed. Typed terms are accepted only
with `--unsigned-license-for-pilot`. After expiry and grace, managed features
degrade while local detection keeps enforcing. See [licensing](../docs/operations/licensing.md).

## Isolated installation rehearsal

Use an empty destination and keep the stack isolated from customer data:

```powershell
node scripts/deployment-prepare.mjs --development --output .aidr-deploy --region self-hosted --tenant-region self-hosted
docker compose --project-directory .aidr-deploy -f .aidr-deploy/compose.yml up -d --wait --wait-timeout 180
node scripts/deployment-migrate.mjs .aidr-deploy
node scripts/deployment-smoke.mjs .aidr-deploy
```

Dashboard: `http://localhost:8080`; API: `http://localhost:8000`. `--development`
is restricted to loopback dashboard and Supabase URLs; public HTTPS endpoints
cannot use this mode to bypass production signing and telemetry requirements.
The smoke runner
rejects non-loopback or non-development deployments. It creates isolated fixture
users/teams, performs real HTTP/SQL authorization and enrollment flows, and passes
a tool call to the built hook evaluator. The canary command is never executed.
Fixtures remain for inspection. `smoke-evidence.json` contains results without
tokens; other files in this private deployment directory may contain fixture keys.

Stop only this Compose project with `docker compose --project-directory
.aidr-deploy -f .aidr-deploy/compose.yml down`. Keep volumes and secrets when
restarting. Do not use `down -v` on customer data.

## Cloud deployment preparation

For a limited Cloudflare Free pilot, see [the Cloudflare deployment path](cloudflare/README.md).
It serves the dashboard and fixed-origin Supabase API through one Worker; it
does not replace the PostgreSQL/Supabase backend or waive the live readiness
gates below. The standard cloud preparation flow in this section produces a
containerized dashboard and trusted ingress, not a Cloudflare deployment.

```powershell
pnpm build
node scripts/deployment-prepare.mjs --mode cloud --output .aidr-cloud --region managed-cloud --tenant-region managed-cloud --dashboard-url https://aidr.example.com --supabase-url https://api.aidr.example.com --device-start-upstream-url https://PROJECT.supabase.co/functions/v1/device-start --artifact-verification-public-key-file C:\secure-delivery\aidr-artifact-signing-public.pem --telemetry-queue-root /var/lib/aidr-telemetry
```

Use a provisioned managed Supabase project in the approved region. Declare that
region and its origin in `deploy/regions.manifest.json` first: replace the
placeholder residency location, set `residency.declared` to `true`, and set `supabase_url` to this installation's
public API proxy origin (`https://api.aidr.example.com` in the example), not the
managed project's origin. The device-start upstream is the separate provider
origin behind the trusted ingress signer; the public proxy must route only
`/functions/v1/device-start` through that signer. Preparation refuses an undeclared region, a region that still holds the
placeholder location, a declared endpoint that is not the `--supabase-url`
origin, and a tenant region that differs from the deployment region. Replace the
anonymous/service-role placeholders in `.env` with that project's keys, and set
`AIDR_DEVICE_START_ANON_KEY` in `.env.ingress` to the same project anonymous key.
Cloud preparation leaves this signer key unset; the deployment doctor fails its
cloud preflight until the real key is configured. Apply repository migrations
using the Supabase migration workflow for the selected project; the local Docker
migration script deliberately refuses cloud mode. Configure `AIDR_ALLOWED_ORIGINS`,
dashboard/verify URLs, the generated DER/PKCS8 signing secrets, premium pack key
and commercial settings from `.env.functions`. Deploy the canonical
`supabase/functions` directories with the per-function JWT settings from
`supabase/config.toml`; some native routes use their own API-key or device-token
authentication.

When premium pack delivery is enabled, `deployment-prepare` also generates a
random `AIDR_PACK_DOWNLOAD_GRANT_SECRET` in the private `.env.functions` file.
It also sets `AIDR_PUBLIC_API_ORIGIN` to the agent-reachable `--supabase-url`;
the internal `api-gw` address must never appear in a customer download URL.
That local file does not configure a managed project: install the same value as
a server-side Edge Function secret on both `packs-manifest` and `packs-download`
through the approved secret-entry process. Do not put it in dashboard `VITE_*`
variables or print it into shell history/logs. Self-hosted Compose reads the
generated value from `.env.functions`; keep that file restricted and preserve
the secret across upgrades. See [secret management](../docs/runbooks/secrets-management.md)
for rotation and handling.
The repository does not ship a provider-side signed canary endpoint: managed
cloud signing readiness remains failed until that endpoint and its live key
binding are implemented and accepted. The staged local secret file is not proof
of provider runtime state.

Cloud signup starts closed. The generated `.env` records `AIDR_SIGNUP_MODE=closed`
for the dashboard; it does not configure managed Supabase Auth. Before enabling
`cloud` signup, separately approve legal text and trial admission, enable signup
in the selected Auth project, then set `AIDR_SIGNUP_MODE=cloud` in `.env`. The
online deployment doctor compares the live dashboard mode and Auth signup
setting. A mismatch fails; a matching setting alone is not a legal or billing
acceptance receipt.

Build/start the generated dashboard Compose service behind the HTTPS ingress.
Configure project SMTP, OAuth redirects, region/retention policy, monitoring and
backup. Verify the same negative authorization and onboarding scenarios in a
separate staging project. This preparation command does not create a cloud
account, region, billing subscription or production deployment.

## Declared regions and TLS renewal

`deploy/regions.manifest.json` holds the regions an operator declares for an
installation: per-region `supabase_url` and a residency declaration (`declared: true`
plus `location`). The selected installation region must explicitly set `declared`
to `true` before preparation or the doctor can pass. This is an operator assertion,
not independent verification of actual provider location. The prepared `deployment.json` records `region`,
`tenant_region` and that declared `regions` block, and the doctor fails an
installation whose tenant and deployment regions do not match, whose region is
not declared, or whose residency location is still a placeholder. These fields
are operator declarations: they are not evidence of provider placement, a live
regional service, a signed data-processing agreement or a legal residency
property. The Docker baseline remains single-host; multi-region placement still
requires additional infrastructure and evidence.

The same output carries `ingress/aidr-tls-renew.service`,
`ingress/aidr-tls-renew.timer` and the renewal script. They are prepared, not
installed or enabled, and the doctor only asserts that both unit files are
present. Enable the timer on the TLS host with the private environment file
described in `deploy/ingress/README.md` so certificate renewal does not depend on
an operator remembering it.

On-prem and air-gapped hosts that cannot reach an ACME CA use customer-supplied
certificates. `deploy/ingress/nginx.onprem.reference.conf` is the reference
ingress with separate dashboard and API vhosts, HSTS and security headers, and
`node scripts/deployment-tls-renew.mjs --mode static --hostname <host> --cert-file
<fullchain.pem> --key-file <key.pem>` validates the chain, hostname, validity
margin and key match, installs the pair under `/etc/aidr/tls/live/<host>/` and
reloads nginx only after `nginx -t` passes (restoring the previous pair
otherwise). Run it once per vhost and again before each certificate expires.

## Endpoint connector installation

For a built or already-extracted Claude package, `--package-dir` must name the
directory containing that package's `package.json`, `dist/` and `resources/`.
The source-tree path below is not present in the extracted customer kit. For a
customer-kit install, first verify the outer envelope with the independent
release verifier, verify the extracted kit, and use the exact approved
`artifacts/aidr-claude-plugin-VERSION.tar.gz` archive. The included `START-HERE.md`
(source: `deploy/FIRST_CUSTOMER.md`) gives the extraction and first-install/update
steps. Use a new empty staging directory for every version; do not extract over
an earlier package.

```powershell
node scripts/endpoint-install.mjs --package-dir packages/claude-code --config .aidr-deploy/agent-config.json
```

The signed package requires `--config` with the independently provisioned
artifact-verification public key; the deployment-generated file shown above must
contain that key. Existing agent configuration is preserved; merge managed
settings explicitly when an endpoint already has configuration. `--home PATH`
supports an isolated installer rehearsal. On an endpoint, the first signed
install passes the separately provisioned `agent-config.json`; on an update,
omit `--config` so the installer uses the existing
`~/.singularity-aidr/config.json` rather than attempting to overwrite it. The
installer copies artifacts/resources to a stable digest directory, preserves
unrelated hooks, backs up changed settings, registers all tool events, and
requires a local deny canary before registration. Repeating it with the same
package does not duplicate hooks; installing a new approved package digest
switches the managed hook registrations while retaining the previous digest
directory. An already enabled AIDR marketplace plugin must be updated through
its plugin path to avoid duplicate invocation.

For Codex endpoints, deploy the same generated `agent-config.json` to
`~/.singularity-aidr/config.json` before registering `aidr-codex-hook`. Signed
commercial connector packages fail closed unless that configuration contains
the independently delivered artifact-verification public key. The release
signing private key is never copied to an endpoint.

Restart Claude and complete an actual host canary. `aidr status --json` reports
local rule/configuration checks and registration evidence; it cannot attest that
the agent host invokes the hook. Other connector delivery paths are documented
in `packages/codex/README.md`, `packages/openclaw/README.md`,
`packages/opencode/README.md`, `packages/sdk/README.md` and the editor platform
guides. A universal MDM installer is still open.

## Policy, MCP and infrastructure operations

- Publish runtime JSON controls in the team policy page. YAML documents remain
  versioned drafts. Only supported fields can be published; stale writes return
  409. Publication does not confirm fleet adoption.
- `aidr discover --json` returns local MCP sources, sanitized server identities,
  risk hints and configuration fingerprints. Invalid explicitly supplied
  configurations produce a non-success exit.
- `aidr scan --target http://127.0.0.1:PORT --save-report PATH --json` persists an
  infrastructure assessment. Enable `policy.ai_infrastructure` with explicit
  target origins/report path to enforce confirmed critical CVEs; stale or missing
  reports require review by default. A successful HTTP response with a failed
  probe is incomplete, not a clean scan.
- Audit exports use private downloads valid for 60 seconds. Each response
  contains up to 500 rows and returns a signed `next_cursor` for the next page;
  follow it until `complete` is true. Storage cleanup remains a required
  operational follow-up.

## Disconnected (air-gapped) installation

The self-hosted control plane needs container images, and a disconnected host
cannot pull them. `scripts/build-airgap-images.mjs` turns a prepared compose file
into `docker save` tarballs plus a digest manifest; `--verify` re-checks the
transferred bundle offline and never contacts a registry or the Docker daemon.
Connector/CLI dependencies are already vendored into the customer kit
(`deploy/vendor`, produced by `scripts/customer-kit.mjs`), and the Linux endpoint
connector has its own signed offline fleet bundle
(`deploy/fleet/linux/build-offline-bundle.sh`); the image bundle covers the
remaining gap.

On the connected staging host (network plus a running Docker daemon):

```powershell
pnpm build
node scripts/deployment-prepare.mjs --mode self-hosted --output .aidr-deploy --region self-hosted --tenant-region self-hosted --dashboard-url https://aidr.customer.example --supabase-url https://api.aidr.customer.example --artifact-verification-public-key-file C:\secure-delivery\aidr-artifact-signing-public.pem --telemetry-queue-root /var/lib/aidr-telemetry
docker compose --project-directory .aidr-deploy -f .aidr-deploy/compose.yml build
node scripts/build-airgap-images.mjs --compose .aidr-deploy/compose.yml --output .aidr-airgap --platform linux/amd64
```

`--compose` reads every `image:` reference from the prepared stack and, for
each `build:` service, the `FROM` base images of its Dockerfile (stage aliases
and `scratch` excluded, `ARG` defaults and build args substituted), so the
disconnected host can rebuild offline. A service with both `build:` and
`image:` (the `aidr-dashboard:<version>` image, and `aidr-aig-*` with
`--with-aig`) is a local build: it is never pulled, must already exist from the
`docker compose build` step, and is saved into the bundle. See the
[on-prem sizing and AIG guide](onprem/README.md). `--plan
<json>` (a `{ "images": [{ "ref": "...", "digest": "sha256:..." }] }` document) or
repeated `--images <ref>` are the alternatives when no compose file is available.
Pinned digests are enforced when supplied. Every `docker save` output is hashed,
and `.aidr-airgap/aidr-airgap-images.manifest.json` is written only after all
images were saved and hashed. If Docker or its daemon is unavailable the command
exits non-zero before writing anything and never reports a bundle it did not
produce. The recorded digests mirror what the staging host pulled; they are not
registry publication and not a publisher identity.

Transfer the whole `.aidr-airgap` directory together with the signed release or
customer kit on the customer-approved media. On the disconnected host:

```powershell
node scripts/build-airgap-images.mjs --verify --compose .aidr-deploy/compose.yml --output .aidr-airgap
# repeat for every entry in aidr-airgap-images.manifest.json:
docker load -i .aidr-airgap/tarballs/<name>.tar
docker compose --project-directory .aidr-deploy -f .aidr-deploy/compose.yml up -d
node scripts/deployment-migrate.mjs .aidr-deploy
```

As with a connected production first boot, do not wait for `/readyz` before
installing the evidence workers, TLS ingress and offsite backup. After those
are active, require `node scripts/deployment-doctor.mjs --deployment
.aidr-deploy --online` to pass; the offline image check alone is not readiness.

`--verify` needs neither network nor Docker: it fails on a missing tarball, a
size or SHA-256 mismatch, a manifest entry that is not a regular file, or an
image set that does not exactly match the supplied plan. Keep the manifest and
tarballs together — a digest list without its bytes proves nothing. This
procedure is delivery media integrity and plan completeness only; notarization,
MDM distribution, registry publication and publisher key custody remain external
and are not claimed here.

Threat-intelligence packs reach a disconnected installation on the same approved
media. `node scripts/import-offline-pack.mjs` verifies the vendor-signed pack
(manifest signature, file hashes, expiry, rollback) before installing it into an
endpoint packs directory or the private `aidr-packs` bucket of this deployment;
see [air-gapped updates](../docs/operations/threat-sync.md#air-gapped-updates).
The license for a disconnected installation is the same signed file described in
[licensing](../docs/operations/licensing.md).

## Release boundary

Run `pnpm quality:static`, `pnpm check`, `pnpm test:ci`,
`pnpm verify:enforcement`, `node scripts/verify-codex-hook.mjs` and package release
gates for the exact candidate. A signed commercial build additionally requires
the existing release-signing environment and candidate evidence. Do not replace
those keys with development keys to obtain a green production result.

The complete capability gaps are in [FEATURE_INVENTORY.md](../FEATURE_INVENTORY.md).
Commercial/customer approvals remain in the existing
[evidence registry](../docs/production-readiness/commercial-go-evidence-registry.json).
