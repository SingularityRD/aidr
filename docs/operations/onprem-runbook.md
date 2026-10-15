# On-prem runbook: from empty host to accepted installation

One page, in order, for the customer's operator and the SingularityRD
installation engineer. Each step links to the detailed reference instead of
repeating it. Do the steps in this order; do not skip the checks.

The product control plane, for on-prem and for the hosted service alike, is the
Supabase stack and the Vite dashboard in this repository (`supabase/`,
`packages/dashboard`, `deploy/`). The marketing website and the vendor `/admin`
panel are separate SingularityRD systems and are not installed at the customer.

> **Status.** The tooling below is implemented and tested in this repository.
> No signed customer release exists yet, and a prepared stack is not
> production acceptance ([first-customer readiness](../production-readiness/first-customer-ready.md)).

Türkçe kısa sürüm: [ilk müşteri kurulum ve kabul kılavuzu](../../deploy/FIRST_CUSTOMER.md).

## Choose the topology

| Topology | When | Reference |
|---|---|---|
| Docker Compose, one Linux host | Pilot, POC, up to roughly 1,000 endpoints on the `medium` profile after your own load test | [deploy/onprem/README.md](../../deploy/onprem/README.md) |
| Kubernetes with the Helm chart | The customer runs Kubernetes and wants chart-managed upgrades; external HA Postgres recommended. The chart is lint- and template-checked but has not yet been installed on a live cluster | [Running AIDR on Kubernetes](kubernetes.md), [`deploy/helm/aidr`](../../deploy/helm/aidr/README.md) |
| Either, air-gapped | No route to the internet from the control plane or endpoints | [Air-gapped hosts](../../deploy/onprem/README.md#air-gapped-hosts) |

The control plane always runs on **Linux**. Endpoints are Windows 10/11 x64
and Linux. Every command in this runbook runs on the Linux control-plane host
unless the step says "endpoint".

## Prerequisites checklist

Collect these before the installation day:

- [ ] Host sized from [`RESOURCE_REQUIREMENTS.md`](../../deploy/RESOURCE_REQUIREMENTS.md)
      (`small`: 4 vCPU, 8 GiB RAM, 100 GiB SSD), 64-bit Linux with systemd,
      Docker Engine with the Compose plugin, Node 24.
- [ ] Two DNS names, for example `console.aidr.example.internal` (dashboard) and
      `api.aidr.example.internal` (API), resolvable from every endpoint.
- [ ] TLS certificates for both names (see [TLS](#tls-public-ca-or-internal-ca)).
- [ ] Time synchronisation on the host and endpoints (see [Time synchronisation](#time-synchronisation)).
- [ ] Firewall: endpoints → host TCP 443 only. Host → internet: nothing
      required for an air-gapped install; otherwise the destinations the
      customer approves (image registry during install, ACME, SMTP, IdP, backup
      target). Supabase Studio stays on loopback (`127.0.0.1:8001`).
- [ ] SMTP relay (internal is fine) for invitations, recovery and alerts.
- [ ] Backup target independent of the host (NFS/SMB share, S3-compatible
      object store) and a second host for the restore drill.
- [ ] Identity provider details if SSO is wanted (SAML or OIDC metadata, SCIM).
- [ ] From SingularityRD over the agreed secure channel: the signed customer
      kit, the release verification public key, the licence public-key
      registry for the release, and the signed licence file.

## Time synchronisation

AIDR checks time in many places: licence `not_before` / `expires_at` and grace,
enrollment codes and device sessions, approval tokens, signed policy and pack
expiry, audit-chain epochs and TLS certificates. A clock that is minutes off
produces rejections that look like product faults.

Requirements:

- The control-plane host and every endpoint synchronise to the **same** NTP
  source hierarchy (the customer's internal NTP servers or domain controllers).
- Offset within 60 seconds; the endpoint doctor warns above 60 seconds and
  fails above 300 seconds.

| Where | Configure | Check |
|---|---|---|
| Linux host / Linux endpoints | `chrony` or `systemd-timesyncd` pointed at the internal NTP servers | `timedatectl` shows `System clock synchronized: yes`; `chronyc tracking` |
| Windows endpoints (domain) | Domain hierarchy (default for domain members); PDC emulator syncs to the internal NTP source | `w32tm /query /status` |
| Windows endpoints (workgroup) | `w32tm /config /manualpeerlist:"ntp.example.internal" /syncfromflags:manual /update` | `w32tm /stripchart /computer:ntp.example.internal /samples:3` |
| Kubernetes | Nodes synchronised by the platform | Node clock offset metric |
| Containers | Use the host clock; nothing to configure | — |

On each managed endpoint `aidr doctor` compares the local clock with the
control plane's HTTP `Date` header and reports the offset (it makes no network
call in local mode). Add the doctor's JSON output to fleet health checks.

## TLS: public CA or internal CA

The stack binds to loopback; an nginx ingress terminates TLS
([ingress README](../../deploy/ingress/README.md)).

**Internal CA (usual for enterprise and air-gapped networks).**

1. Issue server certificates for both names from the internal CA (full chain).
2. Install them with
   `node scripts/deployment-tls-renew.mjs --mode static --hostname <name> --cert-file <fullchain.pem> --key-file <key.pem>`,
   once per name. It validates chain, name, validity margin and key match,
   installs under `/etc/aidr/tls/live/<name>/` and reloads nginx only after
   `nginx -t` passes ([on-prem ingress](../../deploy/ingress/README.md#on-prem-ingress-with-customer-supplied-certificates)).
3. Use `deploy/ingress/nginx.onprem.reference.conf` as the vhost template.
4. Make every endpoint trust the internal root: Windows through GPO/Intune
   (Trusted Root Certification Authorities), Linux through the distribution
   trust store (`update-ca-certificates` / `update-ca-trust`). AIDR's Node
   runtime does not read the OS store by default: point it at the root with
   the machine policy `ca_file` key on releases that support machine policy,
   otherwise set the system-wide environment variable
   `NODE_EXTRA_CA_CERTS=<path to the root PEM>`.
5. Repeat step 2 before the certificate expires; put the expiry in the
   monitoring calendar.

**Public CA (names reachable from the internet).** Use the prepared ACME
renewal units (`ingress/aidr-tls-renew.service` and `.timer`) with Certbot as
described in [public TLS renewal](../../deploy/ingress/README.md#public-tls-renewal).

## Install the control plane

1. Verify the customer kit with the independently delivered verifier and
   extract it into a new directory ([FIRST_CUSTOMER.md](../../deploy/FIRST_CUSTOMER.md)).
2. Install the licence public-key registry delivered for the release over
   `deploy/onprem/license-public-keys.json` and compare its SHA-256 with the
   release notes.
3. Prepare, start and migrate:

   ```sh
   node scripts/deployment-prepare.mjs --mode self-hosted --output /srv/aidr --profile small --region self-hosted --tenant-region self-hosted --dashboard-url https://console.aidr.example.internal --supabase-url https://api.aidr.example.internal --artifact-verification-public-key-file /secure-delivery/aidr-artifact-signing-public.pem --telemetry-queue-root /var/lib/aidr-telemetry
   docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml config --quiet
   docker compose --project-directory /srv/aidr -f /srv/aidr/compose.yml up -d --build
   node scripts/deployment-migrate.mjs /srv/aidr
   ```

   Air-gapped: verify and import the signed offline bundle first
   (`node scripts/onprem-offline-bundle.mjs verify`, then `import`; see
   [the air-gap section](onprem-upgrade.md#disconnected-air-gapped-hosts-one-bundle)),
   then start with `docker compose ... up -d` so that only the loaded images
   are used.
4. Ingress and the device-start signer: configure nginx from the reference
   configs and start the signer service as described in
   [FIRST_CUSTOMER.md](../../deploy/FIRST_CUSTOMER.md) and the
   [ingress README](../../deploy/ingress/README.md). `/functions/v1/device-start`
   must go only to the local signer.
5. Configure SMTP in `/srv/aidr/.env` ([configuration reference](onprem-config-reference.md))
   and recreate the affected services.

## First administrator and licence

```sh
node scripts/license-verify.mjs --license-file /secure-delivery/aidr-license.json
node scripts/deployment-bootstrap.mjs --deployment /srv/aidr --email owner@customer.example --license-file /secure-delivery/aidr-license.json
```

The password is read from stdin ([licensing](licensing.md)). Sign in at the
console URL and enable MFA for the owner account.

## Identity

Optional but recommended: SAML or OIDC sign-in and SCIM provisioning
([OIDC SSO](../production-readiness/oidc-sso-admin.md),
[SCIM](../production-readiness/scim-directory-admin.md)). Test one join, one
role change and one leave before enrolling endpoints at scale; leavers are
handled by the [offboarding runbook](../runbooks/offboarding-and-device-swap.md).

## Endpoints

1. Pilot ring (5–10 devices): install the MSI / `.deb` / `.rpm`
   ([desktop installers](../installation/desktop-installers.md)) with the
   company page values or the managed deployment properties, then on each
   device `aidr doctor` (all lines ✓, including the clock line) and
   `aidr verify`.
2. Special environments (VDI, devcontainers, Remote-SSH, WSL, CI runners):
   [install recipes](../installation/special-environments.md).
3. Browser Guard through browser enterprise policy
   ([Browser Guard enterprise](../installation/browser-guard-enterprise.md)).
4. Inform employees before the wide rollout: publish the
   [notice template](../legal/kvkk-aydinlatma-metni-calisan.tr.md) and set
   `privacy_notice_url` ([KVKK guide](kvkk.md)).
5. Roll out in rings; watch false positives and the Agents page between rings.

## Backup and restore drill

Install the offsite backup timer and the restore-drill timer
([backup runbook](../../deploy/backup/README.md)). A restore drill on a second
host must pass before customer data is accepted. Posture-scanner and
privacy-gateway volumes are not part of the AIDR backup.

## Monitoring

Scrape and alert with the shipped Prometheus rules
([monitoring](../../deploy/monitoring/README.md)). At minimum alert on: dashboard
`/readyz`, database health, backup age, restore-drill result, TLS certificate
expiry, licence expiry, disk space and host clock offset (node exporter
`node_timex_offset_seconds`).

## Acceptance

Run and keep the outputs with the installation record:

- `node scripts/deployment-doctor.mjs --deployment /srv/aidr --online` passes and
  `/readyz` is healthy.
- `aidr doctor` and `aidr verify` pass on every pilot endpoint.
- A synthetic `deny` and a synthetic `ask` appear in the dashboard; the `ask`
  is approved by an approver and the developer's retry succeeds.
- Audit export works; SIEM delivery (if used) shows the events.
- Restore drill passed on the second host.
- The customer's security officer signs the acceptance record.

## Day-2 operations

| Task | Reference |
|---|---|
| Upgrade | [onprem-upgrade.md](onprem-upgrade.md) ([Türkçe](onprem-upgrade.tr.md)) |
| Licence renewal and seat changes | [licensing.md](licensing.md#renewal-seat-changes-and-importing-a-signed-license) |
| Leaver or device swap | [offboarding runbook](../runbooks/offboarding-and-device-swap.md) |
| Retention presets, VERBİS, DPIA | [KVKK guide](kvkk.md) |
| Support case and support bundle | [support process](../runbooks/support-process.md) |
| Uninstall | [deploy/onprem/README.md](../../deploy/onprem/README.md#uninstall) |
