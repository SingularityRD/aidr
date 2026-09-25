# On-premises deployment

In the on-prem option the customer operates the AIDR control plane in its own
environment: the Supabase stack (Postgres, auth, storage, Edge Functions), the
dashboard and, optionally, the AI Infra Guard (AIG) scanning stack. Agent connectors
and Browser Guard enforce on endpoints exactly as in the cloud option; they point at
the customer's control plane instead of the hosted one.

> **Status.** Self-hosted preparation, migration, backup/restore and doctor tooling
> are implemented and tested in this repository. A customer deployment still needs
> the FCR-03/06 rehearsal, a signed candidate and customer acceptance described in
> [first-customer-ready.md](../production-readiness/first-customer-ready.md).
> Preparing a stack is not production acceptance.

## Topologies

| Topology | Use when | Primary reference |
| --- | --- | --- |
| **Docker Compose, single host** | Evaluation or smaller installations | [deploy/README.md](../../deploy/README.md), [deploy/onprem/README.md](../../deploy/onprem/README.md) |
| **Kubernetes (Helm)** | The customer runs Kubernetes and wants chart-managed upgrades | Helm chart under `deploy/helm/`, [docs/operations/kubernetes.md](../operations/kubernetes.md) |
| **Air-gapped** | No internet access from the control plane or endpoints | [deploy/README.md](../../deploy/README.md) "Disconnected (air-gapped) installation" and [deploy/onprem/README.md](../../deploy/onprem/README.md) |

Sizing starts from [deploy/RESOURCE_REQUIREMENTS.md](../../deploy/RESOURCE_REQUIREMENTS.md).
The first-customer installation and acceptance checklist is
[deploy/FIRST_CUSTOMER.md](../../deploy/FIRST_CUSTOMER.md).

## Docker Compose

`scripts/deployment-prepare.mjs --mode self-hosted` generates the stack from the
reviewed upstream Supabase self-hosted baseline (`v0.8.1`, pinned by commit) and adds
the dashboard. The output directory holds `compose.yml`, private `.env` and
`.env.functions`, built dashboard assets, Edge Functions, migrations,
`agent-config.json` and `deployment.json`. Ports bind to loopback, so the customer's
TLS ingress is configured explicitly. The browser receives only the public URL and
anonymous key.

Lifecycle scripts cover the rest of the operation: `deployment-migrate` (checksummed,
locked, atomic migrations), `deployment-bootstrap` (first tenant and entitlement),
`deployment-doctor` (online readiness), `deployment-backup`, `deployment-backup-offsite`,
`deployment-restore-drill`, `deployment-upgrade`, `deployment-maintenance`,
`deployment-tls-renew` and `deployment-offboarding`. The dashboard's `/readyz` stays
unhealthy until signing, the durable telemetry queue, offsite backup and TLS evidence
are configured; a passing `/livez` alone is not acceptance.

The AI Security Posture scanner (`docker-compose.posture-scanner.yml`: scanner server, worker and bridge) is a
separate, optional stack.

## Kubernetes (Helm)

The Helm chart packages the same control plane for Kubernetes. Validate a rendered
release with `pnpm verify:helm` and follow
[docs/operations/kubernetes.md](../operations/kubernetes.md) for values, secrets,
ingress/TLS, storage classes and upgrade order. Database migrations still run through
the checksummed migration tooling, not ad-hoc SQL.

## Air-gapped installation

- **Container images.** `scripts/build-airgap-images.mjs` saves every image referenced
  by the prepared stack into tarballs with a SHA-256 manifest. `--verify` re-checks the
  transferred bundle offline, without Docker or network access.
- **Endpoint packages.** Connector and CLI dependencies are vendored into the customer
  kit (`scripts/customer-kit.mjs`). The Linux endpoint connector has a signed offline
  fleet bundle (`deploy/fleet/linux/build-offline-bundle.sh`); Windows and macOS fleet
  templates are under `deploy/fleet/`.
- **Signed offline license.** A vendor-signed (Ed25519) license file carries the
  entitlement (seats, expiry, modules) and is verified locally at bootstrap. No
  activation server is contacted.
- **Signed rule and intel packs.** Threat-rule and intel updates are delivered as signed
  packs and imported offline. Endpoints verify the signature before use; the signing
  private key never leaves the vendor's custody.
- **Configuration reference.** Every `.env`, `.env.functions` and ingress setting is
  listed in the generated on-prem configuration reference (`pnpm onprem:config-reference`),
  which is drift-checked against the generator.

Delivery integrity (hashes, signatures) is not the same as publisher identity,
notarization or MDM acceptance. Those remain external steps.

## Identity, tenancy and data

The on-prem stack runs the same migrations as the cloud: row-level security on
tenant tables, hash-only API keys, device-code enrollment, SSO (OIDC/SAML) and SCIM
provisioning through the customer's IdP. Agent and Browser Guard telemetry is the
same redacted, counts-only data described in [privacy.md](../privacy.md) and
[privacy-telemetry.md](../contracts/privacy-telemetry.md). With the control plane on
the customer's network, that telemetry does not go to SingularityRD. Verify the
effective egress in the customer environment.

## Related

- [SaaS deployment](saas.md)
- [Security FAQ](../sales/security-faq.md)
- [Upgrade guide](../../deploy/UPGRADE.md)
- [Backup and HA notes](../../deploy/ha/README.md)
