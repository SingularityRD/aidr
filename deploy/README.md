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

From the repository root:

```powershell
pnpm install --frozen-lockfile
pnpm build
node scripts/deployment-prepare.mjs --mode self-hosted --output .aidr-deploy --dashboard-url https://aidr.customer.example --supabase-url https://api.aidr.customer.example
docker compose --project-directory .aidr-deploy -f .aidr-deploy/compose.yml config --quiet
docker compose --project-directory .aidr-deploy -f .aidr-deploy/compose.yml up -d --wait --wait-timeout 180
node scripts/deployment-migrate.mjs .aidr-deploy
```

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

Configure SMTP and approved OAuth providers, provision the first account and
its tenant/entitlement, configure the invoice sales destination and perform
onboarding before inviting customers. Signup is disabled in the generated
self-hosted baseline. Team invitations create manually shared, expiring links;
the application does not claim to send invitation emails.

## Isolated installation rehearsal

Use an empty destination and keep the stack isolated from customer data:

```powershell
node scripts/deployment-prepare.mjs --development --output .aidr-deploy
docker compose --project-directory .aidr-deploy -f .aidr-deploy/compose.yml up -d --wait --wait-timeout 180
node scripts/deployment-migrate.mjs .aidr-deploy
node scripts/deployment-smoke.mjs .aidr-deploy
```

Dashboard: `http://localhost:8080`; API: `http://localhost:8000`. The smoke runner
rejects non-loopback or non-development deployments. It creates isolated fixture
users/teams, performs real HTTP/SQL authorization and enrollment flows, and passes
a tool call to the built hook evaluator. The canary command is never executed.
Fixtures remain for inspection. `smoke-evidence.json` contains results without
tokens; other files in this private deployment directory may contain fixture keys.

Stop only this Compose project with `docker compose --project-directory
.aidr-deploy -f .aidr-deploy/compose.yml down`. Keep volumes and secrets when
restarting. Do not use `down -v` on customer data.

## Cloud deployment preparation

```powershell
pnpm build
node scripts/deployment-prepare.mjs --mode cloud --output .aidr-cloud --dashboard-url https://aidr.example.com --supabase-url https://PROJECT.supabase.co
```

Use a provisioned managed Supabase project in the approved region. Replace the
anonymous/service-role placeholders in the private environment file with that
project's keys. Apply repository migrations using the Supabase migration workflow
for the selected project; the local Docker migration script deliberately refuses
cloud mode. Configure `AIDR_ALLOWED_ORIGINS`, dashboard/verify URLs, the generated
DER/PKCS8 signing secrets, premium pack key and commercial settings from
`.env.functions`. Deploy the canonical `supabase/functions` directories with the
per-function JWT settings from `supabase/config.toml`; some native routes use
their own API-key or device-token authentication.

Build/start the generated dashboard Compose service behind the HTTPS ingress.
Configure project SMTP, OAuth redirects, region/retention policy, monitoring and
backup. Verify the same negative authorization and onboarding scenarios in a
separate staging project. This preparation command does not create a cloud
account, region, billing subscription or production deployment.

## Endpoint connector installation

For a built/extracted Claude package:

```powershell
node scripts/endpoint-install.mjs --package-dir packages/claude-code
```

To initialize a fresh managed endpoint, add `--config .aidr-deploy/agent-config.json`.
Existing agent configuration is preserved; merge managed settings explicitly
when an endpoint already has configuration. `--home PATH` supports an isolated
installer rehearsal. The installer copies artifacts/resources to a stable digest
directory, preserves unrelated hooks, backs up changed settings, registers all
tool events, and requires a local deny canary before registration. Repeating it
does not duplicate its hooks. An already enabled AIDR marketplace plugin must be
updated through its plugin path to avoid duplicate invocation.

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
- Audit exports use private downloads valid for 60 seconds. Requests above 1000
  rows fail explicitly until pagination is implemented. Storage cleanup is a
  required operational follow-up.

## Release boundary

Run `pnpm quality:static`, `pnpm check`, `pnpm test:ci`,
`pnpm verify:enforcement`, `node scripts/verify-codex-hook.mjs` and package release
gates for the exact candidate. A signed commercial build additionally requires
the existing release-signing environment and candidate evidence. Do not replace
those keys with development keys to obtain a green production result.

The complete capability gaps are in [FEATURE_INVENTORY.md](../FEATURE_INVENTORY.md).
Commercial/customer approvals remain in the existing
[evidence registry](../docs/production-readiness/commercial-go-evidence-registry.json).
