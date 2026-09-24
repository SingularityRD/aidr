# DLP authoring storage: saved is not delivered

## Contract and authority

The existing editor invokes canonical `policy-management`:

- `read_dlp_policy`: `{ tenant_id }` → `{ ok: true, version: 0, policy: null }` when empty; otherwise the committed version and normalized document.
- `publish_dlp_policy`: `{ tenant_id, expected_version, policy }` → the committed row, `saved: true`, `delivered: false`, `delivery_status: "not_delivered"`. A stale precondition is HTTP 409 (`policy_version_conflict`). Failed/malformed storage responses are never acknowledged as success.

Both actions verify the access token, session revocation barrier, active tenant membership, active tenant status, tenant quota, and AAL2. Reads are member-scoped; saves require owner/admin. This is stricter than the editor's current `canEditPolicy` flag, which also includes member. AAL1 is refused even when general tenant MFA is optional. Browser validation, claimed actor IDs, and claimed validation status confer no authority.

The server validates with the **actual core DLP schema**, including defaults, strict keys, matcher/regex restrictions, expiry/dominance rules, references and nested tenant ownership. The validated top-level tenant must equal the authenticated selected tenant. Storage owns the next document version independently of the editor's draft version. A single expired exception remains accepted exactly as in core; the scanner prunes it. Stored reads do not revalidate time-dependent expiry, allowing an aging policy to be retrieved for repair (the unchanged editor may label an expired-majority document unreadable).

## Deployable shared schema

Self-hosted/customer-kit packaging copies only `supabase/functions/`. Therefore `_shared/dlp-policy-schema.ts` is a generated deployment artifact of `packages/core/src/dlp/policy.ts`, **not** an independently maintained validator. The only source change is the bare Zod import to the installed core version's pinned Deno `npm:` specifier. No Node/core package tree or shared dependency links are required at runtime.

After changing the engine schema or Zod version:

```sh
node scripts/sync-dlp-edge-schema.mjs --write
node scripts/sync-dlp-edge-schema.mjs --check
pnpm exec vitest run --config vitest.dlp-storage.config.ts
```

The focused suite asserts byte parity and runs valid/invalid documents through the real core schema and server boundary. Deploy both new migrations, in order, and the canonical function artifacts together:

1. `20260916000005_dlp_policy_storage.sql`
2. `20260916000006_dlp_policy_offboarding.sql`

No browser grants or signing keys are introduced. The service-only RPC serializes first insert/update by tenant, rechecks and locks membership/status, compares the version, then atomically writes current policy, revision history and metadata-only audit. History/audit failure rolls back the entire save. Direct service-role table mutations are revoked; history updates/deletes are additionally trigger-protected after migration 06.

## Retention and offboarding

DLP current/history documents use existing `policy_configuration` retention, without changing the ten data classes or backup exclusion. Phases 42 (`dlp_policy_revisions`) and 43 (`tenant_dlp_policies`) are seeded for new runs and backfilled for in-flight runs. The original bounded dispatcher is extended at checked, unique source anchors, preserving fleet/cache and other extensions; unexpected source drift fails migration rather than silently omitting deletion.

The same tenant advisory lock serializes legal holds and deletion. Only an eligible, running, tenant-bound DLP phase can delete records. History is removed before current policy; each batch records counts. Tenant closure and run completion reject residue in either table. Backup copies still require independent expiry/key-destruction evidence.

## Focused evidence

- Own `pnpm install --offline --ignore-scripts`; no shared dependency links.
- `pnpm exec vitest run --config vitest.dlp-storage.config.ts`: 111 tests passing, including 39 unchanged prior policy assertions/tests and 12 core DLP tests.
- Disposable PostgreSQL 17, not an existing project: `supabase/functions/__tests__/dlp-policy-storage-run.sh` applies the new storage migration; proves CAS (including concurrent sessions), actual role permissions/RLS, foreign tenant/viewer/expired membership/suspended tenant refusal, and injected history/audit failures rolling back the current row. It then loads the real shipped retention dispatcher plus fleet/cache extensions and migration 06, and proves hold/retention, bounded ordered deletion, phase backfill, immutable history, tenant isolation, residue rejection, receipts and idempotency.
- Supabase Edge Runtime `v1.76.2` successfully bundles the handler with **only** `supabase/functions` mounted. A nonempty eszip is required for success; no repository-level core source or import map is available in that check.
- Existing `tenant-offboarding-migration.test.mjs`: six tests pass, preserving ten-class/hold/backup assertions. The broader `deployment-offboarding.test.mjs` adds eight passes and one pre-existing Windows doctor-timer assertion failure: it stringifies `{ check, reason }` evidence objects, so its timer-name filter finds none. Neither that test nor the doctor was changed; the issue was reported to the coordinating retention owner.
- `node scripts/check-supabase-edge-contracts.mjs`: passes (17 browser functions; 33/33 config-guarded).
- No full build or `compile:aig` was run. Repository Biome configuration excludes these server/script paths; no lint success is claimed.

Example disposable database run (PowerShell, checkout root):

```powershell
$name = 'aidr-dlp-test-' + [guid]::NewGuid().ToString('N')
docker run --rm -d --name $name --network none -e POSTGRES_HOST_AUTH_METHOD=trust --mount "type=bind,source=$($PWD.Path),target=/work,readonly" postgres:17-alpine
try {
  docker exec $name sh /work/supabase/functions/__tests__/dlp-policy-storage-run.sh
  if ($LASTEXITCODE -ne 0) { throw 'DLP database contracts failed' }
} finally { docker stop $name }
```

## Remaining boundaries

**A saved policy has not been delivered or enforced.** The editor and server still return `delivered: false`. An explicit source-checkout operator bridge now exists: `scripts/provision-dlp-detector.mjs` reads one saved revision through `policy-management` using a short-lived AAL2 access token, requires the expected tenant and version, validates the engine schema, signs a tenant-bound bundle with an existing trusted Ed25519 publisher key, and atomically installs it into an agent runtime's fixed `detectors/<runtime>.json` path. The tool refuses HTTP, redirects, oversized documents, a policy downgrade, and signatures that would outlive 24 hours. It does not take a token or private key on the command line; use protected local files outside the repository.

**The current managed connector enforcement path is input-only.** `evaluateToolCall` scans serialized tool input before execution; it does not wire `output`-direction rules into post-tool/model-output delivery. The standalone core scanner can scan output when a caller explicitly invokes it, but that is not evidence that a connector does. Also, when a connector hook cannot replace the original input, a policy `redact` finding is blocked rather than rewritten. Treat output-direction enforcement and in-place redaction as unsupported until a specific host path passes acceptance.

Example with placeholders only (the output directory must be the target agent's AIDR state directory):

```sh
node scripts/provision-dlp-detector.mjs --endpoint https://example.invalid/functions/v1/policy-management --tenant 22222222-2222-4222-8222-222222222222 --version 7 --runtime opencode --expires-at 2026-09-24T00:00:00Z --token-file /secure/aal2-token --private-key /secure/publisher.pem --output-dir /agent-home/.singularity-aidr/detectors
node --test scripts/provision-dlp-detector.test.mjs
```

The signing key must already match an Ed25519 public key trusted by that agent's managed config, and the agent needs a current signed entitlement for the same tenant with `runtime_detectors`. The output status `signed_bundle_written_not_agent_verified` is deliberately **not** a fleet delivery receipt. A source-tree operator script is not an automatic signed distribution service: token acquisition, secure per-host transport, revocation/renewal inside 24 hours, managed endpoint rotation, host-level enforcement evidence and rollout telemetry are still open. Do not promote T38 to GA until a named candidate is tested in real supported hosts with those controls.

Tests use deterministic handler clients and a real disposable PostgreSQL with minimal unrelated table fixtures. They do not claim a deployed full-Supabase JWT/PostgREST/browser acceptance test, every historical migration combination, production signing authority, or live fleet enforcement. Existing editor wording and its member edit affordance are unchanged; server responses and this report describe storage only.
