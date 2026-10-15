# DLP authoring storage: saved is not delivered

## Contract and authority

The existing editor invokes canonical `policy-management`:

- `read_dlp_policy`: `{ tenant_id }` → `{ ok: true, version: 0, policy: null }` when empty; otherwise the committed version and normalized document.
- `publish_dlp_policy`: `{ tenant_id, expected_version, policy }` → the committed row, `saved: true`, `delivered: false`, `delivery_status: "not_delivered"`. A stale precondition is HTTP 409 (`policy_version_conflict`). Failed/malformed storage responses are never acknowledged as success.

Both actions verify the access token, session revocation barrier, active tenant membership, active tenant status, tenant quota, and AAL2. Reads are member-scoped; saves require owner/admin. This is stricter than the editor's current `canEditPolicy` flag, which also includes member. AAL1 is refused even when general tenant MFA is optional. Browser validation, claimed actor IDs, and claimed validation status confer no authority.

The server validates with the **actual core DLP schema**, including defaults, strict keys, matcher/regex restrictions, expiry/dominance rules, references and nested tenant ownership. The validated top-level tenant must equal the authenticated selected tenant. Storage owns the next document version independently of the editor's draft version. A single expired exception remains accepted exactly as in core; the scanner prunes it. Stored reads do not revalidate time-dependent expiry, allowing an aging policy to be retrieved for repair (the unchanged editor may label an expired-majority document unreadable).

## Tenant custom labels (T38)

Tenant owners/admins define their own labels (`id`, `name`, `description`, `sensitivity`, `redactionToken`) and rules that reference them (`directions` input/output, `action` redact/block/ask, `priority`, `matchMode`). A rule's matchers are dictionary terms (`keyword`), bounded regexes (`regex`, optional `validator` from the fixed list `luhn`, `iban_mod97`, `tc_kimlik`, `tr_vkn`, `us_ssn`: a match that fails the checksum is not a finding), or built-in TR/EN detectors (`detector`). Exceptions (rule/content/match scope, owner, expiry) apply to custom-label rules exactly as to any rule. Everything goes through the same `publish_dlp_policy` CAS/history/audit path and the same signed bundle; there is no separate label store or new migration.

Server-side refusal (core schema, mirrored by the editor): unknown fields, duplicate ids, foreign tenant ids, regexes over 512 characters, invalid/empty-matching regexes, and the structural ReDoS guard `regexRiskIssue` (back-references, a repeated group whose body is quantified or alternates such as `(a|aa)+` or `((a+))+`, `{n,m}` bounds above 1000, more than four unbounded quantifiers), plus at most 256 regex matchers and 10,000 keyword terms per policy (the storage RPC separately caps the document at 64 KiB). The guard is deliberately conservative: write `[ab]+` rather than `(a|b)+`. A signed bundle containing a pattern the engine refuses is not partially applied: the endpoint reports inspection unavailable and withholds output. Matches report `ruleId`, `labelId`, `labelName`, `sensitivity` and `action`, never the raw value; content outside `supportedFormats` is reported `unsupported_format` (unavailable), not clean.

Focused evidence: `packages/core/src/__tests__/dlp/tenant-custom-labels.test.ts` (schema accept/reject, synthetic `PRJ-ACME-123456` caught on input and output with label id and configured action, benign pass, Luhn validator, unsupported format, exception lifecycle, signed-bundle output enforcement and fail-closed unsafe bundle), new cases in `supabase/functions/__tests__/dlp-policy-store.test.ts`, and the editor tests in `packages/dashboard/src/__tests__/dlp-editor.test.tsx`.

Not provided: a `monitor` (report-only) action. Adding it needs the evaluator, common-PII baseline and telemetry paths outside the DLP module to forward non-blocking findings, otherwise it would be a silent allow. A separate `file`/`prompt` scope is not modelled; scope is `directions` plus `supportedFormats`. Real customer label corpora, false-alarm acceptance and model qualification remain external (see T38).

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
- `pnpm exec vitest run --config vitest.dlp-storage.config.ts`: 111 tests passing at the original storage change, including 39 unchanged prior policy assertions/tests and 12 core DLP tests; 189 after the T38 custom-label additions (2026-10-15).
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

**Supported output paths now consume the signed tenant DLP bundle.** Claude PostToolUse, OpenCode output hooks, OpenClaw reply/persistence hooks, and an explicitly configured SDK generic adapter use the shared provisioned-output scanner. It validates captured configuration, signed policy, entitlement and revocation together; delivery rechecks current state and expiration. Cursor/VS Code can observe or stop only the outputs exposed by their host APIs; Codex exposes no equivalent output interception API. These source connections require acceptance in the exact supported host before making a delivery guarantee. When a hook cannot replace the original input, a policy `redact` finding is blocked rather than rewritten. Input DLP runs before outbound reputation/package queries, while preserving stronger local deny decisions.

Example with placeholders only (the output directory must be the target agent's AIDR state directory):

```sh
node scripts/provision-dlp-detector.mjs --endpoint https://example.invalid/functions/v1/policy-management --tenant 22222222-2222-4222-8222-222222222222 --version 7 --runtime opencode --expires-at '<UTC-expiry-within-24-hours>' --token-file /secure/aal2-token --private-key /secure/publisher.pem --output-dir /agent-home/.singularity-aidr/detectors
node --test scripts/provision-dlp-detector.test.mjs
```

The signing key must already match an Ed25519 public key trusted by that agent's managed config, and the agent needs a current, verified signed entitlement for the same tenant. An explicitly installed signed DLP bundle is enforced without requiring a new `runtime_detectors` module: current servers do not issue that module. If a future signed entitlement mandates `runtime_detectors`, a missing bundle fails closed. The operator test exercises both the current premium-module shape and the mandatory-module shape; it does not issue a production licence. The output status `signed_bundle_written_not_agent_verified` is deliberately **not** a fleet delivery receipt. A source-tree operator script is not an automatic signed distribution service: token acquisition, secure per-host transport, revocation/renewal inside 24 hours, managed endpoint rotation, host-level enforcement evidence and rollout telemetry are still open. Do not promote T38 to GA until a named candidate is tested in real supported hosts with those controls.

Tests use deterministic handler clients and a real disposable PostgreSQL with minimal unrelated table fixtures. They do not claim a deployed full-Supabase JWT/PostgREST/browser acceptance test, every historical migration combination, production signing authority, or live fleet enforcement. Existing editor wording and its member edit affordance are unchanged; server responses and this report describe storage only.
