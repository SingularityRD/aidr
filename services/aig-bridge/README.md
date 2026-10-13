# AIG Bridge Service

Python/FastAPI sidecar that bridges **Singularity AIDR** with **Tencent AI-Infra-Guard (AIG)**.

## What it does

The bridge translates AIDR's synchronous-style scan requests into AIG's internal async task workflow.
It provides a clean REST API for AIDR's core to consume, while AIG handles the actual scanning.

The AIG source is tracked directly in this repository under
`vendor/ai-infra-guard/` (it is not a Git submodule). It was imported from the
SingularityRD fork (`https://github.com/SingularityRD/ai-infra-guard`) at tag
`v4.6.1-aidr.1`, commit `809e23df94ff9a9dfe336e3d120abe9a20ea66bf` (Git tree
`2a024a74a5d3255cab7890e6673d8954980c6038`). That fork is based on Tencent
AI-Infra-Guard `v4.6.1` and carries the AIDR hardening changes as committed
source. The pin is recorded in `config/aig-release-sequence.json` and in the
generated `packages/core/src/generated/aig-data-manifest.json`;
`pnpm aig:verify` fails when the vendored tree no longer matches it. Run
`pnpm aig:verify` from the repository root before a demo or release. The bridge maps AIDR's `targets`
list to AIG's singular `target` field, forwards only `timeout`, `headers` and
the optional `model` object, and maps AIG's `doing`/`done` states to
`running`/`completed`. The pinned AIG server requires a model when no upstream default is
configured; never place a real model token in source control or demo logs.

The upstream Python requirements currently resolve `mcp>=1.23.0` to the MCP
SDK 2.x line. The pinned worker still imports the old `streamablehttp_client` symbol,
passes a `timedelta` where SDK 2.x expects seconds, and reads the old
`Tool.inputSchema` attribute. The agent image therefore loads the small,
reviewed `aig_compat/sitecustomize.py` shim at startup. This is a pinned
runtime compatibility boundary, not a claim that arbitrary MCP SDK upgrades
are safe; any dependency change must rerun the bridge and MCP contract tests.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | **Authenticated** detailed readiness report (gate reasons, dataset provenance, `scan_ready`) |
| `GET` | `/api/v1/livez` | Process liveness (public; does not contact AIG or any store) |
| `GET` | `/api/v1/readyz` | Public readiness probe: `{"status":"ready"}` (200) or `{"status":"not_ready"}` (503) only |
| `GET` | `/metrics` | Prometheus metrics; Bearer `BRIDGE_METRICS_TOKEN` (`404` when unset or equal to `BRIDGE_API_KEY`, `401` otherwise). See [deploy/monitoring](../../deploy/monitoring/README.md) |
| `POST` | `/api/v1/uploads` | Store a validated tenant-scoped ZIP or tar.gz archive; return an opaque upload ID |
| `POST` | `/api/v1/scan/infra` | Submit AI infrastructure CVE scan |
| `GET` | `/api/v1/scan/infra/{task_id}` | Poll infra scan results |
| `POST` | `/api/v1/scan/mcp` | Submit MCP server security scan |
| `GET` | `/api/v1/scan/mcp/{task_id}` | Poll MCP scan results |
| `POST` | `/api/v1/scan/agent` | Submit Agent-Scan workflow |
| `GET` | `/api/v1/scan/agent/{task_id}` | Poll Agent-Scan results |
| `POST` | `/api/v1/evaluate/jailbreak` | Submit jailbreak evaluation |
| `GET` | `/api/v1/evaluate/jailbreak/{task_id}` | Poll jailbreak results |
| `GET` | `/api/v1/threats/latest` | Get latest threat intelligence for AIDR sync |

Docker and traffic admission use `/readyz`; `/livez` is process-only and must
not be used to route scan traffic.

Kubelet and Docker probes cannot send credentials, so `/readyz` stays
unauthenticated but reveals nothing beyond ready/not-ready: no versions,
dataset identifiers, gate reasons or internal errors. The detailed report that
names the failing gate is `/api/v1/health`, which uses the same authentication
as the scan routes (API key in `api_key` mode; a broker token with the
`aig:read` scope in `broker` mode; `503` when auth is required but not
configured). Both endpoints share a probe cache of `BRIDGE_HEALTH_CACHE_SECONDS`
(default `5`, clamped to `0`-`30`) and coalesce concurrent probes, so repeated
or concurrent calls do not re-run the AIG, registry, replay-store and dataset
checks. `?capability=` accepts only `infra`, `mcp`, `agent` or `jailbreak`.

## Local Development

PostgreSQL task and JWT replay stores use pure `psycopg==3.2.10` with the
operating system's `libpq`, rather than the self-contained binary wheel. For
local PostgreSQL tests, install `libpq5` on Debian/Ubuntu, `libpq` on macOS,
or make the PostgreSQL client DLLs available on `PATH` on Windows. The SQLite
and mocked paths import the PostgreSQL driver only when needed. Set
`AIG_BRIDGE_TEST_POSTGRES_DSN` to a disposable migrated PostgreSQL database to
run the live task quota, idempotency, lease and JWT replay race tests.

The pinned Docker base is Debian 13 trixie. Its build explicitly updates
`libpq5`, `libssl3t64` and `openssl`, rejects OpenSSL Debian packages older than
`3.5.7-1~deb13u3`, and selects `PSYCOPG_IMPL=python`. This Debian revision
[backports the September 2026 OpenSSL fixes](https://security-tracker.debian.org/tracker/DSA-6531-1);
the upstream version displayed by `openssl version` remains 3.5.7.
The separately pinned `cryptography==50.0.2` wheel
[embeds OpenSSL 4.0.3](https://cryptography.io/en/latest/changelog/#v50-0-2);
updating the operating system libraries does not replace this compiled copy.
`CVE-2026-35189` is a potential PostgreSQL TLS certificate-parsing exposure;
DTLS, QUIC, CMP and SM2 use have not been established for this application's
libpq TCP client. Removing the bundled libraries and enforcing this specific
Debian floor does not establish that every base-image dependency is CVE-free.
The pure driver can be slower than its C extension; re-evaluate with actual
PostgreSQL load if it becomes material.

```bash
# Install dependencies
pip install -r requirements.txt

# Run with hot-reload
uvicorn app.main:app --reload --port 8099

# Set AIG server URL (if running AIG separately)
export BRIDGE_AIG_URL=http://localhost:8088

# Production bridge authentication and tenant scope
export BRIDGE_AUTH_MODE=broker
export BRIDGE_AUTH_REQUIRED=true
export BRIDGE_JWT_SECRET="$(openssl rand -base64 32)"
export BRIDGE_JWT_ISSUER='https://broker.example.com'
export BRIDGE_JWT_AUDIENCE='aidr-aig-bridge'
export BRIDGE_TENANT_REQUIRED=true
export BRIDGE_CORS_ORIGINS='https://demo.example.com'
export BRIDGE_ALLOW_PRIVATE_TARGETS=false
export BRIDGE_VALIDATE_DNS=true
export BRIDGE_SOURCE_ROOT=/app/uploads
export BRIDGE_TASK_BACKEND=postgres
export BRIDGE_TASK_POSTGRES_DSN='postgresql://bridge:secret@postgres.internal/aidr?sslmode=verify-full'
# Apply migrations/001_postgres_task_registry.sql and
# migrations/002_postgres_jwt_replay.sql before starting the bridge.
# Remote scan modes fail closed until the worker has an HTTP(S) egress proxy.
export BRIDGE_RUNTIME_EGRESS_REQUIRED=true
export BRIDGE_EGRESS_PROXY_URL='http://egress-proxy.internal:8080'
# API documentation is disabled by default; enable only on a protected ingress.
export BRIDGE_DOCS_ENABLED=false
export BRIDGE_MAX_BODY_BYTES=52428800
export AIG_BRIDGE_API_KEY="$BRIDGE_API_KEY"
export AIG_TENANT_ID='demo-tenant'

# Run tests
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
PYTHONPATH=. pytest

# Audit the pinned runtime dependency set (must report zero known vulnerabilities)
python -m pip install pip-audit
pip-audit --require-hashes -r requirements-runtime.lock
```

### Source verification and release-signing reference

This is an operator checklist, not a runnable first-customer demo as checked
in: the manifest is unsigned and the example paths/secrets below are
placeholders. The Compose defaults are single-host: a durable SQLite task
registry with `BRIDGE_HA_REQUIRED=false`, and the shipped deny-by-default
`aig-egress` gateway (`deploy/onprem/egress/`). Multi-replica HA switches to the
migrated PostgreSQL registry (see `.env.posture-scanner.example`). Never use a placeholder
signing key or public-key fingerprint to force readiness. For a prepared
on-prem installation use `scripts/deployment-prepare.mjs --with-posture-scanner`
([on-prem guide](../../deploy/onprem/README.md)) instead of this file.

Create a local `.env.posture-scanner` from `.env.posture-scanner.example` if one does not already
exist, and fill its required values. Keep the local file and credentials out
of version control.

```powershell
# The AIG source is part of the AIDR checkout; no submodule step is needed.
pnpm compile:aig
pnpm aig:verify

# A release operator must compile with an external RSA private key, then deploy
# only its public key and the reviewed identifiers. The committed manifest is
# unsigned and deliberately cannot satisfy production readiness.
$env:AIG_SIGNING_PRIVATE_KEY_PATH='C:\secure\aig-release-private.pem'
$env:AIG_SIGNING_KEY_ID='release-key-id'
pnpm compile:aig
$env:AIG_SIGNING_PUBLIC_KEY_HOST_PATH='C:\secure\aig-release-public.pem'
$env:AIG_SIGNING_PUBLIC_KEY_PATH=$env:AIG_SIGNING_PUBLIC_KEY_HOST_PATH
$env:AIG_TRUSTED_SIGNING_KEY_ID=$env:AIG_SIGNING_KEY_ID
$env:AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256='<sha256-of-SPKI-DER-public-key>'
$manifest=Get-Content packages/core/src/generated/aig-data-manifest.json -Raw | ConvertFrom-Json
$env:AIG_EXPECTED_DATA_BUNDLE_ID=$manifest.bundle_id
$env:AIG_EXPECTED_SOURCE_COMMIT=$manifest.source.commit
$env:AIG_RELEASE='true'
$env:AIG_REQUIRE_SIGNED='true'
pnpm aig:verify
Remove-Item Env:AIG_SIGNING_PRIVATE_KEY_PATH

# Use disposable secrets; the upstream AIG API stays private to Compose.
$env:BRIDGE_AUTH_MODE='api_key'
$env:BRIDGE_API_KEY='replace-with-a-long-random-secret'
$env:AIG_AGENT_SHARED_SECRET='replace-with-at-least-32-random-characters'
# Remote scans reach only domains listed in deploy/onprem/egress/allowlist.txt.
docker compose --env-file .env.posture-scanner -f docker-compose.posture-scanner.yml up -d --build

# Synthetic benign scan (do not use a customer target without written scope)
$headers=@{Authorization="Bearer $env:BRIDGE_API_KEY";'X-AIDR-Tenant-ID'='demo-tenant';'Idempotency-Key'='demo-1'}
$body=@{targets=@('https://example.com');scan_type='quick';options=@{timeout=10;model=@{model='gpt-4o-mini';token='demo-token';base_url='https://example.com'}}}|ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:8099/api/v1/scan/infra -Method Post -Headers $headers -ContentType 'application/json' -Body $body
```

The server, worker and bridge images run as UID/GID 1000 with every Linux
capability dropped. The egress gateway drops every capability except
`SETUID`/`SETGID`, which Squid needs to switch to its unprivileged `proxy` user. Before
upgrading an existing installation, snapshot the named volumes and verify that
`aidr-aig-db`, `aidr-aig-logs`, `aidr-aig-uploads`, `aidr-aig-checker-data`, and
`aidr-aig-bridge-state` remain writable by UID/GID 1000. Correct ownership in a
controlled maintenance step; do not restore root execution or broad capabilities.

The current unsigned development manifest records 2,017 generated CVE entries,
146 fingerprints, 14 local MCP categories, and an exact 4,207-file runtime data
tree. These counts are versioned evidence, not a permanent marketing claim or
production readiness evidence. Production readiness additionally requires the
release signature, independently distributed public key and matching live AIG
attestation described below.

### Historical v4.5.1 control-plane evidence (not v4.6.1 acceptance)

An earlier local stack exercised all four bridge submission routes with the
v4.5.1 Tencent server/worker: infrastructure completed against `https://example.com`,
MCP completed against a local SSE fixture, Agent-Scan completed against a
deterministic HTTP fixture, and Jailbreak completed against the local
OpenAI-compatible fixture using `JailBench-Tiny`. The MCP/Agent/Jailbreak
fixtures are synthetic control-plane tests: they prove request translation,
worker connectivity, result envelopes and terminal-state handling, but they do
not prove vulnerability-detection recall. A customer demo must replace them
with an authorized, versioned known-positive and patched fixture and archive the
raw non-secret evidence.

For MCP, the public `categories` list is advisory only. The pinned contract accepts
the exact MCP URL in `prompt` and has no category-filter field; the bridge keeps
the URL unchanged and records the requested categories in operator telemetry
instead of corrupting the upstream target.

### Production security contract

The production `broker` mode fails closed unless a secret of at least 32 UTF-8
bytes, issuer, and audience are all configured. Signed tokens must match that
issuer/audience and carry `aig:scan` for mutating requests or `aig:read` for
reads. `disabled` is rejected whenever `BRIDGE_AUTH_REQUIRED=true`; `api_key`
is retained only for an isolated local sidecar. Scan requests also require
`X-AIDR-Tenant-ID`, and task polling is restricted to the tenant that created
the task. An `Idempotency-Key` can safely retry a request; reusing it with a
different payload returns `409` instead of silently returning the first task.
Multi-replica deployments use `BRIDGE_TASK_BACKEND=postgres` and
`BRIDGE_TASK_POSTGRES_DSN`; this shared database backs both task state and JWT
replay protection. Readiness verifies the task registry schema plus access to
`aig_bridge_jwt_replay` from `migrations/002_postgres_jwt_replay.sql`. Tenant quota,
idempotency reservation and lease acquisition are serialized across replicas
with PostgreSQL transaction locks and constraints. SQLite at
`BRIDGE_TASK_DB=/app/state/tasks.db` remains a single-host fallback and is
reported unready whenever `BRIDGE_HA_REQUIRED=true`.
An ambiguous `reservation:*` row is deliberately never expired automatically:
because AIG has no upstream idempotency contract, an operator must verify that
no upstream task was created before deleting such a row and retrying the job.

Remote URLs are restricted to `http`/`https`, reject credentials/fragments,
and are resolved before submission to block loopback, link-local, metadata,
reserved and (unless explicitly opted in) private addresses. The AIG worker
receives the configured proxy through `HTTP_PROXY`/`HTTPS_PROXY`; readiness and
remote submissions fail closed when the proxy is missing. The egress gateway
must repeat address checks on every DNS resolution and redirect. The Compose
control network is `internal`; the shipped `aig-egress` gateway (pinned Ubuntu
Squid, `deploy/onprem/egress/squid.conf`) is the only AIG service also attached
to an external network. It refuses every destination that is not in the
operator allowlist or that resolves to a loopback, link-local, private, CGNAT,
multicast or reserved address, on every request and redirect hop. The bridge
additionally joins a non-masquerading edge network only so Docker can publish
its loopback port. Workers refuse to register until they can reach the
configured proxy, so readiness cannot pass on a syntax-only proxy value. Set
`BRIDGE_VALIDATE_DNS=false` only for a controlled offline test environment,
never for a customer deployment.

IP literals are normalised the way the C resolver reads them before the
address policy is applied, so decimal (`2852039166`), hex (`0xa9fea9fe`),
octal (`0251.0376.0251.0376`), short (`169.254.43518`, `127.1`) and
IPv4-mapped IPv6 forms of a blocked address are rejected even with DNS
validation disabled.

Inline `agent_config` objects are walked in full (mapping keys and values,
lists, lists of mappings) with a depth limit of 32 and a 20,000-element limit;
exceeding either, or a non-JSON value type, is a `422`. URL keys (`url`,
`base_url`, `api_base_url`, ...) must hold a validated http(s) URL and URLs in
any other field are refused. Host-style keys (`host`, `hostname`, `ip`,
`address`, `proxy`, ...) are validated as `host[:port]` in full. Every other
string is scanned for host literals (`host:port`, `[v6]:port`, bare IPv6,
`user@host`, `host/path` and the IPv4 notations above) and blocked
destinations are refused. To avoid rejecting ordinary data, bare small
numbers (`"1"`, `"10:30"`) and dotted numbers such as `"0.5"` or `"10.2.3"` are
treated as addresses only when they are hex/octal, carry a port, exceed the
range of a version component, or reach loopback/link-local.

MCP URL targets: the pinned AIG worker clones a repository instead of
connecting to a live MCP server whenever the target text contains the
substring `github.com`. The bridge therefore decides that mode from the parsed
URL: only `https://github.com/<owner>/<repo>[.git][/]` (exact lowercase host,
no port, userinfo, query or extra path) is accepted as a repository target.
Any other target that mentions `github.com` anywhere, including
`www.github.com`, `github.com.<other>`, `<other>/github.com/...` and query
strings, is rejected with `422`, as is any target containing whitespace.

MCP source scans accept only the SHA-256 `upload_id` returned by `POST
/api/v1/uploads`. The bridge resolves that opaque ID beneath
`BRIDGE_SOURCE_ROOT/<authenticated-tenant>` and rejects cross-tenant paths,
missing objects, traversal, and symlink escapes before dispatch. API responses
and AIG task payloads carry only `<tenant>/<upload_id>` references; container
filesystem paths never cross the bridge boundary.

Threat intelligence is read from AIG's versioned knowledge API
(`/api/v1/knowledge/vulnerabilities` and `/api/v1/knowledge/mcp`); the bridge
does not fabricate zero-CVE results when AIG is unavailable. The health check
reports `threat_intel_ready=false` and a `null` CVE count until those endpoints
respond with valid metadata. A real AIG server, fingerprint database and
worker are required for a customer/investor demo. The tracked AIDR vendor patch
adds a shared-secret-protected worker readiness route. The bridge combines its
live registered-worker count with loaded vulnerability and MCP knowledge API
counts; configuration-only worker or dataset claims are ignored. `/livez`
remains the process-only liveness endpoint.

Dataset readiness also verifies the existing `aig-data-manifest/v1` contract:
all three generated artifact hashes and sizes, bundle digest, RSA-SHA256
signature, signer key ID, SPKI public-key fingerprint, source commit and bundle
deployment pins. Live AIG CVE and MCP registries must be non-empty, and the
authenticated internal readiness response must attest the exact signed runtime
data-tree digest through the same `bundle_id`, `source_commit` and
`release_sequence` with
`verified=true`. The tracked vendor patch emits this attestation only after it
has verified the immutable runtime tree; its authenticated readiness endpoint
returns `503` when verification fails. Missing keys, an unsigned manifest, a
stale deployment pin, tampering, missing upstream attestation, or an empty live
registry all fail closed. The signing private key is release-only and must never
enter the bridge image or runtime.

The pinned Tencent AIG server has no user-facing authentication layer. The compose file
therefore never publishes the AIG server UI/API; only the authenticated bridge
is bound to host loopback by default. Worker WebSocket registration and the
internal readiness route require `AIG_AGENT_SHARED_SECRET` (at least 32 random
characters), and browser-origin worker connections are rejected. The upstream
data tree also contains paths that collide on case-insensitive hosts. The data
compiler reads pinned Git blobs directly; build and smoke-test the Linux image
separately before release.

### Vendored AIDR hardening

The vendored `v4.6.1-aidr.1` source carries committed AIDR hardening over Tencent
v4.6.1: authenticated worker registration/readiness, redaction of persisted
task secrets, and a dedicated worker scratch directory. Source uploads remain read-only in the
worker and are extracted only below `/work`. Re-run the Go worker/WebSocket
tests whenever the vendored source is updated.

## Bridge image only (development, not a release recipe)

```bash
# Build
docker build -t aig-bridge .

# Run requires a separately configured AIG server, signing keys, task backend,
# broker or isolated local API-key mode, and egress proxy. This abbreviated
# command is not a customer-ready deployment or readiness proof.
docker run -p 8099:8099 \
  -e BRIDGE_AIG_URL=http://aig-server:8088 \
  -e BRIDGE_API_KEY="$BRIDGE_API_KEY" \
  -e BRIDGE_AUTH_REQUIRED=true \
  -e BRIDGE_TENANT_REQUIRED=true \
  aig-bridge
```

## Architecture

See [`docs/architecture/aig-integration.md`](../../docs/architecture/aig-integration.md) for the full integration architecture.

## Attribution

This integration uses AI-Infra-Guard by Tencent Zhuque Lab (Apache 2.0).
See `vendor/ai-infra-guard/NOTICE` for attribution requirements.
