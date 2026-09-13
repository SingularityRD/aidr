# AIG Bridge Service

Python/FastAPI sidecar that bridges **Singularity AIDR** with **Tencent AI-Infra-Guard (AIG)**.

## What it does

The bridge translates AIDR's synchronous-style scan requests into AIG's internal async task workflow.
It provides a clean REST API for AIDR's core to consume, while AIG handles the actual scanning.

The supported upstream contract is Tencent AI-Infra-Guard `v4.5.1`
(`31c72a9799c8b19d89bcb331d4f8038f05462b8f`). Run `pnpm aig:verify` from the
repository root before a demo or release. The bridge maps AIDR's `targets`
list to AIG's singular `target` field, forwards only `timeout`, `headers` and
the optional `model` object, and maps AIG's `doing`/`done` states to
`running`/`completed`. AIG v4.5.1 requires a model when no upstream default is
configured; never place a real model token in source control or demo logs.

The upstream Python requirements currently resolve `mcp>=1.23.0` to the MCP
SDK 2.x line. AIG v4.5.1 still imports the old `streamablehttp_client` symbol,
passes a `timedelta` where SDK 2.x expects seconds, and reads the old
`Tool.inputSchema` attribute. The agent image therefore loads the small,
reviewed `aig_compat/sitecustomize.py` shim at startup. This is a pinned
runtime compatibility boundary, not a claim that arbitrary MCP SDK upgrades
are safe; any dependency change must rerun the bridge and MCP contract tests.

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/v1/health` | Health check + AIG connectivity status |
| `GET` | `/api/v1/livez` | Process liveness (does not require AIG) |
| `GET` | `/api/v1/readyz` | Readiness (AIG and auth must be available) |
| `POST` | `/api/v1/scan/infra` | Submit AI infrastructure CVE scan |
| `GET` | `/api/v1/scan/infra/{task_id}` | Poll infra scan results |
| `POST` | `/api/v1/scan/mcp` | Submit MCP server security scan |
| `GET` | `/api/v1/scan/mcp/{task_id}` | Poll MCP scan results |
| `POST` | `/api/v1/scan/agent` | Submit Agent-Scan workflow |
| `GET` | `/api/v1/scan/agent/{task_id}` | Poll Agent-Scan results |
| `POST` | `/api/v1/evaluate/jailbreak` | Submit jailbreak evaluation |
| `GET` | `/api/v1/evaluate/jailbreak/{task_id}` | Poll jailbreak results |
| `GET` | `/api/v1/threats/latest` | Get latest threat intelligence for AIDR sync |

## Local Development

```bash
# Install dependencies
pip install -r requirements.txt

# Run with hot-reload
uvicorn app.main:app --reload --port 8099

# Set AIG server URL (if running AIG separately)
export BRIDGE_AIG_URL=http://localhost:8088

# Production bridge authentication and tenant scope
export BRIDGE_API_KEY='generate-a-long-random-secret'
export BRIDGE_AUTH_REQUIRED=true
export BRIDGE_TENANT_REQUIRED=true
export BRIDGE_CORS_ORIGINS='https://demo.example.com'
export BRIDGE_ALLOW_PRIVATE_TARGETS=false
export BRIDGE_VALIDATE_DNS=true
export BRIDGE_SOURCE_ROOT=/app/uploads
export BRIDGE_TASK_DB=/app/state/tasks.db
export AIG_BRIDGE_API_KEY="$BRIDGE_API_KEY"
export AIG_TENANT_ID='demo-tenant'

# Run tests
python -m pip install -r requirements-test.txt
PYTHONPATH=. pytest

# Audit the pinned runtime dependency set (must report zero known vulnerabilities)
python -m pip install pip-audit
pip-audit -r requirements.txt
```

### Verified local demo

```bash
git submodule update --init --recursive
pnpm compile:aig
pnpm aig:verify

# Use a disposable secret; the upstream AIG server itself is unauthenticated.
# Keep both published ports on loopback/private ingress.
$env:BRIDGE_API_KEY='replace-with-a-long-random-secret'
docker compose --env-file .env.aig -f docker-compose.aig.yml up -d --build

# Synthetic benign scan (do not use a customer target without written scope)
$headers=@{Authorization="Bearer $env:BRIDGE_API_KEY";'X-AIDR-Tenant-ID'='demo-tenant';'Idempotency-Key'='demo-1'}
$body=@{targets=@('https://example.com');scan_type='quick';options=@{timeout=10;model=@{model='gpt-4o-mini';token='demo-token';base_url='https://example.com'}}}|ConvertTo-Json -Depth 8
Invoke-RestMethod http://127.0.0.1:8099/api/v1/scan/infra -Method Post -Headers $headers -ContentType 'application/json' -Body $body
```

The current verified dataset evidence is 1,925 generated CVE entries, 133
fingerprints and 14 local MCP categories. The running upstream knowledge API
reports 1,891 vulnerability records and 15 MCP records. These counts are
versioned evidence, not a permanent marketing claim.

### Verified v4.5.1 control-plane evidence

The local stack has exercised all four bridge submission routes with the real
Tencent server/worker: infrastructure completed against `https://example.com`,
MCP completed against a local SSE fixture, Agent-Scan completed against a
deterministic HTTP fixture, and Jailbreak completed against the local
OpenAI-compatible fixture using `JailBench-Tiny`. The MCP/Agent/Jailbreak
fixtures are synthetic control-plane tests: they prove request translation,
worker connectivity, result envelopes and terminal-state handling, but they do
not prove vulnerability-detection recall. A customer demo must replace them
with an authorized, versioned known-positive and patched fixture and archive the
raw non-secret evidence.

For MCP, the public `categories` list is advisory only. Tencent v4.5.1 accepts
the exact MCP URL in `prompt` and has no category-filter field; the bridge keeps
the URL unchanged and records the requested categories in operator telemetry
instead of corrupting the upstream target.

### Production security contract

The bridge fails closed when `BRIDGE_AUTH_REQUIRED=true` (the default) but no
`BRIDGE_API_KEY` is configured. Scan requests also require
`X-AIDR-Tenant-ID`, and task polling is restricted to the tenant that created
the task. An `Idempotency-Key` can safely retry a request; reusing it with a
different payload returns `409` instead of silently returning the first task.
The compose deployment persists this ownership/idempotency registry at
`BRIDGE_TASK_DB=/app/state/tasks.db`; a multi-host or multi-replica deployment
must replace it with a shared transactional store before claiming HA.

Remote URLs are restricted to `http`/`https`, reject credentials/fragments,
and are resolved before submission to block loopback, link-local, metadata,
reserved and (unless explicitly opted in) private addresses. The AIG worker
must repeat this check immediately before connecting because DNS answers can
change after the bridge validates them. Set `BRIDGE_VALIDATE_DNS=false` only
for a controlled offline test environment, never for a customer deployment.

MCP source scans are rooted at `BRIDGE_SOURCE_ROOT` (default `/app/uploads`)
and reject traversal, absolute paths outside that root, and symlink escapes.
The bridge does not claim that a source file exists; the worker must perform
the final existence/type check on the shared upload volume.

Threat intelligence is read from AIG's versioned knowledge API
(`/api/v1/knowledge/vulnerabilities` and `/api/v1/knowledge/mcp`); the bridge
does not fabricate zero-CVE results when AIG is unavailable. The health check
reports `threat_intel_ready=false` and a `null` CVE count until those endpoints
respond with valid metadata. A real AIG server, fingerprint database and
worker are required for a customer/investor demo. Tencent v4.5.1 exposes no
authenticated worker-list/health route; consequently `/health` reports
`aig_agent: "unknown"` and `/readyz` proves the server/auth boundary only. A
capability task must complete successfully before advertising a scan type as
ready.

Tencent AIG v4.5.1 has no authentication layer. The compose file therefore
binds both optional host ports to `127.0.0.1` by default. In production expose
only the bridge through an authenticated private ingress; never publish the
AIG server UI/API directly. The upstream data tree also contains case-colliding
paths, so build the pinned source on Linux for complete reproducibility.

## Docker

```bash
# Build
docker build -t aig-bridge .

# Run
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
