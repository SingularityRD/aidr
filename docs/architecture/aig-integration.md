# AIG (AI-Infra-Guard) Integration Architecture

> **Status:** First-customer acceptance open — the owned AIG source is committed
> directly under `vendor/ai-infra-guard` and its data verifies locally, but the
> committed manifest is unsigned. The pinned source is `v4.6.1-aidr.1`
> (`809e23df94ff9a9dfe336e3d120abe9a20ea66bf`).
> **Owners:** AIDR Core Team, AIG Integration Team

The request/response examples below document the earlier `v4.5.1` design and
are **not** current live-scan or production acceptance evidence. For the active
security, readiness and release-signing contract, use the
[bridge runbook](../../services/aig-bridge/README.md) and `pnpm aig:verify`.
Do not present AIG as first-customer ready until the data manifest is signed
with a trusted release key, the runtime attests
the same bundle, and real scan/restore/host acceptance evidence exists.

## 1. Overview

This document defines the integration architecture between **Singularity AIDR** (TypeScript monorepo, runtime security layer for AI coding agents) and **Tencent AI-Infra-Guard (AIG)** (Python/Go scanning platform for AI infrastructure).

The integration combines AIDR's local agent controls with optional AIG-backed infrastructure, MCP, Agent-Scan, and jailbreak evaluation. Any dataset size, platform coverage, or latency claim must be tied to a versioned evidence record before it is used in customer or investor material.

This product includes software developed at Tencent Zhuque Lab. Based on
[Tencent Zhuque Lab AI-Infra-Guard](https://github.com/Tencent/AI-Infra-Guard).

### 1.1 Design Principles

| Principle | Description |
|-----------|-------------|
| **Non-invasive** | AIDR core remains unchanged; AIG functions as an external service |
| **On-demand scanning** | AIG scans are triggered by AIDR policy decisions, not inline in agent execution |
| **Loose coupling** | REST API between AIDR and AIG; no shared runtime or process |
| **Async by default** | Long-running scans return a task ID; results are polled or pushed |
| **Attribution required** | All integrations must attribute Tencent Zhuque Lab per AIG's NOTICE file |

### 1.3 Current source pin and historical task contract

The committed vendor tree, release-sequence registry and generated manifest
all reference the owned `v4.6.1-aidr.1` source at
`809e23df94ff9a9dfe336e3d120abe9a20ea66bf`. Local `pnpm aig:verify`
checks that pin and reports 2,017 generated CVE entries, 146 fingerprints,
14 local MCP categories and a 4,207-file runtime data tree. These are build
counts, **not** a live AIG knowledge API count or detection-rate claim. The
manifest has `signature: null`, so release-mode verification and bridge
dataset readiness must fail closed. A signed release and live acceptance remain open.

Tencent's v4 task API uses `target` (singular), `timeout`, optional `headers`,
and an optional `model` object. A model is required when the upstream has no
default model. The bridge translates its public `targets` request into this
allow-listed payload, normalizes AIG's `doing`/`done` states to
`running`/`completed`, and exposes non-secret fingerprint evidence in the
result response. The raw AIG server has no user-facing authentication layer;
Compose gives it no host port. Only the authenticated bridge binds to host
loopback by default.

The four task routes use the following v4.5.1 contracts: infrastructure sends
`target`, `headers`, `timeout` and `model`; MCP sends the exact URL as
`prompt`, `thread`, `language`, `headers` and optional `model`; Agent-Scan sends
`agent_data` as inline provider YAML plus `eval_model`; and jailbreak sends a
`model` list plus `dataset.dataFile`, `numPrompts`, `randomSeed` and optional
`eval_model`. The bridge deliberately does not append MCP category names to
the URL: v4.5.1 has no category-filter field, so the public category list is an
advisory/operator field. AIG's `status=error` is normalized to a terminal
`failed` result even when its result endpoint still says “not available yet”.

The v4.5.1 agent image is executed with a small compatibility shim because
the upstream imports an old MCP SDK symbol, passes `timedelta` to the SDK 2.x
constructor, and reads `Tool.inputSchema` while SDK 2.x exposes
`input_schema`. This shim is loaded only in the AIG worker and is covered by
the MCP bridge contract test.

The compiler reads pinned Git blobs byte-for-byte, including paths that may
collide on case-insensitive hosts. A Linux image build and live scan still need
separate acceptance; a successful source compilation does not prove them.

### 1.2 Integration Model: Sidecar Service

AIG runs as a **sidecar service** alongside AIDR:

```
┌─────────────────────────────────────────────────────────┐
│                    Docker Host                           │
│                                                          │
│  ┌─────────────────────┐   ┌──────────────────────────┐ │
│  │     AIDR Core        │   │    AIG Sidecar Stack     │ │
│  │  (TypeScript/Node)   │   │                          │ │
│  │                      │   │  ┌────────────────────┐  │ │
│  │  ┌────────────────┐  │   │  │  AIG Server (Go)   │  │ │
│  │  │ Policy Engine  │──┼──┼──│  port 8088          │  │ │
│  │  └────────────────┘  │   │  └────────────────────┘  │ │
│  │         │            │   │                           │ │
│  │  ┌────────────────┐  │   │  ┌────────────────────┐  │ │
│  │  │ AIG Bridge      │──┼──┼──│  AIG Agent (Go)     │  │ │
│  │  │ Client          │  │   │  └────────────────────┘  │ │
│  │  └────────────────┘  │   │                           │ │
│  │                      │   │  ┌────────────────────┐  │ │
│  │  ┌────────────────┐  │   │  │  aig-bridge        │  │ │
│  │  │ Threat Sync     │  │   │  │  (Python/FastAPI)  │  │ │
│  │  └────────────────┘  │   │  │  port 8099          │  │ │
│  └─────────────────────┘   │  └────────────────────┘  │ │
│                            └──────────────────────────┘ │
└─────────────────────────────────────────────────────────┘
```

**Key decisions:**

- AIG runs as a **separate Docker compose stack** within the same Docker network as AIDR
- Python **aig-bridge** service provides a clean REST API for AIDR, abstracting AIG's internal task-based Go API
- AIDR communicates exclusively with the bridge, not directly with AIG's Go server
- The bridge translates AIDR's synchronous-style scan requests into AIG's async task workflow

---

## 2. AIG Service API

The **aig-bridge** (Python/FastAPI) exposes the following endpoints consumed by AIDR:

### 2.1 Infrastructure Scan

```
POST /api/v1/scan/infra
```

Scans AI infrastructure components for known CVEs from the configured AIG vulnerability dataset; the dataset version and count are returned only when the upstream provides verifiable metadata.

**Request:**
```json
{
  "targets": ["https://my-ml-server.com:8080"],
  "scan_type": "full",
  "options": {
    "timeout": 300,
    "headers": {
      "X-Target-Environment": "demo"
    },
    "model": {
      "model": "gpt-4o-mini",
      "token": "<provided-out-of-band>",
      "base_url": "https://api.example.com"
    }
  }
}
```

**Historical example response (not current runtime evidence):**
```json
{
  "task_id": "aig-task-abc123",
  "status": "running",
  "estimated_seconds": 120
}
```

**Result retrieval:** `GET /api/v1/scan/infra/{task_id}`

```json
{
  "task_id": "aig-task-abc123",
  "status": "completed",
  "summary": {
    "total_cves": 1300,
    "matched": 12,
    "critical": 2,
    "high": 5,
    "medium": 3,
    "low": 2
  },
  "findings": [
    {
      "cve_id": "CVE-2024-XXXX",
      "package": "triton-inference-server",
      "version": "2.30.0",
      "severity": "critical",
      "description": "...",
      "remediation": "Upgrade to 2.32.0+"
    }
  ],
  "evidence": [
    {
      "target_url": "https://my-ml-server.com:8080",
      "status_code": 200,
      "title": "Example service",
      "fingerprint": "<aig-fingerprint-or-empty>"
    }
  ]
}
```

### 2.2 MCP Server Scan

```
POST /api/v1/scan/mcp
```

Scans MCP servers for security risks across the versioned AIG knowledge set
(15 records reported by v4.5.1; the local policy compiler currently exposes 14
stable categories).

`categories` is retained for AIDR policy/audit context. It is not interpolated
into the upstream URL or sent as an unsupported v4 field; the upstream MCP
worker evaluates its full rule set.

**Request:**
```json
{
  "target_type": "url",
  "target": "https://mcp-server.example.com/sse",
  "headers": {
    "Authorization": "Bearer <token>"
  },
  "categories": ["prompt_injection", "data_exfiltration", "privilege_escalation"],
  "eval_model": {
    "model": "gpt-4",
    "token": "sk-xxx",
    "base_url": "https://api.openai.com/v1"
  }
}
```

**Historical example response (not current runtime evidence):**
```json
{
  "task_id": "aig-task-mcp-456",
  "status": "running"
}
```

**Result retrieval:** `GET /api/v1/scan/mcp/{task_id}`

```json
{
  "task_id": "aig-task-mcp-456",
  "status": "completed",
  "risk_score": 72,
  "category_breakdown": [
    {
      "category": "prompt_injection",
      "risk": "high",
      "findings": ["MCP tool 'execute_shell' accepts unvalidated user input"]
    },
    {
      "category": "data_exfiltration",
      "risk": "medium",
      "findings": ["Tool 'read_file' returns raw file contents without sanitization"]
    }
  ],
  "summary": "6 of 14 categories have risks; 2 high, 3 medium, 1 low"
}
```

### 2.3 Agent Scan

```
POST /api/v1/scan/agent
```

Runs Agent-Scan on AI agent workflows to detect injection, privilege escalation, and data leakage.

The inline configuration is serialized as provider YAML. For a generic HTTP
agent the v4.5.1 shape is `targets: [{id: "http", config: {url, endpoint,
method, headers, body, transform_response}}]`; the bridge sends this as
`agent_config`, which the Tencent server converts to the worker's
`agent_data` field. A pre-saved `agent_id` is mutually exclusive with inline
configuration.

**Request:**
```json
{
  "agent_config": {
    "targets": [{
      "id": "http",
      "config": {
        "url": "https://agent.example.com",
        "endpoint": "/chat",
        "method": "POST",
        "headers": {"Content-Type": "application/json"},
        "body": {"message": "{{prompt}}"},
        "transform_response": "reply"
      }
    }]
  },
  "eval_model": {
    "model": "gpt-4",
    "token": "sk-xxx",
    "base_url": "https://api.openai.com/v1"
  },
  "language": "en",
  "prompt": "Focus on privilege escalation and data leakage risks"
}
```

**Response:** Same pattern with async task_id.

### 2.4 Jailbreak Evaluation

```
POST /api/v1/evaluate/jailbreak
```

Tests prompt jailbreak resistance using AIG's PromptSecurity evaluation suite.

**Request:**
```json
{
  "target": "https://llm-api.example.com/v1/chat/completions",
  "model": "gpt-4",
  "token": "sk-xxx",
  "base_url": "https://api.openai.com/v1",
  "test_suites": ["jailbreak", "prompt_leak", "role_play_bypass"],
  "language": "en"
}
```

**Response:** Async task_id pattern.

### 2.5 Threat Intel Sync

```
GET /api/v1/threats/latest
```

Returns the latest threat intelligence and scanning rules for AIDR to sync.

**Historical example response (not current runtime evidence):**
```json
{
  "rules_version": "v4.5.1",
  "cve_count": 1891,
  "mcp_risk_categories": [
    {
      "id": "prompt_injection",
      "severity": "critical",
      "description": "MCP tool accepts unvalidated prompt input",
      "aig_pattern": "mcp_prompt_injection_v2"
    }
  ],
  "threat_rules": [
    {
      "id": "aig-001",
      "type": "mcp",
      "pattern": "execute_shell|exec_command|run_process",
      "action": "block",
      "severity": "critical"
    }
  ],
  "last_updated": "2026-05-26T00:00:00Z"
}
```

### 2.6 Health Check

```
GET /api/v1/health
```

**Response:**
```json
{
  "status": "ok",
  "version": "1.0.0",
  "aig_server": "connected",
  "aig_agent": "unknown",
  "scan_ready": true,
  "cve_count": 1891,
  "threat_intel_ready": true
}
```

This response is historical v4.5.1 evidence, not a current readiness example.
The v4.6.1-aidr.1 source adds authenticated worker and dataset
attestation; current `/api/v1/readyz` must reject an unsigned manifest,
missing worker, mismatched runtime tree, or unavailable knowledge API. A
capability task must also complete before advertising a scan type as ready.

---

## 3. Data Flow

### 3.1 On-Demand Scan Flow

```
┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐
│ IDE Agent │──▶│AIDR Plugin│──▶│AIDR Core │──▶│AIG Bridge│──▶│AIG Engine│
│ (request) │   │(hook)    │   │(policy   │   │(FastAPI) │   │(Go/Python)│
└──────────┘   └──────────┘   │engine)   │   └──────────┘   └──────────┘
                               └──────────┘                        │
                                                                    ▼
                                                           ┌──────────────┐
                                                           │  Scan Results │
                                                           │  (async task) │
                                                           └──────────────┘
                                                                    │
                                                                    ▼
                               ┌──────────┐               ┌──────────────┐
                               │ AIDR     │◀──────────────│ AIG Bridge   │
                               │ Policy   │  poll result  │ (poll task)  │
                               │ Engine   │               └──────────────┘
                               └──────────┘
                                    │
                                    ▼
                               ┌──────────┐
                               │ Verdict  │
                               │ (allow/  │
                               │ block/   │
                               │ warn)    │
                               └──────────┘
                                    │
                                    ▼
                               ┌──────────┐
                               │ IDE Agent│
                               │ (response)│
                               └──────────┘
```

### 3.2 Periodic Threat Sync Flow

```
┌──────────┐   every 1h   ┌──────────┐   ┌──────────┐
│ AIDR     │──────────────▶│AIG Bridge│──▶│AIG Server│
│ Threat   │               │  /threats│   │ (rules)  │
│ Sync     │               │  /latest │   └──────────┘
└──────────┘               └──────────┘
     │                           │
     │  New rules/threats        │
     │◀──────────────────────────┘
     ▼
┌──────────────────────────────────────┐
│ AIDR Threat Rule Engine              │
│ • Add new YAML threat definitions    │
│ • Update MCP enforcement policies    │
│ • Refresh CVE database for pkg check │
│ • Update jailbreak detection patterns│
└──────────────────────────────────────┘
```

### 3.3 Detailed Sequence (MCP Scan Example)

```
AIDR Core                  AIG Bridge (8099)           AIG Server (8088)
    │                            │                          │
    │  POST /scan/mcp            │                          │
    │  {target, categories}      │                          │
    │──────────────────────────▶│                          │
    │                            │  POST /api/v1/app/       │
    │                            │  taskapi/tasks           │
    │                            │  {type:"mcp_scan",...}   │
    │                            │─────────────────────────▶│
    │                            │                          │──▶ mcp-scan (Python)
    │                            │  {session_id: "abc"}     │
    │                            │◀─────────────────────────│
    │  {task_id: "abc",          │                          │
    │   status: "running"}      │                          │
    │◀──────────────────────────│                          │
    │                            │                          │
    │  GET /scan/mcp/abc         │                          │
    │  (poll every 5s)          │                          │
    │──────────────────────────▶│                          │
    │                            │  GET /api/v1/app/        │
    │                            │  taskapi/status/abc      │
    │                            │─────────────────────────▶│
    │                            │  {status: "completed",   │
    │                            │   result: {...}}         │
    │                            │◀─────────────────────────│
    │  {status: "completed",    │                          │
    │   findings: [...]}        │                          │
    │◀──────────────────────────│                          │
```

---

## 4. Integration Points with AIDR

### 4.1 Scan Results → Threat Rules

AIG scan findings are translated into AIDR YAML threat definitions at `aidr/threats/`:

| AIG Finding | AIDR Threat Rule |
|------------|------------------|
| MCP tool executes shell commands | New `mcp-exec-shell` threat (severity: critical) |
| Infra CVE detected for package | New `dependency-cve` warning rule |
| Jailbreak bypass succeeds | New `prompt-jailbreak` detection pattern |
| Agent data exfiltration path found | New `data-leak-channel` monitoring rule |

### 4.2 MCP Risk Categories → MCP Enforcement Policy

AIG defines 14 MCP risk categories. These map to AIDR's MCP enforcement policy:

| AIG Category | AIDR Policy Action |
|-------------|-------------------|
| `prompt_injection` | `block` — reject tool calls with injection markers |
| `data_exfiltration` | `block` — block file reads that match PII patterns |
| `privilege_escalation` | `block` — prevent unauthorized state changes |
| `tool_abuse` | `warn` — flag excessive tool invocations |
| `insecure_deserialization` | `block` — reject malformed tool inputs |
| `ssrf` | `block` — restrict outbound URLs to allowlist |
| `supply_chain` | `warn` — flag untrusted MCP servers |
| `runtime_dos` | `monitor` — rate-limit tool calls |
| `credential_leak` | `block` — scrub credentials from tool I/O |
| `path_traversal` | `block` — sanitize file paths |
| `command_injection` | `block` — sanitize shell commands |
| `auth_bypass` | `block` — enforce authentication checks |
| `session_hijack` | `block` — validate session tokens |
| `improper_asset_management` | `warn` — flag untracked assets |

### 4.3 CVE Database → Package Protection

AIG may provide a vulnerability dataset related to AI infrastructure (for example Triton, Ray, vLLM, Ollama, and LangChain). The exact contents and count are deployment evidence, not a static product claim.
AIDR's `package-checker.ts` consumes this via the bridge's threat sync endpoint:

```
Periodic sync → AIG Bridge /threats/latest → AIDR package-checker.ts
    → Updates local CVE cache at ~/.singularity-aidr/cve-cache.json
    → Threat rules reference CVE IDs in package checks
```

### 4.4 Jailbreak Evaluation → Output/PII Detection

AIG's jailbreak evaluation results inform AIDR's output detection. When AIG jailbreak tests reveal
new bypass techniques:

1. AIDR syncs new detection patterns via `/threats/latest`
2. Patterns are added to AIDR's `heuristics.ts` prompt analysis
3. New PII/corporate-data exfiltration patterns are added to allowlist checks

---

## 5. Docker Compose Setup

### 5.1 Service Architecture

```
docker-compose.posture-scanner.yml
├── aig-server      (Go backend, port 8088)
├── aig-bridge      (Python/FastAPI, port 8099)
└── aig-agent       (Go agent, WebSocket connection to aig-server)
```

All services share the internal `aidr-aig-network` control network. A reviewed
egress proxy must join this network and a separate external network; the raw
AIG server has no host port.

### 5.2 Environment Configuration

Copy `.env.posture-scanner.example` to a local `.env.posture-scanner`, then supply the required values.
Keep credentials and signing material out of version control. Configuration is
defined in the local `.env.posture-scanner`:

| Variable | Description | Default |
|----------|-------------|---------|
| `AIG_SOURCE_VERSION` | Pinned owned-source tag | `v4.6.1-aidr.1` |
| `AIG_BIND_ADDRESS` | Authenticated bridge host bind | `127.0.0.1` |
| `AIG_BRIDGE_PORT` | Authenticated bridge host port | `8099` |
| `AIG_TZ` | Timezone | `Asia/Shanghai` |
| `AIG_AGENT_COUNT` | Worker replicas; keep one until distinct live identities are proved | `1` |
| `AIG_AGENT_SHARED_SECRET` | Private server/worker readiness and registration secret | required |
| `AIG_SIGNING_PUBLIC_KEY_HOST_PATH` | Reviewed release public key mounted read-only | required |
| `AIG_TRUSTED_SIGNING_KEY_ID` / `AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256` | Independent signer identity and SPKI pin | required |
| `AIG_EXPECTED_DATA_BUNDLE_ID` / `AIG_EXPECTED_SOURCE_COMMIT` | Release bundle and source pins | required |
| `BRIDGE_AUTH_MODE` / `BRIDGE_JWT_SECRET` / `BRIDGE_JWT_ISSUER` / `BRIDGE_JWT_AUDIENCE` | Production broker authentication | required |
| `BRIDGE_TASK_POSTGRES_DSN` | Migrated, shared task registry and JWT replay-protection store | required for HA |
| `BRIDGE_EGRESS_PROXY_URL` | Reviewed, reachable scanning egress proxy | required |
| `BRIDGE_LOG_LEVEL` | Bridge log level | `INFO` |

### 5.3 Volume Mounts

| Volume | Container Path | Purpose |
|--------|---------------|---------|
| `aig-db` | `/app/db` | SQLite task database |
| `aig-logs` | `/app/logs` | Server logs |
| `aig-uploads` | `/app/uploads` | Uploaded scan files |
| `aig-checker-data` | `/api-checker-data` | Worker checker state |
| `aig-bridge-state` | `/app/state` | Bridge replay/local state |
| `./packages/core/src/generated` | Server `/app/aig-manifest`, bridge `/app/aig-data` | Signed release manifest (read-only bind) |
| `AIG_SIGNING_PUBLIC_KEY_HOST_PATH` | `/run/secrets/aig-signing-public.pem` | Public verification key (read-only bind) |

---

## 6. Monorepo Structure Update

```
aidr/
├── packages/
│   ├── core/                 @singularityrd/aidr-core (unchanged)
│   ├── claude-code/          @singularityrd/aidr-claude-code (unchanged)
│   ├── openclaw/             @singularityrd/aidr-openclaw (unchanged)
│   ├── opencode/             @singularityrd/aidr-opencode (unchanged)
│   ├── extension/            aidr-cursor (unchanged)
│   ├── dashboard/            @singularityrd/aidr-dashboard (unchanged)
│   └── sdk/                  @singularityrd/aidr-sdk (unchanged)
│
├── vendor/
│   └── ai-infra-guard/       # Owned source committed directly in AIDR
│       ├── Dockerfile
│       ├── Dockerfile_Agent
│       ├── docker-compose.yml
│       ├── cmd/              # Go entry points
│       ├── common/           # Go shared libraries
│       ├── mcp-scan/         # MCP scan framework (Python)
│       ├── agent-scan/       # Agent scan framework (Python)
│       ├── AIG-PromptSecurity/ # Jailbreak eval (Python)
│       ├── data/             # CVE DB, fingerprints, rules
│       └── INTEGRATION.md    # NEW: Integration guide
│
├── services/
│   └── aig-bridge/           # NEW: Python/FastAPI bridge service
│       ├── Dockerfile
│       ├── requirements.txt
│       ├── app/
│       │   ├── __init__.py
│       │   ├── main.py
│       │   ├── routers/
│       │   │   ├── __init__.py
│       │   │   ├── scan.py
│       │   │   └── health.py
│       │   ├── models/
│       │   │   ├── __init__.py
│       │   │   └── schemas.py
│       │   └── utils/
│       │       ├── __init__.py
│       │       └── aig_client.py
│       └── README.md
│
├── docker-compose.posture-scanner.yml    # NEW: Docker compose for AIG stack
├── .env.posture-scanner.example          # Safe template for local AIG configuration
├── .env.posture-scanner      # Local AIG configuration; do not commit
│
└── docs/
    └── architecture/
        └── aig-integration.md  # THIS DOCUMENT
```

---

## 7. Security Considerations

### 7.1 Network Security

- All inter-service communication occurs on an isolated Docker bridge network
- Only the authenticated bridge binds to host loopback by default. The raw
  AIG server is internal-only and must never be published directly.
- The worker and server receive egress only through a separately deployed,
  policy-enforcing proxy; Compose does not include that proxy.

### 7.2 API Authentication

- The AIG server has no user-facing authentication layer. Its worker WebSocket
  and internal readiness route require `AIG_AGENT_SHARED_SECRET`, but its
  UI/API must remain private.
- Production AIDR-to-bridge calls use broker tokens and `X-AIDR-Tenant-ID`;
  isolated local mode may use `BRIDGE_API_KEY`. Polling is tenant-scoped and
  `Idempotency-Key` retries are payload-bound.
- All scan requests carry user context for audit logging

### 7.3 Data Isolation

- Scan results remain within the Docker network unless explicitly exported
- AIG's CVE database and rules are read-only from AIDR's perspective
- File uploads for scans are isolated per task

### 7.4 Attribution Requirements

Per AIG's licensing (Apache 2.0 with additional attribution clause):

- Any integration or derivative work must explicitly attribute Tencent Zhuque Lab
- Attribution must appear in documentation and user interface
- See `vendor/ai-infra-guard/NOTICE` for full requirements

---

## 8. Adding New Scan Types

To add a new scan type to the integration:

1. **Implement the scanner** in AIG (Go backend or Python module)
2. **Register a new route** in `common/websocket/api.go` with the task type
3. **Add a new endpoint** in `services/aig-bridge/app/routers/scan.py`
4. **Add request/response models** in `services/aig-bridge/app/models/schemas.py`
5. **Add AIDR client integration** in appropriate `packages/core/src/clients/`
6. **Add threat rules** in `aidr/threats/` if scan findings map to policy actions
7. **Document** the new endpoint in this architecture document

---

## 9. Deployment Architecture

### 9.1 Development

```bash
# AIG source is included directly in the AIDR checkout.
pnpm compile:aig
pnpm aig:verify

# Start the AIG sidecar stack
# Create .env.posture-scanner from .env.posture-scanner.example if no local file exists, then fill it.
$env:BRIDGE_API_KEY='generate-a-long-random-secret'
docker compose --env-file .env.posture-scanner -f docker-compose.posture-scanner.yml up -d --build

# Verify connectivity
curl -H 'Authorization: Bearer ...' -H 'X-AIDR-Tenant-ID: demo-tenant' http://127.0.0.1:8099/api/v1/health

# AIDR connects automatically via AIG_BRIDGE_URL env
```

### 9.2 Production

```bash
# Use a reviewed Linux build and immutable image digests, with:
# - Resource limits set (CPU/memory)
# - Persistent volumes for CVE database and task state
# - A private authenticated ingress for the bridge only
# - No public AIG server/UI port (upstream has no auth)
# - Monitoring, log shipping and health checks configured for orchestration
# - A durable task/tenant store before scaling the bridge or agent
```

### 9.3 Kubernetes

For Kubernetes deployments, the three services (`aig-server`, `aig-agent`, `aig-bridge`) can be
deployed as a single pod with init containers, or as separate deployments with a shared service.
The bridge's REST API is exposed via a ClusterIP service.
