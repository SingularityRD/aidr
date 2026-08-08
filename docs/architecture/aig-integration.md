# AIG (AI-Infra-Guard) Integration Architecture

> **Status:** Implementing — Tencent AIG v4.5.1 runtime verified locally | **Updated:** 2026-08-04
> **Owners:** AIDR Core Team, AIG Integration Team

## 1. Overview

This document defines the integration architecture between **Singularity AIDR** (TypeScript monorepo, runtime security layer for AI coding agents) and **Tencent AI-Infra-Guard (AIG)** (Python/Go scanning platform for AI infrastructure).

The integration combines AIDR's local agent controls with optional AIG-backed infrastructure, MCP, Agent-Scan, and jailbreak evaluation. Any dataset size, platform coverage, or real-time claim must be tied to a versioned evidence record before it is used in customer or investor material.

### 1.1 Design Principles

| Principle | Description |
|-----------|-------------|
| **Non-invasive** | AIDR core remains unchanged; AIG functions as an external service |
| **On-demand scanning** | AIG scans are triggered by AIDR policy decisions, not inline in agent execution |
| **Loose coupling** | REST API between AIDR and AIG; no shared runtime or process |
| **Async by default** | Long-running scans return a task ID; results are polled or pushed |
| **Attribution required** | All integrations must attribute Tencent Zhuque Lab per AIG's NOTICE file |

### 1.3 Verified upstream contract (2026-08-04)

The integration is pinned to the official Tencent repository at tag `v4.5.1`,
commit `31c72a9799c8b19d89bcb331d4f8038f05462b8f`. The checkout is recorded as
the `vendor/ai-infra-guard` submodule and is verified by `pnpm aig:verify`.
The current compiler evidence is 1,925 CVE entries across 108 frameworks, 133
fingerprints and 14 local MCP categories. The running AIG knowledge API reports
1,891 vulnerability records and 15 MCP knowledge records; these are upstream
runtime counts and must not be conflated with the generated consumer index.

Tencent's v4 task API uses `target` (singular), `timeout`, optional `headers`,
and an optional `model` object. A model is required when the upstream has no
default model. The bridge translates its public `targets` request into this
allow-listed payload, normalizes AIG's `doing`/`done` states to
`running`/`completed`, and exposes non-secret fingerprint evidence in the
result response. The v4.5.1 server has no authentication layer; it must remain
on the private Docker network and its optional host bind defaults to loopback.

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

The upstream data tree contains case-colliding paths (for example `Dify` and
`dify`, `LiteLLM` and `litellm`). A Linux build worker is required for complete
case-sensitive source reproducibility; the verification command emits an
explicit warning when those groups are present.

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

**Response:**
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

**Response:**
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

**Response:**
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

Tencent v4.5.1 exposes no authenticated worker-list/health endpoint, so the
bridge intentionally reports `aig_agent: "unknown"`; `/api/v1/readyz` proves
the server/auth boundary only. A capability task must complete before that
scan type is advertised as ready.

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
docker-compose.aig.yml
├── aig-server      (Go backend, port 8088)
├── aig-bridge      (Python/FastAPI, port 8099)
└── aig-agent       (Go agent, WebSocket connection to aig-server)
```

All services share the `aidr-aig-network` bridge network.

### 5.2 Environment Configuration

Defined in `.env.aig`:

| Variable | Description | Default |
|----------|-------------|---------|
| `AIG_SERVER_PORT` | AIG Go server port | `8088` |
| `AIG_BRIDGE_PORT` | Python bridge port | `8099` |
| `AIG_DB_PATH` | SQLite database path | `/app/db/tasks.db` |
| `AIG_UPLOAD_DIR` | File upload directory | `/app/uploads` |
| `AIG_LOG_DIR` | Log directory | `/app/logs` |
| `AIG_TZ` | Timezone | `Asia/Shanghai` |
| `AIG_AGENT_COUNT` | Number of agent workers (v4.5.1 must remain `1` because registration ID is hard-coded) | `1` |
| `BRIDGE_LOG_LEVEL` | Bridge log level | `INFO` |
| `BRIDGE_AIG_URL` | AIG server URL for bridge | `http://aig-server:8088` |

### 5.3 Volume Mounts

| Volume | Container Path | Purpose |
|--------|---------------|---------|
| `aig-data` | `/app/data` | CVE database, fingerprints, rules |
| `aig-db` | `/app/db` | SQLite task database |
| `aig-logs` | `/app/logs` | Server logs |
| `aig-uploads` | `/app/uploads` | Uploaded scan files |
| `aig-agent-data` | `/app/data` | Agent scan data (read-only) |

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
│   └── ai-infra-guard/       # Cloned AIG repository (git submodule)
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
├── docker-compose.aig.yml    # NEW: Docker compose for AIG stack
├── .env.aig                  # NEW: Environment variables for AIG
│
└── docs/
    └── architecture/
        └── aig-integration.md  # THIS DOCUMENT
```

---

## 7. Security Considerations

### 7.1 Network Security

- All inter-service communication occurs on an isolated Docker bridge network
- The bridge and AIG server host binds default to `127.0.0.1`; set
  `AIG_BIND_ADDRESS` only behind an authenticated private ingress
- The upstream AIG server is unauthenticated, so a public `8088` bind is a
  release blocker; the AIDR bridge remains the authenticated ingress

### 7.2 API Authentication

- Tencent AIG v4.5.1 does not validate an API key. Treat the AIG server and
  agent network as private infrastructure and never publish its UI/API.
- AIDR-to-bridge calls use `BRIDGE_API_KEY` plus `X-AIDR-Tenant-ID`; polling is
  tenant-scoped and `Idempotency-Key` retries are payload-bound.
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
# Initialize the pinned AIG submodule
git submodule update --init --recursive
pnpm compile:aig
pnpm aig:verify

# Start the AIG sidecar stack
$env:BRIDGE_API_KEY='generate-a-long-random-secret'
docker compose --env-file .env.aig -f docker-compose.aig.yml up -d --build

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
