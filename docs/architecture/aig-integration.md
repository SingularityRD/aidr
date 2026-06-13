# AIG (AI-Infra-Guard) Integration Architecture

> **Status:** Implementing | **Updated:** 2026-05-26
> **Owners:** AIDR Core Team, AIG Integration Team

## 1. Overview

This document defines the integration architecture between **Singularity AIDR** (TypeScript monorepo, runtime security layer for AI coding agents) and **Tencent AI-Infra-Guard (AIG)** (Python/Go scanning platform for AI infrastructure).

The combined product is positioned as **"the most comprehensive AI agent security platform"** — AIDR provides real-time agent threat protection across multiple IDE platforms, while AIG contributes deep infrastructure scanning, MCP security analysis, Agent-Scan, and jailbreak evaluation.

### 1.1 Design Principles

| Principle | Description |
|-----------|-------------|
| **Non-invasive** | AIDR core remains unchanged; AIG functions as an external service |
| **On-demand scanning** | AIG scans are triggered by AIDR policy decisions, not inline in agent execution |
| **Loose coupling** | REST API between AIDR and AIG; no shared runtime or process |
| **Async by default** | Long-running scans return a task ID; results are polled or pushed |
| **Attribution required** | All integrations must attribute Tencent Zhuque Lab per AIG's NOTICE file |

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

Scans AI infrastructure components for known CVEs (1300+ entries from AIG's vulnerability database).

**Request:**
```json
{
  "targets": ["https://my-ml-server.com:8080"],
  "scan_type": "full",
  "options": {
    "timeout_seconds": 300,
    "depth": "standard"
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
  ]
}
```

### 2.2 MCP Server Scan

```
POST /api/v1/scan/mcp
```

Scans MCP servers for security risks across 14 risk categories defined by AIG.

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

**Request:**
```json
{
  "agent_config": {
    "provider": "dify",
    "base_url": "https://agent.example.com",
    "api_key": "app-xxx"
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
  "rules_version": "2026-05-26-001",
  "cve_count": 1342,
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
  "aig_agent": "connected",
  "scan_ready": true,
  "cve_count": 1342
}
```

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

AIG maintains a database of 1300+ CVEs related to AI infrastructure (Triton, Ray, vLLM, Ollama, LangChain, etc.).
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
| `AIG_AGENT_COUNT` | Number of agent workers | `2` |
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
- The bridge service does not expose ports to the host; only AIDR connects via the internal network
- AIG server port 8088 is exposed only for monitoring/debugging

### 7.2 API Authentication

- Bridge-to-AIG calls include an `api_key` header validated by AIG's middleware
- AIDR-to-bridge calls use a shared secret (`AIG_BRIDGE_API_KEY` env var)
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
# Clone AIG into vendor directory
git submodule add https://github.com/Tencent/AI-Infra-Guard vendor/ai-infra-guard

# Start the AIG sidecar stack
docker compose -f docker-compose.aig.yml up -d

# Verify connectivity
curl http://localhost:8099/api/v1/health

# AIDR connects automatically via AIG_BRIDGE_URL env
```

### 9.2 Production

```bash
# Same Docker compose stack, with:
# - Resource limits set (CPU/memory)
# - Persistent volumes for CVE database
# - Monitoring via Prometheus metrics endpoint
# - Log shipping to centralized logging
# - Health checks configured for orchestration
```

### 9.3 Kubernetes

For Kubernetes deployments, the three services (`aig-server`, `aig-agent`, `aig-bridge`) can be
deployed as a single pod with init containers, or as separate deployments with a shared service.
The bridge's REST API is exposed via a ClusterIP service.
