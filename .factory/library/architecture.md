# Architecture

## System Overview

Singularity AIDR is a multi-platform AI Agent Detection & Response layer with three connectors sharing a common core:

**Components:**
- **Core Library** (`packages/core/`) — Platform-agnostic detection engine
- **Claude Code Connector** — Hook-based integration for Claude CLI
- **OpenClaw Connector** — In-process plugin for OpenClaw gateway
- **OpenCode Connector** — Plugin for OpenCode IDE
- **VS Code/Cursor Extension** — Editor extension for IDE integration

## Data Flow

### Claude Code Path
```
Hook stdin → extract artifacts → check allowlist → check cache → 
heuristics + URL check → DecisionEngine → cache result → audit log → hook stdout JSON
```

### OpenClaw Path
```
before_tool_call event → extract artifacts → check approval store → 
check allowlist → check cache → heuristics + URL check → DecisionEngine → 
cache result → audit log → block/pass
```

## Key Modules

**Detection Pipeline:**
- `extractors.ts` — Extract URLs, commands, file paths from tool inputs
- `heuristics.ts` — Match artifacts against threat patterns
- `engine.ts` — Decision engine combining signals into verdicts
- `clients/url-check.ts` — HTTP client for URL reputation

**Threat Intelligence:**
- `threat-loader.ts` — Load YAML threat definitions from `threats/`
- `intel/provider.ts` — Threat intelligence provider interface
- `community-rules.ts` — Community-contributed threat rules

**Behavioral Analysis:**
- `novelty-detection.ts` — User behavior profiling and anomaly detection
- `behavioral/pattern-matcher.ts` — Pattern matching for behavioral anomalies
- `behavioral/baseline.ts` — User behavior baseline establishment

**ML Components:**
- `ml/embedder.ts` — Text embedding generation
- `ml/similarity.ts` — Cosine similarity and vector operations
- `ml-model.ts` — ML model loading and inference

**Response & Containment:**
- `quarantine.ts` — File quarantine operations
- `contain.ts` — Process containment
- `rollback.ts` — Change rollback capabilities
- `response-config.ts` — Response action configuration

**Observability:**
- `tracing.ts` — OpenTelemetry distributed tracing
- `sentry.ts` — Error tracking integration
- `metrics.ts` — Prometheus metrics collection
- `audit-log.ts` — JSONL audit logging

**Infrastructure:**
- `rule-sync.ts` — Real-time threat rule synchronization from CDN
- `cache.ts` — Verdict caching with TTL
- `allowlist.ts` — User allowlist management
- `config.ts` — Configuration management

## Data Flow Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    AIDR Core v2.0                        │
├─────────────────────────────────────────────────────────┤
│  Detection Engine    │   Policy Engine    │   Response   │
│  • Pattern Match     │   • RBAC/DLP      │   • Block    │
│  • ML/AI (300KB)     │   • Compliance    │   • Quarantine│
│  • Behavioral        │   • Custom Rules  │   • Contain  │
│  • Threat Intel      │                   │   • Rollback │
├─────────────────────────────────────────────────────────┤
│         OpenTelemetry + Prometheus + Sentry              │
├─────────────────────────────────────────────────────────┤
│  Universal SDK  │  LangChain  │  LlamaIndex  │  AutoGen   │
│  CrewAI         │  Generic    │  REST API    │  CLI       │
└─────────────────────────────────────────────────────────┘
```

## Design Principles

1. **Fail-open**: Every internal error returns allow verdict; hooks exit code 0
2. **Data-driven**: Detection patterns in YAML (`threats/`), not hardcoded
3. **Three decisions**: `allow`, `deny`, `ask` with confidence scoring
4. **Sensitivity presets**: paranoid (0.70), balanced (0.85), relaxed (0.95)
5. **Merge precedence**: `deny > ask > allow`

## Naming Conventions

- YAML/JSON data: `snake_case` (`threat_id`, `source_file`)
- TypeScript interfaces: `camelCase` (`threatId`, `sourceFile`)
- Conversion functions bridge at serialization boundaries
