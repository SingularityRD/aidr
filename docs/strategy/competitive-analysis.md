# AI Agent Security Competitive Analysis

> Last Updated: March 2026  
> Scope: AI Agent Detection & Response (AIDR) Market Analysis

---

## Executive Summary

The AI agent security market is rapidly evolving with several established players targeting different segments. Singularity AIDR competes in the **runtime detection & response** layer for AI agents, with a differentiated focus on **privacy-first, multi-platform, lightweight** protection.

---

## Competitor Deep-Dive

### 1. LLM Guard (Protect AI)

**Overview:** Open-source security toolkit for LLM interactions, now part of Protect AI's commercial platform.

| Category | Assessment |
|----------|------------|
| **Positioning** | Enterprise firewall for LLM applications |
| **Core Features** | Input/output scanners, PII anonymization, prompt injection detection, content moderation, secret redaction |
| **Architecture** | API or library deployment; CPU-optimized inference |
| **Integration** | LangChain, Azure OpenAI, Bedrock, etc. |

**Strengths:**
- ✅ Mature open-source community (2.5M+ downloads)
- ✅ 5x lower inference cost vs GPU (CPU-optimized)
- ✅ Extensive scanner library (regex + ML-based)
- ✅ Easy API/Library deployment model
- ✅ Strong enterprise sales motion

**Weaknesses:**
- ❌ Not agent-aware (focused on LLM API calls, not agent actions)
- ❌ Heavyweight for local IDE deployment
- ❌ Cloud-first architecture; requires API calls
- ❌ No behavioral analysis or anomaly detection
- ❌ Limited platform support (no IDE plugins)

**Pricing:**
- Open Source: Free (Apache 2.0)
- Enterprise: Custom pricing (contact sales)
- Hosted API: Usage-based

---

### 2. Langfuse

**Overview:** Open-source LLM engineering platform focused on observability, tracing, and evaluation.

| Category | Assessment |
|----------|------------|
| **Positioning** | LLM observability, tracing, prompt management |
| **Core Features** | Traces/graphs, session tracking, token/cost tracking, prompt versioning, evals, datasets |
| **Architecture** | Cloud-hosted or self-hosted (Docker) |
| **Integration** | OpenTelemetry, LangChain, OpenAI SDK, LiteLLM |

**Strengths:**
- ✅ Excellent observability and tracing capabilities
- ✅ Strong open-source traction (40,000+ builders)
- ✅ Comprehensive evaluation framework (LLM-as-judge, human annotation)
- ✅ Prompt management and versioning
- ✅ Multi-modal support
- ✅ SOC2 Type II & ISO27001 compliant

**Weaknesses:**
- ❌ Not a security product (observability-focused)
- ❌ No real-time threat detection
- ❌ No command/file protection for agents
- ❌ No prevention/blocking capabilities
- ❌ Requires cloud connectivity for most features

**Pricing:**
- Hobby: Free (50k units/month, 30-day retention)
- Core: $29/month (100k units, 90-day retention)
- Pro: $199/month + $300 Teams add-on (SSO, RBAC)
- Enterprise: $2,499/month (custom limits, SLA)
- Additional usage: $8/100k units

---

### 3. Portkey

**Overview:** AI gateway with observability, routing, and guardrails for production AI apps.

| Category | Assessment |
|----------|------------|
| **Positioning** | Control panel for production AI |
| **Core Features** | Universal API, routing, fallbacks, caching, guardrails, prompt management, cost tracking |
| **Architecture** | Cloud gateway or self-hosted (open source core) |
| **Integration** | 200+ LLMs via unified API |

**Strengths:**
- ✅ Production-ready AI gateway (fast, reliable)
- ✅ Excellent cost optimization (caching, smart routing)
- ✅ Simple 3-line integration
- ✅ Open-source core available
- ✅ Strong enterprise features (SSO, RBAC, VPC)
- ✅ SOC2 Type 2, GDPR, HIPAA compliant

**Weaknesses:**
- ❌ Gateway-focused, not agent-aware
- ❌ No file system or command protection
- ❌ Limited to API-level protection
- ❌ Requires routing traffic through gateway
- ❌ No local/IDE deployment option

**Pricing:**
- Developer: Free (10k logs/month, 3-day retention)
- Production: $49/month (100k logs, 30-day retention)
- Enterprise: Custom pricing (10M+ logs, custom retention)
- Overages: $9/100k requests (up to 3M)

---

### 4. LunaSec

**Overview:** Open-source data security platform focused on dependency scanning and vulnerability detection.

| Category | Assessment |
|----------|------------|
| **Positioning** | Data security & dependency vulnerability scanner |
| **Core Features** | LunaTrace (dependency scanner), secrets detection, supply chain security |
| **Architecture** | GitHub App + CLI scanner |
| **Integration** | GitHub, CI/CD pipelines |

**Strengths:**
- ✅ Strong at dependency vulnerability detection
- ✅ Log4Shell/node-ipc type threat detection
- ✅ Open-source community
- ✅ PR-based notifications

**Weaknesses:**
- ❌ Not AI-agent specific
- ❌ No runtime protection
- ❌ No behavioral analysis
- ❌ Limited to supply chain, not operational security
- ❌ No command/URL/file protection

**Pricing:**
- Open Source: Free
- LunaTrace: Free tier + Enterprise (custom)

---

### 5. HiddenLayer

**Overview:** Enterprise AI security platform with ML-based threat detection.

| Category | Assessment |
|----------|------------|
| **Positioning** | Enterprise AI security & threat prevention |
| **Core Features** | Model security, runtime defense, supply chain security, automated red teaming, AIDR (Agent Detection & Response) |
| **Architecture** | Cloud/SaaS with enterprise deployment options |
| **Integration** | API-based, model serving platforms |

**Strengths:**
- ✅ Comprehensive AI security platform
- ✅ ML-based threat detection (patented)
- ✅ Runtime defense capabilities
- ✅ Automated red teaming
- ✅ Strong enterprise traction
- ✅ AWS Marketplace presence

**Weaknesses:**
- ❌ Enterprise-focused (high cost, complex deployment)
- ❌ Not IDE-integrated
- ❌ Heavyweight architecture
- ❌ Requires cloud connectivity
- ❌ No privacy-first local processing option

**Pricing:**
- Enterprise-only: Contact sales
- AWS Marketplace: Available (custom pricing)

---

### 6. Protect AI

**Overview:** Comprehensive AI security platform (parent company of LLM Guard).

| Category | Assessment |
|----------|------------|
| **Positioning** | Broadest AI security solution |
| **Core Features** | Model scanning, LLM Guard, supply chain security, governance, training data protection |
| **Architecture** | Enterprise SaaS platform |
| **Integration** | ML pipelines, model serving, API gateways |

**Strengths:**
- ✅ Unified platform approach
- ✅ Strong research team (ML security experts)
- ✅ Model scanning & vulnerability detection
- ✅ Governance & compliance features
- ✅ Good documentation and playbooks

**Weaknesses:**
- ❌ Complex, multi-product platform
- ❌ Not focused on agent runtime protection
- ❌ No lightweight IDE integration
- ❌ Enterprise sales cycle
- ❌ No privacy-first local mode

**Pricing:**
- LLM Guard Open Source: Free
- Platform: Custom enterprise pricing

---

## Feature Comparison Matrix

| Feature | Singularity AIDR | LLM Guard | Langfuse | Portkey | LunaSec | HiddenLayer | Protect AI |
|---------|-----------------|-----------|----------|---------|---------|-------------|------------|
| **Runtime Detection** | ✅ | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ |
| **Agent-Aware** | ✅ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Command Protection** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **File System Protection** | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **URL/Network Protection** | ✅ | ✅ | ❌ | ❌ | ❌ | ✅ | ✅ |
| **Local Processing** | ✅ | ⚠️ | ❌ | ⚠️ | ✅ | ❌ | ❌ |
| **IDE Integration** | ✅ (3 platforms) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Privacy-First** | ✅ | ⚠️ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Lightweight** | ✅ (<1MB) | ❌ | ❌ | ❌ | ✅ | ❌ | ❌ |
| **Behavioral Analysis** | 🔄 (Q2 2026) | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **Policy as Code** | 🔄 (Q2 2026) | ❌ | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Open Source** | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ⚠️ |
| **Self-Hostable** | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️ | ⚠️ |

Legend: ✅ Available | ❌ Not Available | ⚠️ Partial | 🔄 Roadmap

---

## Singularity AIDR Differentiation

### Core Differentiators

#### 1. Privacy-First Architecture
- **Zero data exfiltration**: All detection runs locally
- **No API keys required**: Optional URL check, no telemetry requirement
- **Local embeddings**: 300KB lightweight models (Q1 2026)
- **No cloud dependency**: Works fully offline

#### 2. Multi-Platform IDE Integration
- **Claude Code**: Native hook integration
- **Cursor**: VS Code extension
- **OpenClaw**: Plugin connector
- **Unified core**: Single detection engine across all platforms

#### 3. Agent-Specific Protection
- Command-level detection (shell, file, web requests)
- Behavioral baselines (Q2 2026)
- Action context awareness
- Deep IDE integration (not just API gateway)

#### 4. Lightweight & Fast
- **<1MB runtime**: Single-file esbuild bundles
- **<50ms latency**: Rule-based heuristics + optional ML
- **No containers**: Native Node.js/TypeScript
- **CPU-optimized**: No GPU required

#### 5. Data-Driven Detection
- **YAML threat rules**: Community-contributed patterns
- **Semantic analysis**: Embeddings for unknown threats
- **Heuristic engine**: Regex + ML hybrid approach

---

## Market Positioning

```
                    High Complexity
                           │
     HiddenLayer           │           Protect AI
     (Enterprise)           │           (Enterprise)
                           │
───────────────────────────┼───────────────────────────
                           │
     Langfuse              │           Portkey
     (Observability)       │           (Gateway)
                           │
                    Low Complexity
                           │
        ┌──────────────────┴──────────────────┐
        │      SINGULARITY AIDR               │
        │  (Privacy-First, Multi-Platform)    │
        └─────────────────────────────────────┘
                           │
     LunaSec               │           LLM Guard
     (Supply Chain)        │           (API Firewall)
                           │
                    Low Agent Awareness
```

---

## Strategic Recommendations

### 1. Double Down on Privacy-First Positioning
- Market heavily on "zero data exfiltration" guarantee
- Competitive comparison: AIDR vs. cloud-only solutions
- Target: Security-conscious enterprises, regulated industries

### 2. Expand Platform Coverage
- Add GitHub Copilot integration
- Support JetBrains IDEs
- Add standalone CLI for CI/CD

### 3. Community-Driven Threat Intelligence
- Open-source threat rule repository
- Community contributions (like Snort rules for AI)
- Threat bounty program

### 4. Keep Price-Performance Advantage
- Maintain free tier for individuals
- 10x cheaper than enterprise competitors
- Transparent pricing vs. "contact sales"

### 5. Build Switching Costs via IDE Integration
- Deep plugin integration creates friction to leave
- Custom rule sharing within teams
- Audit log history and policy versioning

---

## Appendix: Pricing Summary

| Product | Starting Price | Enterprise Pricing |
|---------|---------------|-------------------|
| Singularity AIDR | Free (individual) | $50/seat (Enterprise) |
| LLM Guard | Free (OSS) | Custom |
| Langfuse | Free | $2,499/mo |
| Portkey | Free | Custom |
| LunaSec | Free | Custom |
| HiddenLayer | N/A | Custom |
| Protect AI | Free (OSS) | Custom |

---

*Document maintained by Product Strategy team. Update quarterly.*
