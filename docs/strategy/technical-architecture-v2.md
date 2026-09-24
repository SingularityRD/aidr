# Singularity AIDR Technical Architecture v2

> Technical architecture blueprint for 2026 product evolution
> Version: 2.0 | Last Updated: March 2026

> Historical blueprint, not the current architecture contract. Deployment,
> data-flow, failure-mode and performance claims below require current code and
> candidate-bound evidence; see [privacy](../privacy.md) and the
> [first-customer packet](../production-readiness/first-customer-sales-packet-v8.md).

---

## Architecture Principles

1. **Privacy by Design**: Local heuristics plus explicitly inventoried outbound flows
2. **Failure behavior**: Detection-leg outages can require review; never label an unrun check clean
3. **Performance**: Set latency and package-size targets against a defined workload and signed artifact
4. **Multi-Platform**: Single core, multiple connector implementations
5. **Zero Trust**: Optional sandboxing, strict least-privilege

---

## System Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         SINGULARITY AIDR v2                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                     CONNECTOR LAYER                                 │   │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐             │   │
│  │  │ Claude Code  │  │   Cursor/VS  │  │  OpenClaw    │             │   │
│  │  │   Hook       │  │  Extension   │  │   Plugin     │             │   │
│  │  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘             │   │
│  │         │                  │                  │                      │   │
│  │         └──────────────────┼──────────────────┘                      │   │
│  │                            │                                        │   │
│  │                     ┌──────▼───────┐                                │   │
│  │                     │   Core API   │                                │   │
│  │                     │  (TypeScript)  │                                │   │
│  │                     └──────┬───────┘                                │   │
│  │                            │                                        │   │
│  └────────────────────────────┼────────────────────────────────────────┘   │
│                               │                                           │
│  ┌────────────────────────────▼────────────────────────────────────────┐ │
│  │                      CORE ENGINE LAYER                               │ │
│  │                                                                      │ │
│  │  ┌────────────────────────────────────────────────────────────────┐ │ │
│  │  │                    DETECTION PIPELINE                          │ │ │
│  │  │                                                                  │ │ │
│  │  │   ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │ │ │
│  │  │   │  Extractors  │ -> │  Heuristics  │ -> │    Engine    │  │ │ │
│  │  │   │              │    │              │    │              │  │ │ │
│  │  │   │ • URLs       │    │ • Patterns   │    │ • Verdict    │  │ │ │
│  │  │   │ • Commands   │    │ • Embeddings │    │ • Confidence │  │ │ │
│  │  │   │ • File paths │    │ • Behaviors  │    │ • Signal     │  │ │ │
│  │  │   └──────────────┘    └──────────────┘    └──────────────┘  │ │ │
│  │  │                                                                  │ │ │
│  │  └────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                      │ │
│  │  ┌────────────────────────────────────────────────────────────────┐ │ │
│  │  │                    INTELLIGENCE MODULES                        │ │ │
│  │  │                                                                  │ │ │
│  │  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐         │ │ │
│  │  │  │  Rule-Based  │  │    ML/AI     │  │ Behavioral   │         │ │ │
│  │  │  │   Engine     │  │   Engine     │  │   Analysis   │         │ │ │
│  │  │  ├──────────────┤  ├──────────────┤  ├──────────────┤         │ │ │
│  │  │  │ YAML Threats │  │ 300KB Model  │  │ SQLite Store │         │ │ │
│  │  │  │ Regex Match  │  │ ONNX Runtime │  │  Baselines   │         │ │ │
│  │  │  │ Allowlists   │  │ Cosine Sim   │  │  Anomalies   │         │ │ │
│  │  │  └──────────────┘  └──────────────┘  └──────────────┘         │ │ │
│  │  │                                                                  │ │ │
│  │  └────────────────────────────────────────────────────────────────┘ │ │
│  │                                                                      │ │
│  └──────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
│  ┌──────────────────────────────────────────────────────────────────────┐ │
│  │                      ENTERPRISE & CLOUD LAYER                        │ │
│  │                                                                        │ │
│  │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐              │ │
│  │   │     SSO      │  │   Policy     │  │    Cloud     │              │ │
│  │   │   (OAuth)    │  │    as Code   │  │   Service    │              │ │
│  │   ├──────────────┤  ├──────────────┤  ├──────────────┤              │ │
│  │   │ GitHub OAuth │  │ YAML Config  │  │   Managed    │              │ │
│  │   │ GitLab OAuth │  │ Git Versioned│  │   Tenant     │              │ │
│  │   │ SAML (Okta)  │  │ Drift Detect │  │   SaaS       │              │ │
│  │   └──────────────┘  └──────────────┘  └──────────────┘              │ │
│  │                                                                        │ │
│  └────────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Component Deep Dive

### 1. Lightweight ML Detection

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│               ML DETECTION MODULE                           │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌──────────────────┐      ┌──────────────────────────┐  │
│  │   EMBEDDING      │      │     DETECTION CORE       │  │
│  │     MODEL        │      │                          │  │
│  ├──────────────────┤      │  ┌────────────────────┐  │  │
│  │ Model:           │      │  │  Similarity Search │  │  │
│  │ TinyBERT-style   │      │  │  • Cosine distance │  │  │
│  │                  │      │  │  • Threshold: 0.85 │  │  │
│  │ Size: 300KB      │      │  └────────────────────┘  │  │
│  │ Format: ONNX     │      │                          │  │
│  │ Runtime:         │      │  ┌────────────────────┐  │  │
│  │ ONNX Runtime     │      │  │   Threat Vectors   │  │  │
│  │                  │      │  │  (Pre-computed)    │  │  │
│  │ Latency: <10ms   │      │  │                    │  │  │
│  └────────┬─────────┘      │  │  • 10k malicious   │  │  │
│           │                │  │    command embeds  │  │  │
│           v                │  │  • 50k malicious   │  │  │
│  ┌──────────────────┐      │  │    URL embeds      │  │  │
│  │  INPUT TEXT      │      │  │  • 5k suspicious   │  │  │
│  │  (cmd/url/path)  │      │  │    file patterns   │  │  │
│  └──────────────────┘      │  └────────────────────┘  │  │
│                            │                          │  │
│                            └──────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Technical Specifications

| Aspect | Specification |
|--------|--------------|
| Model Architecture | Distilled transformer (4 layers, 256 hidden) |
| Embedding Dimensions | 256D float32 |
| Vocabulary | 30k BPE tokens |
| Max Sequence Length | 128 tokens |
| Inference Time | <10ms (CPU) |
| Memory Footprint | 300KB model + 10MB runtime |
| Threat Vector DB | 50k entries, 20MB total |

---

### 2. Behavioral Analysis Engine

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│           BEHAVIORAL ANALYSIS MODULE                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────────────────────────────────────────┐  │
│  │              DATA COLLECTION LAYER                  │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  • Command sequences (cmd, args, cwd, timestamp)   │  │
│  │  • File access patterns (path, operation, size)    │  │
│  │  • Network requests (domain, method, frequency)    │  │
│  │  • Time patterns (hour-of-day, day-of-week)      │  │
│  │  • Project context (repo, branch, language)      │  │
│  └────────────────────────┬───────────────────────────────┘  │
│                           │                                 │
│                           v                                 │
│  ┌────────────────────────────────────────────────────┐  │
│  │                 STORAGE LAYER                      │  │
│  ├────────────────────────────────────────────────────┤  │
│  │                                                    │  │
│  │   SQLite Database (~/.singularity-aidr/)         │  │
│  │                                                    │  │
│  │   Tables:                                          │  │
│  │   • events (id, type, data, timestamp)            │  │
│  │   • baselines (user_id, metric, value, std_dev)  │  │
│  │   • anomalies (id, score, reason, acknowledged)    │  │
│  │                                                    │  │
│  │   Retention: 30 days (configurable)              │  │
│  │   Encryption: AES-256 at rest                      │  │
│  │                                                    │  │
│  └────────────────────────┬───────────────────────────────┘  │
│                           │                                 │
│                           v                                 │
│  ┌────────────────────────────────────────────────────┐  │
│  │              ANOMALY DETECTION                     │  │
│  ├────────────────────────────────────────────────────┤  │
│  │                                                    │  │
│  │   Statistical Methods:                             │  │
│  │   • Z-score (>3σ = anomaly)                        │  │
│  │   • Moving average (7-day window)                  │  │
│  │   • Frequency analysis (commands/hour)           │  │
│  │                                                    │  │
│  │   Anomaly Score: 0-1 (1 = high anomaly)          │  │
│  │                                                    │  │
│  └────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### Baseline Establishment

| Phase | Duration | Activities |
|-------|----------|------------|
| Learning | Days 1-7 | Collect initial patterns, no alerts |
| Calibration | Days 8-14 | Tune thresholds, reduce false positives |
| Active | Day 15+ | Full anomaly detection enabled |

---

### 3. Zero-Trust Security Layer

#### Optional Sandboxing

```
┌─────────────────────────────────────────────────────────────┐
│            SANDBOX EXECUTION LAYER                        │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────────────────────────────────────────┐  │
│  │           PRE-EXECUTION VERIFICATION               │  │
│  ├────────────────────────────────────────────────────┤  │
│  │  1. Checksum validation (if known good hash)      │  │
│  │  2. Signature verification (if signed)          │  │
│  │  3. Reputation check (URL/IP lookup)              │  │
│  │  4. Static analysis (if binary/script)            │  │
│  └────────────────────────┬───────────────────────────────┘  │
│                           │                                 │
│           ┌───────────────┴───────────────┐                 │
│           │                               │                 │
│           v                               v                 │
│  ┌───────────────┐            ┌───────────────┐            │
│  │   ALLOWED     │            │   SUSPICIOUS  │            │
│  │   (Direct     │            │   (Sandbox    │            │
│  │    Exec)      │            │    Required)   │            │
│  └───────┬───────┘            └───────┬───────┘            │
│          │                            │                    │
│          v                            v                    │
│  ┌───────────────┐            ┌───────────────┐            │
│  │  Normal Exec  │            │  Sandbox Exec  │            │
│  │               │            │               │            │
│  │  No overhead  │            │  ┌─────────┐  │            │
│  │               │            │  │ nsjail  │  │            │
│  │               │            │  │   or    │  │            │
│  │               │            │  │firejail │  │            │
│  │               │            │  └────┬────┘  │            │
│  │               │            │       │       │            │
│  │               │            │  ┌────▼────┐ │            │
│  │               │            │  │ Isolated│ │            │
│  │               │            │  │ network │ │            │
│  │               │            │  │ readonly│ │            │
│  │               │            │  │  fs     │ │            │
│  │               │            │  └────┬────┘ │            │
│  │               │            │       │       │            │
│  │               │            │  ┌────▼────┐ │            │
│  │               │            │  │ Monitor │ │            │
│  │               │            │  │ & Alert │ │            │
│  │               │            │  └─────────┘ │            │
│  └───────────────┘            └───────────────┘            │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

---

### 4. Enterprise Authentication & Authorization

#### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│         ENTERPRISE AUTHENTICATION MODULE                    │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  ┌────────────────────────────────────────────────────┐  │
│  │              IDENTITY PROVIDERS                      │  │
│  ├────────────────────────────────────────────────────┤  │
│  │                                                    │  │
│  │   ┌──────────┐  ┌──────────┐  ┌──────────┐        │  │
│  │   │  GitHub  │  │  GitLab  │  │   Okta   │        │  │
│  │   │  OAuth   │  │  OAuth   │  │  SAML    │        │  │
│  │   │   2.0    │  │   2.0    │  │   2.0    │        │  │
│  │   └────┬─────┘  └────┬─────┘  └────┬─────┘        │  │
│  │        │             │             │              │  │
│  │        └─────────────┼─────────────┘              │  │
│  │                      │                            │  │
│  │                      v                            │  │
│  │   ┌──────────────────────────────────────────┐    │  │
│  │   │           AUTHENTICATION CORE            │    │  │
│  │   ├──────────────────────────────────────────┤    │  │
│  │   │  • JWT token validation                  │    │  │
│  │   │  • Session management (Redis)           │    │  │
│  │   │  • Token refresh (background)           │    │  │
│  │   │  • MFA verification (if required)       │    │  │
│  │   └──────────────────────────────────────────┘    │  │
│  │                                                   │  │
│  └───────────────────────────────────────────────────┘  │
│                           │                                 │
│                           v                                 │
│  ┌────────────────────────────────────────────────────┐  │
│  │              AUTHORIZATION (RBAC)                  │  │
│  ├────────────────────────────────────────────────────┤  │
│  │                                                    │  │
│  │  Roles:                                            │  │
│  │  ┌──────────┬──────────┬──────────┬──────────┐   │  │
│  │  │  Admin   │  Manager │  Analyst │  User    │   │  │
│  │  ├──────────┼──────────┼──────────┼──────────┤   │  │
│  │  │ Full     │ Team     │ View     │ Personal │   │  │
│  │  │ Access   │ Policies │ Reports  │ Only     │   │  │
│  │  ├──────────┼──────────┼──────────┼──────────┤   │  │
│  │  │ Manage   │ Approve  │ Export   │ Submit   │   │  │
│  │  │ Users    │ Requests │ Logs     │ Events   │   │  │
│  │  └──────────┴──────────┴──────────┴──────────┘   │  │
│  │                                                    │  │
│  └────────────────────────────────────────────────────┘  │
│                                                             │
└─────────────────────────────────────────────────────────────┘
```

#### RBAC Permissions Matrix

| Role | Organization | Team | Project | Personal |
|------|-------------|------|---------|----------|
| Admin | Full | Manage | Configure | View |
| Manager | View | Manage | View | View |
| Analyst | - | View | View | View |
| User | - | - | - | Own |

---

## API Specifications

### Core Engine API

```typescript
// Core detection interface
interface DetectionEngine {
  // Main entry point
  analyze(request: AnalysisRequest): Promise<Verdict>;
  
  // Signal generators
  checkHeuristics(artifacts: Artifact[]): HeuristicSignal[];
  checkML(artifacts: Artifact[]): MLSignal[];
  checkBehavioral(context: Context): BehavioralSignal[];
  checkCache(artifacts: Artifact[]): CacheResult | null;
  
  // Decision
  mergeSignals(signals: Signal[]): Verdict;
  
  // Side effects
  logAudit(verdict: Verdict, request: AnalysisRequest): void;
  updateCache(verdict: Verdict, artifacts: Artifact[]): void;
}

interface AnalysisRequest {
  tool: string;           // "Bash", "Read", "FetchURL", etc.
  input: unknown;         // Tool-specific input
  context: Context;       // Session, user, project info
  timestamp: Date;
}

interface Verdict {
  decision: 'allow' | 'deny' | 'ask';
  confidence: number;      // 0-1
  signals: Signal[];       // Contributing signals
  explanation: string;     // Human-readable
  suggestedAction?: string;
}
```

---

## Infrastructure Requirements

### Local Deployment

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU | 1 core | 2 cores |
| RAM | 512MB | 1GB |
| Disk | 100MB | 500MB |
| OS | Any (Node.js >= 22.12.0) | Latest LTS |

### Cloud Deployment (AIDR Cloud)

| Component | Spec | Notes |
|-----------|------|-------|
| Kubernetes | 1.28+ | Managed k8s (EKS/GKE/AKS) |
| Compute | 4 vCPU / 8GB per pod | Horizontal autoscaling |
| Database | PostgreSQL 15+ | RDS/Cloud SQL/Azure DB |
| Cache | Redis 7+ | ElastiCache/Memorystore |
| Object Storage | S3/GCS/Azure Blob | Audit logs, exports |

### Security Requirements

| Layer | Requirement |
|-------|-------------|
| Transport | TLS 1.3 mandatory |
| Authentication | OAuth 2.0 + PKCE |
| Authorization | RBAC with least privilege |
| Data at Rest | AES-256-GCM |
| Secrets | HashiCorp Vault / AWS Secrets Manager |

---

## Performance Targets

| Metric | Target | Maximum |
|--------|--------|---------|
| Detection Latency | <30ms | <50ms |
| ML Inference | <10ms | <20ms |
| Behavioral Query | <20ms | <50ms |
| Memory (local) | <100MB | <200MB |
| Cold Start | <500ms | <1s |

---

*Document owner: CTO | Review cycle: Quarterly*
