# AIDR Lean - Optimized Core Product

## 🎯 Felsefe: "Sade ama Etkili"

**Vazgeçtiklerimiz (Bloat):**
- ❌ Çoklu agent yönetimi (karmaşık)
- ❌ Complex RBAC/SSO (enterprise bloat)
- ❌ Heavy observability (tracing span spam)
- ❌ Dashboard UI (yerel CLI yeterli)
- ❌ WebSocket real-time (polling yeterli)
- ❌ Session recording (storage israfı)
- ❌ Team features (tek kullanıcı odaklı)

**Odaklandıklarımız:**
- ✅ Tek AI agent, maksimum koruma
- ✅ <50ms detection latency
- ✅ Zero-config, smart defaults
- ✅ CLI-first (web dashboard yok)
- ✅ MITRE ATT&CK native
- ✅ Local-first (privacy)
- ✅ Hafif, hızlı, optimize

---

## 🚀 Core Architecture (Sade)

```
Minimal Stack:
├── Core Engine (TypeScript)
│   ├── Extractors (lightweight)
│   ├── Heuristics (150 rules)
│   ├── Decision Engine
│   └── Cache (TTL-based)
├── Threat Intel
│   ├── Local YAML DB
│   └── Weekly NVD sync (lazy)
└── CLI Interface
    ├── aidr-setup
    ├── aidr-check
    └── aidr-config
```

**No:**
- Web server
- Database (SQLite yeterli)
- Message queue
- Microservices
- Complex auth

---

## 📦 Feature Set (Lean)

### Tier 1: Core (Free Forever)
```typescript
interface CoreFeatures {
  // Detection
  heuristics: 150;           // Local rules
  mitre_mapping: true;       // ATT&CK technique ID'leri
  behavioral_baseline: true; // Simple anomaly (mean + 3σ)
  
  // Response
  actions: ["allow", "deny", "ask"];
  cache: "7_day_ttl";
  audit: "local_jsonl";
  
  // Performance
  latency_budget: "<50ms";
  memory_footprint: "<50MB";
  cpu_usage: "<5%";
}
```

### Tier 2: Smart (Pro - $9)
```typescript
interface SmartFeatures {
  // Enhanced Detection
  nvd_cve_sync: "weekly";           // Lazy update
  exploitability_score: true;       // EPSS integration
  command_chain: true;              // Multi-step detection
  entropy_check: true;              // Base64/obfuscation
  
  // Advanced
  false_positive_learning: true;    // User feedback loop
  custom_rules: 10;                 // User YAML rules
  
  // Retention
  log_history: "30_days";
}
```

### Tier 3: Power (Pro+ - $19)
```typescript
interface PowerFeatures {
  // ML Features (lightweight)
  embedding_similarity: true;       // Lightweight model
  few_shot_learning: true;        // 5-shot pattern learning
  
  // Integration
  webhook_notifications: true;      // Slack/Discord
  siem_export: ["splunk", "datadog"]; // Push only
  
  // Retention
  log_history: "90_days";
  export_formats: ["json", "csv", "stix"];
}
```

**No Enterprise Tier** - Pro+ yeterli, karmaşıklık yok.

---

## ⚡ Optimizasyon Stratejisi

### 1. Detection Pipeline (Hızlı)

```typescript
// Hızlı path: O(1) lookup
class FastDetector {
  private threatMap: Map<string, Threat>; // Pre-compiled
  private regexCache: Map<string, RegExp>;
  
  detect(tool: string, input: string): Verdict {
    // 1. Cache check (1ms)
    const cached = this.cache.get(hash);
    if (cached) return cached;
    
    // 2. Direct match (5ms)
    const threat = this.threatMap.get(`${tool}:${input}`);
    if (threat) return this.block(threat);
    
    // 3. Regex scan (10ms)
    for (const [id, regex] of this.regexCache) {
      if (regex.test(input)) {
        return this.block(id);
      }
    }
    
    // 4. Behavioral check (20ms) - lazy
    if (this.isAnomalous(tool)) {
      return this.ask("Unusual pattern");
    }
    
    return this.allow();
  }
}
```

**Budget:** 95% detection <20ms, 99% <50ms

### 2. Memory Optimizasyonu

```typescript
// Lazy loading - sadece gerekli modüller
const modules = {
  nvd: () => import('./nvd-client').then(m => m.NvdClient), // Sadece istek varsa
  ml: () => import('./ml-detector').then(m => m.MLDetector), // Pro tier'de
  dlp: () => import('./dlp-engine').then(m => m.DLPEngine), // Gerektiğinde
};

// Base memory: 20MB
// + NVD: +10MB (sadece sync sırasında)
// + ML: +20MB (Pro tier, lazy)
```

### 3. Storage Optimizasyonu

```bash
# Minimal footprint
~/.singularity-aidr/
├── config.json           # 1KB - settings
├── threats/              # 50KB - YAML rules
│   └── local/            # 10KB - user custom rules
├── cache/                # 1MB - LRU cache
│   └── verdicts.jsonl    # Rotating 7d
└── audit/                # 5MB - 7d logs
    └── 2026-03.jsonl   # Daily rotation
```

**Total:** <10MB persistent storage

### 4. Battery/CPU Optimizasyonu

```typescript
// Low-power mode (laptop için)
const powerMode = {
  aggressive: false,        // Continuous monitoring değil
  sampling: "1_in_10",      // Her 10 call'den 1'ini deep check
  sleep_interval: 5000,    // 5s idle between scans
  throttle_cpu: true,      // Background thread throttling
};
```

---

## 🎯 Kullanıcı Flow (Optimize)

### Kurulum (15 saniye)
```bash
$ npx aidr-setup

🛡️ AIDR (Optimized)

[1/3] Detecting...        ✓ Claude Code
[2/3] Loading threats...  ✓ 150 rules (2MB)
[3/3] Testing...          ✓ 12ms latency

🎯 Ready! Using 8MB RAM

Usage: Just use Claude Code normally
       AIDR works invisibly

Commands:
  aidr check          # Test detection
  aidr status         # View stats
  aidr config         # Edit settings

[OK]
```

### Günlük Kullanım (Görünmez)
```
# Kullanıcı Claude Code kullanır...
# AIDR arka planda, hiçbir şey göstermez

# Sadece riskli durumda:
⚠️  AIDR paused: curl | bash detected
    Risk: Supply chain attack (T1059)
    
    [Learn More] [Safe Alt] [Proceed]
```

### CLI Interface (Dashboard Yerine)
```bash
# Status check
$ aidr status

🛡️ AIDR Status
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Protection:    🟢 Active (12ms avg)
Threats:       150 rules ready
Today:         67 calls processed
Blocked:       1 (rm -rf /)
Cache hit:     94%
Memory:        8.2MB / 50MB
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

# Quick config
$ aidr config sensitivity paranoid
✓ Updated (150 rules active)

# View recent
$ aidr logs --tail 5
14:32:15  Write   /tmp/test.txt     ✅ Allow
14:28:45  Bash    curl|bash         ⚠️  Ask → Approved
14:15:22  Bash    rm -rf /          🚫 Block (T1659)
```

---

## 🏗️ Teknik Tasarım (Minimal)

### Core Module (Single File)
```typescript
// core/engine.ts - 500 satır, hepsi burada
export class AIDREngine {
  private cache: LRUCache;
  private heuristics: ThreatMap;
  private config: Config;
  
  async process(tool: string, input: any): Promise<Verdict> {
    // Fast path
    if (this.cache.has(key)) return cache.get(key);
    
    // Detect
    const threat = this.heuristics.match(tool, input);
    const verdict = threat ? this.block(threat) : this.allow();
    
    // Cache & log
    this.cache.set(key, verdict);
    this.audit.log(tool, input, verdict);
    
    return verdict;
  }
}
```

### No External Dependencies (Core)
```json
{
  "dependencies": {
    "zod": "^3.22"       // Config validation
  },
  "optionalDependencies": {
    "@anthropic-ai/sdk": "^0.24",  // Pro tier - ML
    "stripe": "^14",              // Pro tier - billing
    "chalk": "^5"                 // CLI coloring
  }
}
```

### Lazy Feature Loading
```typescript
// Sadece gerekirse yükle
class LazyFeatures {
  private mlDetector?: Promise<MLDetector>;
  private nvdClient?: Promise<NvdClient>;
  
  async getML(): Promise<MLDetector> {
    if (!this.mlDetector) {
      this.mlDetector = import('./ml').then(m => new m.MLDetector());
    }
    return this.mlDetector;
  }
}
```

---

## 📊 Benchmark Hedefleri

| Metric | Target | Test Method |
|--------|--------|-------------|
| **Setup Time** | <15s | `time npx aidr-setup` |
| **Detection Latency** | p95 <50ms | Load test 1000 calls |
| **Memory Footprint** | <50MB | `ps aux` peak |
| **Storage** | <10MB | `du -sh ~/.singularity-aidr` |
| **CPU Usage** | <5% | `top` during normal use |
| **Battery Impact** | Minimal | Mac Activity Monitor |
| **Offline Work** | 100% | Disconnect wifi, test |

---

## 🚫 Bilerek Eksik Bıraktıklarımız

### Neden Yok?

**Web Dashboard**
- ❌ Next.js + React = 200MB+ node_modules
- ❌ Browser tab açmak yerine CLI yeterli
- ❌ `aidr status` + `aidr logs` gösterir

**Multi-Agent**
- ❌ Tek developer, tek AI agent yeterli
- ❌ Complexity/Value ratio kötü
- ❌ Team features = 3x code, 1.5x value

**Real-time WebSocket**
- ❌ Polling 30s yeterli (security alerts non-urgent)
- ❌ WebSocket server = complexity + cost

**Session Recording**
- ❌ Privacy risk + storage israfı
- ❌ Audit log (text) yeterli forensics için

**Heavy Observability**
- ❌ OpenTelemetry = 10x overhead
- ❌ Simple metrics (latency/count) yeterli

---

## ✅ Roadmap: Lean Launch

### Week 1: Core (MVP)
- [ ] Single-file engine (core/engine.ts)
- [ ] 150 threat rules (YAML)
- [ ] CLI: setup, status, config
- [ ] <50MB memory target

### Week 2: Polish
- [ ] Performance optimize (cache, lazy load)
- [ ] MITRE mapping
- [ ] Behavioral baseline
- [ ] Error handling

### Week 3: Pro Features
- [ ] NVD sync (weekly, lazy)
- [ ] Command chain detection
- [ ] Custom rules (10 rule limit)
- [ ] Stripe integration

### Week 4: Launch
- [ ] Docs (README only, no wiki)
- [ ] Tests (unit only, e2e yok)
- [ ] Package & publish
- [ ] Hacker News launch

---

## 🎯 Success Metrics (Lean)

### Technical
- Setup: <15s
- Memory: <50MB
- Latency: p95 <50ms
- Storage: <10MB

### Business
- Free tier: 10K users (first month)
- Pro conversion: 5%
- Churn: <3%
- Support tickets: <10/week

### User Satisfaction
- "Just works" feeling
- No configuration needed
- Invisible security (doesn't get in the way)

---

## 📝 Philosophy Summary

```
"Do one thing well"

Before adding a feature:
1. Does it slow down detection? → NO
2. Does it increase memory >50%? → NO
3. Is there a simpler alternative? → USE IT
4. Can it be lazy-loaded? → YES
5. Would 80% users use it? → NO = CUT

Target: Feature-complete, not feature-bloated.
```

---

**Status**: Lean plan complete
**Next**: Start with Week 1 implementation
