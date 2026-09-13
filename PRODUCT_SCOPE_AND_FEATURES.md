# Singularity AIDR — Product Scope & Feature Inventory

> Historical intermediate audit. Current capability/consumer status is maintained
> in [FEATURE_INVENTORY.md](FEATURE_INVENTORY.md) and
> [FEATURE_INVENTORY.json](FEATURE_INVENTORY.json). The module counts and
> unsupported/unwired statements below describe the earlier audit snapshot.

**Method:** every row was derived from the code, not from documentation. A feature is
marked **LIVE** only if it is reachable from a production entry point
(`packages/*/src/{pre-tool-use,post-tool-use,session-start,mcp-server,index,tool-handler,aidr-hook}.ts`,
`packages/core/src/{evaluator,session-start,guard,scan-handler}.ts`) by following real
imports. Reachability was computed mechanically over all non-test TypeScript in
`packages/*/src` and then spot-checked by hand.

**Generated:** 2026-09-11 · companion defect record: `READINESS_BACKLOG.json`

---

## 1. The honest headline

The product **detects and blocks** well, on five connectors, with no account required.
It does **not** respond beyond blocking, and several capabilities that are documented,
tested, exported and shipped in the bundle are **not called by any live code path**.

Of 104 core modules:

| Class | Count | Meaning |
|---|---|---|
| **LIVE** | 58 | reachable from a production entry point |
| **ISLAND** | 31 | imported only by other unreachable modules — a closed subsystem that nothing in the product calls |
| **DEAD** | 15 | no importers at all (includes 2 `.d.ts` typings files and the `index.ts` barrel) |

This distinction is the single most important thing to understand before a customer
deployment: an "exported and unit-tested" module is not a delivered capability.

---

## 2. LIVE capabilities (verified reachable)

### 2.1 Core detection — the product's real strength

| Feature | Entry point | Status |
|---|---|---|
| Tool-call interception (Bash/exec, read, write, edit, delete, WebFetch, MCP) | all connectors | **LIVE** |
| Artifact extraction (commands, URLs, file paths, package specs, content) | `extractors.ts` | **LIVE** |
| YAML threat heuristics — **351 rules across 23 files** | `heuristics.ts` + `threat-loader.ts` | **LIVE** (verified: 351 loaded, malicious probe matches) |
| Decision engine with confidence scoring and `deny > ask > allow` merge | `engine.ts` | **LIVE** |
| Sensitivity presets (paranoid 0.70 / balanced 0.85 / relaxed 0.95) | `types.ts`, `engine.ts` | **LIVE** |
| Verdict cache with TTLs | `cache.ts` | **LIVE** |
| Allowlist (exact-artifact matching) | `allowlist.ts` | **LIVE** |
| Trusted-domain suppression | `trusted-domains.ts` | **LIVE** |
| Audit log (JSONL, with credential/PII redaction) | `audit-log.ts` | **LIVE** |
| Policy evaluation (filesystem / network / MCP / tool rules) | `policy.ts` | **LIVE** |
| Package supply-chain extraction from commands and manifests | `package-extractor.ts` | **LIVE** |
| Package checks: registry lookup, age heuristic, offline intel deny | `package-checker.ts` | **LIVE** (with the caveats in §5) |
| URL reputation lookup | `clients/url-check.ts` | **LIVE code path**, inert without a deployed endpoint |
| File-hash reputation lookup | `clients/file-check.ts` | **LIVE code path**, inert without a deployed endpoint |
| AMSI (Windows antimalware) scanning | `clients/amsi.ts` | **LIVE on Windows only** |
| Plugin scanning at session start | `plugin-scanner.ts`, `plugin-scan-cache.ts` | **LIVE** |
| Incident correlation, normalisation, persistence | `incidents/*` | **LIVE** |
| Signed intel packs (offline deny lists), Ed25519 verification | `intel/loader.ts`, `intel/keyring.ts` | **LIVE** |
| Revocation lists (signed, Ed25519) | `managed.ts`, `evaluator.ts` | **LIVE** |
| Integrity verification + degraded safe mode | `integrity/*` | **LIVE** |
| Remote runtime policy sync | `remote-policy.ts` | **LIVE code path**, requires a control plane |
| OpenTelemetry tracing | `tracing.ts` | **LIVE** |
| Installation identity (0600, 0700 dir) | `installation-id.ts` | **LIVE** |
| Managed state / entitlement / device bootstrap | `managed.ts`, `session-start.ts` | **LIVE**, requires a control plane (§5) |

### 2.2 Connectors

| Connector | Features | Status |
|---|---|---|
| **Claude Code** | PreToolUse, PostToolUse, SessionStart, MCP allowlist tools, health bin | **LIVE** (verified: denies `rm -rf /`, pipe-to-shell, credential files) |
| **Cursor / VS Code** | `aidr-hook.cjs` in both modes, managed hook installers, commands (enable/disable/config/audit/health) | **LIVE** (verified: 17/17 integration tests) |
| **OpenClaw** | `before_tool_call`, allowlist tools, gateway/session plugin scan | **LIVE** (verified: 21 tests; self-approval removed) |
| **OpenCode** | `tool.execute.before`, allowlist tools, startup scan | **LIVE** (verified: 7/7 contract tests) |
| **Codex** | — | **NOT SUPPORTED** — denies 100% of calls, absent from every build/CI gate (AIDR-017) |

### 2.3 CLI, SDK, dashboard

| Feature | Status |
|---|---|
| `aidr setup` — real rule count, real detection self-test, CSPRNG key, honest "not yet active" reporting | **LIVE** (verified) |
| `aidr status`, `aidr config --get/--set/--list` | **LIVE** |
| SDK client + 5 framework adapters (LangChain, LlamaIndex, AutoGen, CrewAI, generic) with fail-closed enforcement | **LIVE** (verified 60/60 tests) |
| SDK Express/Next.js middleware | **LIVE** |
| Dashboard: routing, auth (Supabase/Google/Azure), onboarding, agents, events, incidents, API keys, billing, AutoSecOps, settings, public pages, CSP/HSTS | **LIVE** |
| Dashboard team administration (create team, invite, role change, remove member) | **ISLAND** — implemented, unreachable (AIDR-008) |
| Dashboard team policy editor | **ISLAND** — implemented, unreachable (AIDR-009) |
| Stripe webhook (signature-verified, replay-protected, event/status allow-list) | **IMPLEMENTED, UNDEPLOYED** (AIDR-023) |

---

## 3. Capabilities that are shipped but NOT wired (the gap)

These are exported from the package, covered by tests, bundled into the shipped
artifacts — and called by nothing on a live path. **A customer cannot use them today.**

### 3.1 ADR "response" capabilities — the answer to the ADR comparison

| Capability | Module | Live? |
|---|---|---|
| Response layer (verdict → concrete action, recorded and bounded) | `response-actions.ts` | **LIVE** (new) |
| Snapshot on deny — preserve a copy of a blocked write's target before it is overwritten | `response-actions.ts` | **LIVE**, off by default |
| Auto-quarantine (move a file aside, manifest, restore) | `quarantine.ts` | **ISLAND** |
| Auto-containment (Docker/Podman isolation) | `contain.ts` | **ISLAND** (and must refuse rather than run unisolated) |
| Auto-rollback (filesystem snapshot + restore) | `rollback.ts` | **ISLAND** |
| Response configuration (hot-reloadable response rules) | `response-config.ts` | **ISLAND** |
| Response audit (tamper-evident signed action records) | `response-audit.ts` | **ISLAND** |

**What this means now.** AIDR's response surface was previously just a
pre-execution verdict. As of this wave there is a real response path: a blocking
verdict can produce a concrete, recorded, reversible action, and the chosen action
is **snapshot-on-deny** — because the connector decides *before* the tool executes,
the blocked write never happened, so the runtime must not move or delete the target.
It copies the prior contents into `~/.singularity-aidr/response-vault` and leaves the
original byte-identical.

The safety boundaries are part of the design, not documentation: the action is off by
default, allowed verdicts never trigger it, a severity floor and a size ceiling bound
it, every skip and failure is reported with a machine-readable reason, a response
failure leaves the blocking verdict intact, records never contain file contents, and
the vault is created mode 0700.

**An operator can now see it.** The action is written to the audit log as a
`response_action` entry (paths and outcomes only — never contents), and the block
message shown to the user names what was preserved and where:

```
Singularity AIDR blocked this action.
Severity: warning
Category: secrets
Reason: Access SSH key or config file
Response: snapshot: preserved a copy of /home/u/.ssh/authorized_keys at /home/u/.aidr/response-vault/2026-…_authorized_keys
```

A failed action is reported too, explicitly, rather than being omitted:
`response action(s) failed: snapshot (snapshot_failed) - nothing was preserved`.

**Still not delivered:** rollback is not connected, and the response record is not yet
written to a tamper-evident signed chain (`response-audit.ts` remains unwired). So the
product is best described as *detect, block, preserve evidence, and tell the operator* —
a truthful step up from detect-and-block, but not yet the full triage → contain →
remediate → verify → report loop that an ADR-class product implies.

### 3.2 AIG (AI-Infra-Guard) integration

**Status as of 2026-09-11: being rebuilt natively.** The previous integration was
dead weight — but the reason was a compiler defect, not a fundamental problem, and it
is now fixed.

**Root cause of the dead weight.** `scripts/compile-aig-data.mjs` compiled the
fingerprint dataset down to `name/author/severity/desc` only. It discarded the
upstream `http:` detection blocks (method, path, matchers) and `version:` extractors,
so the shipped index could not identify anything. That is why nothing consumed it:
there was nothing usable to consume. AIG's fingerprint YAML is a real detection DSL —
here is an actual upstream entry:

```yaml
info:
  name: Agentic-Flow
  metadata: {product: agentic-flow, vendor: ruvnet}
http:
  - method: GET
    path: /health
    matchers:
      - body="\"checks\":" && body="\"api\":" && body="\"version\":"
version:
  - method: GET
    path: /health
    extractor: {part: body, group: 1, regex: '"version"\s*:\s*"([0-9][0-9.a-zA-Z\-]+)"'}
```

**What is now built and verified.**

| Piece | Status |
|---|---|
| Compiler emits full detection blocks (probes, matchers, version extractors) | **DONE** — 146/146 fingerprints carry HTTP detection, 40 carry version extractors |
| Dataset upgraded to upstream **v4.6.1** (160 commits ahead of the pinned v4.5.1) | **DONE** — 2,043 CVEs / 115 frameworks, 146 fingerprints, 14 MCP categories |
| Native TypeScript infra scanner (`packages/core/src/aig-infra-scan.ts`) | **DONE** — HTTP probes, AND-ed matchers, version extraction, CVE applicability |
| Zero Go server, zero Python worker, zero Docker, zero LLM API key | **DONE** |
| Safety posture: loopback/private only by default, bounded concurrency, per-request timeout, total deadline, body cap, no redirects, no credentials | **DONE** |
| "Cannot check" never reported as "clean" (`error` field separates the two) | **DONE** |
| 26 unit tests incl. a real HTTP server round-trip | **PASSING** |
| Compiled data now shipped in `dist/generated/` (was missing entirely) | **DONE** |
| CLI surface: `aidr scan --target ... [--json] [--file] [--allow-public]` | **DONE** — verified end-to-end: identified a served product, matched 3 real CVEs with CVSS scores, exits 2 when critical/high findings exist so it is CI-usable |
| 17 CLI tests incl. "a scan that did not happen is never reported as clean" | **PASSING** |
| Session-start summary of findings | **NOT DONE** |
| Policy action on critical CVEs | **NOT DONE** |
| MCP scan, Agent scan, Jailbreak evaluation | **NOT DONE** (design below) |

**Why this is the right architecture for a lightweight, full-feature product.** AIG
splits into capabilities that need very different machinery:

| AIG capability | Upstream implementation | Native equivalent |
|---|---|---|
| AI Infra scan | Go server + fingerprints + CVE corpus | **Deterministic** — HTTP probes + version compare. Now native. No stack. |
| CVE / vulnerability matching | Go + YAML corpus | **Deterministic** — index lookup + semver rules. Now native. |
| MCP scan (risk categories) | Python + **LLM** eval | Hybrid: the deterministic checks (tool poisoning, name confusion/typosquat, CORS, scope creep, secret exposure in config) are native; the semantic LLM review stays optional. |
| Agent scan | Python + **LLM** | Requires a model to reason about agent behaviour; keep optional and BYO-key. |
| Jailbreak evaluation | Python + prompt datasets + eval model | Requires a model to judge responses; keep optional and BYO-key. |

So the honest split is: **two of AIG's five capabilities are pure logic and are now
native with no runtime cost; three are LLM-driven by nature** and should be offered as
opt-in features that use the customer's own model, never as a hidden dependency. That
keeps the product lightweight while still covering the feature suite.

**Consequence for the shipped stack.** `services/aig-bridge`, `docker-compose.aig.yml`
and the pinned `vendor/ai-infra-guard` submodule are no longer required for infra
scanning or CVE matching. They remain only as the data source for the compiler. The
submodule can stay as a build-time input (or be replaced by a pinned data download),
but it no longer needs to be deployed, and the previous "bridge is permanently
unhealthy / `scan_ready` is never emitted / MCP findings read from the wrong fields"
defects stop mattering for the native path.

### 3.3 DLP / advanced detection

| Capability | Module(s) | Live? |
|---|---|---|
| PII detection + redaction | `pii-detector.ts`, `dlp/pii-detector.ts` | **NO** |
| Secret detection | `dlp/secret-detector.ts` | **NO** |
| Content classification, entropy detection | `dlp/content-classifier.ts`, `dlp/entropy-detector.ts` | **NO** |
| Output safety scanning (prompt-injection / leak detection on tool results) | `output-scanner.ts` | **NO** — no importers at all |
| Novelty detection (z-score anomaly) | `novelty-detection.ts` | **NO** |
| Behavioural analysis (baseline, anomaly, pattern matching) | `behavioral-analyzer.ts`, `behavioral/*` | **NO** |
| Multi-factor risk scoring | `risk-scorer.ts` | **NO** |
| Attack-chain analysis | `command-chain-analyzer.ts` | **NO** |
| ML similarity / embedder / model | `ml/*`, `ml-model.ts` | **NO** — and `ml-model.ts` only sets a flag; no weights ship |
| MITRE ATT&CK mapping | `mitre-attack/mapper.ts` | **NO** |
| Federated threat-intel sharing | `federated.ts` | **NO** |
| Community rule voting/promotion | `community-rules.ts` | **NO** |
| SIEM export (CEF/LEEF) | `siem-export.ts` | **NO** |
| Compliance reporting (SOC 2 style) | `compliance-report.ts` | **NO** — and it fabricates evidence (§5) |
| Metrics (Prometheus format) | `metrics.ts` | **NO** |
| MCP transport / inventory | `mcp-transport.ts`, `mcp-inventory.ts` | **NO** |
| Duplicate policy engine | `policy-engine.ts` | **NO** — divergent second implementation; its YAML loader calls `JSON.parse` on YAML |
| Duplicate audit log | `audit.ts` | **NO** — second audit implementation |

---

## 4. Feature matrix by connector (live path only)

| Capability | Claude Code | Cursor/VS Code | OpenClaw | OpenCode | CLI |
|---|---|---|---|---|---|
| Command / URL / file extraction | ✅ | ✅ | ✅ | ✅ | — |
| Heuristic rules (351) | ✅ | ✅ | ✅ | ✅ | ✅ (self-test) |
| Policy evaluation | ✅ | ✅ | ✅ | ✅ | — |
| Allowlist | ✅ | ✅ | ✅ | ✅ | — |
| Audit log | ✅ | ✅ | ✅ | ✅ | — |
| URL reputation | code path | code path | code path | code path | — |
| File reputation | code path | code path | code path | code path | — |
| Package supply-chain | ✅ | ✅ | ✅ | ✅ | — |
| AMSI (Windows) | ✅ | ✅ | ✅ | ✅ | — |
| Plugin scanning | ✅ | ✅ | ✅ | ✅ | — |
| Session-start scan | ✅ | — | ✅ | ✅ | — |
| Output scanning | ❌ (module unwired) | ❌ | ❌ | ❌ | — |
| DLP / PII | ❌ (module unwired) | ❌ | ❌ | ❌ | — |
| Quarantine / contain / rollback | ❌ (modules unwired) | ❌ | ❌ | ❌ | — |
| AIG scans | ❌ (module unwired) | ❌ | ❌ | ❌ | — |

---

## 5. Known limits that affect a sale

1. **Reputation checks are inert without a deployed endpoint.** URL, file and package
   hash reputation all resolve to first-party services that do not exist yet. Worse,
   scoped npm packages (`@scope/name`) are skipped and reported "clean" at confidence
   1.0, and npm's `sha512-` integrity is not recognised, so hash reputation never runs
   for npm (AIDR-020).
2. **No control plane is deployed**, so device enrolment, dashboard telemetry, signed
   entitlement enforcement and remote policy cannot activate. Local detection no
   longer depends on it (AIDR-016).
3. **Cryptomining coverage is command/file shaped, not a reputation feed.**
   `threats/mining.yaml` (17 rules, MITRE ATT&CK T1496) now catches known miner
   binaries, pool-connection shapes, miner-only flags, wallet-shaped payout targets,
   miner-named package installs and install hooks that stage a miner (AIDR-027).
   A miner that is renamed *and* invoked without any pool endpoint, miner-only flag or
   wallet address — e.g. one that reads its own config file — is still not caught.
4. **Compliance and health reports fabricate values.** `compliance-report.ts` hardcodes
   SOC 2 controls as "effective" with a false evidence line ("DLP content
   classification enabled") while DLP is unwired, and floors coverage/uptime.
   `health.ts` uses a placeholder free-disk estimate. Neither is on a live path, but
   neither may be shown to a customer as-is.
5. **The Stripe handler is implemented but undeployed and cannot yet succeed**: no
   Stripe Checkout session is created anywhere, so events resolve as `unlinked`.
6. **The threat-pattern rewrite for ReDoS introduced one confirmed evasion** on a
   long-argument PowerShell command (AIDR-021, being corrected), and two rules remain
   slow (~100 ms on 80 KB).
7. **Build ordering is fragile** (AIDR-014): running a build concurrently with the
   test suite deletes `packages/core/dist` mid-run and fails unrelated suites.

---

## 6. What "turnkey for critical customers" would require

Ordered by what a critical customer would notice first:

1. **Wire the response lifecycle** (or stop claiming "Response"): at minimum
   quarantine + rollback with signed action records, driven by the existing verdict
   path. This is the largest genuine capability gap against ADR-class products.
   Note that `contain.ts` cannot isolate as written: its generic `isolate()` throws
   in the container path, and when no container runtime is available it **executes the
   operation unisolated** and only reports `isolated: false`. Anyone who wires it in
   must gate on that flag or the "containment" will run the very operation it was
   meant to contain.
2. **Finish the native AIG wiring.** The scanner and dataset now work (§3.2); the
   remaining step is exposing findings to the operator (CLI command, session-start
   summary, policy action on critical CVEs) and then retiring `services/aig-bridge`,
   `docker-compose.aig.yml` and the deployment half of the submodule, which the native
   path makes unnecessary. Decide explicitly whether MCP/Agent/Jailbreak scans are
   offered as opt-in LLM-backed features (customer's own key) or dropped.
3. **Deploy the reputation + control-plane services**, or make every dependent
   feature report "unavailable" instead of "clean".
4. **Close the coverage and correctness defects** in the backlog (cryptomining, scoped
   packages/sha512, the gap evasion, the nine Edge Functions the dashboard calls that
   do not exist).
5. **Delete or finish the dead/island subsystems** — DLP, ML, behavioural, SIEM,
   compliance, MCP transport, the duplicate policy engine and audit log. Each one is
   either a real feature to finish or a maintenance and credibility liability.
6. **Correct every readiness claim** so customer-facing material matches measured
   behaviour (this document plus `RELEASE_READINESS_REPORT.md` supersede the older
   status files).
