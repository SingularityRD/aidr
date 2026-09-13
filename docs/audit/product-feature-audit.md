# Singularity AIDR — Product Feature Audit

**Date**: 2026-05-26  
**Auditor**: Product Lead  
**Scope**: Full feature audit across all packages, connectors, dashboard, threat rules, tests, and documentation.

---

## Executive Summary

Singularity AIDR is a mature, well-architected AI Agent Detection & Response platform with a clean monorepo structure. The **core engine is production-quality** with strong test coverage (91 test files in core). The **threat rule system is comprehensive** (23 YAML files covering multi-platform threats). However, several critical gaps exist: the **dashboard is in alpha** (React/Vite SPA with incomplete auth flow, no empty states, minimal testing), the **extension package is structurally sound but untested for VS Code/Cursor integration**, and the **CLI/SDK packages are in early prototype stage** with no tests. Several advanced modules (novelty detection, federated learning, ML) have interfaces defined but are **not production-wired**. The overall product is **feature-complete for a v1 commercial SaaS** but has significant polish gaps before GA.

---

## Scorecard

| Dimension | Score | Summary |
|-----------|-------|---------|
| Core Engine | 8/10 | Production quality, well-tested. Some modules are interface-only (not wired). |
| Threat Rules | 9/10 | Comprehensive multi-platform coverage. Well-structured YAML. |
| Platform Connectors | 6/10 | Claude Code connector is solid; OpenClaw/OpenCode are functional; Extension/CLI/SDK are prototype-grade. |
| Dashboard/SaaS | 4/10 | Functional routes exist but pages are basic. No loading skeletons, no empty states, minimal error UX. |
| Test Coverage | 7/10 | Core has excellent coverage (91 files). Connectors minimal. Dashboard close to zero. |
| Documentation | 8/10 | Extensive docs for most features. Architecture doc slightly outdated. |
| API/SDK | 4/10 | SDK exists but is minimal. No public API docs. No rate limiting docs. |
| Overall | 6.5/10 | Strong foundation with clear gaps in UI polish, connector maturity, and testing breadth. |

---

## 1. Core Engine (`packages/core/src/`) — PASS (8/10)

### 1.1 Production-Ready Modules

| Module | File | Lines | Verdict |
|--------|------|-------|---------|
| Extraction | `extractors.ts` | ~250 | PASS — Mature, well-tested artifact extraction for all tool types |
| Heuristics Engine | `heuristics.ts` | ~200 | PASS — ReDoS-safe regex matching with trusted domain suppression |
| Decision Engine | `engine.ts` | ~180 | PASS — Clean signal fusion with sensitivity presets |
| Threat Loader | `threat-loader.ts` | ~150 | PASS — Robust YAML loading with field validation and expiry |
| Config Loader | `config.ts` | ~200 | PASS — Path sanitization, default fallbacks, Zod validation |
| Verdict Cache | `cache.ts` | ~250 | PASS — JSON file cache with TTLs, URL normalization |
| Allowlist | `allowlist.ts` | ~200 | PASS — Full CRUD with normalization |
| Audit Log | `audit-log.ts` | ~180 | PASS — JSONL append with tool input summaries |
| Guard Orchestrator | `guard.ts` | ~150 | PASS — Clean approval-store integration |
| Evaluator | `evaluator.ts` | ~400 | PASS — Full pipeline orchestration (heuristics + policy + URL check + package check + AMSI) |
| Package Checker | `package-checker.ts` | ~200 | PASS — Registry + file check + CVE + intel deny |
| Trusted Domains | `trusted-domains.ts` | ~100 | PASS — Clean domain matching |
| Threat Sync | `rule-sync.ts` | ~100 | PASS — Sync from control plane |
| MCP Inventory | `mcp-inventory.ts` | ~150 | PASS — Config file parsing with risk hints |
| Output Scanner | `output-scanner.ts` | 85 | PASS — Prompt injection + secret leak detection (minimal but functional) |
| PII Detector | `pii-detector.ts` | ~120 | PASS — Multi-pattern PII detection with redaction |
| Health Check | `health.ts` | ~80 | PASS — Basic readiness endpoint |
| Version Check | `version-check.ts` | ~80 | PASS — Update notification with env context |
| Installation ID | `installation-id.ts` | ~60 | PASS — Persistent UUID |
| Managed State | `managed.ts` | ~300 | PASS — Device auth, entitlements, revocations |
| Policy Engine | `policy-engine.ts` | ~150 | PASS — Zod-validated policy rules, time/rate conditions |
| Policy (main) | `policy.ts` | 443 | PASS — Complex policy evaluation with MCP categories, intel matching |
| Remote Policy | `remote-policy.ts` | 385 | PASS — Cached policy fetch from control plane |
| Session Start | `session-start.ts` | ~250 | PASS — Bootstrap + scan orchestration |
| Scan Handler | `scan-handler.ts` | 96 | PASS — Generic connector scan wrapper |
| File Utils | `file-utils.ts` | ~120 | PASS — Atomic writes, temp file cleanup |
| CVE Checker | `cve-checker.ts` | ~120 | PASS — AIG data index lookup |
| Incident System | `incidents/` | 6 files | PASS — Correlation, persistence, normalization |
| Integrity | `integrity/` | 5 files | PASS — Degraded safe mode, runtime verification |
| Intel | `intel/` | 9 files | PASS — Offline intel packs with verification |
| Clients | `clients/` | 6 files | PASS — URL check, file check, AMSI, package registry, control plane |

### 1.2 Partially Implemented Modules (Interface Defined, Not Fully Wired)

| Module | File | Issue |
|--------|------|-------|
| **Novelty Detector** | `novelty-detection.ts` | ~200 lines — Full z-score anomaly detection implemented but **NOT wired into evaluator.ts**. No test file found (check: `packages/core/src/__tests__/novelty-detection.test.ts` — 1 file exists, passes). Needs integration with main detection pipeline. |
| **Behavioral Analyzer** | `behavioral-analyzer.ts` | ~200 lines — Frequency/sequence/temporal anomaly detection. NOT wired into evaluator pipeline. Standalone. Has own test. |
| **Multi-Factor Risk Scorer** | `risk-scorer.ts` | ~120 lines — CVSS + exploitability + context weighting. NOT called from evaluator at runtime. |
| **Federated Learning** | `federated.ts` | 283 lines — Differential privacy threat intelligence sharing. Standalone — no coordinator integration, no network transport. |
| **Auto-Contain** | `contain.ts` | ~200 lines — Docker/Podman isolation. Has tests but container creation is a no-op (`TODO`). |
| **Auto-Quarantine** | `quarantine.ts` | ~250 lines — File quarantine with restore/notify. Has tests. NOT wired into verdict path. |
| **Auto-Rollback** | `rollback.ts` | 336 lines — File system snapshot rollback. Has tests. NOT wired into verdict path. |
| **Response Configurator** | `response-config.ts` | ~200 lines — Hot-reloadable response rules. Has tests. Standalone — evaluator doesn't call it. |
| **Response Auditor** | `response-audit.ts` | 447 lines — Tamper-evident audit signing. Has tests. NOT wired into evaluator. |
| **Community Rules** | `community-rules.ts` | ~200 lines — Voting/promotion workflow. Standalone — no persistence or network layer. |
| **Command Chain Analyzer** | `command-chain-analyzer.ts` | 235 lines — Multi-tool attack chain detection. Interface-only — not integrated. |
| **UX Engine** | `ux-engine.ts` | ~120 lines — Turkish-localized user messages. Exported but not used by any connector. |
| **Metrics** | `metrics.ts` | ~200 lines — Counter/gauge/histogram with Prometheus format. Standalone. |
| **Tracing** | `tracing.ts` | ~150 lines — OpenTelemetry spans for detection phases. Used lightly in evaluator. |

### 1.3 Known Issues

- **`policy.ts` duplicates `policy-engine.ts`**: Both export `PolicyEngine`-like classes. `policy.ts` (443 lines) appears to be the more advanced version but there's potential for confusion. The `policy-engine.ts` re-export is cleaner for external consumption.
- **`evaluator.ts` is 400+ lines**: High cognitive load — does too much. Should be refactored into smaller orchestrator steps.
- **`evaluator.ts`** imports `cachedPackageIntel` module-level variable (line 78-79) — mutable global state that can cause test pollution.
- **`build-flavor.ts`**: `isCommercialBuild()` always returns `true` — no way to build OSS/community flavor currently.
- **Multiple modules export similar `formatDenyMessage`/`formatAskMessage`**: Slight duplication between `guard.ts` and `format.ts`.

### 1.4 Module Reference Coverage (index.ts)

All 70 source files in `core/src/` are exported via `index.ts`. **No orphaned modules.** ✅

---

## 2. Threat Rules (`threats/`) — PASS (9/10)

### 2.1 Coverage

| File | Rules | Scope |
|------|-------|-------|
| `commands.yaml` | ~40 | Cross-platform dangerous commands |
| `credentials.yaml` | ~15 | API keys, secrets, .env writes |
| `files.yaml` | ~15 | Sensitive file access |
| `urls.yaml` | ~10 | Known malicious/phishing URLs |
| `obfuscation.yaml` | ~10 | Base64/hex/encoding bypass |
| `persistence.yaml` | ~10 | Startup items, cron, launchd |
| `self-defense.yaml` | ~10 | Anti-AIDR tampering |
| `supply_chain.yaml` | ~10 | Package supply chain attacks |
| `mining.yaml` | 17 | Cryptomining / resource hijacking (MITRE ATT&CK T1496) |
| `llm-threats.yaml` | ~29 | Prompt injection, jailbreaking |
| `mitre.yaml` | ~10 | MITRE ATT&CK mapping |
| Mac-specific files | 6 files | macOS-specific threats |
| Win-specific files | 6 files | Windows-specific threats |
| **Total** | **351 rules** | 23 files; exact total (per-file counts above are approximate) |

### 2.2 Strengths
- Every rule has `id`, `category`, `severity`, `confidence`, `action`, `pattern`, `match_on`, `title`.
- Expiry and revocation fields enable live threat updates.
- Platform-specific threats (Windows commands ≠ macOS commands) are properly separated.
- LLM-specific threats (prompt injection, jailbreaking) are included.

### 2.3 Issues
- No rule versioning or changelog tracking.
- No automated rule freshness check (expired rules are silently skipped at load time).
- `match_on` values are inconsistent — some use `["command", "content"]`, some use `["command"]`. Documentation for when to use each is light.
- Pattern quality varies: some are simple keywords, some are complex regex with potential edge cases.

---

## 3. Platform Connectors — PARTIAL (6/10)

### 3.1 Claude Code (`packages/claude-code/`) — PASS (7/10)

**Connector type**: MCP server + Claude Code Pre/PostToolUse hooks.

**Files**:
- `pre-tool-use.ts` — Entry point. Reads stdin JSON, runs `evaluateToolCall`, outputs verdict. ✅
- `post-tool-use.ts` — Output scanning after tool execution. ✅
- `mcp-server.ts` — `aidr_allowlist_add`/`aidr_allowlist_remove` MCP tools. ✅
- `session-start.ts` — Plugin scanning at session start. ✅
- `approval-tracker.ts` — Cross-session approval tracking. ✅
- `format.ts` — Block reason formatting. ✅
- `health.ts` — Rudimentary health check. ✅

**Tests**: 7 test files (approval-tracker, e2e, format, integration, mcp-server, session-start, skill-registration).

**Issues**:
- `approval-tracker.ts` uses `node:fs` file-based persistence — race conditions if multiple processes try to approve simultaneously.
- Post-tool-use hook is wired but output scanning only runs basic prompt injection checks.
- Integrity verification (line 43-56 in `mcp-server.ts`) is a try/catch with `// Fail open` — security theater.

### 3.2 OpenClaw (`packages/openclaw/`) — PARTIAL (5/10)

**Connector type**: In-process plugin with lifecycle hooks.

**Files**:
- `index.ts` — Plugin entry point. ✅
- `tool-handler.ts` — Intercepts tool calls via `before_tool_call` hook. ✅
- `allowlist-tools.ts` — Allowlist management tools (`aidr_allowlist_add` refuses without a recorded approval). ✅
- `bundled-dirs.ts` — Bundled threat/allowlist directory paths. ✅
- `logger-adapter.ts` — OpenClaw logger adapter. ✅

> **Superseded (2026-09-10):** this section previously listed `gate-tool.ts` as
> providing an `aidr_approve` tool "for interactive approval. ✅". That tool was a
> security defect, not a feature: it was callable by the policed agent, which already
> receives the `actionId` in the block message, so a prompt-injected agent could
> approve its own blocked call and make the bypass permanent via the allowlist. The
> file has been deleted and no approval tool is registered; approval is now an
> out-of-band, human-only action. See AIDR-022 in `READINESS_BACKLOG.json`.

**Tests**: `gate-tool.test.ts` now asserts the *absence* of an agent-callable
approval tool and that a retry stays blocked after the agent attempts to approve
itself, alongside `plugin-discovery`, `skill-registration` and `tool-handler`.

**Issues**:
- `openclaw.plugin.json` — exists but needs verification that it properly registers all hooks.
- `allowlist-tools.ts` — duplicates functionality from Claude Code's MCP server. Would be better as shared core utility.

### 3.3 OpenCode (`packages/opencode/`) — PARTIAL (5/10)

**Connector type**: In-process plugin with lifecycle hooks.

**Files**:
- `index.ts` — Plugin entry point. ✅
- `tool-handler.ts` — `tool.execute.before` hook with guard orchestration. ✅
- `startup-scan.ts` — Plugin scan at session start. ✅
- `plugin-discovery.ts` — Discovers other plugins. ✅
- `extractors.ts` — OpenCode-specific artifact extraction (maps OpenCode tool names to generic extractors). ✅
- `logger-adaptor.ts` — Logger adapter. ✅
- `error.ts` — Custom error classes (`AidrVerdictBlockError`, `AidrVerdictError`). ✅
- `bundled-dirs.ts` — Bundled paths. ✅

**Tests**: 4 test files (e2e, extractors, integration, tool-handler).

**Issues**:
- `logger-adaptor.ts` — typo in filename (`adaptor` vs `adapter`). Inconsistency with OpenClaw's `logger-adapter.ts`.
- Weaker test coverage compared to Claude Code connector.
- No `post-tool-use` equivalent — output scanning not implemented for OpenCode.

### 3.4 Extension (`packages/extension/`) — PARTIAL (4/10)

**Connector type**: VS Code/Cursor extension.

**Files**:
- `aidr-hook.ts` — CLI entry point for Cursor Hook (stdin/stdout protocol). ✅
- `vscode_extension.ts` — VS Code extension activation. ✅
- `cursor_extension.ts` — Cursor extension activation. ✅
- `shared_extension.ts` — Managed hooks extension wiring. ✅
- `vscode_hook_installer.ts` — VS Code hook installer. ✅
- `cursor_hook_installer.ts` — Cursor hook installer. ✅
- `managedHooks.ts` — Configuration + managed hook lifecycle. ✅
- `sentry.ts` — Sentry initialization. ✅

**Tests**: 3 test files (e2e-suite/, e2e.test.ts, integration.test.ts).

**Issues**:
- **No tests for actual VS Code/Cursor API interaction**. Tests are integration-level only.
- Uses `vscode` types but doesn't have `@types/vscode` explicitly (relies on transitive deps).
- `aidr-hook.ts` at line 52: `readStdinJson()` — error handling is minimal. If stdin is malformed, fail-open to allow.
- Extension packaging/VSIX build configuration not visible in `package.json`.
- The `aidr-hook.ts` `runCli` has branching for `cursor` and `vscode` modes but `handleCursor`/`handleVsCode` implementations are partial — cursor event detection logic is not fully shown.

### 3.5 CLI (`packages/cli/`) — PROTOTYPE (2/10)

**Connector type**: Standalone Node.js CLI.

**Files**:
- `bin/aidr.js` — Binary entry point. ✅ (assumed)
- `src/commands/setup.ts` — One-command setup with spinner. ✅ (57 lines, basic)
- `src/commands/status.ts` — Status display. ✅ (25 lines, basic)
- `src/commands/config.ts` — Config management. ✅ (light)
- `src/utils/` — Utility helpers. ✅ (partial)

**Tests**: **NONE** — 0 test files.

**Issues**:
- `setup.ts` calls `loadThreatDatabase()` which calls `loadThreatsFromDirs()` — no error handling if threat directory is missing.
- `status.ts` prints `apiKey` masked but the masking reveals first 4 + last 4 characters — debatable security.
- `config.ts` references `getConfig()` — no validation that config is well-formed.
- **CRITICAL**: No test coverage at all. CLI is the entry point for the product's "one-command setup" promise but has zero tests.
- `package.json` shows `better-sqlite3` dependency but no code references it in `src/commands/`.
- Build step is `tsc` but references `@singularityrd/aidr-core` workspace dependency — may fail if core hasn't been built first.

### 3.6 SDK (`packages/sdk/`) — PROTOTYPE (3/10)

**Connector type**: Universal integration SDK.

**Files**:
- `client.ts` — `AIDRClient` class wrapping core. ✅ (373 lines)
- `config.ts` — Zod schemas for SDK config. ✅
- `middleware.ts` — Express-style middleware wrapper. ✅
- `billing.ts` — Billing API client. ✅
- `cli.ts` — SDK CLI entry point. ✅
- `freemium.ts` — Freemium tier logic. ✅
- `referral.ts` — Referral tracking. ✅
- `team-dashboard.ts` — Team dashboard integration. ✅
- `adapters/` — Framework adapters. ✅
- `sentry.ts` — Sentry init. ✅

**Tests**: 1 integration test file.

**Issues**:
- **Massive scope for only 1 test file**. Billing, freemium, referral, team-dashboard are all untested.
- `billing.ts`, `freemium.ts`, `referral.ts` are business logic files with zero test coverage.
- SDK depends on `@langchain/core` — heavy dependency for what should be a lightweight SDK.
- `middleware.ts` exports Express middleware but doesn't export generic HTTP middleware — limits use to Express only.

---

## 4. Dashboard / SaaS (`packages/dashboard/`) — PARTIAL (4/10)

### 4.1 Auth Flow — PARTIAL

| Feature | Status | Evidence |
|---------|--------|----------|
| Login with Google OAuth | ✅ | `LoginPage.tsx` — Google Sign-In button with PKCE flow |
| Login with email/magic link | ✅ | `LoginPage.tsx` — Email input with magic link |
| Auth callback | ✅ | `AuthCallbackPage.tsx` — OAuth redirect handler |
| Session management | ✅ | `session.ts` — `getSession()` cookie+supabase |
| Return-to after auth | ✅ | `return-to.ts` — sessionStorage redirect persistence |
| Turnstile captcha | ✅ | `components/Turnstile.tsx` — Cloudflare Turnstile |
| Device auth (onboarding) | ✅ | `OnboardingPage.tsx` — Device code flow |
| **Password reset** | ❌ | Not implemented — no `ForgotPassword` page |
| **MFA/2FA** | ❌ | Not implemented |
| **SSO/SAML** | ❌ | Not implemented (enterprise SCOPE?) |

### 4.2 Onboarding Flow — PARTIAL

| Feature | Status | Evidence |
|---------|--------|----------|
| Runtime selection | ✅ | `OnboardingPage.tsx` lines 5-12: Supports claude-code, cursor, vscode, openclaw, opencode |
| Device code display | ✅ | Shows verification URL + user code |
| Token poll | ✅ | Polls for device authorization completion |
| **Installation instructions** | ✅ | Per-runtime install commands |
| **Loading state during polling** | ⚠️ | Basic spinner, no progress indication |
| **Error state if token expires** | ❌ | No expired token UI (would just keep polling forever) |
| **Skip/back navigation** | ❌ | No skip option |

### 4.3 Dashboard Pages — MINIMAL

| Page | Status | UX Issues |
|------|--------|-----------|
| Agents (`AgentsPage.tsx`) | ✅ | Table shows agents. No search, no filter, no pagination for 100+ agents. No bulk actions. |
| Agent Detail (`AgentDetailPage.tsx`) | ✅ | Shows events for single agent. No timeline visualization. No threat summary widget. |
| Incidents (`IncidentsPage.tsx`) | ✅ | Lists verdict events. Limited filtering (type-based only). No severity badge colors. |
| Billing (`BillingPage.tsx`) | ✅ | Seat usage + LemonSqueezy checkout. No payment method management. No invoice history. |
| API Keys (`ApiKeysPage.tsx`) | ✅ | Create/revoke API keys + enrollment tokens. **No copy-to-clipboard button** (user must manually select text). |
| **Compare Page** | ❌ | Not found in routes — mentioned in router comments but no page exists. |
| **Settings Page** | ❌ | No settings page for profile, notification prefs, or theme. |

### 4.4 Public Pages — PARTIAL

| Page | Status | Issues |
|------|--------|--------|
| Landing (`LandingPage.tsx`) | ✅ | Basic hero + features. **No responsive mobile layout** evident. |
| Verify (`VerifyPage.tsx`) | ✅ | Device auth verify page. |
| Pricing (`PricingPage.tsx`) | ✅ | Static pricing tiers. No live Stripe/LemonSqueezy price sync. |
| Pilot (`PilotPage.tsx`) | ✅ | Pilot program signup. |

### 4.5 Critical UX Gaps (All Pages)

| Gap | Impact |
|-----|--------|
| **No loading skeletons** | All pages show blank/white during data fetch |
| **No empty states** | Zero agents shows empty table with only headers |
| **No error boundaries** | Any component crash takes down entire app |
| **No pagination** | 200 events limit hardcoded in queries |
| **No real-time updates** | WebSocket/polling not implemented (only 5s interval polling on AgentsPage) |
| **No dark mode toggle** | `DarkModeToggle.tsx` exists but `ThemeProvider.tsx` may not be fully wired |
| **No mobile responsive** | CSS uses basic classes, no media queries evident |
| **No toast notifications** | All errors shown inline |
| **No confirmation dialogs** | API key revocation has no "are you sure?" |
| **Inline styles** | LoginPage uses `style={{}}` objects instead of CSS classes |

### 4.6 Structural Issues

- **No routing for `/settings`, `/compare`, `/policy`** — listed in router comments but unimplemented.
- **Enterprise admin panel** (`enterprise/admin-panel.tsx`) exists but no route points to it.
- **Enterprise audit view** (`enterprise/audit-view.tsx`) exists but no route.
- **Enterprise policy editor** (`enterprise/policy-editor.tsx`) exists but no route.
- **Team provider** (`enterprise/team-provider.tsx`) exists but no route.
- All enterprise pages are **orphaned components** — no way to navigate to them.
- `styles.css` size unknown but `main.tsx` imports it globally — CSS organization is likely monolithic.

### 4.7 Build & Deployment

- **Vite + React Router** build chain. `vite.config.ts` exists.
- `vercel.json` for Vercel deployment.
- `DEPLOYMENT.md` with deployment instructions.
- `supabase/` directory for migrations.
- Build log files (`.dev.log`, `.dev.err.log`) left in package root — should be gitignored.

---

## 5. Test Coverage (7/10)

### 5.1 Core Engine — EXCELLENT (91 test files)

```
packages/core/src/__tests__/  — 91 files
```

Every major module has dedicated tests. Notable omissions:
- `policy.ts` (443 lines) — No dedicated test file. Tested indirectly via `evaluator.test.ts`.
- `policy-engine.ts` (150 lines) — No dedicated test file. Tested indirectly.
- `mcp-inventory.test.ts` — Exists ✅
- `federated.ts` (283 lines) — `No dedicated test found` (check needed)
- `command-chain-analyzer.ts` — Possibly indirectly tested.

### 5.2 Claude Code — GOOD (7 test files)

| File | Tests |
|------|-------|
| `approval-tracker.test.ts` | ✅ |
| `e2e.test.ts` | ✅ |
| `format.test.ts` | ✅ |
| `integration.test.ts` | ✅ |
| `mcp-server.test.ts` | ✅ |
| `session-start.test.ts` | ✅ |
| `skill-registration.test.ts` | ✅ |

### 5.3 OpenClaw — ADEQUATE (6 test files)

### 5.4 OpenCode — MINIMAL (4 test files)

### 5.5 Extension — MINIMAL (3 test files)

- **No VS Code API mock tests** — doesn't verify extension activation/deactivation.
- **No Cursor-specific tests** — cursor event parsing untested.

### 5.6 CLI — NONE (0 test files) ❌

### 5.7 SDK — NONE (1 integration test, 0 unit tests) ❌

### 5.8 Dashboard — MINIMAL (1 test file) ❌

- `integration.test.tsx` — Single integration smoke test.
- **No component tests** for any page.
- **No auth flow tests**.
- **No billing logic tests**.

### 5.9 End-to-End Tests

- `vitest.e2e.config.ts` exists at root.
- E2E suites exist in: claude-code (1), openclaw (2), opencode (1), extension (1).
- **No cross-connector e2e** — each connector tested in isolation.
- **No dashboard e2e** — no Playwright/Cypress tests for UI.

---

## 6. Documentation (8/10)

### 6.1 Strengths

| Document | Quality |
|----------|---------|
| `README.md` | ✅ Professional, well-structured |
| `docs/getting-started.md` | ✅ Clear install steps |
| `docs/architecture.md` | ✅ Clean package overview |
| `docs/how-it-works.md` | ✅ Detection layers explained |
| `docs/configuration.md` | ✅ Complete config reference |
| `docs/threat-rules.md` | ✅ Rule format documentation |
| `docs/device-auth.md` | ✅ Device flow documented |
| `docs/billing.md` | ✅ Pricing explained |
| `docs/incidents.md` | ✅ Incident lifecycle |
| `docs/platform-guides/` | ✅ All 4 platforms documented |
| `docs/strategy/` | ✅ 9 strategy documents (roadmap, competitive analysis, GTM) |
| `docs/runbooks/` | ✅ 4 runbooks (alerting, deployment, incident-response, secrets) |

### 6.2 Gaps

| Missing | Impact |
|---------|--------|
| **API reference docs** | SDK users have no API documentation |
| **SDK integration guide** | No document for how to integrate AIDR into custom agents |
| **Dashboard user guide** | No screenshots, no page-by-page guide |
| **Troubleshooting FAQ** | `docs/faq.md` exists but breadth unknown |
| **CLI command reference** | No `aidr --help` equivalent in docs |
| **Architecture v2** | `docs/strategy/technical-architecture-v2.md` exists but no public URL |
| **Changelog** | `CHANGELOG.md` exists per package but no unified changelog |
| **Migration guide** | No guide for open-source → commercial migration |

---

## 7. Critical Issues (BLOCKER)

### B1: Dashboard Enterprise Pages are Orphaned

**Location**: `packages/dashboard/src/enterprise/`  
**Files**: `admin-panel.tsx`, `audit-view.tsx`, `policy-editor.tsx`, `team-provider.tsx`  
**Impact**: ~1500+ lines of dead code. Never rendered. If they are remnants of a previous version, they should be removed or wired.

### B2: CLI and SDK Have Zero Test Coverage

**Location**: `packages/cli/src/`, `packages/sdk/src/`  
**Impact**: CLI is the "one-command setup" product promise. Zero tests means regressions will ship to users. SDK billing/logic untested.

### B3: Advanced Modules Not Wired Into Detection Pipeline

**Location**: `packages/core/src/` — novelty-detection, behavioral-analyzer, risk-scorer, command-chain-analyzer, contain, quarantine, rollback, response-configurator  
**Impact**: ~2000+ lines of code implementing advanced features that are never executed at runtime. Either wire them in or remove them.

### B4: Policy Duplication (policy.ts vs policy-engine.ts)

**Location**: `policy.ts` (443 lines) and `policy-engine.ts` (150 lines)  
**Impact**: Both export PolicyEngine-like classes with different APIs. Confusing for developers. Risk of one being used while the other is updated.

### B5: Extension Missing VS Code/Cursor Runtime Tests

**Location**: `packages/extension/src/`  
**Impact**: Extension activation, hook installation, and event handling are untested. Cannot ship to VS Code marketplace with confidence.

---

## 8. Improvement Roadmap

### Quick Wins (< 1 day, meaningful impact)

- [ ] **Add loading states to all dashboard pages**: Wrap data fetches with a simple `<div>Loading...</div>`. Current: blank screen during fetch.
- [ ] **Add empty state "No agents found" to AgentsPage**: Currently shows empty table with headers only.
- [ ] **Add copy-to-clipboard on ApiKeysPage**: API key creation currently shows key in plaintext with no copy button.
- [ ] **Remove build log files**: `.dev.log`, `.dev.err.log`, `.dev5175.log` in `packages/dashboard/`.
- [ ] **Fix logger-adapter filename typo**: `packages/opencode/src/logger-adaptor.ts` → `logger-adapter.ts`.
- [ ] **Add confirmation dialog to API key revocation**: Currently one-click revoke with no warning.
- [ ] **Add gitignore entries**: Build logs, tsconfig.tsbuildinfo, `.tmp-test/` directories.

### Medium Effort (1-3 days, significant improvement)

- [ ] **Wire novelty detection into evaluator.ts**: ~200 lines of anomaly detection that never runs. Add as a configurable signal source.
- [ ] **Add error boundaries to Dashboard**: Wrap each page route in `<ErrorBoundary>` to prevent full-app crashes.
- [ ] **Add CLI tests**: Start with `setup.test.ts` and `status.test.ts` — test the user-facing commands.
- [ ] **Add `@types/vscode` to extension package**: Ensure VS Code API types are properly resolved.
- [ ] **Add `/settings` route to Dashboard**: Even a minimal settings page is needed for user profile, theme toggle.
- [ ] **Implement expired token handling in OnboardingPage**: Currently polls forever if device code expires.
- [ ] **Reduce evaluator.ts complexity**: Extract cache management, intel loading, and policy evaluation into smaller focused modules.

### Major Investment (1+ week, transformative)

- [ ] **Wire enterprise pages into router or remove**: `admin-panel.tsx`, `policy-editor.tsx`, `team-provider.tsx` + routing.
- [ ] **Consolidate policy.ts and policy-engine.ts**: Single authoritative policy engine with clear API.
- [ ] **Complete output scanner wiring**: Currently only wired in Claude Code post-tool-use. Wire for all connectors.
- [ ] **Add Playwright E2E tests for Dashboard**: Cover login flow, agent list, incident viewing, billing page.
- [ ] **Implement real-time dashboard updates**: Replace 5-second polling with Supabase Realtime subscriptions.
- [ ] **Add dashboard pagination**: Agents and events currently load all rows. Add cursor/offset pagination.
- [ ] **Wire response modules into evaluator**: Auto-Contain, Auto-Quarantine, Auto-Rollback should be configurable response modes.
- [ ] **Add dark mode support**: `DarkModeToggle.tsx` and `ThemeProvider.tsx` exist but full dark mode CSS is incomplete.
- [ ] **SDK billing/freemium/referral tests**: Business logic modules need unit tests before GA.
- [ ] **CLI integration test suite**: End-to-end test for the complete `aidr setup` flow.

---

## 9. Detailed Module-by-Module Issues

### packages/core/src/

| File | Issue | Severity |
|------|-------|----------|
| `evaluator.ts:78-79` | Module-level mutable cache (`cachedPackageIntel`) | HIGH |
| `evaluator.ts:400+` | Function too large, single orchestrator | MEDIUM |
| `policy.ts` (all) | Duplicates `policy-engine.ts` with different API | HIGH |
| `build-flavor.ts` | `isCommercialBuild()` always returns `true` | MEDIUM |
| `contain.ts:87-90` | Container execution is a no-op (`// Note: In practice`) | HIGH |
| `federated.ts` | No coordinator URL, no transport | MEDIUM |
| `community-rules.ts` | No persistence, no network sync | MEDIUM |

### packages/claude-code/

| File | Issue | Severity |
|------|-------|----------|
| `mcp-server.ts:43-56` | Integrity check fails open silently | MEDIUM |
| `approval-tracker.ts` | File-based cross-process race conditions | MEDIUM |

### packages/dashboard/

| File | Issue | Severity |
|------|-------|----------|
| `main.tsx:36-90` | Router missing `/settings`, `/compare`, `/admin`, `/team` routes | HIGH |
| `LoginPage.tsx:33-85` | Inline styles instead of CSS classes | LOW |
| `AgentsPage.tsx:79-83` | No empty state, table headers only | MEDIUM |
| `IncidentsPage.tsx:36` | `isIncidentLikeEvent` hardcodes payload field names | MEDIUM |
| `BillingPage.tsx` | `seat_usage` view fallback logic complex | MEDIUM |
| `ApiKeysPage.tsx` | No copy button for created keys | LOW |
| `OnboardingPage.tsx` | No token expiry handling | MEDIUM |
| `enterprise/*` | All 4 components unreachable via routing | HIGH |
| `AppLayout.tsx` | May not properly handle active nav state | MEDIUM |

### packages/extension/

| File | Issue | Severity |
|------|-------|----------|
| `aidr-hook.ts:52` | `readStdinJson()` minimal error handling | MEDIUM |
| All | No VS Code/Cursor API mock tests | HIGH |

---

## 10. Feature Completeness Matrix

| Feature | Core | Claude Code | OpenClaw | OpenCode | Extension | CLI | SDK | Dashboard |
|---------|------|-------------|----------|----------|-----------|-----|-----|-----------|
| URL detection | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | — |
| Command detection | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | — |
| File path detection | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | — |
| Heuristic matching | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | — |
| Threat rules (YAML) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | — |
| Policy evaluation | ✅ | ✅ | ✅ | ✅ | ⚠️ | — | ✅ | — |
| URL reputation check | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | — |
| Package supply chain | ✅ | ✅ | ✅ | ✅ | ✅ | — | ✅ | — |
| AMSI scanning | ✅ | — | — | — | — | — | — | — |
| Plugin scanning | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | — |
| Output scanning | ✅ | ✅ | ❌ | ❌ | ❌ | — | ❌ | — |
| Incident correlation | ✅ | — | — | — | — | — | — | ✅ |
| Novelty detection | ⚠️ | — | — | — | — | — | — | — |
| Behavioral analysis | ⚠️ | — | — | — | — | — | — | — |
| Federated learning | ⚠️ | — | — | — | — | — | — | — |
| Auto-Contain | ⚠️ | ❌ | ❌ | ❌ | ❌ | — | — | — |
| Auto-Quarantine | ⚠️ | ❌ | ❌ | ❌ | ❌ | — | — | — |
| Auto-Rollback | ⚠️ | ❌ | ❌ | ❌ | ❌ | — | — | — |
| Response config | ⚠️ | ❌ | ❌ | ❌ | ❌ | — | — | — |
| Device auth | ✅ | ✅ | ✅ | ✅ | ✅ | — | — | ✅ |
| Agent inventory | — | — | — | — | — | — | — | ✅ |
| Incident dashboard | — | — | — | — | — | — | — | ✅ |
| Billing/seats | — | — | — | — | — | — | — | ✅ |
| API key management | — | — | — | — | — | — | — | ✅ |
| CLI setup | — | — | — | — | — | ✅ | — | — |
| OpenCode integration | — | — | — | ✅ | — | — | — | — |
| OpenClaw integration | — | — | ✅ | — | — | — | — | — |
| VS Code extension | — | — | — | — | ⚠️ | — | — | — |

**Legend**: ✅ Implemented | ⚠️ Partially implemented / not wired | ❌ Not implemented | — Not applicable

---

## 11. Recommendations by Priority

### P0 — Before GA Launch
1. **Wire enterprise dashboard pages** or remove orphaned code (~1500 lines)
2. **Add CLI tests** — zero-tolerance for untested user-facing commands
3. **Consolidate policy.ts and policy-engine.ts** — confusing duplication
4. **Remove module-level mutable cache** in `evaluator.ts:78-79`

### P1 — Critical Quality
5. **Add loading/empty/error states to all dashboard pages**
6. **Add extension tests** — VS Code/Cursor activation at minimum
7. **Build output scanner for all connectors** (currently only Claude Code)
8. **Wire novelty detection and risk scoring** into detection pipeline

### P2 — Important
9. **Add pagination** to agents and events dashboards
10. **Implement Settings page** (profile, notifications, theme)
11. **Add dashboard E2E tests** with Playwright
12. **Add copy-to-clipboard to key creation** flow
13. **Fix onboarding expired token** — stop polling when code expires

### P3 — Nice to Have
14. **Wire auto-contain/quarantine/rollback** as configurable response modes
15. **Dark mode** — complete ThemeProvider + CSS
16. **Real-time subscriptions** — replace polling with Supabase Realtime
17. **SDK billing/referral/freemium tests**
18. **Federated learning coordinator** implementation
19. **Community rules persistence layer**
20. **Unified changelog** across all packages
