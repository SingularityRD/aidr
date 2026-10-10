# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project

Singularity AIDR — an AI Agent Detection & Response layer that guards the commands,
files and web requests of AI coding agents. Connectors: Claude Code, Cursor, VS Code,
OpenClaw, OpenCode, Codex. The detection engine is a shared core; every connector and
the CLI consume it. Alongside it: an MCP gateway, **Browser Guard** (a Chrome/Edge/Firefox
extension that masks TR/EN personal data and secrets before prompts reach AI chat sites)
and the **AIDR Privacy** engine that Browser Guard's detection reuses. See
`docs/architecture.md` and `docs/product/overview.md` for the design and
`READINESS_BACKLOG.json` for the current defect/readiness record.

## Commands

```bash
pnpm install                               # Install all dependencies
pnpm ci:local --keep-going                   # Run every .github/workflows/ci.yml gate locally (CI is disabled); ci:local:quick for the fast subset, --list for steps
pnpm test                                    # Run all tests (builds automatically, E2E excluded)
pnpm test -- --reporter=verbose              # Verbose test output
pnpm test -- packages/core/src/__tests__/extractors.test.ts  # Single test file
pnpm test -- -t "test name"                  # Run single test by name
pnpm test:e2e                                # All E2E tests (Claude Code + OpenClaw + Cursor + VS Code)
pnpm test:e2e:claude                         # Claude Code E2E only
pnpm test:e2e:openclaw                       # OpenClaw E2E only (requires gateway + token)
pnpm test:e2e:cursor                         # Cursor extension E2E only
pnpm test:e2e:vscode                         # VS Code extension E2E only
pnpm test:e2e:browser-guard                  # Browser Guard real-browser E2E (Playwright + fixtures)
pnpm test:e2e:real-host                      # Real Claude Code/Codex/OpenCode/OpenClaw binaries vs a scripted mock model (no API keys)
pnpm test:privacy                            # Build @singularityrd/aidr-privacy and run its node --test suites (not part of `pnpm test`)
pnpm build                                  # Build all packages (tsc + esbuild bundle)
pnpm build:browser-guard                    # Build the Browser Guard extension bundles
pnpm verify:privacy-rules                   # Drift check: privacy rule files copied into other packages match packages/privacy
pnpm verify:helm                            # Render/validate the on-prem Helm chart (deploy/helm)
pnpm onprem:config-reference                # Regenerate / drift-check the on-prem configuration reference
pnpm build:sea                              # Build standalone SEA binaries (requires official Node.js, not Homebrew)
pnpm lint                                   # Lint with Biome
pnpm lint:fix                               # Lint + auto-fix
pnpm check                                  # Type check all packages
pnpm changeset                              # Create a changeset for your changes
pnpm run version                            # Apply changesets: bump versions, generate changelogs, sync manifests
bash scripts/pre-release-audit.sh           # Pre-release content audit (requires .gitleaks.toml symlink)
```

## Repository Structure

TypeScript monorepo. Connector packages and their shared core:

- `packages/core/` — `@singularityrd/aidr-core`: Platform-agnostic detection engine (extractors, heuristics, URL check client, decision engine, caching)
- `packages/claude-code/` — `@singularityrd/aidr-claude-code`: Claude Code hook entry points (pre-tool-use, post-tool-use, session-start, health, mcp-server)
- `packages/openclaw/` — `@singularityrd/aidr-openclaw`: OpenClaw plugin connector. `sync-assets.mjs` (run by `pnpm build`) generates its rules and skills under `dist/resources/` (build output, gitignored with `dist/`).
- `packages/opencode/` — `@singularityrd/aidr-opencode`: OpenCode plugin connector
- `packages/extension/` — `aidr-cursor`: Cursor and VS Code extensions
- `packages/cli/` — `@singularityrd/aidr-cli`: local setup/status/config CLI. Ships its own copy of the rules via `scripts/sync-assets.mjs` (core publishes only `dist/`).
- `packages/sdk/` — `@singularityrd/aidr-sdk`: security client and framework-neutral generic middleware
- `packages/dashboard/` — control-plane dashboard (Vite/React app; its Edge Functions live in the root `supabase/functions`)
- `packages/codex/` — `@singularityrd/aidr-codex`: Codex CLI connector, implemented as a native
  `PreToolUse` hook (verified against `codex-cli 0.141.0`). Codex fails **open** on a crashing
  or untrusted hook, so this connector translates `ask` into an explicit `deny` and turns
  internal errors into a deny as well — see `packages/codex/README.md`. Ships its own copy of
  the rules via `scripts/sync-assets.mjs`.
- `packages/mcp-gateway/` — `@singularityrd/aidr-mcp-gateway`: loopback MCP gateway (HTTP + stdio
  bridge) that inspects MCP tool results before they reach the model; signed manifests and
  operator-only approval (`aidr-mcp-approve`), never an MCP tool.
- `packages/browser-guard/` — `@singularityrd/aidr-browser-guard`: Chrome/Edge/Firefox MV3
  extension. Contracts in `src/types.ts`; `src/engine/` (detection, reversible placeholder vault,
  exact-data match, file sanitisation), `src/sites/` (ChatGPT, Gemini, Claude, Copilot,
  Perplexity, DeepSeek, Mistral, Grok + generic), `src/dom/`, `src/content/`, `src/background/`
  (managed policy, counts-only telemetry per `docs/contracts/privacy-telemetry.md`, native host
  bridge). Detection reuses browser-safe `packages/privacy/src` modules via relative imports;
  browser code must not import `node:` modules. E2E harness in `e2e/`.
- `packages/privacy/` — `@singularityrd/aidr-privacy` 0.6.0: TR/EN privacy engine (checksum
  TCKN/IBAN/Luhn, phones, addresses, secrets), optional native host (NER/OCR) and enterprise
  gateway (`/platform`). Tests run with `node --test` via `pnpm test:privacy`, not vitest.
- `services/aig-bridge/` — Python/FastAPI bridge for the SingularityRD-owned AI Infra Guard source, tracked directly under `vendor/ai-infra-guard/` (not a submodule)
- `supabase/` — canonical migrations + Edge Functions (all Edge Functions, including the dashboard's, live here)
- `threats/` — YAML threat definitions (data, not code); 494 rules across 29 files (`grep -h '^- id:' threats/*.yaml | wc -l`)
- `allowlists/` — Trusted domain allowlists
- `hooks/` — `hooks.json` registering hooks with Claude Code
- `skills/` — `security-awareness/SKILL.md`, synced into connector `resources/`

Readiness and defect tracking live in `READINESS_BACKLOG.json` (authoritative),
`RELEASE_READINESS_REPORT.md`, and `docs/production-readiness/`.

## Test Tiers

| Tier | Scope | Files | Requires |
|------|-------|-------|----------|
| 1 — Unit | Core library functions | `packages/core/src/__tests__/*.test.ts` | pnpm dev deps |
| 2 — Integration | Hook/plugin entry points | `packages/claude-code/src/__tests__/`, `packages/openclaw/src/__tests__/e2e-integration.test.ts` | pnpm dev deps |
| 3 — E2E (Claude Code) | Full plugin in Claude CLI | `packages/claude-code/src/__tests__/e2e.test.ts` | `claude` CLI + `ANTHROPIC_API_KEY` |
| 3 — E2E (OpenClaw) | Full plugin in OpenClaw gateway | `packages/openclaw/src/__tests__/e2e.test.ts` | OpenClaw gateway (token read from `~/.openclaw/openclaw.json`) |
| 3 — E2E (Cursor extension) | Singularity AIDR extension in Cursor Extension Host | `packages/extension/src/__tests__/e2e.test.ts` | Installed Cursor executable |
| 3 — E2E (VS Code extension) | Singularity AIDR extension in VS Code Extension Host | `packages/extension/src/__tests__/e2e.test.ts` | Installed VS Code executable |
| 1 — Unit (Browser Guard) | Engine, vault, sites, editor, content, background | `packages/browser-guard/src/__tests__/*.test.ts` (jsdom where marked) | pnpm dev deps |
| 3 — E2E (Browser Guard) | Built extension in Chromium against hermetic AI-site fixtures | `packages/browser-guard/e2e/` | `playwright-core` Chromium build |
| 3 — E2E (real host, mock model) | Real, unmodified Claude Code / Codex / OpenCode / OpenClaw binaries with AIDR installed from the build in a disposable HOME; a scripted loopback mock model supplies the tool calls, so it proves host enforcement, not model behaviour | `scripts/real-host-e2e/` (records: `docs/evidence/real-host/`) | `claude` on PATH (or `AIDR_CLAUDE_PATH`); network on first run to install pinned Codex/OpenCode/OpenClaw (+ Node 24 for OpenClaw) into `.ci-local/real-host`; no API keys |
| Privacy (node --test) | `@singularityrd/aidr-privacy` suites | `packages/privacy/tests/**/*.test.mjs` | Node >= 22.16; optional Python/libseccomp/OpenSSL (named skips) |

`pnpm test` runs tiers 1–2 automatically (builds via `globalSetup` before running). Tier 3 (E2E) is excluded — run with `pnpm test:e2e` (all), `pnpm test:e2e:claude`, `pnpm test:e2e:openclaw`, `pnpm test:e2e:cursor`, `pnpm test:e2e:vscode`, `pnpm test:e2e:browser-guard`, or `pnpm test:e2e:real-host` (local-only opt-in step `real-host-mock-model` in `pnpm ci:local`; `--evidence-dir docs/evidence/real-host` refreshes the records `deploy/native/interception-matrix.json` cites, whose sha256 is pinned in `deploy/native/support-matrix.json`). Cursor and VS Code are not covered by the real-host tier. The privacy package is run separately with `pnpm test:privacy`.

**Claude Code E2E prerequisites:** `claude` CLI in PATH, valid `ANTHROPIC_API_KEY`, and AIDR must **not** be installed via the Claude Code marketplace (duplicate-plugin conflict with `--plugin-dir`).

**OpenClaw E2E prerequisites:** Running OpenClaw gateway with Singularity AIDR installed. Auth token is read from `~/.openclaw/openclaw.json` automatically (override via `OPENCLAW_GATEWAY_TOKEN` env var). See `docs/development.md` for gateway setup.

**Cursor / VS Code E2E prerequisites:** Installed Cursor / VS Code executables. Cursor headless agent coverage in `pnpm test:e2e:cursor` additionally requires the `agent` CLI (PATH or `AIDR_AGENT_PATH`) plus valid auth (`agent login` or `CURSOR_API_KEY`); if unavailable, only that headless sub-suite is skipped. Optional executable overrides: `AIDR_CURSOR_PATH`, `AIDR_AGENT_PATH`, `AIDR_VSCODE_PATH`, `VSCODE_EXECUTABLE_PATH`.

## Architecture

This is a **multi-platform plugin family** sharing one detection core. The six
supported connectors are Claude Code, Cursor/VS Code (one extension package),
OpenClaw, OpenCode and Codex; the CLI and SDK consume the same core.

1. **Claude Code Connector** (`packages/claude-code/src/`) — `pre-tool-use.ts` reads tool call JSON from stdin, orchestrates core, outputs verdict JSON to stdout. `session-start.ts` scans installed plugins for threats. Both are bundled by esbuild into single CJS files.

2. **OpenClaw Connector** (`packages/openclaw/src/`) — In-process plugin using `api.on('before_tool_call')`. Registers `aidr_allowlist_add` / `aidr_allowlist_remove` only; there is deliberately **no** agent-callable approval tool (approval is operator-controlled and out-of-band). Bundled into a single CJS file.

3. **Core Library** (`packages/core/src/`) — Platform-agnostic TypeScript library:
   - `extractors.ts` — Extracts URLs, commands, file paths from tool inputs
   - `threat-loader.ts` — Loads YAML threat definitions from `threats/`
   - `heuristics.ts` — Matches extracted artifacts against threat patterns
   - `clients/url-check.ts` — HTTP client for URL reputation checking and endpoint resolver
   - `engine.ts` — Decision engine combining signals into a Verdict
   - `cache.ts` — JSON file verdict cache with TTLs
   - `allowlist.ts` — User allowlist management
   - `trusted-domains.ts` — Trusted domain loading and matching
   - `audit-log.ts` — JSONL audit log for verdicts
   - `installation-id.ts` — Persistent installation UUID (`~/.singularity-aidr/installation-id`)
   - `version-check.ts` — Version check via POST with environment context
   - `session-start.ts` — Session start orchestrator (scan + version check)
   - `plugin-scanner.ts` — Plugin file scanning for threats
   - `plugin-scan-cache.ts` — Plugin scan result cache

4. **Plugin Config** — `hooks/hooks.json` registers hooks, `.claude-plugin/plugin.json` is the plugin manifest, `skills/security-awareness/SKILL.md` provides security knowledge to Claude.

**Data flow (Claude Code):** Hook stdin → extract artifacts → check allowlist → check cache → heuristics + URL check → DecisionEngine → cache result → audit log → hook stdout JSON

**Data flow (OpenClaw / OpenCode):** `before_tool_call` (or `tool.execute.before`) → extract artifacts → check whether an **operator-recorded** approval already exists for this exact artifact → check allowlist → check cache → heuristics + reputation checks → DecisionEngine → cache result → audit log → block (throw) or pass. No approval tool is exposed to the agent.

## Key Conventions

- All detection patterns are data (YAML in `threats/`), not hardcoded
- **Enforcement default: local.** `ConfigSchema.mode` defaults to `"local"`, so a
  fresh install evaluates every tool call with no account or network access.
  `managed` is an opt-in layer; an un-enrolled managed install disables managed-only
  features but still enforces locally. Never make enrollment a precondition for
  detection.
- **Failure policy is per layer, not global — do not describe the product as
  blanket "fail-open":**
  - *Detection internals* (a threat rule that errors, an optional reputation lookup,
    cache/intel/policy load): skip that signal, log it, and continue. This is
    deliberate and must never be reported to the user as a clean result.
  - *Connector entry points*: fail **closed**. Claude Code, OpenClaw, OpenCode and
    the Cursor/VS Code hook return a deny (or block) on an internal error rather than
    silently allowing the call. Extension hooks always exit with code `0` and emit a
    deny verdict — a killed hook must not pass the call through uninspected.
  - *Security controls* (auth, tenant isolation, rate limits, webhook signatures,
    approval): fail closed.
- Verdicts use three decisions: `allow`, `deny`, `ask` with confidence scoring
- `ask` is a **block pending out-of-band human approval**. No connector exposes an
  approval tool to the agent; the model receives the `actionId` in the block reason,
  so an agent-callable approval would let a prompt-injected agent approve its own
  block.
- Sensitivity presets: paranoid (0.70), balanced (0.85), relaxed (0.95)
- Merge precedence when multiple signals fire: `deny > ask > allow`
- URL/file/package reputation checks require a deployed first-party endpoint; with
  none configured those legs are inert and must not be presented as "clean"
- Standalone binary via Node.js SEA for distribution (no runtime deps)
- Naming: YAML/JSON data uses `snake_case` (`threat_id`, `source_file`); TypeScript interfaces use `camelCase` (`threatId`, `sourceFile`). Conversion functions bridge the two at serialization boundaries.

## Pre-PR Checklist

Before creating a pull request, run the @"code-simplifier:code-simplifier (agent)" subagent on all changed files to review for clarity, consistency, and maintainability improvements. Apply any suggested changes before opening the PR.

