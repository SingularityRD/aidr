# CHANGELOG_AGENT (Verification Pass)

**Date:** 2026-04-30

## Added

- `packages/core/src/output-scanner.ts`
  - Adds structured output findings (`secret_leak`, `prompt_injection_payload`, `system_prompt_leakage`, `unsafe_tool_instruction`).
- `packages/core/src/mcp-inventory.ts`
  - Adds MCP/tool-server inventory parsing + risk hints from known config shapes.
- `packages/core/src/__tests__/output-scanner.test.ts`
- `packages/core/src/__tests__/mcp-inventory.test.ts`

## Changed

- `packages/core/src/index.ts`
  - Exports output scanner + MCP inventory APIs.
- `packages/core/src/session-start.ts`
  - Loads MCP inventory and logs warning when risky servers are detected (best-effort, non-blocking).
- `packages/claude-code/src/post-tool-use.ts`
  - Scans output payload text and surfaces output-safety warning context.
- `packages/claude-code/src/__tests__/integration.test.ts`
  - Adds regression test for risky output safety context.

## Verification Results (This Pass)

- `pnpm check`: pass
- `pnpm build`: pass (required elevated run due to sandbox `spawn EPERM`)
- `pnpm test:unit`: pass (86 files / 1639 tests)
- Targeted tests:
  - `llm-threats.test.ts`: pass
  - `pii-enhancement.test.ts`: pass
  - `audit-log.test.ts`: pass
  - `output-scanner.test.ts`: pass
  - `mcp-inventory.test.ts`: pass
  - `packages/claude-code/src/__tests__/integration.test.ts`: pass

## Remaining Limits

- Output safety is currently wired to Claude post-tool-use path, not yet all connectors.
- MCP modeling is inventory/risk-hint level; no full semantic policy layer yet.
