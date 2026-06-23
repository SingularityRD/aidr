# AIDR Feature Map (Truth Pass)

**Date:** 2026-04-30  
**Scope:** hostile verification status after runtime/tests/build checks

| Feature | Status | Evidence |
|---|---|---|
| LLM threat rules (`threats/llm-threats.yaml`) | Implemented + tested | `packages/core/src/__tests__/llm-threats.test.ts` passes (29/29) |
| Prompt injection detection (direct/indirect/system prompt extraction/tool misuse/memory poisoning) | Implemented + tested | Rule hits validated in `llm-threats.test.ts`; loaded via normal threat loading path used by unit/integration suites |
| PII/secret detection expansion | Implemented + tested | `packages/core/src/pii-detector.ts` + `pii-enhancement.test.ts` passes (20/20) |
| Audit redaction | Implemented + tested | `packages/core/src/__tests__/audit-log.test.ts` secret redaction test passes |
| Dashboard incidents UX improvements | Implemented + build-verified | `pnpm -C packages/dashboard build` passes; page compiles in unit/integration run |
| Demo seed data | Test fixture implemented | `packages/core/src/__tests__/demo-seed.ts` + `demo-seed.test.ts` pass in unit suite; not yet a product CLI seed command |
| Output safety scanner | Minimally implemented + partially wired | `packages/core/src/output-scanner.ts`, tests pass; wired in Claude `post-tool-use` hook (`packages/claude-code/src/post-tool-use.ts`) |
| MCP/tool-server inventory | Minimally implemented + partial | `packages/core/src/mcp-inventory.ts`, tests pass; session-start warns on risky discovered servers |

## Explicit Non-Claims

- This file does **not** claim complete MCP semantic enforcement. Current support is inventory/risk hints only.
- This file does **not** claim full platform-wide output scanning. Current wiring is implemented in Claude post-tool-use path.
- This file does **not** claim demo seed is a production data seeding command; current implementation is test-fixture oriented.
