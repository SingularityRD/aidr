# AIDR Project Audit (Hostile Verification Snapshot)

**Date:** 2026-04-30

## Baseline

| Area | Status | Evidence |
|---|---|---|
| Working tree cleanliness | Dirty (large pre-existing unrelated churn) | `git status --short`, `git diff --stat` |
| Typecheck | Pass | `pnpm check` |
| Build | Pass | `pnpm build` (after elevated rerun due to sandbox EPERM) |
| Unit tests | Pass | `pnpm test:unit` => 86 files / 1639 tests |

## Verified Security Claims

| Claim | Result | Evidence |
|---|---|---|
| LLM threat rule file exists and is active | Verified | `threats/llm-threats.yaml` + passing LLM rule tests |
| Prompt injection/system prompt extraction/tool misuse/memory poisoning checks | Verified | `packages/core/src/__tests__/llm-threats.test.ts` |
| PII detector enhancements | Verified | `packages/core/src/pii-detector.ts` + `pii-enhancement.test.ts` |
| Audit log redaction | Verified | `audit-log.test.ts` redaction case |
| Claude integration stability | Verified | `packages/claude-code/src/__tests__/integration.test.ts` pass |
| Dashboard incident page buildability | Verified | dashboard build passes |

## Newly Closed/Reduced Gaps

- Output safety: **implemented minimally** (`packages/core/src/output-scanner.ts`) and wired into Claude `post-tool-use`.
- MCP inventory: **implemented minimally** (`packages/core/src/mcp-inventory.ts`) and wired into session-start warning path.

## Remaining Blockers

| Blocker | Priority | Exact Area | Next Step |
|---|---|---|---|
| Full connector-wide output scanning coverage | P1 | non-Claude runtime output paths | add shared output hook integration in other connectors |
| Full MCP semantic policy model | P2 | policy/evaluator layer | map inventory to enforceable policy intents, not only risk hints |
| Repo hygiene (large unrelated dirty diff) | P1 | repository root | isolate security hardening changes into clean branch/cherry-pick set |
