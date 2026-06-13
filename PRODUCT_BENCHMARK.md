# Product Benchmark (Engineering-Focused)

**Date:** 2026-04-30

This benchmark is intentionally limited to implementation-relevant gaps and does not make go-to-market claims.

## Security Capability Positioning

| Capability | Current AIDR State | Verified in Code |
|---|---|---|
| Input/tool-call policy enforcement | Strong | core evaluator/engine + connector integration tests |
| LLM prompt-injection class detection | Present | `threats/llm-threats.yaml` + `llm-threats.test.ts` |
| Secret/PII detection + redaction | Present | `pii-detector.ts` + `pii-enhancement.test.ts` + `audit-log.test.ts` |
| Output safety scanning | Partial | `output-scanner.ts` + Claude post-tool-use wiring |
| MCP/tool server visibility | Partial | `mcp-inventory.ts` + session-start warnings |

## Engineering Gaps vs. “Pilot-Ready” Standard

1. Output safety coverage must be generalized across all connector output paths.
2. MCP inventory must evolve from warning-only to policy-aware semantics.
3. Current repository has heavy unrelated dirty state; release prep needs a clean, reviewable change set.
