# Product Benchmark (Engineering-Focused)

> **SUPERSEDED — historical record (2026-04-30). Do not use this file to judge
> readiness.** Superseded by `READINESS_BACKLOG.json` (per-defect record with
> evidence) and `RELEASE_READINESS_REPORT.md` (current assessment).
>
> Two rows in the table below were **wrong at the time they were written** and are
> corrected here, because a reader would otherwise take them as verified coverage:
>
> - "Output safety scanning | Partial | `output-scanner.ts` + Claude post-tool-use
>   wiring" — `output-scanner.ts` has **zero importers**; it is not wired into any
>   connector. Recorded as a dead module, not partial coverage.
> - "MCP/tool server visibility | Partial | `mcp-inventory.ts` + session-start
>   warnings" — `mcp-inventory.ts` also has **zero importers**, and
>   `session-start.ts` contains no MCP/inventory reference, so no session-start
>   warning path exists.
>
> The "input/tool-call policy enforcement | Strong" row was also misleading in a way
> that mattered: enforcement existed in code but was **inactive by default** for a
> fresh install until the defect tracked as AIDR-015 was fixed.

## Original content (2026-04-30, retained verbatim below)

This benchmark is intentionally limited to implementation-relevant gaps and does not make go-to-market claims.

## Security Capability Positioning

| Capability | Current AIDR State | Verified in Code |
|---|---|---|
| Input/tool-call policy enforcement | Strong | core evaluator/engine + connector integration tests |
| LLM prompt-injection class detection | Present | `threats/llm-threats.yaml` + `llm-threats.test.ts` |
| Secret/PII detection + redaction | Present | `pii-detector.ts` + `pii-enhancement.test.ts` + `audit-log.test.ts` |
| Output safety scanning | Partial | `output-scanner.ts` + Claude post-tool-use wiring |
| MCP/tool server visibility | Partial | `mcp-inventory.ts` + session-start warnings |

## Engineering Gaps vs. "Pilot-Ready" Standard

1. Output safety coverage must be generalized across all connector output paths.
   *(Still open: the module has no importers at all — see the correction above.)*
2. MCP inventory must evolve from warning-only to policy-aware semantics.
   *(Still open: the module has no importers at all — see the correction above.)*
3. Current repository has heavy unrelated dirty state; release prep needs a clean, reviewable change set.
   *(Addressed: 23 tracked scratch/lint logs and committed test artifacts were removed — AIDR-012.)*
