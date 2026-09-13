# AIDR Feature Map

> **SUPERSEDED — historical record (2026-04-30). Do not use this file to judge
> readiness.**
>
> This table was written before the later hardening waves and before the security
> and integration audits of 2026-09-10. Some rows are now outdated in both
> directions. Superseded by `READINESS_BACKLOG.json` (per-defect status with
> evidence) and `RELEASE_READINESS_REPORT.md` (current assessment).

## Why this file is retained

It is the record of an earlier "truth pass" and its explicit non-claims are still
methodologically correct — they refused to claim complete MCP enforcement, full
platform-wide output scanning, or a production demo-seed command. That discipline
is preserved in the current backlog.

## Corrections required if you are reading this for status

| Row as written here | Actual verified state (2026-09-10) |
|---|---|
| "MCP/tool-server inventory — minimally implemented + partial, session-start warns on risky discovered servers" | `mcp-inventory.ts` has **zero importers**; `session-start.ts` contains no MCP/inventory reference. The claim that it is "wired into the session-start warning path" is false. |
| "Output safety scanner — minimally implemented + partially wired (Claude post-tool-use)" | `output-scanner.ts` has **zero importers**. The only caller of `pii-detector.detectPII` was that module. |
| "Demo seed data — test fixture implemented" | Accurate; still a test fixture, not a product command. |
| "LLM threat rules / PII detection / audit redaction — implemented + tested" | Accurate; these remain among the genuinely working parts. |

For the current, evidence-backed position use `READINESS_BACKLOG.json`. Notably it
records that the highest-severity defect found in this wave was not in any of the
rows above: with the default configuration the product enforced nothing at all
(AIDR-015).
