# Claude Code PreToolUse hook latency — 2026-10-11

Audit item 30 in [production-gaps-2026-10-10](../audit/production-gaps-2026-10-10.md).

This is a local engineering measurement. It is **not** production P95/P99 acceptance:
- It ran in one cloud container, not on customer hardware.
- No antivirus or Defender was present.
- No tenant DLP or NER policy was loaded.
- It used the development build of `packages/claude-code/dist/pre-tool-use.cjs` on branch `claude/focused-gates-0u1is2`.

## Environment

| Item | Value |
| --- | --- |
| OS | Linux 6.18 (cloud container) |
| CPU | 4 vCPU, Intel Xeon @ 2.10GHz |
| Node | v22.22.0 |
| Invocation | One `node pre-tool-use.cjs` process per call, Claude Code hook JSON on stdin, all `AIDR_*` variables cleared, default local config |

The same method as `pre-tool-use-latency.test.ts`. A cold run uses a fresh `HOME` for each call. A warm run reuses a persistent `HOME`. One untimed spawn primes the OS file cache first.

## Results (ms)

| Scenario | n | p50 | p95 | p99 | max | errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Cold, fresh HOME, `ls -la` | 30 | 468 | 521 | 570 | 570 | 0 |
| Warm, `ls -la` / `git status` | 100 | 489 | 535 | 572 | 613 | 0 |
| Warm, malicious `curl … \| sh` (deny) | 30 | 476 | 518 | 528 | 528 | 0 |
| Warm, 200 KB command | 20 | 254 | 313 | 2184 | 2184 | 0 |
| Concurrent, 8 parallel × 10 rounds on 4 vCPU | 80 | 1313 | 1410 | 1431 | 1431 | 0 |

## Reading

- **Cold medians are well inside the 1500 ms test budget.** Every cold sample is too. The 9 Oct Windows record had a cold median of 1498 ms; this Linux host has no ACL/PowerShell cost, so the two results are not comparable.
- **The 200 KB case is mostly rejected early by the input bounds,** which is why its median is faster. It had one 2.2 s outlier.
- **Under 8-way concurrency on 4 vCPU, latency scales with CPU contention:** p95 1.4 s.
- **Still to do before this item closes:**
  - Windows with Defender and the real ACL path.
  - macOS.
  - Tenant DLP and NER enabled.
  - The final signed artifact.
  - Concurrent agents on customer hardware.
