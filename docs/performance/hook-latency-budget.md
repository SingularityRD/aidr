# PreToolUse hook latency budget

Every tool call an agent makes waits for the PreToolUse hook. The hook is a
new Node.js process per call, so its cost is paid on every command, file read
and web request. This page publishes the budget, explains how it is measured
and gated, and records the latest measurement.

> **This is an engineering budget, not an SLA.** The numbers below were
> measured on one shared Linux cloud VM. They are not customer hardware
> results. Windows with Defender, the signed release artifact and representative
> customer machines still have to be measured (see "Still open").

## Budget

The machine-readable budget is in
[`scripts/benchmarks/hook-latency-budget.json`](../../scripts/benchmarks/hook-latency-budget.json).

| Level | Value | Applies to | Enforced by |
|---|---|---|---|
| Product target | p50 ≤ 400 ms, p95 ≤ 600 ms | Steady state of a session (one persistent HOME) on reference hardware: a quiet 4-vCPU Linux VM, or Windows 11 with Defender, Node 22+ | Release measurement (manual, below) |
| Measurement gate | p95 ≤ 1200 ms warm, ≤ 1500 ms cold; zero errors | `scripts/benchmarks/hook-latency.mjs --budget-file …` on reference hardware | Release checklist |
| CI gate | p95 of 20 warm calls < 3000 ms | Shared, loaded CI runners | `packages/claude-code/src/__tests__/pre-tool-use-latency.test.ts` (runs in `pnpm test`) |

The CI gate is generous on purpose. Shared runners are loaded, and a
wall-clock bound cannot tell a slow algorithm from a busy machine. It catches
order-of-magnitude regressions, such as an extra YAML parse, a network call or
a process spawn per call, not noise. Set `AIDR_HOOK_LATENCY_P95_BUDGET_MS`
(p95) or `AIDR_HOOK_LATENCY_BUDGET_MS` (cold median) to change it on a slow
machine. Do not raise the shipped values to make a failing run pass.

## How to measure

```bash
pnpm --filter @singularityrd/aidr-claude-code build
node scripts/benchmarks/hook-latency.mjs --samples 30 \
  --budget-file scripts/benchmarks/hook-latency-budget.json \
  --json hook-latency.json
```

The script runs the hook the way Claude Code does:

- It spawns `node packages/claude-code/dist/pre-tool-use.cjs` once per call,
  writes the hook JSON to stdin and times from spawn to exit.
- `AIDR_*` and `NODE_COMPILE_CACHE*` variables are cleared and the default
  local configuration is used.
- One untimed call primes the OS file cache.
- Scenarios use the phase names of the
  [benchmark harness](../../scripts/benchmarks/README.md):
  - `cold_local`: a fresh HOME for every call.
  - `warm_local`: one persistent HOME, with seven benign commands in rotation
    so the runaway guard never fires.
  - Each phase has a benign and a blocked (`curl … | sh`) scenario.
- A wrong decision or a non-zero exit counts as an error.
- It prints p50, p95, p99 and max, and exits 1 when `--budget-file` is given
  and a scenario's p95 or error count breaks the budget.

Record the load average next to the result. The `--json` report includes it.

## Latest measurement (2026-10-14)

- Host: 4 vCPU Intel Xeon @ 2.80 GHz, Linux, Node v22.22.0.
- The host was **heavily shared**: the load average was 27 to 53 throughout,
  with other agents compiling and testing. Absolute numbers are therefore 2 to
  3 times the quiet-host numbers in
  [the 2026-10-11 record](../production-readiness/hook-latency-2026-10-11.md)
  (about 0.5 s p50).
- The before/after comparison is still meaningful, because both builds ran on
  the same host in the same window.
- Raw samples:
  [after](evidence/hook-latency-2026-10-14-after.json),
  [before](evidence/hook-latency-2026-10-14-before.json).

All values are in ms.

| Scenario | n | Before p50 / p95 | After p50 / p95 | Errors |
|---|---:|---:|---:|---:|
| cold, benign | 30 | 1872 / 2459 | 1154 / 1775 | 0 |
| cold, blocked | 15 | 1694 / 2863 | 1256 / 2518 | 0 |
| warm, benign | 30 | 1517 / 2035 | 898 / 1215 | 0 |
| warm, blocked | 15 | 1511 / 2400 | 844 / 1084 | 0 |

An interleaved A/B run (30 warm calls per arm, alternating call by call) gave
p50 2435 → 1374 ms and 2440 → 1271 ms in the two orders. In CPU profiles of a
cold call, total sampled time fell from about 2.5 s to about 1.15 s on the
loaded host. YAML parsing and the garbage collection it caused (about 250 ms →
60 ms) disappeared from the profile.

### What changed

The hook used to parse several YAML data files on every call, after the threat
rules themselves were already pre-parsed at build time:

- `threats/mappings/frameworks.yaml` (39 KB, the largest).
- `threats/flow/capabilities.yaml` (14 KB).
- The trusted-installer and model-source allowlists.

On a cold JIT that was the largest avoidable cost left. `compile-threat-cache.mjs`
now pre-parses these files too (`DATA_PARSE_CACHE`), and
`packages/core/src/yaml-parse-cache.ts` serves them. The safety model is the
same as for the rules:

- Entries are keyed by the SHA-256 of the exact file content, so the file on
  disk stays authoritative.
- Edited, user-supplied or newer content misses the cache and is parsed as
  before, with the same errors.
- A hit returns a private copy, so a long-lived process cannot alter the
  cache.

Already in place before this change:

- The V8 compile cache for the hook bundle (`hook-compile-cache.ts`).
- Pre-parsed threat rules.
- Lazy Sentry loading.

### Not done, and why

- **Resident daemon.** A per-user evaluator process with the hook as a thin
  client would remove most of the per-call process cost. It is an architecture
  change that needs its own security review: a local IPC endpoint the agent
  must not be able to reach, and a fail-closed client contract. It is not small
  and safe enough to add here.
- **Rule prefiltering.** Regex evaluation of the rules (`runThreat`) is now
  the largest single item in the profile. Skipping rules by tool type or a
  literal prefilter would cut it, but every skipped rule is a detection
  decision. It needs per-rule evidence and is left for a dedicated change.

## Still open (needs a human or other hardware)

- A measurement on Windows 11 with Defender, using the real ACL path, the
  signed MSI install and the koffi AMSI backend. Without koffi, AMSI adds a
  PowerShell start of about 0.3 to 0.5 s per call; see
  [AMSI Scanning](../amsi-scanning.md).
- A quiet reference-hardware run, to confirm the product target (p50 ≤ 400 ms,
  p95 ≤ 600 ms).
- Concurrent agents on representative customer hardware.
