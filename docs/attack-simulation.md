# Attack Simulation Self-Test (`aidr simulate`)

`aidr simulate` is a **defensive self-test**. It feeds a corpus of harmless,
defanged detection fixtures to Singularity AIDR's own local evaluator and reports
what the product detects — the way an [EICAR test file](https://www.eicar.org/download-anti-malware-testfile/)
proves an anti-virus engine is alive without shipping a real virus.

It is safe to run anywhere: **nothing is ever executed**. Every fixture is passed
to the detector as data and the returned verdict is scored. No command runs, no
file is read, and no network socket is opened.

```bash
aidr simulate                     # run the full corpus, print a table
pnpm simulate                     # same, from a source checkout
```

## What it proves

- The shipped threat rules still load and match the behaviours they describe
  (prompt injection, exfiltration, destructive commands, obfuscation, supply
  chain, MCP tool poisoning, self-defense, and TR/EN personal data / secrets).
- The prompt scanner (`scanPrompt`) and tool-output scanner (`scanModelOutput`)
  still flag secrets, personal data and injection payloads.
- A benign "twin" of each risky fixture is **not** flagged, so the score is a
  measure of real detection, not of blocking everything.

## How it works

The corpus lives in `packages/cli/src/commands/simulate-corpus.ts`. It is built
from what the product already ships:

- the threat-rule ids/titles in `threats/*.yaml`, and
- the attack strings already committed in the core, connector and MCP-gateway
  test fixtures.

Every fixture is defanged:

- **No live credentials.** Anything shaped like a token is assembled at load time
  from obviously-fake parts (a visible `SIMULATED` / `FAKE` / `EXAMPLE` marker),
  so a secret scanner sees only string concatenation.
- **Reserved endpoints only.** Every URL is `*.invalid`, `*.example`,
  `example.com`, or a TEST-NET range (`192.0.2.0/24`, `198.51.100.0/24`,
  `203.0.113.0/24`). The cloud-metadata IP `169.254.169.254` appears only as a URL
  string being fetched — which is exactly what the product should flag — and
  nothing resolves or opens it.

Each fixture reaches the detector on one of three surfaces, mirroring the
connectors:

| Surface  | Evaluated with                              |
|----------|---------------------------------------------|
| tool     | `extractFromToolCall` + `evaluateToolCall`  |
| prompt   | `scanPrompt`                                |
| output   | `scanModelOutput`                           |

### Sandbox

The self-test derives its configuration from **your effective config**
(sensitivity, disabled threats, `heuristics_enabled`, local policy, prompt
protection) but forces `mode: local` and switches off every network and
persistence leg (reputation lookups, cache, audit logging, control plane, intel
packs, incidents). It runs inside a throwaway `HOME`, and it copies any custom
rules from `~/.singularity-aidr/threats` so the report reflects the rules that
actually run on this machine.

### What is *not* counted

Offline, the URL / file / package **reputation legs are inert** — with no
first-party endpoint configured they return "not verified clean; requires review"
rather than a clean result (see `CLAUDE.md`). Such a result is neither a
detection nor a clean pass, so `aidr simulate` **excludes it from the score**
(reported under "not counted"). The same applies to a `managed_disabled` or
`config_invalid` verdict, or any input the evaluator could not inspect.

## Scoring

- **Detection score** — the percentage of counted malicious fixtures whose
  verdict meets or exceeds the case's declared minimum outcome (`ask` or `deny`).
  `ask` and `deny` both count as "flagged": `ask` is a block pending out-of-band
  human approval.
- **Benign false-positive rate** — the percentage of benign twins that were
  flagged.
- **Misses** — malicious fixtures that were not flagged to their expected level,
  listed with their actual verdict.

`--min-score N` makes the command exit non-zero when the detection score is below
`N`, which is useful as a regression gate in CI.

## Options

```
aidr simulate [--suite <names>] [--sensitivity <level>]
              [--format table|json|html] [--output <file>]
              [--min-score <n>] [--connector <name>]
```

| Option | Description |
|--------|-------------|
| `--suite` | Comma-separated categories to run: `injection`, `exfiltration`, `destructive`, `encoding`, `supply-chain`, `mcp`, `self-defense`, `privacy`. Default: all. |
| `--sensitivity` | Override sensitivity: `paranoid`, `balanced`, `relaxed`. Default: your config. A stricter preset can turn some `deny` results into `ask` and vice-versa. |
| `--format` | `table` (default), `json`, or a self-contained, shareable `html` report. |
| `--output` | Write the report to a file instead of stdout. |
| `--min-score` | Exit non-zero when the detection score is below this value (0–100). |
| `--connector` | Drive a **built connector entry point** instead of the in-process evaluator: `claude-code`, `codex`, `cursor`, or `vscode`. Tool-call fixtures run through the connector's real `dist` binary; prompt and output fixtures fall back to the in-process scanners because those are separate connector surfaces. The entry points are located from the CLI's own source checkout (`<repo>/packages/cli`), never from the current directory; an installed CLI refuses connector mode. |

### Connector mode

```bash
aidr simulate --connector claude-code --suite destructive,exfiltration
```

This spawns the same binary that ships (`packages/claude-code/dist/pre-tool-use.cjs`,
`packages/codex/dist/pre-tool-use.cjs`, or the Cursor/VS Code extension hook) and
drives its stdin/stdout, so the report reflects the connector, not just the
library. Codex has no working `ask` verb, so it reports an `ask` as a `deny`;
that stricter block still counts as a detection.

## Examples

```bash
# Full run, human-readable
aidr simulate

# Just the injection and privacy suites, as JSON
aidr simulate --suite injection,privacy --format json

# A customer-presentable HTML report
aidr simulate --format html --output aidr-simulation.html

# CI gate: fail the build if detection drops below 95%
aidr simulate --min-score 95
```

## Extending the corpus

Add a case to the appropriate category array in
`packages/cli/src/commands/simulate-corpus.ts`. Reuse an existing attack string
from `threats/*.yaml` or a committed test fixture rather than authoring new
offensive tooling, keep endpoints reserved, and assemble any fake credential from
parts at load time. The schema and safety invariants are enforced by
`packages/cli/src/__tests__/simulate.test.ts`.
