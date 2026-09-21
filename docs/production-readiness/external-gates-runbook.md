# External gates 18, 19, and 27 runbook

Use this runbook when an operator can supply the real host, credentials, and release-candidate evidence. These gates are fail-closed: **synthetic credentials, synthetic acceptance, synthetic evidence, placeholders, or copied results are never valid.** Run against one immutable candidate and retain both passes and failures.

## 1. Prepare the real hosts

Install the supported, customer-representative **Cursor** and **Visual Studio Code** versions on the execution machine. Locate the executables with `cursor`/`code`, or set explicit paths:

```powershell
$env:AIDR_CURSOR_PATH = 'C:\path\to\Cursor.exe'
$env:AIDR_VSCODE_PATH = 'C:\path\to\Code.exe'
# VSCODE_EXECUTABLE_PATH is also accepted when AIDR_VSCODE_PATH is unset.
```

The doctor searches the PATH and standard install locations as well. Gate 18 is `pnpm verify:native-host`; it must observe real host side effects, not merely a version probe.

## 2. Supply credentials without committing them

Use an approved secret manager, an ephemeral shell, or a local ignored environment file. Do **not** put secrets in tracked files, command transcripts, evidence, or `.npmrc` committed to the repository. Supply only live credentials for the actual services/hosts:

- `ANTHROPIC_API_KEY` — Claude E2E
- `OPENCLAW_GATEWAY_TOKEN` and, where required, `OPENCLAW_E2E_HOST` — OpenClaw
- `OPENCODE_API_KEY` — OpenCode
- `CURSOR_API_KEY` — Cursor headless agent (or authenticate with `agent login`)
- `AIDR_AGENT_PATH` — optional Cursor `agent` executable override
- `AIDR_E2E_ENABLE_IDE_HOST=1` — enable IDE-host coverage when the run requires it

Bind the run to the exact candidate with `AIDR_E2E_RC_DIGEST` (the candidate `release-inventory.json` SHA-256). If evidence is supplied separately, use the repository's candidate/evidence variables: `AIDR_CANDIDATE_SHA256` or `AIDR_RELEASE_CANDIDATE_SHA256`, `AIDR_GATE18_EVIDENCE`, `AIDR_GATE19_EVIDENCE`, `AIDR_GATE27_EVIDENCE`, `AIDR_AIG_E2E_EVIDENCE`, `AIDR_SUPABASE_E2E_EVIDENCE`, and `AIDR_DASHBOARD_BROWSER_EVIDENCE`. Each evidence JSON must contain the matching `candidate_digest`; a mismatch, missing binding, or unreadable file is not evidence.

## 3. Collect candidate-bound evidence

Run the real acceptance procedure on the same candidate, host versions, configuration, and permitted network. Record redacted JSON/log/JUnit output and the operator, timestamps, environment, observed side effect, result, and candidate digest. Keep evidence under the configured evidence directory; never edit a result to manufacture a PASS. Gate 19 is the real `pnpm test:e2e`, and its external receipts must be fresh and digest-bound. Gate 27 is the real package-consumer installation rehearsal, not a development-tree test.

## 4. Warm the authenticated pnpm cache

Configure registry authentication through the approved secret manager or user-level pnpm configuration, outside the repository. Then warm the cache from the lockfile using the real registry access:

```bash
pnpm install --frozen-lockfile
pnpm store path
```

Confirm the reported store exists (or set `PNPM_STORE_DIR`), and do not commit `.npmrc`, tokens, or generated secrets. Gate 27 uses `pnpm verify:package-install` and requires a release-built `dist` tree; development source maps/test directories cause a fail-closed result.

## 5. Diagnose before running gates

From the repository root:

```bash
pnpm external-gates:doctor -- --json
```

Inspect every field rather than treating `ok` as acceptance: the doctor checks executable paths, evidence existence/binding, candidate digest shape, and pnpm-store metadata, but explicitly does **not** assert credential validity, acceptance, evidence validity, or PASS.

## 6. Run each gate and capture its result

Use the evidence-index runner so the declared command, log, result, and candidate binding are recorded:

```bash
node scripts/generate-v8-evidence-index.mjs --run 18-native-host
node scripts/generate-v8-evidence-index.mjs --run 19-release-e2e
node scripts/generate-v8-evidence-index.mjs --run 27-empty-path-package-install
```

The underlying commands are respectively `pnpm verify:native-host`, `pnpm test:e2e`, and `pnpm verify:package-install`. Preserve a genuine `FAIL`, `NOT_RUN`, or `unknown`; never substitute a local fixture or synthetic receipt.

## 7. Final rehearsal

After the tree and candidate are settled, run the orchestrator once, sequentially:

```bash
node scripts/run-evidence-gates.mjs
node scripts/generate-v8-evidence-index.mjs --verify
```

Do not modify or commit the generated evidence after this rehearsal; any change makes the candidate-bound stamps stale. Review the final index and logs, publish only the evidence for the exact candidate, and report any unavailable host, invalid credential, missing receipt, or failed gate as open.

References: [`scripts/external-gates-doctor.mjs`](../../scripts/external-gates-doctor.mjs), [`scripts/generate-v8-evidence-index.mjs`](../../scripts/generate-v8-evidence-index.mjs), [`scripts/run-evidence-gates.mjs`](../../scripts/run-evidence-gates.mjs), and [`scripts/run-e2e-release.mjs`](../../scripts/run-e2e-release.mjs).
