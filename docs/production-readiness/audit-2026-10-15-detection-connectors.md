# Detection & connector audit — 15 October 2026

Scope owned for this pass: the detection engine and rules (`packages/core` detection
paths, `threats/`, `allowlists/`), the connectors (`packages/claude-code`, `codex`,
`opencode`, `openclaw`, the Cursor/VS Code extension hook side), and the
`packages/cli` setup/verify/doctor commands. Out of scope (other agents own them):
`packages/desktop`, `packages/browser-guard`, `supabase/`, `packages/dashboard`,
`deploy/`.

This record has two halves:

1. **Re-verification** of every `DET-*`, `CON-*` and `MSC-11..13` finding from
   [`ga-audit-2026-10-12.findings.json`](ga-audit-2026-10-12.findings.json) on this
   checkout, by re-running each finding's own reproduction against the **built**
   connectors (not source).
2. A **fresh adversarial audit** of the current code (much changed 13–15 Oct):
   bypasses, connector coverage gaps, fail-open paths, developer-facing false
   positives, latency and TR/EN message quality.

Everything was exercised against the real built hooks with an isolated `HOME`, the
same way the shipped connectors run. Harnesses and raw case files are kept out of the
repo (session scratchpad); the regression tests that lock in each fix are in
`packages/core/src/__tests__/exfil-deny-regression.test.ts`. Payload idioms below are
described rather than quoted verbatim.

Environment: Windows 11, Node 24, pnpm 10.29.3, development build of each connector.

---

## Part 1 — Re-verification of the 2026-10-12 findings

Each finding's reproduction from the findings JSON was replayed. **All `DET-*`,
`CON-*` and `MSC-11..13` items that were fixed on 12–13 Oct remain closed on this
checkout; none regressed.**

### Detection (DET-1 … DET-6)

| ID | Reproduction (built `pre-tool-use.cjs`, isolated HOME) | Result |
|----|--------------------------------------------------------|--------|
| DET-1 | reverse-shell quoting / concatenation / variable-indirection forms of the dev-tcp, socat and ncat one-liners | **deny** (CLT-CMD-003 / CLT-CMD-030 / CLT-CMD-004); the `command_normalized` view catches the obfuscated forms |
| DET-2 | Node net reverse shell; Node `-e` spawning a child process | **deny** CLT-CMD-039; the child-process form **ask** CLT-CMD-037 |
| DET-3 | a b64 blob decoded inside a shell substitution and run | **deny** CLT-OBFUS-012 |
| DET-4 | netcat with the `-c` exec flag | **deny** CLT-CMD-004 |
| DET-5 | fetch of a `deno.land/x/<attacker>` installer script into a shell | **deny** CLT-CMD-001 (the latent suppression margin is unchanged; still code-read, not independently reproduced as allow) |
| DET-6 | miner binary; stratum-protocol mining-pool URL; 70 KB command (truncation) | **deny** CLT-MINE-001 / CLT-MINE-004 / input-limit deny — closed items still closed |

### Connectors (CON-1 … CON-14)

| ID | Reproduction | Result |
|----|-------------|--------|
| CON-1 | host-native self-disable/uninstall: `claude plugin disable|uninstall|marketplace remove aidr`, `code --uninstall-extension`, `openclaw plugins disable`, `openclaw config set …enabled false`, `npm uninstall -g @singularityrd/aidr-codex`, removing the `aidr-codex-hook` binary, removing the OpenClaw extension dir | **deny** CLT-SELF-007 / CLT-SELF-001. The `rm`/`mv` of host config files (`~/.claude/plugins`, `~/.cursor/hooks.json`, `~/.codex/config.toml`) are **ask** (CLT-SELF-003) — `require_approval` by design, since those files hold the user's other settings; the dangerous *disable/uninstall* forms all deny. |
| CON-2 | OpenClaw `process{submit|paste|send-keys}` and `nodes{run}` with shell payloads (reverse shell, recursive root delete) | **block**; `exec` + driven-process parity holds. Residual: `process{write}` of **interpreter** source to a background REPL is not a shell payload and is not caught — pre-existing, low-severity, noted below. |
| CON-3 | OpenCode `patch`/`list`/`multiedit` of SSH authorized_keys, `.claude/settings.json`, a shell rc file | **block** (CLT-FILE-002 / CLT-SELF-004 / persistence); normalization closed |
| CON-4 | MCP argv: `mcp__ssh__run` with a recursive-delete argv, and a `cmd`+`args` reverse shell | **deny** CLT-CMD-006 / CLT-CMD-003 |
| CON-5/6 | Cursor/VS Code shim — no real host in this env; code paths unchanged (external dependency, still open per support matrix) | n/a here |
| CON-8 | `git clone`, `npm install react`, `pip install requests`, docs `WebFetch`, `Write` README with a link, `ls -la` | **allow** — no spurious ask on routine dev actions |
| CON-10 | credential-read evasions: cd-then-cat of an SSH key, a glob of the key, recursive grep of the `.ssh` dir, `Grep` over `~/.aws`, `Glob` for the key | **ask** CLT-FILE-003 / CLT-FILE-008 / AIDR-FLOW-004 — closed |

### MSC-11 / MSC-12 / MSC-13

Code-read items; unchanged on this checkout and outside the detection/connector
behaviour re-run. No regression introduced by this pass. (`MSC-11` SEA packaging,
`MSC-12` `aidr simulate --min-score` default, `MSC-13` headless-Linux `aidr setup`
credential — all still as recorded on 12 Oct.)

---

## Part 2 — Fresh adversarial audit (new findings, fixed this pass)

Nine P0s and the bulk of the P1 bypasses from 12 Oct were already closed. The fresh
pass concentrated on the areas the brief named: exfiltration channels, single-command
credential leaks, interpreter reverse shells, PowerShell egress, latency, and
developer-facing false positives. Four new gaps were found and fixed; several
observations are recorded as accepted residuals.

### AUDIT-DET-1 (P1, fixed) — one-shot credential exfiltration only asked; now denies, and two egress channels were not classified at all

- **Severity:** P1 (security).
- **Repro (built `pre-tool-use.cjs`, isolated HOME).** Before the fix:
  - uploading a credential file off-host in a single command — `wget` post-file of a dotenv,
    `curl` upload (`-T` / `--upload-file`) of a dotenv, `curl` data-binary of a dotenv,
    `curl` form upload of a cloud-creds file, `scp` of an SSH key, piping a dotenv into netcat,
    and dumping the environment into a `curl` POST — all gave **ask** (AIDR-FLOW-002 /
    CLT-CRED-004), not deny. The brief requires single-command credential exfiltration to
    **deny**.
  - `tftp` with a `put` of an SSH key, and a `put` driven over `tftp` stdin, → **allow**
    (fail-open): `tftp`/`ftp` were in no egress role list, so the channel was invisible to the
    flow engine.
  - `rsync` of the whole `.ssh` directory to a remote → **ask** only: the credential
    *directory* as a copy source was not secret-grade.
  - a credential read inside a shell substitution feeding an egress (a `cat` of a cloud-creds
    file inside `$( … )`, or a process substitution `<( … )`) → **ask** CLT-CRED-004: the read
    was not surfaced to the flow engine, so the chain did not escalate.
  - PowerShell `WebClient.UploadFile` of a dotenv and `Invoke-WebRequest -InFile <credfile>
    -Method Put` → **ask** CLT-URL-004, not deny.
- **Fix.**
  - `packages/core/src/toxic-flow.ts:276,294,402,509,1085` — new `singleCallSecretExfil`
    flag on the exfil-chain finding, set when the secret read **and** the data egress are in
    the *same* call; `applyToxicFlow` then emits **deny** instead of the balanced-default `ask`
    (an operator-chosen `monitor` still only monitors; a secret read in an *earlier* call still
    asks, as before).
  - `packages/core/src/toxic-flow-classify.ts:549` (`uploadedLocalFiles`) — curl/wget body
    files (`-T`, `--upload-file`, `--post-file`, data `@file`, form `field=@file`, `-InFile`)
    are recorded as secret reads when the path is credential-grade.
  - `packages/core/src/toxic-flow-classify.ts:713`/`:716` (`SUBSTITUTION_FILE_READ`,
    `substitutionSecretReads`) — a `cat`/`head`/decoder of a file inside `$( … )`, backticks,
    or `<( … )` feeding an egress is recorded as a secret read.
  - `packages/core/src/toxic-flow-classify.ts:800,919` (`handleFtpPut`) — `tftp`/`ftp`/`atftp`
    are classified: a `put` of a credential file is a secret read + data upload.
  - `threats/flow/capabilities.yaml:132,137,142` — the `~/.ssh`, `~/.gnupg`, `~/.aws`
    directories are secret-grade copy sources (embedded copy regenerated).
  - `threats/win-commands.yaml:822` (CLT-WIN-CMD-062, **block**) — PowerShell
    `UploadFile`/`UploadData`/`Invoke-WebRequest -InFile` of a credential-grade source.
- **After:** every form above → **deny** (AIDR-FLOW-002, or CLT-WIN-CMD-062 for the
  PowerShell uploads). Benign uploads (a build artifact over `curl -T`, a bundle over `scp`,
  a public dir over `rsync`) stay **allow**.
- **Regression tests:** `exfil-deny-regression.test.ts` → `AUDIT-DET-1` describe (10 exfil
  forms + the balanced-default deny + the earlier-read-still-asks control + 3 benign controls).

### AUDIT-DET-2 (P2, fixed) — PHP socket reverse shell only asked

- **Severity:** P2 (security); asymmetry with the other interpreters.
- **Repro.** A PHP one-liner that opens a socket to a remote host and then runs a shell
  (a socket-open function plus one of the PHP process-running functions) → **ask**
  CLT-CMD-038, while the Python (CLT-CMD-023), Perl (CLT-CMD-033), Ruby (CLT-CMD-032) and
  Node (CLT-CMD-039) equivalents all **block**.
- **Fix.** `threats/commands.yaml:577` — new CLT-CMD-040 (**block**): a PHP socket open
  followed by any of the PHP process-running functions, on `command` and `command_normalized`.
- **After:** → **deny** CLT-CMD-040. A benign `php -r 'echo 1+1;'` stays allow.
- **Regression tests:** `exfil-deny-regression.test.ts` → `AUDIT-DET-2`.

### AUDIT-DET-3 (P2, fixed) — PowerShell credential upload only asked

Folded into the fix list above (CLT-WIN-CMD-062). Covered by the `AUDIT-DET-3` describe.

### AUDIT-PERF-1 (P1, fixed) — benign hook latency dominated by an unconditional Windows ACL probe

- **Severity:** P1 (ux / adoption). Budget: benign hook < 300 ms median on Windows.
- **Repro.** CPU-profile of a benign `git status` hook call (`--cpu-prof`): ~0.5 s of the call
  was `VerdictCache` → `loadOrCreateCacheKey` → `preparePrivateLocalFile` →
  `windowsTargetsAreAlreadyPrivate` (native `whoami`/`icacls`/`cmd dir` spawns) plus
  `inspectResponseBarrier` → `userInfo`. The verdict cache was opened on **every** call even
  though it only ever holds URL and package verdicts, and a plain `git status` produces
  neither. Median benign latency ~436 ms idle / ~2 s under load.
- **Fix.** `packages/core/src/evaluator.ts:2258` — open the `VerdictCache` (and run its
  Windows ACL key hardening) only when the call actually has a URL artifact or
  `package_check` is enabled. No behaviour change for cached URL/package verdicts.
- **After:** benign median ~300 ms (p95 ~365 ms) measured on a machine pinned at 100% CPU;
  idle would be lower. The cache still loads for URL/package calls, which are the only ones
  that read or write it.

### Residuals and accepted observations (not fixed this pass)

- **AUDIT-OBS-1 (CON-2 residual, low).** OpenClaw `process{action:write}` of **interpreter**
  source to a backgrounded REPL is inspected as a shell command, so interpreter source that is
  destructive without being a shell idiom is not caught. Driven-process **shell** payloads
  (submit/paste/send-keys) and `nodes{run}` argv are caught. Fixing this needs per-interpreter
  inspection of REPL stdin and is tracked separately.
- **AUDIT-OBS-2 (DNS exfil, low).** A DNS lookup whose label is built from a recon command
  (`whoami`) → **ask** (CLT-CMD-021), not deny. A DNS lookup whose label is a file read
  (a decoder reading a file into the name) **denies** via the exfil chain. Leaving the
  pure-recon form at ask avoids false positives on scripted DNS tooling.
- **AUDIT-OBS-3 (writing a local dotenv, low / by design).** Appending to a `.env.local` file
  → **ask** (CLT-CRED-003). Writing to a dotenv is common in a demo but can also plant secrets;
  the guard is kept as an ask on purpose. All the brief's named benign actions (`git clone`,
  `npm install react`, `pip install`, reading source, docs `WebFetch`, `ls`, build directory
  cleanup, `docker build`, `make`, `cargo build`) pass clean.
- **DET-5 (deno.land suppression).** Unchanged; the whole-domain trust margin for a
  path-scoped public registry remains a code-read latent item, backed today by an unrelated
  rule. Not independently reproducible as an allow.

### False-positive sweep (developer actions that must stay allow)

`git clone`, `git pull`, `npm install` / `npm ci` / `pnpm install` / `yarn add`,
`pip install -r requirements.txt`, `cargo build --release`, `docker build`, `make test`,
`curl https://api.github.com/...`, reading `.env.example`, `cat package.json`,
`Grep` over `src`, docs `WebFetch`, build-directory cleanup, `find`,
`chmod +x scripts/build.sh`, `git reset --hard origin/main` → all **allow**. No new
false positives were introduced by the AUDIT-DET-1 flow changes (benign uploads and
copies verified allow).

### Latency

Benign median ~300 ms after AUDIT-PERF-1 (was ~436 ms idle / ~2 s loaded). Blocking
calls add the rule-match cost only. See AUDIT-PERF-1.

### TR/EN message quality

Spot-checked the Turkish verdict text for the new/changed rules and the flow reasons:
CLT-CMD-040 (`PHP soketiyle ters kabuk`), CLT-WIN-CMD-062 (`PowerShell ile kimlik
bilgisi dosyasını dışarı yükleme`) and AIDR-FLOW-002 (`Bu oturumda riskli birleşim …`)
all read as fluent, native Turkish with the English rule id preserved. No machine-
translation artefacts in the touched strings.

---

## Verification performed

- Targeted vitest: `exfil-deny-regression.test.ts` (new), `toxic-flow.test.ts`,
  `toxic-flow-capabilities.test.ts` (embedded-copy drift), `command-threats.test.ts`,
  `win-commands-threats.test.ts`, `gap-evasion-regression.test.ts`, `heuristics.test.ts`
  — all pass. `connector-parity.test.ts` passes (one DLP-audit assertion is flaky under
  parallel load for the single-process Codex hook — passes in isolation; pre-existing,
  not caused by this pass).
- ReDoS invariant: the new rule regexes (CLT-CMD-040, CLT-WIN-CMD-062) and the new
  classifier regex (`SUBSTITUTION_FILE_READ`) use only bounded gaps; checked against
  60 KB adversarial inputs (<50 ms).
- Full `pnpm check`, `pnpm lint`, `pnpm test` at the end of the pass (see commit log).


---

## Part 3 — False positives that blocked ordinary development (coordinator addendum)

Reported when the AIDR hook was installed globally on a shared machine: it blocked
ordinary development work by other agents. For an enterprise sale this is a shipping
blocker — developers disable a tool that blocks normal coding. Each was reproduced
with the built Claude Code hook using realistic PreToolUse JSON (before/after), then
fixed so legitimate work passes while the attack each rule targets still triggers.
Regression tests both ways live in `packages/core/src/__tests__/data-not-instruction-regression.test.ts`.

**General principle applied:** content an agent writes into a source or docs file is
DATA, not instructions, unless the file is an agent-instruction surface (CLAUDE.md,
AGENTS.md, .cursorrules, Copilot instructions, MCP / tool manifests). The engine now
enforces this in `dropDataNotInstructionMatches` (`packages/core/src/evaluator.ts`),
applied to the heuristic matches just before they become a verdict.

| # | Rule | Before (blocked legitimate work) | After | Fix |
|---|------|----------------------------------|-------|-----|
| 1 | LLM-TOOL-001 (tool_misuse) | `Write` of TypeScript source containing a regex .exec() call, or a child-process helper, → **deny** | **allow** | Model-manipulation families (prompt-injection, jailbreak, prompt-extraction, tool-misuse, memory-poisoning) are dropped on an authored write to a non-instruction file; kept for instruction surfaces and for untrusted reads / MCP content. |
| 2 | LLM-INJ-003 (prompt_injection) | a code comment and a status message about the browser developer mode setting (loading an unpacked extension) → **block** | **allow** | Same authored-write gate; plus the over-broad generic "developer mode" token was removed from LLM-INJ-003 (the explicit jailbreak tokens stay), so technical prose about browser settings never trips it on any surface. |
| 3 | CLT-SELF-007 (self_defense) | a read-only `cat` / `grep` of repo source that happened to contain an `aidr` CLI string → **deny** | **allow** | On a pure read-only inspection command (viewer / searcher, no execution), the CLI-invocation rule CLT-SELF-007 is dropped — it targets a real invocation, not a sought string. Every other self-defense rule (state-directory and approval-store access) still applies to reads. |
| 4 | LLM-TOOL-003 (tool_misuse) | `Write` of CLI help text such as "schedule 'aidr heartbeat' with your device management tool" → **block** | **allow** | Authored-write gate (tool_misuse is a model-manipulation family). |
| 5 | CLT-SELF-008 (self_defense) | `Write` of a test fixture that builds a `<tmp>/home/<state-dir>/...` path, and a README that merely names the folder → **deny** | **allow** | The content match stays on the rule (a script body or MCP argument that acts on the dir still blocks), but the gate exempts the content hit for an authored write to a docs / test file. A write whose TARGET is the real install / state directory, and a script (.js / .sh / .py) whose body reads the resolved `~/.singularity-aidr`, still deny. |
| 6 | CLT-AGENT-RH-006 (agent_sabotage) | redirecting or truncating a scratch `.log` file (e.g. test output) → **ask** | **allow** | Narrowed to audit / security logs only: `/var/log/…`, `audit*.log` / `*.jsonl`. Wiping AIDR's own audit log or a system log still blocks; truncating `build.log` / `test-output.log` does not. |
| 7 | AIDR-FLOW-002 (toxic_flow) | a plain read-only HTTP GET health check to a vendor site, after an earlier tool output held a secret-looking value → **block** (exfil chain) | **allow** | A GET with no request body no longer counts as data egress merely because the command contains a `$( … )` substitution somewhere; substitution carries data only when inside the URL (where it could place a secret in the query). A body / upload or piped stdin still carries data, and a long-token query is still flagged. |

**Negative controls (still block after the fix), all re-run:** a jailbreak written into
CLAUDE.md or .cursorrules (instruction surfaces); an actual `aidr uninstall`; reading the
approval key or store under the state directory, including via globs / braces; wiping an
audit `.jsonl` or a `/var/log` file; a script file whose body reads the resolved state
directory. All remain `deny` / `ask`.
