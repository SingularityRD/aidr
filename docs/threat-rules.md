# Threat Rules

Singularity AIDR uses YAML-based threat definitions to match tool call artifacts against known dangerous patterns. All detection logic is data - no patterns are hardcoded.

## Rule Files

Rules ship in the `threats/` directory at the repository root:

| File | Scope |
|------|-------|
| `commands.yaml` | Dangerous command patterns (pipe-to-shell, reverse shells, destructive ops) |
| `urls.yaml` | Malicious URL and domain patterns |
| `files.yaml` | Sensitive file path writes |
| `credentials.yaml` | Credential exposure patterns |
| `persistence.yaml` | Persistence mechanisms (cron, systemd, shell RC, LaunchAgents) |
| `obfuscation.yaml` | Encoding and obfuscation techniques |
| `supply_chain.yaml` | Supply chain risk patterns |
| `mining.yaml` | Cryptomining / resource hijacking (MITRE ATT&CK T1496): miner binaries, pool connections, miner flags, wallet payout targets, miner package installs |
| `self-defense.yaml` | Attempts to disable or bypass Singularity AIDR |
| `context-poisoning.yaml` | Data and context poisoning: writes to agent instruction/memory/config files, hidden or injected instructions in what is written, MCP tool poisoning, memory-store writes. Uses dedicated `match_on` values evaluated with operation context; see [poisoning-protection.md](poisoning-protection.md) |
| `mitre.yaml` | MITRE ATT&CK technique mappings |
| `script-content.yaml` | Pipe-to-shell, reverse shells and encoded execution written into scripts (see [Commands written into scripts](#commands-written-into-scripts)) |
| `win-*.yaml` | Windows-specific variants of the above |
| `mac-*.yaml` | macOS-specific variants (osascript, Keychain, LOLBins, defense evasion) |

`threats/mappings/frameworks.yaml` is not a rule file (the loader reads only `threats/*.yaml`). It maps every rule id to OWASP Top 10 for LLM Applications 2025, OWASP Top 10 for Agentic Applications 2026 and MITRE ATLAS; a new rule needs an entry there or the test suite fails. See [Security framework coverage](framework-coverage.md) (regenerate with `pnpm coverage:frameworks -- --write`).

## Rule Schema

```yaml
- id: "CLT-CMD-001"
  category: tool
  severity: critical
  confidence: 0.95
  action: block
  pattern: "curl\\s[^|]*\\|\\s*(bash|sh|zsh|ksh|dash)"
  match_on: command
  title: "Remote code execution via curl pipe to shell"
  expires_at: null
  revoked: false
```

### Fields

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique identifier (e.g. `CLT-CMD-001`) |
| `category` | string | Threat category (`tool`, `network_egress`, `secrets`, `supply_chain`) |
| `severity` | enum | `critical`, `high`, `medium`, or `low` |
| `confidence` | float | 0.0-1.0, used with sensitivity threshold |
| `action` | enum | `block`, `require_approval`, or `log` |
| `pattern` | string | Regex pattern |
| `match_on` | string or list | `command`, `url`, `file_path`, `content`, or `domain`; plugin/skill package scans only: `plugin_content`, `plugin_orphan_bytecode` (see [AI security posture](ai-security-posture.md)) |
| `title` | string | Human-readable description |
| `expires_at` | string or null | ISO 8601 expiration date, or `null` for permanent |
| `revoked` | boolean | Set `true` to disable a rule without removing it |
| `case_insensitive` | boolean | *(optional)* Match pattern case-insensitively (default: `false`) |

`match_on` accepts a single value or a list. For example, credential patterns may match on both `command` and `content`:

```yaml
  match_on: [command, content]
```

## What Gets Checked

**Bash commands (cross-platform):**
- Pipe-to-shell attacks, reverse shell patterns (incl. Python/Ruby/zsh socket shells), destructive operations
- Download-and-execute chains, privilege escalation
- Data exfiltration, persistence mechanisms (cron, systemd, shell RC, `at` jobs), credential exposure
- Obfuscation (base64-decode-exec, hex escapes, eval-decode, Python encoded payloads)
- Python one-liners with dangerous imports
- Cryptomining / resource hijacking (T1496): known miner binaries (`xmrig`, `minerd`,
  `cpuminer`, `ethminer`, `nbminer`, `phoenixminer`, `t-rex`, `lolminer`, `gminer`,
  `xmr-stak`, …) including `./`-prefixed and path-qualified forms, miner downloads,
  `stratum+tcp://` / `stratum+ssl://` pool URLs, pool endpoints on `-o`/`--url`/
  `--pool`/`-P`, miner-only flags (`--donate-level`, `--cpu-priority`, `--coin`,
  `-a cryptonight`, `--threads` combined with a pool), Monero/Ethereum wallet payout
  targets, miner-named package installs, install hooks that stage a miner, and
  miner registration in cron/systemd/launchd

**Bash commands (macOS-specific):**
- osascript RCE (AppleScript `do shell script`, JXA execution, piped/remote scripts)
- macOS LOLBins (`dscl`, `networksetup`, `systemsetup`, `kickstart`, `installer`, `hdiutil`, `pkgutil`)
- Keychain attacks (`security find-generic-password`, `dump-keychain`, `unlock-keychain`, `delete-keychain`, direct SQLite access)
- Defense evasion (Gatekeeper disable via `spctl`, SIP disable via `csrutil`, quarantine removal, firewall disable via `pfctl`, TCC reset via `tccutil`, security daemon unloading)
- Privilege escalation (`dscl -passwd`, `dseditgroup` admin group add)
- Destructive operations (`diskutil eraseDisk`, `tmutil delete` — ransomware indicator)
- Persistence (LaunchAgents via `osascript`/`launchctl`, login items, SecurityAgentPlugins, emond rules, `DYLD_INSERT_LIBRARIES`, Folder Actions, periodic scripts)
- Obfuscation (base64-to-osascript, DYLD injection, binary plist conversion via `plutil`, Swift inline execution)
- Supply chain (Homebrew install without version pin, remote `.pkg` install, cask installs)

**File writes/edits:**
- System authentication files, SSH keys and config, shell RC files
- macOS LaunchAgents/LaunchDaemons, TCC.db, authorization DB, kernel extensions, SecurityAgentPlugins, emond rules, Safari credential stores, Managed Preferences, Keychain files
- Cron directories, systemd unit files
- Credential files (`.env`, `.aws/credentials`, `.netrc`)
- Git hooks, URLs and credentials embedded in content

### Commands written into scripts

A `curl … | bash` that the agent *runs* is denied by `commands.yaml`. Written into a
file, the same line used to reach the engine only as a URL, so with the reputation leg
off (the default) the write was allowed. `script-content.yaml` closes that gap. Its
rules use `match_on: code:<language>` and run in the code-guard leg
(`packages/core/src/code-guard.ts`) on the text a call adds: a Write's content, the new
lines of an Edit/MultiEdit, the `+` lines of an `apply_patch`, an MCP `write_file` /
`edit_file`, or a heredoc redirected into a file. The payload is found anywhere in the
text, including after more than 64 KB of other lines.

| `match_on` | Files |
|---|---|
| `code:shell` | `.sh .bash .zsh .ksh .command`, shell rc files, `.git/hooks/*`, and any file whose `#!` line names a POSIX shell |
| `code:powershell` | `.ps1 .psm1`, or a `pwsh` / `powershell` shebang |
| `code:batch` | `.bat .cmd` |
| `code:dockerfile`, `code:makefile` | `Dockerfile`/`Containerfile`, `Makefile`/`*.mk` |
| `code:ci_config` | CI pipelines and git-hook managers: `.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, `.husky/`, … (the paths of the `ci_config` edit view) |
| `code:npm_script` | the `scripts` values of a `package.json` (for an edited fragment, every `"key": "value"` string) |

| Rule | Detects | Action |
|---|---|---|
| `CLT-SCRIPT-001` | download piped into a shell (`curl`/`wget`/`fetch` `\| sh`, also through `sudo`/`env`, across a `\` line continuation), `bash <(curl …)`, `source <(curl …)`, `sh -c "$(curl …)"` | ask |
| `CLT-SCRIPT-002` | PowerShell download run with `Invoke-Expression` (`iwr \| iex`, `iex (New-Object Net.WebClient).DownloadString(…)`) | ask |
| `CLT-SCRIPT-003` | reverse shell (`sh -i` with `/dev/tcp`, `nc -e /bin/sh`, `mkfifo` back-pipe, `socat … EXEC:sh`) | deny |
| `CLT-SCRIPT-004` | encoded payload decoded into a shell (`base64 -d \| sh`, `xxd -r \| sh`, `eval` of decoded text) | ask |
| `CLT-SCRIPT-005` | PowerShell `-EncodedCommand`, or `FromBase64String` run with `iex` | ask |

Why `ask` and not `deny`: writing a script is not running it, and CI files, Dockerfiles
and installers legitimately fetch toolchains this way, so a human decides. Reverse shells
are the exception: they have no ordinary development use, and a script in a git hook, CI
job or npm lifecycle script later runs without any further tool call AIDR could inspect.

Not matched: documentation (`README.md`, `docs/*.md` and every other file without a
script language), comment lines (`#`, `//`, `::`, `REM`), and downloads that are saved and
verified rather than piped (`curl -o tool.tgz …; sha256sum -c …`). The rules are not run
by `aidr scan --code`, which reports on a project's existing code rather than on what an
agent writes. Known limits: a pipe inside a quoted `echo` string still matches, and the
edited fragment of a `package.json` cannot be tied to its `scripts` object.

**URLs:**
- Known malware/phishing/scam patterns
- Paste sites used for C2, direct IP address URLs
- Executable file downloads

## Trusted Installer Domains

Pipe-to-shell commands targeting known installer domains are suppressed from heuristic matches. The allowlist lives in `allowlists/trusted-installer-domains.yaml`:

```yaml
- domain: bun.sh
  reason: Bun JavaScript runtime installer
- domain: brew.sh
  reason: Homebrew package manager installer
```

Domains are matched by suffix with dot boundary (e.g. `bun.sh` matches `cdn.bun.sh` but not `notbun.sh`).

## Licensing

Threat rules are licensed under the [Detection Rule License 1.1](../threats/LICENSE), separate from the proprietary first-party source terms in [LICENSE](../LICENSE). See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

## Custom (User) Threats

You can add local, custom threat rules without modifying the repo by placing YAML files under:

- `~/.singularity-aidr/threats/*.yaml`

Behavior:

- Files are loaded on every evaluation (best-effort).
- If a custom rule uses the same `id` as a built-in rule, the custom rule **overrides** the built-in definition.
- You can still suppress rules globally via `disabled_threats` in `~/.singularity-aidr/config.json`.
