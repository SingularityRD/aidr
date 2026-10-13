# AIDR CLI

The `aidr` command provides local setup and diagnostics for AIDR connectors. It
does not deploy a control plane or create a cloud account.

This is not a one-command customer download. The release operator must first
grant access to a signed, approved version in the private registry. `aidr setup`
configures local AIDR state and installs or updates the connector of every agent
host it finds in your home directory (see [Setup](#setup)).

Install the exact approved version from the private registry using
[Package Installation](../../docs/package-installation.md), then inspect the
available commands:

```sh
aidr --help
```

## Language

Help and the output of `aidr status`, `aidr pending` and `aidr approve` are
available in English and Turkish. Turkish is used when `AIDR_LOCALE=tr`, the
configuration key `locale` is `"tr"`, or the shell locale is Turkish
(`LANG=tr_TR.UTF-8`); everything else stays English. Flags, command names,
`--json` output and the `approve` confirmation word are the same in both
languages. Other commands still print English.

## Setup

Run `aidr setup` after the operator has supplied any approved runtime
configuration (commercial builds need the release verification key in
`~/.singularity-aidr/config.json`). It is idempotent: a rerun changes nothing
that is already in place.

- **No credential in local mode.** The default local mode needs no account, no
  credential and no OS vault, so setup works on headless Linux, WSL, containers
  and CI. Only a managed configuration gets a CLI credential, kept in the OS
  vault or, on a host without one, in the machine-bound encrypted file store
  (`~/.singularity-aidr/sealed`); `--secret-store file-acl` (plaintext) is used
  only when chosen explicitly.
- **Host detection** uses the same home-directory measurement as `aidr status`
  (never the current directory).
- **Connector install / update** for every detected host, or only `--host
  codex,opencode,...`:

  | Host | What setup does |
  | --- | --- |
  | Codex | Registers `aidr-codex-hook` for `PreToolUse`, `UserPromptSubmit` and `PostToolUse` in `~/.codex/hooks.json`, preserving other hooks. Requires `@singularityrd/aidr-codex` to be installed (the command on PATH); trust the hooks with `/hooks` afterwards. |
  | OpenCode | Pins `@singularityrd/aidr-opencode@<this CLI's version>` in `~/.config/opencode/package.json` and lists it in `opencode.json`; OpenCode installs it at its next start. An `opencode.jsonc` is left to you. |
  | OpenClaw | Runs `openclaw plugins install npm:@singularityrd/aidr-openclaw@<version>` when `openclaw` is on PATH. |
  | Cursor / VS Code | Runs `cursor` / `code --install-extension <file> --force` for the verified VSIX you pass with `--cursor-vsix` / `--vscode-vsix`. |
  | Claude Code | Runs `claude plugin marketplace add <dir>` and `claude plugin install aidr@aidr` for the verified, extracted plugin you pass with `--claude-plugin-dir`. |

  A host whose CLI or artifact is missing is reported as a manual step with the
  exact commands; a config file AIDR cannot parse is never rewritten; a changed
  file is backed up next to itself first. Every result is re-measured, so setup
  reports a host as installed only when `aidr status` would. `--dry-run` shows
  the plan without writing anything; `--no-install` only configures and prints
  the manual steps. Setup exits `1` when an install failed. Installing a plugin
  directory or VSIX loads code into the host, so `--claude-plugin-dir`,
  `--cursor-vsix` and `--vscode-vsix` need the same operator confirmation as
  `aidr uninstall` (type `install`, or `--yes` with
  `AIDR_OPERATOR_NONINTERACTIVE=1`).

Setup is not a substitute for the customer acceptance procedure: a registration
does not prove the host executes it, so run a host-side deny canary.

## Explicit behavioral learning

Learning is disabled until an active managed entitlement and the installed,
operator-signed tenant detector policy authorize it. The policy must name two
different Ed25519 authorities: an execution supervisor and an independent operator
who classifies the execution as benign and consents to bounded baseline retention.
Generating local keys does not grant either role or change the signed policy.

Run these commands from a dedicated private operator directory. Create each
authority in its own operator account, with separate custody from
the agent and from the other authority. Only public keys and key IDs belong in
the signed tenant policy. The authority reference contains an opaque vault ID;
never pass a private key in an argument, environment variable, or support log.

```sh
aidr learning keygen --role execution --out execution-authority.json
aidr learning keygen --role approval --out approval-authority.json
```

The default is the platform vault. Windows DPAPI, macOS Keychain and Linux Secret
Service use stdin for private key writes. `--secret-store file-acl` is an explicit,
reduced-protection fallback: a separate owner-only PKCS8 file sits beside the
reference. A reference and its private file must remain in a private operator
directory. Existing files are never overwritten; lost or unreadable keys require
operator-approved policy rotation rather than automatic replacement.

The concrete execution path accepts a JSON request file containing only
`sessionId`, `toolName: "Bash"`, and `toolInput` with `command` and `execution_shell`.
Set `execution_shell` to `"powershell.exe"` on Windows or `"/bin/sh"` on POSIX.
Execution requires that fixed shell to match the current host. The original shell
binding is preserved when another operator approves on a different OS. Ingestion
runs on the original execution host.
It selects the installed policy by connector runtime; request files cannot select
another tenant, configuration, policy, shell, working directory or environment.

```sh
aidr learning execute --runtime opencode --request request.json --key-ref execution-authority.json --out execution.json
aidr learning export-authority --runtime opencode --out broker-authority.json
aidr learning approve --runtime opencode --request request.json --receipt execution.json --broker-authority broker-authority.json --key-ref approval-authority.json --out approval.json
aidr learning ingest --runtime opencode --request request.json --receipt execution.json --approval approval.json
```

The execution supervisor must use foreground, deterministic commands. A receipt
proves the inspected shell invocation exited successfully and its complete bounded
output passed inspection. It does not attest business success, success of every
subcommand, or completion of detached work. Timeout, nonzero exit, invalid UTF-8,
output above 2 MiB, or an observed unfinished process prevents receipt issuance.
Raw output and private keys are never printed. The deadline is 60 seconds.
If a command runs but receipt publication fails, investigate before running it
again; a missing receipt does not roll back its effects.

Approval displays the actual request and its verified scope in an interactive
terminal and requires an exact phrase bound to the execution ID. Empty answers,
cancellation and piped input deny approval.
Trust and expiry are checked again after the prompt. Ingestion verifies both
signatures, the original input and installed tenant/device/session/policy/corpus
bindings before accepting an observation; replay does not add another sample.
Cold-start execution also needs the signed tenant's explicit unavailable-detector
skip policy and an available clean ML leg; an absent corpus never authorizes it.

Transfer the request, execution receipt and private broker-authority handoff to
the independent approval station through the operator's approved channel. The
handoff contains signed entitlement and classifier policy, including potentially
confidential matchers; it contains no API key or private signing key. The approval
station must already trust the issuer in its fixed AIDR configuration and have
current revocation evidence. It verifies the broker's target device and tenant
against both signatures without needing the broker's OS vault. Return only the
signed approval for ingestion on the execution host.
## Commands

| Command | What it does |
|---------|--------------|
| `aidr assistant [--no-open]` | Singularity AIDR Setup Assistant: the same setup, verify and company connection as a step-by-step page in the browser, served from 127.0.0.1 with a one-time address (Windows, Linux; see [Setup Assistant](../../docs/installation/desktop-installers.md#setup-assistant-aidr-assistant)) |
| `aidr setup [--dry-run] [--host <ids>] [--no-install]` | Write local configuration and install or update the connector of every detected host (see [Setup](#setup)) |
| `aidr status [--json]` | Measured installation state (detection self-test, connectors, data loss), ending with a one-line verdict: protected hosts, hosts to restart, hosts needing a manual step (exact command) |
| `aidr verify [--json]` | Pass a harmless canary (data only, never executed) and its benign twin through each registered connector's real hook entry point; PASS / FAIL / SKIP per host |
| `aidr doctor [--json]` | Hosts detected, hooks registered, rule count, core version, mode, DLP policy status, agent permission profiles, approval store and last verdict; exits `1` when any check fails |
| `aidr support-bundle [--out <path>] [--audit-entries <n>] [--json]` | Write a redacted `.tar.gz` diagnostic bundle (versions, doctor checks, hook registrations, config, recent verdict metadata, threat-rule hashes) and list its contents; never overwrites, uploads nothing, aborts if a redaction check fails. See [docs/support-diagnostics.md](../../docs/support-diagnostics.md) |
| `aidr pending [--json]` | Blocked agent actions (`ask` verdicts) waiting for an operator decision |
| `aidr approve <actionId>` | **Operator only.** Approve one retry of exactly that call; 15-minute default (`--ttl <minutes>`), single-use, `--permit-allowlist` to also let the agent allowlist it once |
| `aidr allowlist list [--json]` | Show allowlist entries (commands appear as hashes) |
| `aidr allowlist add <url\|command\|file_path> <value>` | **Operator only.** Add a permanent exception |
| `aidr allowlist remove <type> <value>` | Remove an entry (command text or hash prefix) |
| `aidr audit tail [-n N] [--json]` | Most recent audit entries, re-redacted |
| `aidr audit export [--since 24h\|ISO] [--format jsonl\|csv] [-o file]` | Redacted export across rotated log files |
| `aidr audit verify [--json] [--expect-root <fp>] [--response-chain <path>]` | Verify the signed verdict log and response-action chain (or only the given response chain) and report the first broken link. Both modes exit `0` verified, `1` broken, `2` unverifiable (config/log unreadable, log or signing key missing, or no signed chain enabled) |
| `aidr privacy scan [file] [--json] [--mask] [--types <list>] [--fail-on none\|any\|secret]` | Local TR/EN personal-data and secret scan of a file or stdin; see [Privacy scan](#privacy-scan) |
| `aidr profile list\|show\|validate\|test` | Inspect, validate and dry-run agent permission profiles; `aidr profile show <template> --template` prints a shipped template. See `docs/agent-profiles.md` |
| `aidr aibom [--format cyclonedx-json\|json] [-o file] [--path <project>] [--config <paths…>] [--scan-report <file>]` | AI Bill of Materials (CycloneDX 1.6): agents and their protection state, MCP servers with the 14 risk-category flags, AI SDKs/frameworks/models from the project's manifests, model files, skills/plugins and known vulnerabilities. Secrets are redacted; exits `1` when a source could not be read. See [AI-BOM](../../docs/ai-bom.md) |
| `aidr uninstall [--dry-run] [--keep-data] [--host <ids>] [--hooks-only]` | **Operator only.** Remove the connector of every host, the AIDR-managed hooks, `~/.singularity-aidr` and the AIDR vault items; see [Uninstall](../../docs/getting-started.md#uninstall) |
| `aidr config`, `aidr scan`, `aidr collect`, `aidr discover` | See `aidr <command> --help` |

### Operator-only commands

`aidr approve` and `aidr allowlist add` widen what an agent may do, so they are
out-of-band, human-only actions. They print what will be allowed and require the
operator to type a confirmation word (`approve` / `allow`) in an interactive
terminal. Automation may pass `--yes`, which is honoured only when
`AIDR_OPERATOR_NONINTERACTIVE=1` is also set. Approvals are HMAC-protected with a
per-install key kept in the OS credential vault. On a Linux host with no vault
(headless server, WSL, container) the default `operator_approvals.key_storage:
"auto"` keeps the key in the machine-bound encrypted file store
(`~/.singularity-aidr/sealed`, AES-256-GCM, owner-only) instead, so asks can still
be approved there; `"os-vault"` makes the vault mandatory (no vault: approvals
disabled, asks stay blocked). Single use is enforced through a ledger stored next
to the key, so restoring an old `approvals.json` does not replay an approval. This stops a prompt-injected agent from approving its own block through
its tools; it is not a boundary against code running as the same OS user with
full shell access. The self-defense rules `CLT-SELF-007`..`009` deny an agent
that tries to run these commands or touch the AIDR state directory.
See [Operator approvals](../../docs/configuration.md#operator-approvals) for the
flow, the on-disk format and the residual risk.

### Privacy scan

`aidr privacy scan` checks one UTF-8 text file, or standard input when no file (or `-`)
is given, for Turkish and English personal data and secrets: checksum-validated T.C.
kimlik (TCKN), IBAN (mod-97), Luhn payment cards, phones, e-mail, labelled fields such as
passport or tax numbers, addresses, private keys and provider tokens. It uses the core DLP
detectors (the drift-checked copy of the AIDR Privacy rules) plus the credential detector
that quarantines tool output. The scan runs entirely on the local machine; nothing is
uploaded.

```sh
aidr privacy scan customers.csv                 # table: type, count, line numbers
aidr privacy scan notes.txt --json              # {findings:[{type,start,end,line}], counts, incomplete, reasons}
aidr privacy scan notes.txt --mask > clean.txt  # text with [TC_KIMLIK], [IBAN], [SECRET] ... placeholders
cat export.log | aidr privacy scan --fail-on secret   # gate: fail only on secrets and private keys
aidr privacy scan data.txt --types tckn,iban,email
```

- Matched values are never printed. The table and JSON carry the type, offsets (UTF-16
  code units in the decoded text) and 1-based line only. With `--mask`, the redacted text
  goes to stdout and the summary to stderr.
- `--types` takes detector names (`tc_kimlik`, `iban`, `phone`, `email`, `credit_card`,
  `us_ssn`, `address`, `person`, `date_of_birth`, `passport`, `national_id`, `tax_id`,
  `bank_account`, `ip_address`, `mac_address`, `secret`, `private_key`, `classified`) or
  the aliases `tckn`, `tc`, `card`, `ssn`, `ip`, `mac`. Default: all.
- Input is capped at 4 MiB. Larger input, binary content (NUL bytes) and non-UTF-8 text
  are refused with an error rather than partly scanned. The TR/EN rules inspect at most
  1 MiB of text, so a longer input is reported as incomplete.
- Exit codes: `0` no finding that `--fail-on` counts; `2` findings that `--fail-on` counts
  (`any` by default, `secret` = secrets and private keys only, `none` = never); `3` the
  input was not fully inspected (for example over the 1 MiB rule limit or a truncated
  private key) and no counted finding was found. An incomplete scan is never reported as
  clean, and `--mask` refuses to print a partly masked copy. `1` usage or input error.
- The detectors are rule-based (no learned NER), so names and addresses are found only
  next to a label or phrase. A result with no findings is not proof that a file holds no
  personal data.
