# Getting Started

**Singularity AIDR is not yet released for customer use: the steps below apply to an
approved release, and none is approved yet ([Release status](../README.md#release-status)).**
For the shortest path (installer, restart your AI tools, `aidr status` / `aidr verify`)
read the [Quickstart](quickstart.md) ([Türkçe](quickstart.tr.md)); every install and
deployment guide is listed by role in [Installation guides](installation/README.md).

This page covers the desktop installers and the per-tool connector packages for Claude
Code, Cursor/VS Code, OpenClaw, OpenCode and Codex. The AIDR CLI is a setup/diagnostic
utility, not an agent connector. Use only a signed version approved for customer
installation.

## Local protection and release builds

Two statements elsewhere in these docs can look contradictory; both are true:

- **Detection is local and needs no account.** Every connector checks every tool call on
  the device itself, with no cloud account, enrollment or network. Signing in to an AIDR
  control plane ("managed" mode) only adds central features: dashboard, central policy,
  dashboard approvals, telemetry. When those are missing or lapse, local detection keeps
  deciding every call.
- **Release builds are "managed-only": they always run in managed mode and always check
  that they are genuine.** Until the device is enrolled, managed mode simply has its
  central features off and decides every call locally, exactly as above. A signed
  release build also verifies its own files against the release trust key
  (`integrity.public_keys_pem`, see [Integrity verification](integrity.md)) before it
  inspects anything. Without that key it blocks every tool call and says so ("Singularity
  AIDR blocked this action because it cannot verify its own installation (release
  verification key missing) … aidr setup --release-key <key.pem>"); it does not run
  unprotected. The desktop installers already contain the key and `aidr setup` sets it up
  for each user; for the per-tool packages run `aidr setup --release-key <file.pem>` once
  (it asks the operator to confirm and prints the key's fingerprint). `aidr doctor` shows
  whether the key is set up.

## Current customer-installation status

The first-customer readiness decision is still **NO-GO**: no customer-installable
release is approved at this checkout, the candidate-bound evidence index has no
candidate digest and all 30 gates are `NOT_RUN`. See the
[readiness profile](production-readiness/first-customer-ready.md). Do not replace the
release with a source build or an unapproved version.

## Desktop installers (primary path, Windows and Linux)

For a workstation, the primary installation path after approval is the
desktop installer for its OS: download it from the AIDR dashboard's Download
page, run it, restart your AI tools. It bundles the standalone `aidr` CLI and
hook binaries, the rules and the release trust key (no Node.js), runs
`aidr setup` for the logged-in user and ends with `aidr status` /
`aidr verify` showing what is protected and what still needs a step. If no
supported AI tool is installed for that user yet, setup changes nothing and exits
with code `3` (not an error; the package still installs): install the AI tool,
then run `aidr setup`. Installer endpoints update with `aidr update` (`--check`
only reports), which verifies the signed catalog and the installer's SHA-256,
runs `aidr verify` and puts the previous version back on failure; `update.auto`
(`notify` by default, `install`, `off`) controls the automatic check. Windows
(signed MSI, also for Intune / SCCM / GPO) and Linux (.deb, .rpm, tarball)
installers are described in [Desktop installers](installation/desktop-installers.md).
**macOS installers are not offered yet**; on macOS use the connector packages
below (Browser Guard works on macOS in Chrome, Edge and Firefox). The installers
are built and signed by the release-candidate workflow and fall under the same
gated release decision as everything else on this page.

The rest of this page describes the per-connector packages, for hosts the
installers do not cover (Codex, Cursor, VS Code) and for macOS.

## Installation flow after approval

The connector packages detect locally as soon as they are installed, before any
enrollment, but as release builds they first need the release trust key (see
[Local protection and release builds](#local-protection-and-release-builds)). Managed
features require a separately deployed control plane and an operator-provisioned
runtime configuration. Check the tested host versions in the
[compatibility matrix](compatibility-matrix.md).

1. Provision the release trust key: `aidr setup --release-key <file.pem>` writes it to
   `integrity.public_keys_pem` after operator confirmation.
2. Install the exact approved connector version using [Package Installation](package-installation.md).
3. Complete that host's registration and trust steps.
4. Use managed features only after the operator has deployed the control plane and supplied the signed tenant configuration.

See [Device Auth](device-auth.md) for the managed-enrollment flow; use it only
after the deployed authentication method has passed a live end-to-end check.

## Prerequisites

- **Node.js >= 22.12.0** for Claude Code, OpenClaw, OpenCode, Codex, and the AIDR CLI; not required for Cursor/VS Code.
- **pnpm** (for building from source)

## Claude Code

Download the Claude plugin archive from a publisher-verified release bundle and
verify the bundle's signature and artifact hashes before extracting it. Before
installing, provision the independently distributed Ed25519 public key with
`aidr setup --release-key <file.pem>`, which writes it to `integrity.public_keys_pem` in
`~/.singularity-aidr/config.json` (Windows:
`%USERPROFILE%\.singularity-aidr\config.json`). The resulting configuration is:

```json
{ "integrity": { "enabled": true, "verify_on_start": true, "public_keys_pem": ["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"] } }
```

Release builds are managed-only and verify their signed artifacts before they
inspect anything; when this trust configuration is missing or invalid they block
every tool call and name the fix (`aidr setup --release-key <key.pem>`). See
[Integrity verification](integrity.md). The same key is required for every
connector below. Never put a signing private key on an endpoint. Then, from the Claude Code prompt:

```
/plugin marketplace add /absolute/path/to/extracted/aidr-claude-plugin
/plugin install aidr@aidr
```

Restart Claude Code, then confirm the plugin is present and active in Claude
Code before relying on it. Installation alone does not prove that the host loaded
the plugin or that a particular action was blocked; complete the host-side
acceptance checks in the [first-customer runbook](../deploy/FIRST_CUSTOMER.md).

## Cursor (preview — no real-host acceptance evidence yet)

Download the signed `aidr-cursor.vsix` from an approved release and install it
via the Extensions panel (`Extensions > Install from VSIX`). Then run
`Singularity AIDR: Enable protection` from the command palette (`Ctrl+Shift+P`).
Cursor `preToolUse` ask verdicts are returned as explicit denies; Cursor's hook
response does not provide an enforceable AIDR approval prompt. No Cursor version has
been accepted on a real host: whether Cursor enforces the deny, and what it does when
the hook is killed or times out, has not been observed.

## VS Code (preview — no real-host acceptance evidence yet)

Download the signed `aidr-vscode.vsix` from an approved release and install it
via the Extensions panel. For VS Code Local hooks, first enable
`chat.useClaudeHooks` in VS Code User Settings, then enable protection from the
command palette. AIDR checks this prerequisite but does not change the editor
setting. Confirm the setting and installed hooks in **Show hook health**.

Local source builds are for development only. The protected release-candidate
pipeline prepares, signs, packages, and verifies distributable VSIX files.

## OpenClaw

Install the approved version from the private registry. Registry access and the
exact command are in [Package Installation](package-installation.md).

```bash
openclaw plugins install npm:@singularityrd/aidr-openclaw@VERSION
```

> **Note:** OpenClaw's `plugins.code_safety` audit may flag Singularity AIDR with
> a `potential-exfiltration` warning when file reads and network requests
> coexist. Reputation checks can send full URLs and package metadata; managed
> telemetry and deep scans have separate paths. Review the actual configuration
> and [privacy data flows](privacy.md) before dismissing the warning.

## OpenCode

Use the version-pinned package and OpenCode configuration in
[Package Installation](package-installation.md). A source checkout is for
development only.


See [Platform Guide: OpenCode](platform-guides/opencode.md) for tool mapping and verdict behavior.

## Codex

Install the approved package and register/trust its `PreToolUse` hook as
described in [Package Installation](package-installation.md) and the
[Codex connector guide](../packages/codex/README.md). Codex host hooks can fail
open if the host does not run them; the connector is not endpoint isolation.

## AIDR CLI

The CLI is a separate setup and diagnostics package. Install it from the private
registry using [Package Installation](package-installation.md), then run
`aidr setup --dry-run` to see what it would do and `aidr setup` to configure AIDR
and install or update the connector of every agent host found in your home
directory. Exit code `3` means no supported AI tool was found yet (nothing failed);
`1` is a real problem. Local mode (the default) needs no account, credential or OS credential
vault, so this works on headless Linux, WSL and containers too; only a managed
configuration stores a credential (in the OS vault, or the machine-bound
encrypted file store `~/.singularity-aidr/sealed` where there is none). Commercial
builds additionally need the operator-provided release verification key:
`aidr setup --release-key <file.pem>`.

## Verify It Works

`aidr status` ends with a one-line verdict: protected hosts, hosts to restart
because setup registered them while they were open, and hosts that need a
manual step with the exact command. `aidr verify` then passes a harmless canary
through each registered connector's real hook entry point as data (nothing is
executed) and prints PASS / FAIL / SKIP per host; in-process plugins (OpenCode,
OpenClaw) are SKIP and are confirmed inside the host. `aidr doctor` prints one line per
check and exits non-zero on a problem; `aidr doctor --verbose` adds the reason and the
fix under each line.

Then verify with the safe, non-executing deny canary in the host acceptance
procedure in the [first-customer runbook](../deploy/FIRST_CUSTOMER.md). Do not
run a live payload as an installation test. Record the host-side block and test
the disabled, crashed, and timed-out hook cases too.

### What a fresh install does with URLs and packages

URL, file and package reputation lookups are off by default, and no first-party
reputation endpoint is deployed. Routine work such as `git clone
https://github.com/...`, `npm install react`, `pip install requests` or a
documentation fetch is decided by the local threat rules and an offline
typosquat check; when they find nothing the call proceeds and the audit log
records it as `reputation_not_checked` (not checked, never "clean"). A rule hit,
a likely typosquat (`npm install lodahs`) or an install straight from a URL, Git
or local path still asks or denies. To hold every unchecked URL or package for
review instead, set `url_check.unchecked_action` / `package_check.unchecked_action`
to `"ask"` (see [Configuration](configuration.md#url_check)). On Codex, OpenClaw and
OpenCode an `ask` blocks the call until a person approves it in their own terminal: the
message shows the command, for example `aidr approve 3f9c2a7b` (the first 8 characters
of the id); `aidr approve` alone lists the waiting actions to pick from. Cursor
`preToolUse` asks are denied.

## Uninstall

`aidr uninstall` removes AIDR completely and asks for confirmation first (type
`uninstall`; automation passes `--yes` with `AIDR_OPERATOR_NONINTERACTIVE=1`):

1. the receipt-managed Claude Code hooks written by the endpoint/fleet installer
   (only entries carrying the installer marker; your own hooks stay);
2. the connector of every agent host — the Claude Code marketplace plugin
   (`claude plugin uninstall aidr@aidr` and `claude plugin marketplace remove
   aidr`), the Cursor / VS Code extension (`cursor` / `code
   --uninstall-extension`), the OpenClaw plugin (`openclaw plugins uninstall
   aidr-openclaw`), the OpenCode plugin entry and package pin, and the Codex
   `aidr-codex-hook` handlers in `~/.codex/hooks.json` and `config.toml`;
3. the local data directory `~/.singularity-aidr` (configuration, allowlist,
   audit log, approvals, quarantined files, keys) and the AIDR items in the OS
   credential vault (operator-approval key and ledger, audit-chain root keys,
   CLI and managed credential references).

Options: `--dry-run` shows what would be removed, `--keep-data` keeps step 3,
`--host codex,opencode` limits step 2, `--json` prints a machine-readable report
and `--hooks-only` keeps the previous behaviour (step 1 only).

Changed host files are backed up next to themselves. A host whose CLI is not on
PATH is reported with the exact manual command, and while any connector is still
registered the data directory is kept (a hook must not be left pointing at
deleted files); the command then exits `1`. It does not uninstall global npm
packages (`npm uninstall --global @singularityrd/aidr-codex`) or the CLI itself,
and it cannot find vault items behind behavioral-learning authority keys
(`aidr learning keygen`): their references live in the operator's own directory,
so the operator who holds them revokes them. Browser Guard is
a browser extension: remove it from the browser or the enterprise browser policy.
Managed fleets should use the fleet uninstall script (for Windows,
`Uninstall-Aidr.ps1`; see [deploy/fleet/windows/README.md](../deploy/fleet/windows/README.md)).
