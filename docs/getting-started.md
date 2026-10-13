# Getting Started

Connector guides cover Claude Code, Cursor/VS Code, OpenClaw, OpenCode, and Codex. The AIDR CLI is a setup/diagnostic utility, not an agent connector. Use only a signed version approved for customer installation.

## Current customer-installation status

The current first-customer readiness decision is **NO-GO**. There is no
customer-installable release approved at this checkout: the candidate-bound
evidence index has no candidate digest and all 30 gates are `NOT_RUN`. See the
[readiness profile](production-readiness/first-customer-ready.md). The steps
below describe a gated installation flow for a future approved release; they
are not a currently usable customer quickstart. Do not replace the release with
a source build or an unapproved version.

## Installation flow after approval

Local detection works without a cloud account. Managed features require a
separately deployed control plane and an operator-provisioned runtime
configuration; sign-in is not part of a local-only installation.

1. Install the exact approved connector version using [Package Installation](package-installation.md).
2. Complete that host's registration and trust steps.
3. Use managed features only after the operator has deployed the control plane and supplied the signed tenant configuration.

See [Device Auth](device-auth.md) for the managed-enrollment flow; use it only
after the deployed authentication method has passed a live end-to-end check.

## Prerequisites

- **Node.js >= 22.12.0** for Claude Code, OpenClaw, OpenCode, Codex, and the AIDR CLI; not required for Cursor/VS Code.
- **pnpm** (for building from source)

## Claude Code

Download the Claude plugin archive from a publisher-verified release bundle and
verify the bundle's signature and artifact hashes before extracting it. Before
installing, provision the independently distributed Ed25519 public key in
`~/.singularity-aidr/config.json` (Windows:
`%USERPROFILE%\.singularity-aidr\config.json`). Commercial builds fail closed
when this trust configuration is missing or invalid; never put a signing
private key on an endpoint. Then, from the Claude Code prompt:

```
/plugin marketplace add /absolute/path/to/extracted/aidr-claude-plugin
/plugin install aidr@aidr
```

Restart Claude Code, then confirm the plugin is present and active in Claude
Code before relying on it. Installation alone does not prove that the host loaded
the plugin or that a particular action was blocked; complete the host-side
acceptance checks in the [first-customer runbook](../deploy/FIRST_CUSTOMER.md).

## Cursor

Download the signed `aidr-cursor.vsix` from an approved release and install it
via the Extensions panel (`Extensions > Install from VSIX`). Then run
`Singularity AIDR: Enable protection` from the command palette (`Ctrl+Shift+P`).
Cursor `preToolUse` ask verdicts are returned as explicit denies; Cursor's hook
response does not provide an enforceable AIDR approval prompt.

## VS Code

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
directory. Local mode (the default) needs no account, credential or OS credential
vault, so this works on headless Linux, WSL and containers too; only a managed
configuration stores a credential (in the OS vault, or the machine-bound
encrypted file store `~/.singularity-aidr/sealed` where there is none). Commercial
builds additionally need the operator-provided release verification key.

## Verify It Works

Verify with the safe, non-executing deny canary in the host acceptance
procedure in the [first-customer runbook](../deploy/FIRST_CUSTOMER.md). Do not
run a live payload as an installation test. Record the host-side block and test
the disabled, crashed, and timed-out hook cases too.

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
