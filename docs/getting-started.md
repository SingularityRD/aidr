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

Local detection works without a cloud account or enrollment. Release builds are
managed-only, so every installation needs the release trust key
(`integrity.public_keys_pem`, see [Integrity verification](integrity.md)) before the
connector can inspect anything. Managed features require a separately deployed control
plane and an operator-provisioned runtime configuration. Check the tested host versions
in the [compatibility matrix](compatibility-matrix.md).

1. Provision the release trust key in `integrity.public_keys_pem`.
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
installing, provision the independently distributed Ed25519 public key in
`integrity.public_keys_pem` in `~/.singularity-aidr/config.json` (Windows:
`%USERPROFILE%\.singularity-aidr\config.json`):

```json
{ "integrity": { "enabled": true, "verify_on_start": true, "public_keys_pem": ["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"] } }
```

Release builds are managed-only and verify their signed artifacts before they
inspect anything; when this trust configuration is missing or invalid they block
every tool call (`Singularity AIDR inspection unavailable`). See
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
registry using [Package Installation](package-installation.md); run `aidr setup`
only after the operator has provided the approved runtime configuration and
secret-store requirements.

## Verify It Works

Verify with the safe, non-executing deny canary in the host acceptance
procedure in the [first-customer runbook](../deploy/FIRST_CUSTOMER.md). Do not
run a live payload as an installation test. Record the host-side block and test
the disabled, crashed, and timed-out hook cases too.

## Uninstall

How AIDR is removed depends on how it was installed:

- **Endpoint / fleet install** (the endpoint installer or the Windows/Unix fleet
  scripts): run `aidr uninstall` (add `--json` for a machine-readable report).
  It removes only the AIDR-managed hook registrations from
  `~/.claude/settings.json` and leaves your own hooks, configuration, connector
  files and receipt in place. It **requires the installation receipt**
  `~/.singularity-aidr/installation.json` written by that installer; if the
  receipt is missing or does not verify, it refuses to change anything and
  reports a reason code such as `receipt_missing`. Managed fleets should use the
  fleet uninstall script (for Windows, `Uninstall-Aidr.ps1`; see
  [deploy/fleet/windows/README.md](../deploy/fleet/windows/README.md)).
- **Claude Code marketplace install** (`/plugin marketplace add` +
  `/plugin install`): there is no receipt, so `aidr uninstall` refuses with
  `receipt_missing`. Remove it from the Claude Code prompt instead:

  ```
  /plugin uninstall aidr@aidr
  /plugin marketplace remove aidr
  ```

  then restart Claude Code. `~/.singularity-aidr/` (configuration, allowlists,
  audit log) is kept; delete it yourself only if you no longer need it.
- **Cursor / VS Code**: uninstall the extension from the Extensions panel.
- **OpenClaw / OpenCode / Codex**: remove the package and its entry from the
  host's plugin or hook configuration.
