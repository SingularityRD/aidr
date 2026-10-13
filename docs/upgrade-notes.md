# Upgrade notes

What an administrator has to do, and what behaves differently, when moving an installation
from a `0.6.0` (or earlier) build to a release built from the current source tree. Package
version numbers are assigned when a release is cut (`pnpm run version` applies the pending
changesets under [`.changeset/`](../.changeset/); one of them is a breaking change, so the
linked packages take a major version bump). The per-package `CHANGELOG.md` files are written
from those changesets at that point; until then they end at `0.6.0`, and this page is the
administrator summary of what is pending.

Before upgrading, check the [compatibility matrix](compatibility-matrix.md): it lists the
host versions each connector has been tested on. Cursor and VS Code are a **preview — no
real-host acceptance evidence yet**; no host version is tested for them.

## Required before you upgrade

1. **Node.js 22.12 or newer** on every endpoint that runs a Node-based connector (Claude
   Code, OpenClaw, OpenCode, Codex), the CLI, the SDK or the MCP Gateway. The AIDR Privacy
   package needs Node.js 22.16 or newer. Upgrade the runtime first; older runtimes are no
   longer supported.
2. **Provision the release trust key.** Release builds verify their signed artifact
   manifest before they inspect anything. The endpoint configuration
   (`~/.singularity-aidr/config.json`, Windows `%USERPROFILE%\.singularity-aidr\config.json`)
   must contain the independently distributed Ed25519 public key:

   ```json
   {
     "integrity": {
       "enabled": true,
       "verify_on_start": true,
       "public_keys_pem": ["-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----\n"]
     }
   }
   ```

   Without a valid key the connector cannot verify itself and blocks every tool call. Every
   connector then says so: "Singularity AIDR blocked this action because it cannot verify its
   own installation (release verification key missing). Nothing runs until this is fixed. Ask
   your IT admin to run: aidr setup --release-key <key.pem> (details: aidr doctor)", and the
   Claude Code session-start banner says every tool call in the session is blocked. See
   [Integrity verification](integrity.md). Never put a signing private key on an endpoint.
3. **Expect managed mode.** Release builds are managed-only: they run with `mode: "managed"`,
   signed entitlements required and integrity verification on, whatever the configuration
   file says. Local detection still runs on every tool call without an account; managed
   features (dashboard, central policy, telemetry, approvals in the dashboard) start only
   after enrollment. With no `control_plane.endpoint` configured, managed mode now uses
   `https://aidr.singularityrd.com`; set your own endpoint for a self-hosted control plane.
   Source and development builds keep the `local` default and contact nothing.

## Licensing and entitlement behaviour

Local detection does not depend on a licence, enrollment or network access. On an enrolled
installation whose signed entitlement is missing, invalid or expired beyond its offline
grace period, the managed-only features stop and the local rules keep deciding every tool
call. See [Licensing](operations/licensing.md).

## Per connector

| Connector | What to do | What changes |
| --- | --- | --- |
| Claude Code | Install the new signed plugin archive (`/plugin marketplace add` + `/plugin install aidr@aidr`) and restart Claude Code. | The archive's `hooks/hooks.json` registers a new `UserPromptSubmit` hook (prompt protection: secrets block, personal data warns, tenant DLP applies). `PreToolUse` denies input over 8 MiB and has an internal 10 s deadline (`AIDR_PRE_TOOL_USE_DEADLINE_MS`), below the 15 s host timeout. Each hook is now two files, `dist/<hook>.cjs` and `dist/<hook>.bundle.cjs`; copy them together. |
| Cursor / VS Code (preview — no real-host acceptance evidence yet) | Install the new VSIX, then run `Singularity AIDR: Enable protection` again; hooks are only (re)written by that command. Check **Show hook health**. | Managed prompt hooks: Cursor `beforeSubmitPrompt`, VS Code Local `UserPromptSubmit` (still needs `chat.useClaudeHooks`). |
| Codex CLI | Register `aidr-codex-hook` as a `UserPromptSubmit` handler in addition to `PreToolUse`, then review trust for both in Codex `/hooks`. | `shell`, `local_shell` and `exec` calls that pass an argv array are now inspected (before, they were allowed uninspected, so new denies can appear). An operator-approved `ask` releases the identical retry. A DLP `redact` rule stays a deny on Codex. |
| OpenClaw | Install the new plugin version. | A failed initialisation still registers `before_tool_call` and blocks every call. Prompt gate `before_agent_run` and pre-model tool-output quarantine (embedded runner). The exported `getSageVersion` is renamed `getAidrVersion`. |
| OpenCode | Install the new plugin version. | A failed initialisation blocks every call instead of letting the host run them uninspected. DLP `redact` rewrites the arguments in place, or blocks. `chat.message` prompt protection. `getSageVersion` is renamed `getAidrVersion`. |

## New behaviour that can change verdicts

- **Prompt protection** (`prompt_protection`, on by default): prompts carrying secrets are
  blocked before they reach the model; personal data warns. See
  [Configuration](configuration.md#prompt_protection).
- **Session toxic-flow detection** (`toxic_flow`, on by default): the call that completes a
  private-data + untrusted-content + external-communication chain is asked (balanced) or
  denied (paranoid). See [Toxic flow](toxic-flow.md).
- **Operator approvals**: an `ask` is released only by a person's approval outside the agent
  (`aidr approve <first 8 characters of the id>` in their own terminal, or the dashboard in managed mode). No connector gives the agent
  an approval tool. See [Configuration](configuration.md#operator_approvals).
- **Shell argv inspection**: argv-array shell commands are normalised and inspected; a
  command that is neither a string nor valid argv is denied as `malformed_command`.
- **More rules**: the shipped rule set changes between releases; `aidr coverage` prints the
  installed count and the framework mapping.

## CLI, SDK and MCP Gateway

- `aidr config -s <secret-key>` now prompts for the value instead of taking it as an argument.
- `aidr scan` / `aidr collect` exit codes: `2` means at least one version-confirmed critical or
  high CVE, `1` means a target could not be scanned or a finding could not be confirmed.
  Update CI gates that read these codes.
- `aidr audit verify` exits `0` verified, `1` broken, `2` unverifiable.
- New operator commands: `aidr pending`, `aidr approve`, `aidr allowlist`, `aidr audit
  tail|export`, `aidr privacy scan`, `aidr coverage`.
- Managed discovery uploads send a keyed pseudonym per target instead of its address; the
  control plane rejects raw addresses, so upgrade every collector before its next upload.
- SDK: the LangChain, LlamaIndex, AutoGen and CrewAI adapters and the `aidr-sdk` executable are
  removed (use `createGenericMiddleware` / `createMiddleware`). URL reputation is off by
  default; like core `url_check.unchecked_action`, a `fetch` that local rules find nothing in
  is allowed with `metadata.category: "reputation_not_checked"` (never reported as clean),
  and `urlReputationUncheckedAction: "ask"` restores hold-for-review. An enabled reputation
  leg that cannot answer still returns an indeterminate `ask`. Set `urlReputationEnabled:
  true` to opt in.
- MCP Gateway: `tools/call` arguments are inspected before they reach the upstream server
  (`arguments_blocked`, `approval_required`, `detection_unavailable`); server-initiated
  sampling, elicitation and roots are denied by default.

## Control plane

- Plan features are enforced server-side: gated features return `402 plan_feature_required`
  (`503` when the plan cannot be read). Local detection and verdict ingest are never gated.
- On-premises operators: follow the [upgrade guide](../deploy/UPGRADE.md)
  (`pnpm deploy:upgrade`); configuration variables are listed in the
  [on-prem configuration reference](operations/onprem-config-reference.md).

## Versioning note

Browser Guard has its own version line (`1.0.0`); the connector, CLI, SDK, dashboard and
gateway packages are versioned together.
