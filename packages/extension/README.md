# Singularity AIDR

Singularity AIDR evaluates supported, named tool calls that an enabled Cursor or VS Code hook forwards to it and returns a verdict. Whether the host enforces that verdict depends on the host, version, and event path; no real-host acceptance is recorded. Disabled, crashed, timed-out, unmapped, and directly bypassed paths are not covered uniformly.

## What it does

For a forwarded shell command, file operation, or URL fetch, Singularity AIDR checks the request before the host action. A returned `deny` alone does not prove that the host prevented the side effect.

### Detection layers

- **Local heuristics** — pattern matching against dangerous commands, suspicious URLs, sensitive file paths, credential exposure, and obfuscation techniques
- **Package supply-chain checks** — registry existence and age analysis for npm/PyPI packages
- **Reputation checks** — first-party URL/domain and file/package hash lookups (optional and off by default; they need a configured first-party endpoint and are never reported as "clean" when unavailable)

### Verdicts

| Decision | Meaning |
|----------|---------|
| **Allow** | No threats detected — tool call proceeds |
| **Ask** | Suspicious activity — approval depends on the host; unsupported approval responses are denied |
| **Deny** | Threat detected — AIDR returns a deny response; host-side blocking is not yet accepted on a real host |

Cursor's `preToolUse` response does not provide an enforceable approval prompt,
so an `ask` verdict is returned as an explicit deny.

In managed mode an `ask` is also submitted to the AIDR dashboard and the reason
includes `Approval requested in the AIDR dashboard: <request_id>`. After an
administrator approves it there, the identical retry is released once by a
control-plane-signed, single-use token. `operator_approvals.dashboard_only: true`
turns every remaining `ask` into a deny so only the dashboard can release it. See
[dashboard approvals](../../docs/configuration.md#managed-mode-dashboard-approvals).

With `operator_approvals.mode: "operator"` every `ask` (on every Cursor and VS Code
event) is denied with an approval reference instead of a native prompt, recorded
for `aidr pending`, and exactly one retry is released after `aidr approve
<actionId>` in your own terminal. The default `host_dialog` mode keeps the native
behaviour and lists the ask in `aidr pending` for information only. See
[`operator_approvals`](../../docs/configuration.md#operator_approvals).

### Prompt protection

The managed hooks also inspect the user's prompt before it is sent to the model
(`prompt_protection` in `~/.singularity-aidr/config.json`: secrets `block`,
personal data such as TC Kimlik, IBAN, email and phone numbers `warn` by default).

| Host | Event | Block | Warn |
|------|-------|-------|------|
| Cursor | `beforeSubmitPrompt` | `{"continue": false, "user_message": "…"}` | Prompt sent with the notice in `user_message` and the audit log; the event has no model-context field |
| VS Code (Local agent hooks) | `UserPromptSubmit` | `{"continue": false, "stopReason": "…"}` | `systemMessage` to the user; no documented model-context field |

The reason names the kind of data found, never the value. A prompt that cannot be
inspected (over the 1 MiB hook input limit, unreadable, or an internal error) is
blocked while secrets are in `block` mode and otherwise sent with a "not inspected"
notice; an inspection still running after 20 s is handled the same way
(`AIDR_PROMPT_INSPECTION_DEADLINE_MS`, 100–28000). A provisioned tenant DLP policy
applies to the prompt and blocks on any action other than `allow`. Audit entries use
`tool_name` `beforeSubmitPrompt` / `UserPromptSubmit` and record kinds and counts
only. Cursor attachments are not inspected. Host-side enforcement of these responses
has not been accepted on a real Cursor or VS Code host.

## Getting started

For VS Code Local agent hooks, enable `chat.useClaudeHooks` in VS Code User
Settings before running Enable protection. The extension checks and reports
this prerequisite but does not change editor settings. Cursor users do not need
this VS Code setting.

1. Install the extension
2. Open the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
3. Run **Singularity AIDR: Enable protection**

Protection applies to supported tool calls intercepted by the installed host hooks.

In managed mode, Enable protection starts or reuses the persisted browser
authorization session. After authorizing the displayed code, run Enable
protection again to finish enrollment. Local mode needs no browser enrollment.
Bundled rules are loaded from `dist/resources/`, inside the verified release
artifact.

## Commands

| Command | Description |
|---------|-------------|
| `Singularity AIDR: Enable protection` | Install managed hooks |
| `Singularity AIDR: Disable protection` | Remove managed hooks |
| `Singularity AIDR: Open config` | Open `~/.singularity-aidr/config.json` |
| `Singularity AIDR: Open audit log` | View the verdict audit trail |
| `Singularity AIDR: Show hook health` | Check hook installation status |

Command titles, settings and notifications follow the editor's display language
(English or Turkish; `package.nls*.json` and `l10n/`). The block and approval
messages written by the hook follow `AIDR_LOCALE`, the `locale` configuration
key or the shell locale, as described in
[configuration](../../docs/configuration.md#locale).

## Provisioned tenant detector policy

The hooks can also evaluate a tool call against an operator-delivered, signed
tenant detector policy (DLP and behavioural detectors). The bundle is read from a
fixed location under the local AIDR state directory, per hook runtime:

```
~/.singularity-aidr/detectors/cursor.json
~/.singularity-aidr/detectors/vscode.json
```

The bundle is accepted only when it is signed by a key listed in
`licensing.public_keys_pem` (ed25519), is inside its validity window, and is
bound to the same tenant as the verified managed entitlement. Provisioning is
opt-in: with no bundle and no `runtime_detectors` module on the signed
entitlement, the hooks evaluate exactly as they do without a tenant policy. A
bundle that is present but invalid — or required by the signed entitlement and
missing — produces a deny verdict when the hook runs. Cursor managed hooks also
request `failClosed: true`. These source-level responses do not prove how a real
host handles a process killed or timed out before it can return JSON; that
failure path remains a native-host acceptance requirement.

The policy's labels and rules are whatever the tenant's signed bundle defines;
this extension ships no customer label taxonomy and assumes none.

**Output limitations.** Cursor can return an MCP-output replacement, but this
has not been verified against a real host; non-MCP tool output is advisory and
the original can reach the model. VS Code `PostToolUse` runs after the action
and returns context/block information without replacing bytes already returned,
so the original may already be in the model transcript. Cursor
`afterAgentResponse` is observation-only. These output hooks do not take a
provisioned tenant detector policy, so that policy does not apply to tool
**output**. None of these paths is a pre-execution or accepted containment
guarantee.

## Release packaging

Distributable VSIX files come from the protected release-candidate pipeline.
It prepares and signs `dist`, generates the SBOM/checksum, and runs the
canonical packager. The explicitly named
`package:vsix:from-signed-dist` command is only for a restored, already signed
RC `dist`; it performs no build or signing and fails closed if any evidence is
missing. The host-specific variants follow the same `:from-signed-dist`
contract.

## Privacy

When enabled, URL reputation sends the extracted **full URL** (not just a hash)
to the configured reputation endpoint. Package checks can send package names,
versions, registry metadata and file hashes to registries and the configured
reputation service. This leg does not upload file contents; managed telemetry,
deep scans and diagnostics have separate documented data flows. Disable URL,
file and package checks and verify egress for an offline source/development
pilot. See [privacy](../../docs/privacy.md).

The Cursor and VS Code extensions do not initialize Sentry or send extension
crash telemetry. Command errors are shown locally, and hook verdicts are written
to the configured local JSONL audit log. Native-host acceptance receipts are
also local and are emitted only when the acceptance runner supplies the complete
`AIDR_NATIVE_TEST_*` environment contract.

## Links

- [GitHub](https://github.com/singularityrd/aidr)
- [Configuration docs](https://github.com/singularityrd/aidr/blob/main/docs/configuration.md)
- [Threat rules](https://github.com/singularityrd/aidr/blob/main/docs/threat-rules.md)
- [Privacy](https://github.com/singularityrd/aidr/blob/main/docs/privacy.md)
