# OpenCode

## Installation

Install a signed, approved version from private GitHub Packages using the
[package installation guide](../package-installation.md). For a pinned
installation, declare the exact approved version in
`~/.config/opencode/package.json`:

```json
{
  "dependencies": {
    "@singularityrd/aidr-opencode": "VERSION"
  }
}
```

Then enable the plugin in global config (`~/.config/opencode/opencode.json`):

```json
{
  "plugin": ["@singularityrd/aidr-opencode"]
}
```

The package is not on public npm; it is published through the private GitHub
Packages registry after protected release promotion. Local path installation is
for development only.

## How It Works

Singularity AIDR uses OpenCode plugin hooks:

- `tool.execute.before` - extracts artifacts and runs the Singularity AIDR evaluator before tool execution
- `tool.execute.after` - inspects completed tool output and replaces risky, oversized, or unsupported output with a quarantine notice before model consumption; it runs after the tool action, so it cannot undo that action
- `chat.message` - prompt protection: inspects the user's message before it is stored or sent; secrets block (text replaced, hook throws), personal data warns (see [configuration](../configuration.md#prompt_protection))
- `experimental.chat.messages.transform` - adds queued plugin-scan findings to the first user message and prompt-protection warning notices to the message they concern; this is advisory context, not a provider-stream gate
- `tool` - registers the allowlist tools (`aidr_allowlist_add`, `aidr_allowlist_remove`)

OpenCode exposes no pre-consumption hook for arbitrary provider streams or
non-tool content; those channels are not inspected by this plugin.

For `ask` verdicts, Singularity AIDR blocks the tool call and returns an action ID in
the error message. The agent is told to report that reference and stop; **it cannot
approve the action itself**, because approval is an out-of-band, human-only action.

## Tool Mapping

| OpenCode tool | Singularity AIDR extraction |
|---------------|-----------------|
| `bash` | command + URL extraction |
| `webfetch` | URL extraction |
| `read` | file path |
| `write` | file path + content |
| `edit` | file path + edited content |
| `apply_patch` | `patchText` normalized to every target path + added-content section |
| `ls` | file path |
| `glob` | pattern as file_path artifact |
| `grep` | pattern as content artifact |

Unmapped tools pass through unchanged.

## Verdict Handling

- `allow`: tool continues
- `deny`: blocked immediately with a Singularity AIDR reason
- `ask`: blocked, pending out-of-band human approval

## Singularity AIDR Tools

- `aidr_allowlist_add`: permanently allowlist a URL/command/file path. It **refuses**
  unless a genuine approval was already recorded, so it is not a way to approve a
  blocked action.
- `aidr_allowlist_remove`: remove an allowlisted artifact

There is deliberately **no** `aidr_approve` tool. An approval tool the model could
call would let a prompt-injected agent approve its own block, and the model already
receives the `actionId` in the block reason. Approvals are made by an operator
through the out-of-band `ApprovalStore` or by editing the allowlist file.

**Honest limitation:** OpenCode exposes no host-native confirmation API this plugin
can drive (upstream `anomalyco/opencode#12046` is still open), so there is no
in-session approval prompt. A blocked action stays blocked for the session; the user
must allowlist the artifact or take a different action. Blocking is the safe failure
mode, and a future host primitive should be wired to the operator-held
`ApprovalStore` without being exposed as a model-callable tool.

## Verify Installation

Use the safe, non-executing deny canary in the
[first-customer acceptance procedure](../../deploy/FIRST_CUSTOMER.md). Do not
run a live payload as an installation test; confirm the host-side block and
also test disabled, crashed, and timed-out hook cases.
Record the exact OpenCode version/build during acceptance: the automated
contract test exercises the plugin/core boundary, not host-version behavior.
There is no in-session AIDR approval prompt; `ask` actions remain blocked until
an operator approves out of band or allowlists the exact artifact.

## Development

```bash
pnpm --filter @singularityrd/aidr-opencode run build
pnpm test -- packages/opencode/src/__tests__/integration.test.ts
pnpm test:e2e:opencode
```

## Real-host acceptance

Recorded by `pnpm test:e2e:real-host` (see [development](../development.md#real-host-e2e-with-a-scripted-mock-model)): the real host binary on linux/x64, AIDR installed from the development build in a disposable HOME, and a scripted loopback mock model in place of a real one. It proves what the host does with AIDR's answer at each boundary, not how a real model behaves or how broad detection is. Record: [`docs/evidence/real-host/opencode.json`](../evidence/real-host/opencode.json)
(OpenCode 1.18.32, `opencode run`, plugin loaded from a local `file://` path).

- `tool.execute.before`: `curl … | sh` and a read of `~/.ssh/id_rsa` were refused with no
  side effect; a benign bash call ran; the same call ran with the plugin absent.
- `chat.message`: a prompt carrying a token never reached the model.
- `tool.execute.after`: a token in bash output reached the model only as AIDR's
  quarantine notice.
- A plugin initialisation failure (integrity check) blocked the prompt.

How the interactive TUI presents a blocked prompt is not covered.

`tool.execute.before`, `chat.message` (prompt protection, sold since 2026-09-30) and
`tool.execute.after` are part of the sold support matrix
(`deploy/native/support-matrix.json`) and are `enforced` in
`deploy/native/interception-matrix.json` on this record only: OpenCode 1.18.32 on
linux/x64, the development build and a scripted mock model. Prompt protection inspects the
user's own text parts; synthetic parts such as attached file contents are not inspected.
