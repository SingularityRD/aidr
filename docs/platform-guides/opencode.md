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
