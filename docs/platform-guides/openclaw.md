# OpenClaw

## Installation

Install an approved signed version from the private registry using the
[package installation guide](../package-installation.md). Local source builds
are for development only; do not copy a workspace package directory as a
customer installation.

## How It Works

The OpenClaw connector runs in-process using the OpenClaw plugin API:

- **`before_tool_call`** - Intercepts `exec`, `web_fetch`, `write`, `edit`, `read`, and `apply_patch`. Runs the full detection pipeline.
- **`after_tool_call`** - Inspects tool output after execution and records risky or incomplete results; carrying that observation forward depends on OpenClaw providing matching tool-call, run, or session identifiers. It is observation-only and cannot undo the action or prove the same-turn model did not see the original result.
- **`tool_result_persist`** - Synchronously replaces risky or incompletely inspected output before it is written to the transcript. This is still a post-execution boundary.
- **`message_sending` / `reply_payload_sending`** - Inspect and replace risky or incompletely inspected generated responses before channel delivery. A correlated finding from opaque binary tool output is marked unsupported/incomplete and routes through this protection path rather than being treated as clean.
- **`before_agent_run`** - Prompt protection gate (embedded and CLI runners): inspects the user's prompt before model submission and blocks secrets (and, per `prompt_protection`, personal data); see [configuration](../configuration.md#prompt_protection). A non-bundled plugin needs `plugins.entries.aidr-openclaw.hooks.allowConversationAccess: true`.
- **`before_prompt_build`** - Adds plugin-scan findings and prompt-protection warnings (for example a Turkish ID number or IBAN in the prompt) as context for the model; blocking is left to `before_agent_run`.
- **`aidr_allowlist_add` / `aidr_allowlist_remove`** - Manage the on-disk allowlist. `aidr_allowlist_add` refuses unless a genuine approval was already recorded, so it cannot be used to approve a blocked action.
- **`gateway_start` / `session_start`** - Scans installed plugins for threats.

The post-execution hooks do not prevent the tool side effect, and no provider
token-stream interception is implemented. Same-turn model isolation from an
original tool result remains a real-host acceptance question.

## Intercepted Tools

| OpenClaw Tool | Maps To |
|---------------|---------|
| `exec` | Bash command extraction |
| `web_fetch` | URL extraction |
| `write` | File path + content extraction |
| `edit` | File path + content extraction |
| `read` | File path extraction |
| `apply_patch` | File path extraction from diffs |

## Approving a flagged action

When Singularity AIDR flags a tool call it is blocked, and **there is no approval
tool the agent can call**. This is deliberate: the model necessarily receives the
`actionId` in the block reason, so an agent-callable approval would let a
prompt-injected agent approve its own block. Approval is an out-of-band, human-only
action.

To let a specific action through, an operator either:

- records an approval in the operator-held `ApprovalStore` that owns the connector
  process, or
- adds the exact artifact to `~/.singularity-aidr/allowlist.json`.

Both paths are covered by tests. An entry is matched on the exact artifact, so it
does not widen to similar commands.

**Honest limitation:** OpenClaw exposes no host-native confirmation API that this
plugin can drive, so there is no in-session approval prompt. While an action is
blocked, the agent cannot proceed with it; the user must allowlist the artifact or
take a different action. Blocking is the safe failure mode.

## Security Awareness Skill

The skill is registered in `openclaw.plugin.json` and bundled into `resources/skills/` during build.

## Code Safety Warning

OpenClaw's `plugins.code_safety` audit may flag Singularity AIDR with a
`potential-exfiltration` warning because local file reads and network requests
coexist in the bundle. The URL reputation leg sends extracted full URLs (not
hashes); package checks may send names, versions and hashes. This is not
evidence that file contents are uploaded by those legs. Review the actual
configuration and outbound traffic before dismissing the warning.
