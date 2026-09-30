# OpenClaw

## Installation

Install an approved signed version from the private registry using the
[package installation guide](../package-installation.md). Local source builds
are for development only; do not copy a workspace package directory as a
customer installation.

## How It Works

The OpenClaw connector runs in-process using the OpenClaw plugin API:

- **`before_tool_call`** - Intercepts `exec`, `web_fetch`, `write`, `edit`, `read`, and `apply_patch`. Runs the full detection pipeline.
- **Tool-result middleware** (`api.registerAgentToolResultMiddleware`, OpenClaw 2026.9+) - Pre-model tool-output quarantine: the embedded runner awaits it after the tool executed and before the result enters the model context. A risky or incompletely inspected result is replaced by a fresh text-only notice (`Singularity AIDR quarantined this tool output before it reached the model`, rule identifiers only), so the same-turn model never reads the original. Inspection, integrity and initialisation failures also quarantine. Requires `contracts.agentToolResultMiddleware: ["openclaw"]` (shipped in `openclaw.plugin.json`) and explicit enablement (`plugins.entries.aidr-openclaw.enabled: true`); otherwise OpenClaw drops the registration and the connector logs the boundary as `enforced: false`. Only the embedded `openclaw` runtime is claimed: OpenClaw's Codex native-hook relay does not feed a middleware result back to the model.
- **`after_tool_call`** - Inspects tool output after execution and records risky or incomplete results; carrying that observation forward depends on OpenClaw providing matching tool-call, run, or session identifiers. It is observation-only and cannot undo the action or prove the same-turn model did not see the original result.
- **`tool_result_persist`** - Synchronously replaces risky or incompletely inspected output before it is written to the transcript. This is still a post-execution boundary.
- **`message_sending` / `reply_payload_sending`** - Inspect and replace risky or incompletely inspected generated responses before channel delivery. A correlated finding from opaque binary tool output is marked unsupported/incomplete and routes through this protection path rather than being treated as clean.
- **`before_agent_run`** - Prompt protection gate (embedded and CLI runners): inspects the user's prompt before model submission and blocks secrets (and, per `prompt_protection`, personal data); see [configuration](../configuration.md#prompt_protection). A non-bundled plugin needs `plugins.entries.aidr-openclaw.hooks.allowConversationAccess: true`.
- **`before_prompt_build`** - Adds plugin-scan findings and prompt-protection warnings (for example a Turkish ID number or IBAN in the prompt) as context for the model; blocking is left to `before_agent_run`.
- **`aidr_allowlist_add` / `aidr_allowlist_remove`** - Manage the on-disk allowlist. `aidr_allowlist_add` refuses unless a genuine approval was already recorded, so it cannot be used to approve a blocked action.
- **`gateway_start` / `session_start`** - Scans installed plugins for threats.

No output hook prevents the tool side effect (use `before_tool_call` for that),
and no provider token-stream interception is implemented. Same-turn model
isolation from a risky tool result rests on the tool-result middleware above,
accepted on the embedded runner only (see Real-host acceptance below).

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

## Real-host acceptance

Recorded by `pnpm test:e2e:real-host` (see [development](../development.md#real-host-e2e-with-a-scripted-mock-model)): the real host binary on linux/x64, AIDR installed from the development build in a disposable HOME, and a scripted loopback mock model in place of a real one. It proves what the host does with AIDR's answer at each boundary, not how a real model behaves or how broad detection is. Record: [`docs/evidence/real-host/openclaw.json`](../evidence/real-host/openclaw.json)
(OpenClaw 2026.9.6 embedded runner, `openclaw agent --local`, on Node.js 24.21.0).

- `before_tool_call`: `curl … | sh` and a read of `~/.ssh/id_rsa` were refused with no side
  effect; a benign exec ran; the same exec ran with the plugin absent.
- `before_agent_run`: a prompt carrying a token never reached the model.
- A plugin integrity failure blocked the prompt.
- Tool-result middleware: a token in exec output reached the model only as AIDR's
  quarantine notice (the same-turn follow-up request carried the notice, never the token).
  The earlier record showed this as a gap, when the connector relied on
  `after_tool_call`/`tool_result_persist` alone.
- `message_sending` is not exercised: `agent --local` does not deliver through a channel.
  The gateway process is not exercised either.

**Sold scope.** Tool-call blocking (`before_tool_call`), the prompt gate
(`before_agent_run`) and the pre-model tool-output quarantine (tool-result middleware) are
part of the sold support matrix (`deploy/native/support-matrix.json`; the prompt gate and
the quarantine since 2026-09-30) and are `enforced` in
`deploy/native/interception-matrix.json` on the record above only. That scope carries the
record's conditions: the embedded runner, `plugins.entries.aidr-openclaw.enabled: true` for
the quarantine, `hooks.allowConversationAccess: true` for a non-bundled prompt gate, and
neither the Codex nor the Copilot harness. `message_sending`/`reply_payload_sending`
(`pre-delivery-response`) stays `declared-not-proven`.
