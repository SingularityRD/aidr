# @singularityrd/aidr-codex

Singularity AIDR enforcement for the **OpenAI Codex CLI** (`codex`), implemented
as a native `PreToolUse` hook.

Verified against `codex-cli 0.141.0`.

## What it does

Every shell command and every patch Codex is about to apply is inspected by the
shared AIDR detection core before it runs. A call that matches a threat rule is
blocked with an explanation; a benign call proceeds untouched.

```
codex (PreToolUse) ──stdin JSON──▶ aidr-codex-hook ──▶ AIDR core
                                          │
                                          ├─ allow → no output, call proceeds
                                          └─ block → explicit deny + reason
```

## Install

```toml
# ~/.codex/config.toml
[[hooks.PreToolUse]]
matcher = "^(Bash|apply_patch)$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "aidr-codex-hook"
timeout = 10
```

Or equivalently, in `~/.codex/hooks.json`:

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^(Bash|apply_patch)$",
        "hooks": [{ "type": "command", "command": "aidr-codex-hook", "timeout": 10 }]
      }
    ]
  }
}
```

Two configuration details that are easy to get wrong and fail **silently** if
you do — both were established by running the real binary:

- The event name is **PascalCase** (`hooks.PreToolUse`). A lower-case
  `hooks.pre_tool_use` table is accepted by the TOML parser and then ignored, so
  the hook never runs and nothing warns you.
- Do **not** add a top-level `"description"` key to `hooks.json`. The file schema
  rejects unknown keys, so the whole file fails to parse and no hooks load.

## Trust — read this before relying on it

Codex will not run a hook it has not reviewed. An **untrusted hook is dropped
during discovery and never invoked**, which means no enforcement and no visible
error. After installing, review and trust the hook through Codex's hook UI, or
run with `--dangerously-bypass-hook-trust` in automation that already vets its
hook sources.

## How this connector handles Codex's fail-open behaviour

This matters more than any other detail here. Verified against `codex-cli`
0.141.0 by driving the real binary and reading its event stream:

| Hook behaviour | Codex result |
|---|---|
| Well-formed `permissionDecision: "deny"` | **Blocks** the tool call |
| `permissionDecision: "ask"` | Unsupported — the call **proceeds** |
| `deny` with an **empty** reason | **Proceeds** |
| Hook crashes / times out / malformed JSON | **Proceeds** |
| Hook not trusted | **Never runs** — proceeds |
| Plain text on stdout, exit 0 | Ignored — proceeds |

Every failure mode is fail-open, and a hook cannot change that. AIDR's own
convention is that connector entry points fail **closed**, so this connector is
written to give Codex the only answer it honours:

- **`ask` is translated into `deny`.** Codex has no working "ask" verb, so
  emitting one would let a call through that AIDR wanted a human to review. The
  approval reference travels in the reason text instead. The model cannot act on
  it — approval is operator-held and out-of-band, and no approval tool is exposed
  to the agent.
- **Internal errors become an explicit deny.** A failure in our own logic still
  blocks, instead of returning an empty response that Codex would read as "carry
  on".
- **The reason is never empty.** An empty reason fails open.
- **Unreadable input blocks.** If the hook cannot parse the call, it cannot judge
  it.

The one remaining fail-open path is the process being killed before it writes
anything. That is a property of the host and is recorded, not hidden.

## `apply_patch` is inspected too

Codex sends patch bodies in `tool_input.command`, whereas Claude Code's
`Edit`/`Write` tools use `file_path` / `old_string` / `new_string`. Passing
`apply_patch` to the shared extractor unchanged would fall through to its
unknown-tool path and the patch content would never be examined, so this
connector extracts both the patch body and every `*** Update/Add/Delete File:`
target. An `authorized_keys` write hidden inside a patch is caught.

## Approval

Approval is **operator-held**. There is no agent-callable approval tool, by
design: the model receives the approval reference in the block reason, so an
agent-invokable approval would let a prompt-injected agent approve its own block.

Note that Codex runs each hook in a **fresh process**, so an in-memory approval
cannot survive from the blocked call to the retry. A blocked `ask` therefore
stays blocked until an operator records the artifact in the allowlist.

## Provisioned tenant detector policy

An operator can deliver a signed tenant detector policy (DLP and behavioural
detectors) for this connector at a fixed location under the local AIDR state
directory:

```
~/.singularity-aidr/detectors/codex.json
```

The bundle is accepted only when it is signed by a key listed in
`licensing.public_keys_pem` (ed25519), is inside its validity window, and is
bound to the same tenant as the verified managed entitlement. Provisioning is
opt-in: with no bundle and no `runtime_detectors` module on the signed
entitlement, the hook evaluates exactly as it does without a tenant policy.
A bundle that is present but invalid — or required by the signed entitlement and
missing — becomes an explicit `deny`, because this host fails open on anything
else.

The policy's labels and rules are whatever the tenant's signed bundle defines;
this connector ships no customer label taxonomy and assumes none.

## Configuration

| Variable | Purpose |
|---|---|
| `AIDR_THREATS_DIR` | Override the threat-rule directory |
| `AIDR_ALLOWLISTS_DIR` | Override the allowlist directory |

Without an override the connector resolves rules next to its own installed
location (`resources/threats`), then falls back through the repository and user
directories. If no rule directory can be found, the connector **blocks** rather
than reporting a clean result it cannot support.

## Verifying an install

```bash
# Blocks a known threat and allows a benign command.
node scripts/verify-codex-hook.mjs
```

The connector also emits machine-readable capability evidence:

```bash
aidr-codex-hook --health
```

The shipped configuration registers only `PreToolUse`. Its health output
therefore reports input inspection as inline blocking, output inspection as
unavailable, and `inlineOutputBlocking: false`. Adding `PostToolUse` would make
tool output observable only after execution; it still would not prove that the
output was blocked before model consumption. The evidence also records Codex's
host-owned fail-open boundary and does not claim that registration or trust was
verified on the endpoint.

## Scope

The hook covers `Bash` and `apply_patch` tool calls before execution. It does
not inspect or quarantine their output before the model consumes it. Codex's hosted tools (for
example `WebSearch`) do not pass through the tool-hook path, so treat this — as
OpenAI's own documentation does — as a strong guardrail rather than a complete
enforcement boundary.
