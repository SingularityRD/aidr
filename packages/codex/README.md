# @singularityrd/aidr-codex

Singularity AIDR's `PreToolUse` connector for the **OpenAI Codex CLI** (`codex`)
evaluates named `Bash` and `apply_patch` calls only when an enabled, trusted hook
forwards them and returns a verdict. Codex enforces that verdict; disabled,
untrusted, crashed, timed-out, or out-of-matcher paths can proceed. The same hook,
registered for `UserPromptSubmit`, also provides prompt protection (secrets block,
personal data warns) before a prompt reaches the model. A real-host acceptance record
([`docs/evidence/real-host/codex.json`](../../docs/evidence/real-host/codex.json):
`codex exec` 0.141.0, linux/x64, development build, scripted mock model) shows both
boundaries holding for the scripted cases; a signed customer release, other versions and
platforms have not been accepted.

Verified against `codex-cli 0.141.0`.

**Release scope.** Codex CLI is one of the six connectors in the intended direct-GA
order scope (Product decision of 2026-10-11, commercial gate `COM-010`).
That is a target, not acceptance: the release decision stays NO-GO until a signed
artefact, a private-registry install and real-host receipts exist for each supported
platform and Codex version. Selling Codex as GA always carries these limits: Codex
fails open on a crashing, timed-out or untrusted hook (this connector maps `ask` and
its own internal errors to an explicit deny); there is no output-side interception
before the model (see [Tool-output inspection](#tool-output-inspection-posttooluse)
and [Scope](#scope)); and the packaged hook matcher covers `Bash` and `apply_patch`
only.

## What it does

For calls reaching the registered matcher, the shared AIDR detection core
evaluates the request before the host action. It returns an explicit deny with
an explanation for a matched threat, or no output for an allowed call. A returned
deny does not itself prove host-side blocking on the target Codex build.

```
codex (PreToolUse) ──stdin JSON──▶ aidr-codex-hook ──▶ AIDR core
                                          │
                                          ├─ allow → no output, call proceeds
                                          └─ block → explicit deny + reason
```

## Install

Install the exact approved version from the private registry:

```bash
npm install --global @singularityrd/aidr-codex@VERSION
```

Registry credentials and release prerequisites are in
[Package Installation](../../docs/package-installation.md). Do not install a
locally built or unsigned package on a customer endpoint.

Commercial packages require the AIDR runtime configuration before the hook is
registered. Generate `agent-config.json` with `scripts/deployment-prepare.mjs`
and an independently delivered Ed25519 artifact-verification public key, then
deploy that file as `~/.singularity-aidr/config.json` on the endpoint. The
artifact key is separate from the licensing/entitlement key. Never distribute
the artifact-signing private key in the package or endpoint configuration.

The hook deliberately refuses to start when its signed manifest, verification
key, or any signed runtime resource is missing or changed. After the managed
configuration and package are installed, register the hook with Codex:

```toml
# ~/.codex/config.toml
[[hooks.PreToolUse]]
matcher = "^(Bash|apply_patch)$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "aidr-codex-hook"
timeout = 10

# Prompt protection (see "Prompt protection" below). No matcher: Codex ignores
# matchers for this event.
[[hooks.UserPromptSubmit]]

[[hooks.UserPromptSubmit.hooks]]
type = "command"
command = "aidr-codex-hook"
timeout = 10

# Tool-output inspection (see "Tool-output inspection" below).
[[hooks.PostToolUse]]
matcher = "^(Bash|mcp__.+)$"

[[hooks.PostToolUse.hooks]]
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
    ],
    "UserPromptSubmit": [
      {
        "hooks": [{ "type": "command", "command": "aidr-codex-hook", "timeout": 10 }]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "^(Bash|mcp__.+)$",
        "hooks": [{ "type": "command", "command": "aidr-codex-hook", "timeout": 10 }]
      }
    ]
  }
}
```

Each handler is trusted separately: review and trust all three with `/hooks`.

The event name is **PascalCase** (`hooks.PreToolUse`). A lower-case
`hooks.pre_tool_use` table was accepted by the TOML parser but ignored by the
tested Codex 0.141.0 host. Review and trust the registered hook with `/hooks`
before relying on it. Repeat host acceptance for the Codex version being sold.

Codex does not provide a `codex hooks install` or `codex hooks uninstall`
subcommand in the locally inspected 0.153.2 CLI. Deploy or remove the AIDR
handler in the configuration file directly, preserving other handlers.

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

## Prompt protection (`UserPromptSubmit`)

The same `aidr-codex-hook` command, registered for `UserPromptSubmit`, inspects the
user's prompt before Codex starts a turn with it (Codex 0.141.0,
`codex-rs/hooks/src/events/user_prompt_submit.rs` at `rust-v0.141.0`):

| Outcome | Output | Codex result |
|---|---|---|
| Secret found (`prompt_protection.secrets: block`, the default) | `{"decision":"block","reason":"…"}` | Turn stopped; the reason names the kind of data, never the value |
| Personal data (`prompt_protection.pii: warn`, the default), incl. TC Kimlik, IBAN, TR phones | `systemMessage` + `hookSpecificOutput.additionalContext` | Prompt sent; the user sees a warning, the model a "do not repeat" note |
| Clean | empty stdout | Prompt sent |
| Uninspectable prompt or internal error | block when secrets are `block`, else a "not inspected" warning; a failure outside the inspection exits 2 with a stderr reason | — |

The hook answers before its 10 s timeout: after 7 s an unfinished inspection blocks when
secrets are `block` or a tenant DLP policy is provisioned, and otherwise sends the prompt
with a "not fully inspected" warning (`AIDR_PROMPT_INSPECTION_DEADLINE_MS`, 100–9000). A
provisioned tenant DLP policy (`~/.singularity-aidr/detectors/codex.json`) applies to the
prompt; any tenant action other than `allow` blocks. Audit entries use
`tool_name: "UserPromptSubmit"` and record kinds and counts only.

Codex's fail-open behaviour applies here too: an untrusted, crashed or timed-out
`UserPromptSubmit` hook lets the prompt through. `aidr-codex-hook --health` reports
`promptInspection` and `inlinePromptBlocking` for the declared configuration; it does
not prove the handler is registered or trusted on the endpoint.

A prompt that carries a canary credential value (`aidr canary deploy`) is always
blocked and recorded as a canary incident (`tool_name: "UserPromptSubmit"`, canary
ids only), whatever the `prompt_protection` settings.

## Tool-output inspection (`PostToolUse`)

Registered for `PostToolUse`, the same command inspects a tool's result
(`tool_response`: the command output for `Bash`, the `CallToolResult` for an MCP
tool) with the shared output scanner: hidden Unicode payloads, poisoned or
injected instructions, leaked secrets and canary values.

| Outcome | Output |
|---|---|
| Clean | empty stdout |
| Finding | `{"decision":"block","reason":"…"}`; the reason names rule ids only, never content |
| Missing or uninspectable result, internal error | block with a "could not inspect" reason; a failure outside the inspection exits 2 with a stderr reason |

In codex-cli 0.141.0's source (`codex-rs/core/src/tools/registry.rs` at
`rust-v0.141.0`) a `PostToolUse` block makes Codex hand the model the reason in
place of the tool result; the tool itself already ran. That replacement has not
been observed in a live Codex session, so `--health` keeps reporting output
inspection as `post_execution_observation` and `inlineOutputBlocking: false`.

Findings also feed session-level detection: secrets become private data and
injection payloads untrusted content for toxic-flow chains
(`docs/toxic-flow.md`), a canary value is recorded as a canary incident, and the
block is written to the audit log (`source: "codex-output-inspection"`, rule ids
and sizes only). Codex runs `PostToolUse` only for calls that succeeded and
`Bash` results carry no exit code, so this hook cannot report failed calls to the
runaway guard's repeated-failure signal.

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

Codex runs each hook in a **fresh process**, so an in-memory approval cannot
survive from the blocked call to the retry. The connector therefore records every
`ask` in the file-backed operator approval store
(`~/.singularity-aidr/approvals.json`). In their own terminal the operator runs
`aidr pending` and `aidr approve <actionId>` (interactive confirmation); the next
identical call — same tool, input and Codex session — is then released once,
within 15 minutes by default. A permanent exception is `aidr allowlist add`.
Residual risk and the key handling are described in
[docs/configuration.md](../../docs/configuration.md#operator-approvals).

**Managed mode.** When the installation is enrolled, every `ask` is also submitted
to the AIDR dashboard and the deny reason says
`Approval requested in the AIDR dashboard: <request_id>`. An administrator (a
different, MFA-authenticated person) approves it there; the next identical call
polls the request, verifies the control-plane-signed token against the approval
keys in the signed entitlement and spends its nonce, so exactly one retry runs —
across Codex's one-process-per-hook model. The agent cannot mint or replay a
token. `operator_approvals.dashboard_only: true` makes this the only channel. See
[dashboard approvals](../../docs/configuration.md#managed-mode-dashboard-approvals).

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

## Behavioral baseline status

A signed policy can provision behavioral and novelty detectors, but this
connector does not provide a trusted, input-bound post-execution success receipt
to promote baseline samples. Product preflight therefore starts cold and does
not persist or restore learned baselines. Baseline-dependent detection is
unavailable and asks by default; a signed policy may explicitly select
`behavioral.unavailable_action: "skip"`, which remains a visible
`behavioral_unavailable` warning rather than a clean result. Do not treat
behavioral baseline detection as production-ready until a verified feedback
path and independent efficacy evaluation are available.

## Configuration

| Variable | Purpose |
|---|---|
| `AIDR_THREATS_DIR` | Override the threat-rule directory |
| `AIDR_ALLOWLISTS_DIR` | Override the allowlist directory |

Without an override the connector resolves rules next to its own installed
location (`dist/resources/threats`), then falls back through the repository and user
directories. If no rule directory can be found, the connector **blocks** rather
than reporting a clean result it cannot support.

## Verifying an install

From a repository checkout, the hook verifier exercises the built connector.
It needs the release artifact manifest, which only the release build writes
(a plain `pnpm build` does not), so build that first:

```bash
pnpm --filter @singularityrd/aidr-codex build:release
# Blocks a known threat and allows a benign command.
pnpm verify:codex        # = node scripts/verify-codex-hook.mjs
```

On an endpoint (no checkout), the installed connector emits machine-readable
capability evidence:

```bash
aidr-codex-hook --health
```

The shipped configuration registers `PreToolUse`, `UserPromptSubmit` and
`PostToolUse`. Its health output therefore reports tool input and prompt
inspection as inline blocking, output inspection as post-execution observation,
and `inlineOutputBlocking: false`: the output replacement described above is
taken from the host source, not proven by a live run. The evidence also records Codex's
host-owned fail-open boundary and does not claim that registration or trust was
verified on the endpoint.

## Scope

The packaged matcher covers `Bash` and `apply_patch` tool calls before
execution. It does not inspect or quarantine their output before the model
consumes it. MCP and other local function tools are outside this matcher;
hosted tools such as `WebSearch` do not pass through the tool-hook path, and
some specialized paths may opt out. Only the named, tested tool and host
versions belong in an enforcement claim.
