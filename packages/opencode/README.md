# Singularity AIDR for OpenCode

Singularity AIDR evaluates named tool calls forwarded by an enabled OpenCode `tool.execute.before` plugin hook and returns a verdict. Host enforcement and disabled, crashed, unmapped, or directly bypassed paths require real-host acceptance; a returned verdict alone does not prove side-effect prevention.

## Inspected tool calls

- `bash` commands
- `webfetch` URLs
- File operations (`read`, `write`, `edit`, `apply_patch`, `ls`, `glob`, `grep`)

OpenCode's `apply_patch` `patchText` is normalized to a file edit. AIDR checks
every parsed target path and added-text section through the same core policy
path as `edit`; if AIDR cannot parse the complete patch, it blocks the call.

Unmapped tools pass through unchanged.

## Install

For a signed customer install, use the private-registry steps in
[Package Installation](../../docs/package-installation.md). Source checkouts
and local plugin paths are for development only.

## Behavior

- **deny** verdicts: AIDR returns a deny response to the host; real-host
  confirmation that the side effect is prevented is still required
- **ask** verdicts: AIDR returns a **blocked** response, with an approval reference (`actionId`) the model
  must hand to the user; nothing the model can call can approve it
- **allow** verdicts: pass through to the host

Tool results are inspected in OpenCode's `tool.execute.after` hook, after the
tool has executed. When a finding or incomplete inspection is detected, the
plugin attempts to replace supported output shapes with a quarantine notice.
For raw MCP results, replacement is limited to mutable plain-data objects. If
the shape is unsupported or immutable, AIDR reports `replacement_unavailable`;
the original result may remain visible to OpenCode and the model. Even when a
mutation succeeds locally, real-host acceptance that OpenCode honors it before
same-turn model consumption has not been established. Oversized, malformed, or
opaque results are never reported as clean, but output quarantine is not
guaranteed for them. The plugin's structured
`aidr.output_inspection.health` and `aidr.output_inspection.coverage` events do
not include the original result; this does not control copies held by the host.

OpenCode does not currently provide a pre-consumption hook for arbitrary
provider streams or non-tool content. The health event reports that channel as
`unsupported_by_host_preconsumption_api` rather than implying coverage.

## Prompt protection

The `chat.message` hook inspects the user's message after OpenCode assembles it and
before it is stored or sent to the model (`prompt_protection` in
`~/.singularity-aidr/config.json`: secrets `block`, personal data such as TC Kimlik,
IBAN, email and phone numbers `warn` by default; a provisioned tenant DLP policy also
applies and blocks on any action other than `allow`).

- **block**: every inspected text part is replaced with the block notice, a TUI toast
  is shown when the TUI is attached, and the hook throws, which aborts the prompt. The
  notice names the kind of data found, never the value.
- **warn**: the message is sent; a TUI toast warns the user, and a notice for the model
  (do not repeat or copy the data, tell the user) is attached to that message through
  `experimental.chat.messages.transform` on every model call. The notice is never
  persisted.
- A prompt that cannot be inspected, or whose inspection is still running after 10 s
  (`AIDR_PROMPT_INSPECTION_DEADLINE_MS`, 100–60000), is blocked while secrets are in
  `block` mode and otherwise sent with a "not inspected" warning. If the plugin fails to
  initialise, prompts get the same uninspected-prompt policy.
- Audit entries use `tool_name: "chat.message"` and record kinds and counts only.

Only the user's own text parts are inspected; `synthetic` parts OpenCode generates
(for example the contents of an attached file) are not. How the OpenCode TUI presents
the thrown error has not been accepted on a real host.

## Provisioned tenant detector policy

An operator can deliver a signed tenant detector policy (DLP and behavioural
detectors) for this connector at a fixed location under the local AIDR state
directory:

```
~/.singularity-aidr/detectors/opencode.json
```

The bundle is accepted only when it is signed by a key listed in
`licensing.public_keys_pem` (ed25519), is inside its validity window, and is
bound to the same tenant as the verified managed entitlement. Provisioning is
opt-in: with no bundle and no `runtime_detectors` module on the signed
entitlement, the plugin evaluates exactly as it does without a tenant policy.
A bundle that is present but invalid — or required by the signed entitlement and
missing — blocks the tool call rather than being treated as an empty policy.

The policy's labels and rules are whatever the tenant's signed bundle defines;
this connector ships no customer label taxonomy and assumes none.

Behavioral and novelty baselines are not production-ready in this connector:
`tool.execute.after` exposes the call identity and arguments, but no trusted
success status. A cold or unavailable baseline is fail-closed (`ask`) by
default. A signed tenant policy may explicitly set
`behavioral.unavailable_action: "skip"`; this reports a visible
`behavioral_unavailable` warning verdict rather than a clean result, while the
independent known-threat model and other configured detectors still run.
Baseline promotion requires a host success receipt bound to the preflight call
and independent efficacy evaluation.

## Approval Flow

OpenCode does not expose a plugin-spawned permission dialog, so there is **no
agent-callable approval tool**. An earlier version registered
`aidr_approve({ actionId, approved: true })`; because the block message contains
the `actionId`, a prompt-injected agent could approve its own blocked call and
re-issue it. That tool has been removed.

Approval is an **out-of-band, human-only action**:

1. Singularity AIDR blocks an `ask` verdict, returns an `actionId` and records the
   ask in the operator approval store (`~/.singularity-aidr/approvals.json`)
2. The model reports that reference to the user and stops
3. In their own terminal the user runs `aidr pending` to review the call and
   `aidr approve <actionId>` to approve it (interactive confirmation). The
   approval is HMAC-protected, bound to the exact tool and artifact set, expires
   after 15 minutes by default and is single-use. Alternatively the user
   permanently allowlists the artifact with `aidr allowlist add`.
4. Only then does a retry of the original tool call succeed — once

Singularity AIDR also provides:

- `aidr_allowlist_add` to permanently allow a URL/command/file path (**requires a
  prior out-of-band approval** granted with `aidr approve <actionId>
  --permit-allowlist`; knowing an `actionId` is not approval)
- `aidr_allowlist_remove` to remove an allowlisted entry

### Honest limitation

OpenCode has no host API this plugin can drive to ask the user a question from
outside the model's tool surface (tracked upstream in
[anomalyco/opencode#12046](https://github.com/anomalyco/opencode/pull/12046)), so
approval happens in a separate terminal rather than in the session. The channel
is not a boundary against code running as the same OS user with full shell
access (see [docs/configuration.md](../../docs/configuration.md#operator-approvals));
the self-defense rules `CLT-SELF-007`..`009` deny the agent running `aidr approve`
(however it is quoted or wrapped) or touching the AIDR state directory and the
approval key, which lives in the OS credential vault. Blocking remains the safe failure mode — a
blocked action is recoverable, a self-approved one is not.

## Session Startup Scanning

Singularity AIDR automatically scans all installed OpenCode plugins when a new session starts.

### What's Scanned

- **NPM plugins**: Packages listed in `opencode.json` config (global + project)
- **Local plugins**: Files in `~/.config/opencode/plugins/` (global)
- **Project plugins**: Files in `.opencode/plugins/` (project-specific)

### When Scanning Runs

- **Trigger**: Once per session on `session.created` event
- **Not on**: `session.updated` (to avoid repeated scans)
- **Performance**: Results are cached for fast subsequent sessions

### How Findings Are Shown

1. **System Prompt Injection**: Findings appear as first message in agent's context
2. **One-Shot**: Only injected once per session (not repeated)
3. **Agent Notification**: Agent sees threats and can inform user
4. **Console Logging**: Findings also logged to OpenCode console

### What Gets Scanned

- Plugin source code (JS/TS/PY files)
- Package metadata (package.json)
- Embedded URLs (checked against threat intelligence)
- Suspicious patterns (credentials, obfuscation, persistence)

### Self-Protection

- Singularity AIDR excludes itself from scanning (`@singularityrd/aidr-opencode`)
- Startup plugin-scan errors are logged without disabling OpenCode. Tool-call
  evaluation errors use a separate deny path; neither behavior establishes
  what OpenCode does if the plugin process crashes before returning a result.

### Cache Location

Scan cache stored at `~/.singularity-aidr/plugin_scan_cache.json` for performance.

## Build

```bash
pnpm --filter @singularityrd/aidr-opencode run build
```

This copies `threats/` and `allowlists/` into `packages/opencode/resources/`.

## Test

```bash
pnpm test -- packages/opencode/src/__tests__/integration.test.ts
```
