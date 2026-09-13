# Singularity AIDR for OpenCode

Singularity AIDR integrates with OpenCode as a plugin and evaluates tool calls before they run.

## What it protects

- `bash` commands
- `webfetch` URLs
- File operations (`read`, `write`, `edit`, `ls`, `glob`, `grep`)

Unmapped tools pass through unchanged.

## Install

Clone the repo, build the OpenCode package, then point OpenCode to this package path:

```bash
git clone https://github.com/singularityrd/aidr
cd aidr
pnpm install
pnpm --filter @singularityrd/aidr-opencode run build
```

Global config (`~/.config/opencode/opencode.json`):

```json
{
  "plugin": ["/absolute/path/to/aidr/packages/opencode"]
}
```

## Behavior

- **deny** verdicts: blocked immediately
- **ask** verdicts: **blocked**, with an approval reference (`actionId`) the model
  must hand to the user; nothing the model can call can approve it
- **allow** verdicts: pass through

Tool results are inspected in OpenCode's `tool.execute.after` hook before they
are returned to the model. A result containing a detected secret or prompt
injection is replaced with a short quarantine notice. Results over 256 KiB and
runtime values that cannot be inspected are also quarantined; they are never
reported as clean after a partial inspection. The plugin emits structured
`aidr.output_inspection.health` and `aidr.output_inspection.coverage` log events
without including the original result.

OpenCode does not currently provide a pre-consumption hook for arbitrary
provider streams or non-tool content. The health event reports that channel as
`unsupported_by_host_preconsumption_api` rather than implying coverage.

## Approval Flow

OpenCode does not expose a plugin-spawned permission dialog, so there is **no
agent-callable approval tool**. An earlier version registered
`aidr_approve({ actionId, approved: true })`; because the block message contains
the `actionId`, a prompt-injected agent could approve its own blocked call and
re-issue it. That tool has been removed.

Approval is an **out-of-band, human-only action**:

1. Singularity AIDR blocks an `ask` verdict and returns an `actionId`
2. The model reports that reference to the user and stops
3. The user approves out of band — either by permanently allowlisting the exact
   artifact (`~/.singularity-aidr/allowlist.json`), or by having the host
   process that owns the `ApprovalStore` record the approval
   (`approveAction` in `@singularityrd/aidr-core`)
4. Only then does a retry of the original tool call succeed

Singularity AIDR also provides:

- `aidr_allowlist_add` to permanently allow a URL/command/file path (**requires a
  prior out-of-band approval**; knowing an `actionId` is not approval)
- `aidr_allowlist_remove` to remove an allowlisted entry

### Honest limitation

OpenCode has no host API this plugin can drive to ask the user a question from
outside the model's tool surface (tracked upstream in
[anomalyco/opencode#12046](https://github.com/anomalyco/opencode/pull/12046)).
Until that exists, **an `ask` verdict cannot be approved mid-session**: the call
stays blocked and the user must allowlist the artifact (or take another action)
instead. That is the safe failure mode — a blocked action is recoverable, a
self-approved one is not. When a host confirmation primitive is available, wire
it to `ApprovalStore` **without** exposing it as a model-callable tool.

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
- Fail-open philosophy: Errors don't block OpenCode

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


