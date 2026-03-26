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
- **ask** verdicts: blocked with an explicit `aidr_approve` action ID
- **allow** verdicts: pass through

## Approval Flow

OpenCode does not expose a plugin-spawned permission dialog, so Singularity AIDR uses tool-based approval:

1. Singularity AIDR blocks an `ask` verdict and returns an `actionId`
2. Ask the user for explicit confirmation in chat
3. If approved, call:

```ts
aidr_approve({ actionId: "...", approved: true })
```

4. Retry the original tool call

Singularity AIDR also provides:

- `aidr_allowlist_add` to permanently allow a URL/command/file path (requires recent approval)
- `aidr_allowlist_remove` to remove an allowlisted entry

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



