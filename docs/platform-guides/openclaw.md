# OpenClaw

## Installation

Install from npm or build from source:

```bash
# From npm (recommended)
openclaw plugins install @singularityrd/aidr-openclaw

# From source
pnpm install && pnpm build
cp -r packages/openclaw aidr
openclaw plugins install ./aidr
```

The build copies threat definitions, allowlists, and skills into `packages/openclaw/resources/`.

## How It Works

The OpenClaw connector runs in-process using the OpenClaw plugin API:

- **`before_tool_call`** - Intercepts `exec`, `web_fetch`, `write`, `edit`, `read`, and `apply_patch`. Runs the full detection pipeline.
- **`aidr_allowlist_add` / `aidr_allowlist_remove`** - Manage the on-disk allowlist. `aidr_allowlist_add` refuses unless a genuine approval was already recorded, so it cannot be used to approve a blocked action.
- **`gateway_start` / `session_start`** - Scans installed plugins for threats.

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

OpenClaw's `plugins.code_safety` audit will flag Singularity AIDR with a `potential-exfiltration` warning. This is a false positive - `readFile` and `fetch` coexist in the same bundle because Singularity AIDR reads local config/cache files and separately sends URL hashes to a reputation API. No file content is transmitted.



