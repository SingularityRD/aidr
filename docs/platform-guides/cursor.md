# Cursor / VS Code

## Installation

### Cursor

Download the signed `aidr-cursor.vsix` from an approved release and install it
via `Extensions > Install from VSIX`.

### VS Code

Download the signed `aidr-vscode.vsix` from an approved release and install it
via `Extensions > Install from VSIX`.

The repository does not provide a local signing shortcut. Distributable VSIX
files come from the protected release-candidate pipeline so the archive is
bound to its signed manifest, SBOM, checksum, and release inventory.

## Usage

For VS Code Local agent hooks, first enable `chat.useClaudeHooks` in VS Code
User Settings. The extension does not change this editor setting; its Enable
Protection command checks the prerequisite, and Hook Health reports its state.
Cursor does not require this VS Code setting.

Open the command palette (`Ctrl+Shift+P`) and use:

| Command | Description |
|---------|-------------|
| `Singularity AIDR: Enable protection` | Install managed hooks |
| `Singularity AIDR: Disable protection` | Remove managed hooks |
| `Singularity AIDR: Open config` | Open `~/.singularity-aidr/config.json` |
| `Singularity AIDR: Open audit log` | Open the audit log file |
| `Singularity AIDR: Show hook health` | Display hook status |

## How It Works

The extension installs managed hooks into the Cursor/VS Code agent system. When a tool call is intercepted, the hook spawns `aidr-hook.cjs` as a subprocess, which runs the same detection pipeline as the Claude Code connector. Cursor `preToolUse` cannot enforce an approval (`ask`) response, so AIDR maps that verdict to an explicit deny.

The same runner also provides prompt protection: Cursor `beforeSubmitPrompt` and VS Code Local `UserPromptSubmit` are registered with the tool hooks, so a prompt carrying a secret is stopped (`continue: false`) before it is sent, and personal data is flagged. See [configuration](../configuration.md#prompt_protection) for the per-host behaviour.

## Scope

The extension supports a configurable scope setting:

- **User** - Hooks apply globally for the current user
- **Workspace** - Hooks apply only to the current workspace

Configure via `aidr.cursor.scope` (Cursor) or `aidr.vscode.scope` (VS Code) in settings.

## E2E Testing

Extension E2E tests run inside installed IDE hosts (no IDE auto-download):

```bash
AIDR_E2E_ENABLE_IDE_HOST=1 pnpm test:e2e:cursor
AIDR_E2E_ENABLE_IDE_HOST=1 pnpm test:e2e:vscode
```

Cursor headless agent coverage in `pnpm test:e2e:cursor` additionally requires:

- `agent` CLI in `PATH` (or `AIDR_AGENT_PATH`)
- Valid agent auth (`agent login` or `CURSOR_API_KEY`)

Optional executable overrides:

- `AIDR_E2E_ENABLE_IDE_HOST` - set to `1` to enable real IDE Extension Host E2E suites
- `AIDR_CURSOR_PATH` - absolute path to Cursor executable
- `AIDR_AGENT_PATH` - absolute path to the `agent` CLI used by Cursor headless E2E
- `AIDR_VSCODE_PATH` - absolute path to VS Code executable
- `VSCODE_EXECUTABLE_PATH` - alternate VS Code executable override

If the `agent` CLI is missing or unauthenticated, only the Cursor headless agent sub-suite is skipped; other extension host E2E tests continue.
Extension hooks always exit with code `0`. The host reads the JSON response to determine whether to block the tool call.

## Build Details

The extension bundles `threats/` and `allowlists/` from the repo root into `packages/extension/resources/` during build (via `sync-assets.mjs`). These are not checked into git.

See [Building the Extension](../../doc/build_extension.md) for platform-specific build instructions.
