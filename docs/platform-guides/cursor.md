# Cursor / VS Code

> **Status: preview — no real-host acceptance evidence yet.** The extension returns its verdicts, but no Cursor or VS Code
> version has been observed enforcing them on a real host (deny, ask-as-deny,
> `failClosed`, a killed or timed-out hook). See the
> [compatibility matrix](../compatibility-matrix.md) and the
> [Real-host acceptance](#real-host-acceptance) section below.

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

### Hook command, updates and uninstall

The managed hook command never names the versioned extension directory. It runs a
shim next to the hooks file (`.cursor/hooks/aidr-hook` or `.claude/hooks/aidr-hook`,
`.cmd` on Windows), which starts a small launcher kept at
`~/.singularity-aidr/extension-hooks/<cursor|vscode>/aidr-hook-launcher.cjs`. The
launcher loads the runner recorded in `runner.json` next to it and, if that version
directory is gone (an extension update), the newest installed version's runner.

- The extension activates on startup (`onStartupFinished`) and re-points the launcher
  at the running version for every scope that already has managed hooks. It never
  installs hooks on its own.
- With no runner left (for example after removing the extension without Disable
  protection) the launcher answers with a **deny** in the host's format and exits 0;
  if the launcher or the editor runtime is missing, the shim itself answers with the
  deny. A dangling hook never exits 1 without a verdict.
- **Show hook health** checks the shim, editor runtime, launcher and runner, and
  reports any break as `status: BROKEN` with the reason.
- Uninstalling runs the extension's `vscode:uninstall` cleanup, which removes only
  AIDR's managed entries from every hook file it recorded, its shims and the
  launcher. It runs when the editor finishes removing the extension (after a
  restart).

VS Code Local hooks are read from the Claude settings files, so the user-scope file is
`~/.claude/settings.json`, which the Claude Code CLI also reads (the CLI then runs the
same AIDR hook). The extension merges into that file: only entries carrying
`--managed-by aidr-vscode` are added or removed, every other key and hook is kept,
the previous contents are saved to `settings.json.aidr-backup` before each change, and
an unchanged install does not rewrite the file.

### Verified host versions

The hook contract is verified on Cursor 3.19.7 and VS Code 1.137.0
([acceptance run](../evidence/native-host-acceptance-run-20260916.md)). The extension
reads the host version at activation; on another major.minor line, or when the Cursor
version cannot be read, it shows a one-time "unverified host version" warning and
Show hook health reports the status. Protection stays on: unrecognised hook payloads
are denied.

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

`pnpm --filter aidr-cursor build` produces a development `dist/`. Distributable VSIX files are packaged from a signed release candidate only; see [Release packaging](../../packages/extension/README.md#release-packaging) and the [VS Code/Cursor section of the deployment runbook](../runbooks/deployment.md#vs-codecursor-extension-publishing).

## Real-host acceptance

Tested host versions for every connector, generated from these records: [compatibility matrix](../compatibility-matrix.md). Treat any other host version as unverified.

Cursor and VS Code are **not** covered by `pnpm test:e2e:real-host`: their installers
could not be downloaded in the environment that produced the real-host records, so
every Cursor and VS Code row in `deploy/native/interception-matrix.json` stays
`declared-not-proven`.
