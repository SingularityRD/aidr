# @singularityrd/aidr-claude-code

Singularity AIDR connector for **Claude Code**, shipped as hook entry points plus
a bundled MCP server.

The plugin registers a `PreToolUse` hook (the decision point), a `PostToolUse`
hook (tool-output inspection), a `SessionStart` hook (installed-plugin scan and
version check) and a `health` command used by the endpoint installer and the
release consumer gate. Every hook reads the tool call from stdin and writes a
verdict to stdout; an internal error produces a **deny** verdict rather than a
silent allow, because a hook that dies must not let a call through uninspected.

## What it does

- Extracts commands, URLs, file paths and package installs from the tool input
  and evaluates them against the shared detection core (`@singularityrd/aidr-core`)
  using the local YAML threat corpus in `resources/`.
- Inspects tool output before it is consumed by the model, with bounded size and
  time, and fails closed when inspection is incomplete.
- Records decisions in the local audit log and, when a managed control plane is
  configured, forwards scoped telemetry.
- Loads the pinned native AMSI addon from `dist/vendor/koffi` on Windows so file
  and buffer reputation can use the host antimalware interface. The installer
  refuses to register hooks when that payload is missing.

## Installation

Install through the endpoint installer or the Claude Code plugin marketplace:

```bash
node scripts/endpoint-install.mjs            # from the release bundle
```

A fresh install enforces locally with no account or network access. Managed
features are an opt-in layer on top of local enforcement.

## Entry points

| Artifact | Purpose |
| --- | --- |
| `dist/pre-tool-use.cjs` | `PreToolUse` decision hook |
| `dist/post-tool-use.cjs` | Tool-output inspection hook |
| `dist/session-start.cjs` | Session scan and version check |
| `dist/mcp-server.cjs` | Bundled MCP server |
| `dist/health.cjs` | `aidr --json` health probe (declared `bin`) |

## Licence

Proprietary. See `LICENSE` in this package.
