# Singularity AIDR

**AI Agent Detection & Response (AIDR)** - a lightweight detection and response layer for AI agents that guards commands, files, and web requests.

<p align="center">
  <img src="images/aidr-logo-shaded.png" alt="Singularity AIDR" width="50%">
</p>

Singularity AIDR intercepts tool calls (Bash commands, URL fetches, file writes) via hook systems in [Claude Code](docs/platform-guides/claude-code.md), [Cursor / VS Code](docs/platform-guides/cursor.md), [OpenClaw](docs/platform-guides/openclaw.md), and [OpenCode](docs/platform-guides/opencode.md), and checks them against:

- **URL reputation** - cloud-based malware, phishing, and scam detection
- **Local heuristics** - YAML-based threat definitions for dangerous patterns
- **Package supply-chain checks** - registry existence, file reputation, and age analysis for npm/PyPI packages
- **Plugin scanning** - scans other installed plugins for threats at session start

## Quick Start

### Claude Code

Requires [Node.js >= 18](https://nodejs.org/).

```
/plugin marketplace add https://github.com/singularityrd/aidr.git
/plugin install aidr@aidr
```

### Cursor

Build and install the extension, then run `Singularity AIDR: Enable protection` from the command palette.

```bash
pnpm install && pnpm -C packages/extension run package:cursor:vsix
```

### OpenClaw

```bash
# From npm (recommended)
openclaw plugins install @singularityrd/aidr-openclaw

# From source
pnpm install && pnpm build
cp -r packages/openclaw aidr && openclaw plugins install ./aidr
```

### OpenCode

Use a local source checkout and add the plugin path in OpenCode config:

```bash
git clone https://github.com/singularityrd/aidr
cd aidr
pnpm install
pnpm --filter @singularityrd/aidr-opencode run build
```

```json
{
  "plugin": ["/absolute/path/to/aidr/packages/opencode"]
}
```

See [Getting Started](docs/getting-started.md) for detailed instructions.

## Documentation

| Document                                         | Description                                    |
| ------------------------------------------------ | ---------------------------------------------- |
| [Getting Started](docs/getting-started.md)       | Installation for all platforms                 |
| [How It Works](docs/how-it-works.md)             | Detection layers, data flow, verdicts          |
| [Configuration](docs/configuration.md)           | All config options and file paths              |
| [Threat Rules](docs/threat-rules.md)             | YAML rule format and what gets checked         |
| [Package Protection](docs/package-protection.md) | npm/PyPI supply-chain checks                   |
| [Plugin Scanning](docs/plugin-scanning.md)       | Session-start plugin scanning                  |
| [AMSI Scanning](docs/amsi-scanning.md)           | Windows antimalware scanning via AMSI          |
| [Architecture](docs/architecture.md)             | Monorepo structure, packages, design decisions |
| [Development](docs/development.md)               | Building, testing, tooling, conventions        |
| [Control Plane](docs/control-plane.md)           | Auth, dashboard, and licensing (optional)      |
| [Billing](docs/billing.md)                       | Agent-seat enforcement + billing notes         |
| [Pricing](docs/pricing.md)                       | Proposed pricing model                         |
| [FAQ](docs/faq.md)                               | Common questions                               |
| [Privacy](docs/privacy.md)                       | What data is sent, what stays local            |

**Platform guides:** [Claude Code](docs/platform-guides/claude-code.md) · [Cursor / VS Code](docs/platform-guides/cursor.md) · [OpenClaw](docs/platform-guides/openclaw.md) · [OpenCode](docs/platform-guides/opencode.md)

## Current Limitations

- MCP tool call interception (`mcp__*`) is not yet implemented
- Custom user threat definitions (`~/.singularity-aidr/threats/`) are not yet implemented

## Privacy

Singularity AIDR sends URL hashes and package hashes to SingularityRD reputation APIs. File content, commands, and source code stay local. Both services can be disabled for fully offline operation. See [Privacy](docs/privacy.md) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding conventions, and the threat rule contribution process.

## License

Copyright 2026 SingularityRD.

- Source code: [Apache License 2.0](LICENSE)
- Threat detection rules (`threats/`): [Detection Rule License 1.1](threats/LICENSE)


