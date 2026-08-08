# Singularity AIDR

**AI Agent Detection & Response (AIDR)** - a lightweight detection and response layer for AI agents that guards commands, files, and web requests.

<p align="center">
  <img src="images/aidr-logo-shaded.png" alt="Singularity AIDR" width="50%">
</p>

Singularity AIDR intercepts tool calls (Bash commands, URL fetches, file writes) via hook systems in [Claude Code](docs/platform-guides/claude-code.md), [Cursor / VS Code](docs/platform-guides/cursor.md), [OpenClaw](docs/platform-guides/openclaw.md), and [OpenCode](docs/platform-guides/opencode.md), and checks them against:

- **Reputation checks** - first-party URL/domain and package hash lookups (optional, privacy-preserving)
- **Local heuristics** - YAML-based threat definitions for dangerous patterns
- **Package supply-chain checks** - registry existence, file reputation, and age analysis for npm/PyPI packages
- **Plugin scanning** - scans other installed plugins for threats at session start

## Quick Start

Singularity AIDR is designed to be set up with minimal friction:

1. Install the connector for your runtime.
2. On first run, you will see a short **verification code** and a **verification URL**.
3. Open the URL, sign in, and approve the device.
4. Your agent is enrolled and protected.

See [Device Auth](docs/device-auth.md) for the exact flow.

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
| [Getting Started](docs/getting-started.md)       | Installation for supported runtimes            |
| [Device Auth](docs/device-auth.md)               | Browser-based device authorization (v1)        |
| [Pilot Program](docs/pilot-program.md)           | Waitlist, approval, and pilot expectations     |
| [How It Works](docs/how-it-works.md)             | Detection layers, data flow, verdicts          |
| [Configuration](docs/configuration.md)           | All config options and file paths              |
| [Threat Rules](docs/threat-rules.md)             | YAML rule format and what gets checked         |
| [Package Protection](docs/package-protection.md) | npm/PyPI supply-chain checks                   |
| [Plugin Scanning](docs/plugin-scanning.md)       | Session-start plugin scanning                  |
| [AMSI Scanning](docs/amsi-scanning.md)           | Windows antimalware scanning via AMSI          |
| [Architecture](docs/architecture.md)             | Monorepo structure, packages, design decisions |
| [Development](docs/development.md)               | Building, testing, tooling, conventions        |
| [Control Plane](docs/control-plane.md)           | Auth, dashboard, and licensing                 |
| [Billing](docs/billing.md)                       | Agent-seat enforcement + billing notes         |
| [Pricing](docs/pricing.md)                       | Proposed pricing model                         |
| [FAQ](docs/faq.md)                               | Common questions                               |
| [Privacy](docs/privacy.md)                       | What data is sent, what stays local            |

**Platform guides:** [Claude Code](docs/platform-guides/claude-code.md) · [Cursor / VS Code](docs/platform-guides/cursor.md) · [OpenClaw](docs/platform-guides/openclaw.md) · [OpenCode](docs/platform-guides/opencode.md)

## Current Limitations

- MCP tool call interception (`mcp__*`) is best-effort via generic input scanning (tool-specific semantics are not modeled yet)
- Custom user threat definitions are supported via `~/.singularity-aidr/threats/*.yaml` (override by `id`)

## Privacy

Singularity AIDR does not send your source code or file contents. Depending on configuration, it may send privacy-preserving indicators (for example URL hashes and package hashes) to first-party reputation endpoints. See [Privacy](docs/privacy.md) for details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding conventions, and the threat rule contribution process.

## Closed-Source / Commercial Builds

For commercial/closed-source distribution, use `pnpm build:release`. Release builds intentionally **omit sourcemaps** (`.map`) and `sourceMappingURL` references to reduce source leakage.

## License

Copyright 2026 SingularityRD.

- First-party AIDR source code and release artifacts: proprietary commercial terms in [LICENSE](LICENSE). Legal approval of the current Release Candidate is still required before customer distribution.
- Threat detection rules (`threats/`): [Detection Rule License 1.1](threats/LICENSE)
- Third-party component notices: [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Those components retain their original licence terms.
