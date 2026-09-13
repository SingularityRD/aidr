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

For the portable customer candidate, start with the [first customer installation guide](deploy/FIRST_CUSTOMER.md)
and [v7 candidate status and verification report](docs/production-readiness/2026-09-13-customer-candidate-v7.md).
Deployment details cover both [self-hosted and cloud preparation](deploy/README.md).
The current capability inventory is [FEATURE_INVENTORY.md](FEATURE_INVENTORY.md),
with the machine-readable record in [FEATURE_INVENTORY.json](FEATURE_INVENTORY.json).
The [detailed production and sales gap audit](PRODUCTION_SALES_GAPS.md) maps every
capability to remaining implementation, acceptance tests, owners and dependencies.
Production acceptance and commercial release evidence remain separately gated.

Singularity AIDR evaluates the supported tool calls exposed by each installed
host hook against shipped local threat rules, with no account or network access
required. Coverage when a hook is disabled, unavailable or bypassed depends on
the host and must be checked on the customer's selected runtime and OS.

1. Install the connector for your runtime.
2. Local detection is active immediately.
3. Managed features (dashboard telemetry, signed intel packs, remote policy) are an
   **opt-in** second step: start the agent once and follow the verification URL it
   prints, or configure an API key.

> **Managed enrollment requires a deployed control plane.** If your deployment does
> not have one, the product runs in local mode and the managed features are
> unavailable — local detection is unaffected. See
> [Configuration](docs/configuration.md) for the `mode` setting
> (`local` default, `managed` opt-in).

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
# From the configured private package registry (requires access)
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
- **Remote URL and file reputation checks require configured services and feeds.**
  The installation candidate includes backend functions; production feed freshness
  and latency require deployment acceptance. Unavailable checks are not reported
  as "clean"; see `READINESS_BACKLOG.json` (AIDR-020).
- **Managed mode (device enrollment, dashboard telemetry, signed intel packs,
  remote policy) requires a deployed control plane.** It is not reachable in a
  default install. Local enforcement does not depend on it.
- The [Codex connector](packages/codex/README.md) is included in package, release
  and hook verification. Native host acceptance is still required: Codex can fail
  open when a hook process is unavailable. This is not endpoint isolation.

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
