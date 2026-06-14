# Singularity AIDR

**AI Agent Detection & Response (AIDR) + AIDR Scan** — closed-source, 8 engines, one signed binary.

<p align="center">
  <img src="images/aidr-logo-shaded.png" alt="Singularity AIDR" width="50%">
</p>

AIDR is the world's most complete AI agent security platform. **8 engines in one binary**:

| # | Engine | Source | Plan |
|---|---|---|---|
| 1 | **Edge Guard** — URL reputation, local heuristics, package supply-chain, plugin scanning | AIDR | Free |
| 2 | **CVE Scanner** — 1,354+ entries, semver-based | AIG → AIDR Scan | Pro |
| 3 | **MCP 14-Category Risk Scorer** — RCE, shell, file, network, exfil, … | AIG → AIDR Scan | Pro |
| 4 | **Agent Workflow Scanner** — prompt injection, priv esc, data leak | AIG → AIDR Scan | Pro |
| 5 | **Jailbreak Eval** — 8 red-team suites (DAN, role-play, prompt leak, token injection) | AIG → AIDR Scan | Pro |
| 6 | **DLP Engine** — 50+ PII/secret patterns | LLM Guard → AIDR Scan | Pro |
| 7 | **Policy Engine** — YAML DSL, live preview | NeMo → AIDR Scan | Pro |
| 8 | **Output Validator** — Zod/JSONSchema | Guardrails AI → AIDR Scan | Pro |

AIDR Scan is derived from Tencent AI-Infra-Guard (Apache 2.0), re-implemented as a native in-process TypeScript engine. Sub-50ms cold scan, ~5MB CLI binary, 165 KB total runtime footprint.

## Quick Start

```bash
# Unix / macOS
curl -fsSL https://aidr.dev/install.sh | sh

# Windows PowerShell
irm https://aidr.dev/install.ps1 | iex
```

Or install via npm:

```bash
npm install -g @singularityrd/aidr-cli
# or
pnpm add -g @singularityrd/aidr-cli
```

Then:
```bash
aidr --version
aidr setup
aidr scan cve lodash@4.17.20 --ecosystem npm
aidr scan mcp https://example-mcp.dev/sse
aidr scan stats
```
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
| [Getting Started](docs/getting-started.md)       | Installation for all platforms                 |
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

- Source code: [Apache License 2.0](LICENSE)
- Threat detection rules (`threats/`): [Detection Rule License 1.1](threats/LICENSE)


