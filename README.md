# Singularity AIDR

**AI Agent Detection & Response (AIDR)** - a lightweight detection and response layer for AI agents that guards commands, files, and web requests.

<p align="center">
  <img src="images/aidr-logo-shaded.png" alt="Singularity AIDR" width="50%">
</p>

Singularity AIDR intercepts tool calls (Bash commands, URL fetches, file writes) via hook systems in [Claude Code](docs/platform-guides/claude-code.md), [Cursor / VS Code](docs/platform-guides/cursor.md), [OpenClaw](docs/platform-guides/openclaw.md), [OpenCode](docs/platform-guides/opencode.md) and [Codex](packages/codex/README.md), and checks them against:

- **Reputation checks** - first-party URL/domain and package hash lookups (optional, privacy-preserving)
- **Local heuristics** - YAML-based threat definitions for dangerous patterns
- **Package supply-chain checks** - registry existence, file reputation, and age analysis for npm/PyPI packages
- **Plugin scanning** - scans other installed plugins for threats at session start

## Quick Start

The current decision is **NO-GO for a customer or production release**. Start with
the [current first-customer readiness profile](docs/production-readiness/first-customer-ready.md)
and [first customer installation guide](deploy/FIRST_CUSTOMER.md); local test
passes do not replace signed-candidate or live-host acceptance.
For approved package installation, see [Package Installation](docs/package-installation.md).
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
3. Managed features (dashboard telemetry, signed intel packs, remote policy) are
   available only after the control plane, an authentication method, and the
   tenant's signed runtime configuration have passed live acceptance.

> **Managed enrollment requires a deployed and live-accepted control plane.** If
> your deployment does not have one, or its authentication method has not passed
> an end-to-end check, the product runs in local mode and managed features are
> unavailable — local detection is unaffected. See
> [Configuration](docs/configuration.md) for the `mode` setting
> (`local` default, `managed` opt-in).

### Claude Code

Requires [Node.js >= 22.12.0](https://nodejs.org/).

Download and extract the signed `aidr-claude-plugin-<version>.tar.gz` artifact
from the approved release, then add that extracted directory:

```
/plugin marketplace add /absolute/path/to/extracted/aidr-claude-plugin
/plugin install aidr@aidr
```

### Cursor

Download the signed `aidr-cursor.vsix` from an approved release, install it
through `Extensions > Install from VSIX`, then run `Singularity AIDR: Enable
protection` from the command palette. Source builds are not release artifacts;
the protected release-candidate pipeline produces and verifies the signed VSIX.

### OpenClaw

Install the exact version from the private registry only after the signed
release is approved; see [Package Installation](docs/package-installation.md).
Source checkout/builds are for development, not customer installation.

### OpenCode

Install from the private registry after the signed release is approved. The
versioned setup and configuration are in [Package Installation](docs/package-installation.md).

See [Getting Started](docs/getting-started.md) for detailed instructions.

## Documentation

| Document                                         | Description                                    |
| ------------------------------------------------ | ---------------------------------------------- |
| [Getting Started](docs/getting-started.md)       | Installation for supported runtimes            |
| [Package Installation](docs/package-installation.md) | Private registry installs and prerequisites |
| [Device Auth](docs/device-auth.md)               | Browser-based device authorization (v1)        |
| [Pilot Program](docs/pilot-program.md)           | Current pilot status and application prerequisites |
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
| [Pricing](docs/pricing.md)                       | Historical proposal; no approved price or offer |
| [FAQ](docs/faq.md)                               | Common questions                               |
| [Privacy](docs/privacy.md)                       | What data is sent, what stays local            |
| [Privacy RC source](packages/privacy/README.md)  | Imported candidate; not wired into agent enforcement |

**Platform guides:** [Claude Code](docs/platform-guides/claude-code.md) · [Cursor / VS Code](docs/platform-guides/cursor.md) · [OpenClaw](docs/platform-guides/openclaw.md) · [OpenCode](docs/platform-guides/opencode.md) · [Codex](packages/codex/README.md)

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
- The [Privacy 0.5.0 release candidate](packages/privacy/README.md) is a private
  workspace package, not an active AIDR hook, cloud gateway or customer release.
  Provider upload paths and enterprise identity still require integration tests.

## Privacy

Local heuristics do not upload source code or file contents. If enabled, URL
reputation sends each URL, including its host and path, to the configured
endpoint; query parameters are sent only when explicitly enabled. Package
checks may send package names, versions, and registry metadata, while file
checks send SHA-256 hashes. These values are not all anonymous. See
[Privacy](docs/privacy.md) for the other configured outbound data flows.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development setup, coding conventions, and the threat rule contribution process.

## Closed-Source / Commercial Builds

For commercial/closed-source distribution, use `pnpm build:release`. Release builds intentionally **omit sourcemaps** (`.map`) and `sourceMappingURL` references to reduce source leakage.

## License

Copyright 2026 SingularityRD.

- First-party AIDR source code and release artifacts: proprietary commercial terms in [LICENSE](LICENSE). Legal approval of the current Release Candidate is still required before customer distribution.
- Threat detection rules (`threats/`): [Detection Rule License 1.1](threats/LICENSE)
- Third-party component notices: [THIRD_PARTY_NOTICES](THIRD_PARTY_NOTICES). Those components retain their original licence terms.
