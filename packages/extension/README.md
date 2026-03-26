# Singularity AIDR

Singularity AIDR is a lightweight AI Agent Detection & Response layer that protects AI agents from executing dangerous actions on your machine.

## What it does

When an AI agent makes a tool call — running a shell command, writing a file, or fetching a URL — Singularity AIDR intercepts it and checks for threats before it executes.

### Detection layers

- **URL reputation** — cloud-based lookup for malware, phishing, and scam URLs
- **Local heuristics** — pattern matching against dangerous commands, suspicious URLs, sensitive file paths, credential exposure, and obfuscation techniques
- **Package supply-chain checks** — registry existence, file reputation, and age analysis for npm/PyPI packages

### Verdicts

| Decision | Meaning |
|----------|---------|
| **Allow** | No threats detected — tool call proceeds |
| **Ask** | Suspicious activity — you are prompted for approval |
| **Deny** | Threat detected — tool call is blocked |

## Getting started

1. Install the extension
2. Open the command palette (`Ctrl+Shift+P` / `Cmd+Shift+P`)
3. Run **Singularity AIDR: Enable protection**

That's it. Singularity AIDR now monitors all agent tool calls.

## Commands

| Command | Description |
|---------|-------------|
| `Singularity AIDR: Enable protection` | Install managed hooks |
| `Singularity AIDR: Disable protection` | Remove managed hooks |
| `Singularity AIDR: Open config` | Open `~/.singularity-aidr/config.json` |
| `Singularity AIDR: Open audit log` | View the verdict audit trail |
| `Singularity AIDR: Show hook health` | Check hook installation status |

## Privacy

Singularity AIDR sends URL hashes and package hashes to SingularityRD reputation APIs. File content, commands, and source code stay local. Both services can be disabled for fully offline operation.

## Links

- [GitHub](https://github.com/singularityrd/aidr)
- [Configuration docs](https://github.com/singularityrd/aidr/blob/main/docs/configuration.md)
- [Threat rules](https://github.com/singularityrd/aidr/blob/main/docs/threat-rules.md)
- [Privacy](https://github.com/singularityrd/aidr/blob/main/docs/privacy.md)


