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

## Provisioned tenant detector policy

The hooks can also evaluate a tool call against an operator-delivered, signed
tenant detector policy (DLP and behavioural detectors). The bundle is read from a
fixed location under the local AIDR state directory, per hook runtime:

```
~/.singularity-aidr/detectors/cursor.json
~/.singularity-aidr/detectors/vscode.json
```

The bundle is accepted only when it is signed by a key listed in
`licensing.public_keys_pem` (ed25519), is inside its validity window, and is
bound to the same tenant as the verified managed entitlement. Provisioning is
opt-in: with no bundle and no `runtime_detectors` module on the signed
entitlement, the hooks evaluate exactly as they do without a tenant policy. A
bundle that is present but invalid — or required by the signed entitlement and
missing — produces a deny verdict; the hook still exits with code `0` so a
killed or failed hook can never pass the call through uninspected.

The policy's labels and rules are whatever the tenant's signed bundle defines;
this extension ships no customer label taxonomy and assumes none.

**Limitation.** This is the extension's pre-tool-call path only. The output
inspection paths (`postToolUse`, `afterAgentResponse`) audit and, where the host
allows it, quarantine results; they do not take a detector policy, so a
provisioned tenant DLP policy does not apply to tool **output**.

## Privacy

Singularity AIDR sends URL hashes and package hashes to SingularityRD reputation APIs. File content, commands, and source code stay local. Both services can be disabled for fully offline operation.

## Links

- [GitHub](https://github.com/singularityrd/aidr)
- [Configuration docs](https://github.com/singularityrd/aidr/blob/main/docs/configuration.md)
- [Threat rules](https://github.com/singularityrd/aidr/blob/main/docs/threat-rules.md)
- [Privacy](https://github.com/singularityrd/aidr/blob/main/docs/privacy.md)


