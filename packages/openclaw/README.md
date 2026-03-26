# @singularityrd/aidr-openclaw

**Singularity AIDR** - AI Agent Detection & Response plugin for [OpenClaw](https://openclaw.dev).

Singularity AIDR intercepts tool calls (shell commands, URL fetches, file writes) and checks them against URL reputation services, local heuristic threat rules, and package supply-chain checks before they execute.

## Installation

```bash
openclaw plugins install @singularityrd/aidr-openclaw
```

## What It Does

- Intercepts `exec`, `web_fetch`, `write`, `edit`, `read`, and `apply_patch` tool calls
- Checks URLs against cloud-based malware/phishing detection
- Matches commands and file paths against YAML-based threat definitions
- Validates npm/PyPI packages against supply-chain risks
- Scans installed plugins for threats at session start
- Provides a `aidr_approve` gate tool for interactive approval of flagged actions

## Configuration

Singularity AIDR works out of the box with no configuration. Optional config file at `~/.singularity-aidr/config.json`:

```json
{
  "sensitivity": "balanced",
  "url_check": { "enabled": true },
  "file_check": { "enabled": true }
}
```

## Links

- [Source & documentation](https://github.com/singularityrd/aidr)
- [OpenClaw platform guide](https://github.com/singularityrd/aidr/blob/main/docs/platform-guides/openclaw.md)
- [Privacy policy](https://github.com/singularityrd/aidr/blob/main/docs/privacy.md)

## License

Apache License 2.0 - Copyright 2026 SingularityRD.



