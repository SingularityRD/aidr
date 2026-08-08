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

The first-party OpenClaw integration is proprietary and distributed under the
commercial terms in the repository [LICENSE](../../LICENSE) and the applicable
Order Form. Threat resources retain the [Detection Rule License 1.1](resources/threats/LICENSE).
Third-party components retain their original terms listed in
[THIRD_PARTY_NOTICES](../../THIRD_PARTY_NOTICES). Legal approval of the
current Release Candidate remains open.


