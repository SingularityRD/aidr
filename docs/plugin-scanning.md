# Plugin Scanning

Singularity AIDR scans other installed plugins for threats at every session start. Each plugin's files are run through the same threat definitions and URL checks used for runtime tool interception.

## Supported Platforms

| Platform | Plugin Source |
|----------|-------------|
| Claude Code | `~/.claude/plugins/installed_plugins.json` |
| OpenClaw | `~/.openclaw/extensions/` directory |

## How It Works

1. At session start, Singularity AIDR reads the list of installed plugins
2. Each plugin's source files are scanned against threat definitions
3. URLs found in plugin code are checked against URL reputation
4. Results are cached locally and only re-checked when a plugin changes
5. Findings are logged to the audit log with `type: "plugin_scan"`

## Audit Log Entry

```json
{
  "type": "plugin_scan",
  "timestamp": "2026-02-09T10:30:00Z",
  "plugin_key": "example-plugin@marketplace",
  "findings_count": 1,
  "findings": [
    {
      "threat_id": "CLT-CMD-001",
      "title": "Pipe to shell",
      "severity": "high",
      "confidence": 0.9,
      "artifact": "curl ... | bash",
      "source_file": "setup.sh"
    }
  ]
}
```

## Skill and plugin package rules (T01–T09)

In addition to the command rules, every readable plugin file is checked against
the deterministic skill-scan rules in `threats/skill-scan.yaml`, a port of the
AI-Infra-Guard Skill-Scan (SkillTrustBench T01–T09) taxonomy: hidden or
concealment instructions, zero-width/bidirectional Unicode smuggling, memory
poisoning, remote payload execution, Python bytecode shipped without source,
credential exfiltration, excessive permissions, persistence, tool hijacking,
insecure dependencies and hard-coded credentials. Findings name the file and
line; a matched credential is replaced by a short digest. Scan a package on
demand with `aidr scan --skill <dir>`; see
[AI security posture](ai-security-posture.md).

> **Note:** Claude Code does not currently provide a hook for plugin installation events. The session-start approach ensures all plugins are scanned before each session begins.

