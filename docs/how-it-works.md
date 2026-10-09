# How It Works

Singularity AIDR intercepts tool calls made by AI agents, extracts security-relevant artifacts, and checks them against multiple threat detection layers.

## Detection Layers

1. **URL reputation** - Optional lookup for malware, phishing, and scam URLs. Off by default; it needs a configured first-party reputation endpoint, and an unavailable lookup is never reported as "clean".
2. **Local heuristics** - YAML-based regex patterns matching dangerous commands, suspicious URLs, sensitive file paths, credential exposure, and obfuscation techniques.
3. **Package supply-chain checks** - Registry existence and age analysis, plus optional file hash reputation when a first-party endpoint is configured, for npm/PyPI packages. See [Package Protection](package-protection.md).
4. **Plugin scanning** - Scans other installed plugins for threats at session start. See [Plugin Scanning](plugin-scanning.md).

## Intercepted Tools

| Platform | Hooks / Tools |
|----------|---------------|
| Claude Code | `UserPromptSubmit` (prompt protection), `PreToolUse` on every tool (`matcher: "*"`), `PostToolUse` |
| Cursor | `beforeSubmitPrompt` (prompt protection), `beforeShellExecution`, `preToolUse` (Write, Edit, Delete, WebFetch), `beforeMCPExecution`, `beforeReadFile` |
| VS Code | `UserPromptSubmit` (prompt protection, Local agent hooks), `PreToolUse` on `Bash`, `WebFetch`, `Write`, `Edit`, `Read`, `Delete` |
| OpenClaw | `before_agent_run` (prompt protection), `before_tool_call` on `exec`, `web_fetch`, `write`, `edit`, `read`, `apply_patch`, agent tool-result middleware |
| OpenCode | `chat.message` (prompt protection), `tool.execute.before`, `tool.execute.after` |
| Codex CLI | `UserPromptSubmit` (prompt protection), `PreToolUse` on `Bash` and `apply_patch` |

Prompt protection and tool-call blocking are sold, and recorded as enforced on a real host
(one host version each, linux/x64, scripted mock model), for Claude Code, Codex, OpenCode
and OpenClaw; see `deploy/native/interception-matrix.json`. Cursor and VS Code have no
real-host record.

For tool calls outside these known shapes (including `mcp__*`), Singularity AIDR falls back to a generic string-scan extractor and still applies heuristics + URL checks.

## Data Flow

```
Tool call received
  │
  ├─ Extract artifacts (URLs, commands, file paths, content)
  │
  ├─ Check allowlist → if allowlisted → allow
  │
  ├─ Check cache → if cached → use cached verdict
  │
  ├─ Run local heuristics (pattern matching against threat definitions)
  │
  ├─ Query URL reputation (for extracted URLs)
  │
  ├─ Check packages (for install commands / manifest writes)
  │
  ├─ Decision engine combines all signals → verdict
  │
  ├─ Cache result
  │
  └─ Audit log → return verdict
```

## Verdicts

| Decision | Meaning |
|----------|---------|
| `allow`  | No threats detected, tool call proceeds |
| `ask`    | Suspicious - user prompted for approval |
| `deny`   | Confirmed threat - tool call blocked |

When multiple signals fire, merge precedence is: `deny > ask > allow`.

## Failure behavior

Not every error is an `allow`. An unavailable enabled URL or package reputation
leg is surfaced as incomplete inspection and can require review; an invalid
commercial artifact fails startup. Cursor/VS Code hooks use host responses to
communicate decisions, so a process exit code alone does not prove that an
action was allowed or blocked. Verify the installed host's interception path.

## Sensitivity Presets

The confidence threshold determines when a detection escalates from `ask` to `deny`:

| Preset | Threshold | Behavior |
|--------|-----------|----------|
| `paranoid` | 0.70 | Blocks on any suspicion |
| `balanced` | 0.85 | Blocks confirmed threats, warns on suspicious (default) |
| `relaxed` | 0.95 | Only blocks high-confidence malware |

Configure in `~/.singularity-aidr/config.json` with `"sensitivity": "paranoid"`.

On OpenClaw and OpenCode, `ask` verdicts remain blocked until an operator approves out of band; these plugins cannot open a host-native approval dialog, and the agent cannot approve its own action. `paranoid` mode promotes `ask` to a hard `deny` on those connectors. Claude Code supports a host approval UI. Cursor `preToolUse` cannot enforce an `ask` response, so its adapter maps `ask` to an explicit deny. See the [OpenClaw](../packages/openclaw/README.md#approving-a-flagged-action) and [OpenCode](../packages/opencode/README.md#approval-flow) connector notes.
