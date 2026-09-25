---
"@singularityrd/aidr-core": minor
"@singularityrd/aidr-claude-code": minor
"@singularityrd/aidr-openclaw": minor
"@singularityrd/aidr-opencode": minor
"aidr-cursor": minor
---

Session toxic-flow ("lethal trifecta") and behavioral chain detection.

- The shared evaluator now tracks, per agent session, private-data access, untrusted-content exposure and external communication. It flags the call that completes a dangerous chain: `lethal_trifecta` (AIDR-FLOW-001), `exfil_chain` (AIDR-FLOW-002), `injection_to_action` (AIDR-FLOW-003) and `bulk_sensitive_access` (AIDR-FLOW-004).
- The verdict reason names the chain and the earlier steps: tool, redacted target and age.
- Every connector that uses `evaluateToolCall` gets it: Claude Code, Cursor/VS Code, OpenClaw, OpenCode, Codex and the MCP gateway.
- Post-execution output findings feed the session record in Claude Code, OpenClaw, OpenCode and Cursor/VS Code.
- New `toxic_flow` config: `enabled`, `action` (`auto` asks in balanced and denies in paranoid, or `ask`, `deny`, `monitor`), `window_minutes`, `bulk_sensitive_threshold` and trusted domains, MCP servers and git remotes. It is on by default.
- Session records are stored in `~/.singularity-aidr/session-flow/`, HMAC-protected and bounded.
- A tampered record is treated as a stricter posture, not as a clean slate. A state I/O failure is a skipped signal and is recorded as `toxic_flow_unavailable`, never as a clean result.
- See `docs/toxic-flow.md`.
