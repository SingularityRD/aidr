---
"@singularityrd/aidr-claude-code": minor
---

- New `UserPromptSubmit` hook (`dist/user-prompt-submit.cjs`, registered in `hooks/hooks.json`). It blocks prompts that contain secrets, warns on PII and applies tenant DLP. A tenant policy that cannot be verified always blocks.
- For a DLP `redact` rule, `PreToolUse` now returns the redacted `updatedInput` with no `permissionDecision`, so the user's normal permission flow still applies.
- `PreToolUse` reads stdin under an 8 MiB limit and denies larger input. It has an internal deadline (default 10 s, below the 15 s hook timeout; override with `AIDR_PRE_TOOL_USE_DEADLINE_MS`) and denies exactly once when the deadline passes.
- The MCP server's `aidr_allowlist_remove` checks the result of the save and no longer echoes raw errors. Post-tool-use guidance names the real `aidr allowlist add` command.
