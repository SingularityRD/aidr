---
"@singularityrd/aidr-openclaw": minor
---

- If initialisation fails, the plugin still registers `before_tool_call` and blocks every call with `AIDR failed to initialise: <code>`. The code is non-sensitive; the raw error goes to the host log only. When the integrity check fails, `before_tool_call` returns the same block reason.
- An `ask` that an operator approves out of band releases the identical retry. The allowlist tools accept a one-shot operator grant (`aidr approve --permit-allowlist`).
- `getSageVersion` is renamed to `getAidrVersion`.
