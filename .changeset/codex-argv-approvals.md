---
"@singularityrd/aidr-codex": minor
---

- `shell`, `local_shell` and `exec` calls that pass the command as an argv array are now extracted and inspected. Before, they produced no artifacts and were allowed without inspection.
- An `ask` that an operator approves out of band (`aidr approve`) now releases the identical retry. Before, Codex's fresh-process hook could never be approved.
- A DLP `redact` rule stays a deny: codex-cli 0.141.0 runs the original input when it rejects or loses a rewrite. A guard also refuses a redacted allow if one ever reaches the hook.
