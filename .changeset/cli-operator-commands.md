---
"@singularityrd/aidr-cli": minor
---

New operator commands:

- `aidr pending`
- `aidr approve <actionId>` asks for confirmation on an interactive TTY. Scripts can use `--yes` with `AIDR_OPERATOR_NONINTERACTIVE=1`.
- `aidr allowlist list|add|remove`
- `aidr audit tail` and `aidr audit export --since --format jsonl|csv`. Exports are re-redacted and CSV output is formula-safe.
- `aidr doctor` exits non-zero when it finds a problem.

`aidr scan` gains `--skill <dir>` and `--upload`, and `aidr discover` gains `--upload` to send posture findings to the enrolled control plane. Setup guidance and connector-status remedies print the real release version.
