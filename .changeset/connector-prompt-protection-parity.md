---
"@singularityrd/aidr-core": minor
"aidr-cursor": minor
"@singularityrd/aidr-codex": minor
"@singularityrd/aidr-opencode": minor
"@singularityrd/aidr-openclaw": minor
"@singularityrd/aidr-cli": patch
---

Prompt protection on every connector whose host exposes a pre-model prompt hook (secrets block, personal data including TC Kimlik, IBAN and TR phone numbers warns, tenant DLP applies):

- Core: new `inspectUserPrompt` runner (config, tenant DLP, deadline, audit and the documented failure policy around `scanPrompt`) and `resolvePromptInspectionDeadlineMs` (`AIDR_PROMPT_INSPECTION_DEADLINE_MS`).
- Cursor: managed `beforeSubmitPrompt` hook (`continue: false` + `user_message` on block). VS Code Local agent hooks: managed `UserPromptSubmit` (`continue: false` + `stopReason` on block, `systemMessage` on warn). A hook that fails before reading its payload now also returns the prompt stop fields.
- Codex: `aidr-codex-hook` handles `UserPromptSubmit` (`decision: "block"` + reason, or `systemMessage` + `additionalContext`); `--health` reports `promptInspection`.
- OpenCode: `chat.message` hook blocks (text replaced, hook throws) or warns (toast + model notice via `experimental.chat.messages.transform`).
- OpenClaw: `before_agent_run` gate blocks; warnings reach the model through `before_prompt_build`.
- CLI: Codex setup guidance includes the `UserPromptSubmit` handler.
