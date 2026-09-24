---
"@singularityrd/aidr-opencode": minor
---

- A DLP `redact` rule now rewrites `output.args` in place with the redacted input. If the rewrite fails, the call is blocked.
- If initialisation fails (integrity check, resource load, logger crash), the plugin still registers its tool gate and blocks every call with `AIDR failed to initialise: <code>`. Before, the host ran calls uninspected.
- An `ask` that an operator approves out of band releases the identical retry.
- `getSageVersion` is renamed to `getAidrVersion`.
