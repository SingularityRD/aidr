---
"@singularityrd/aidr-core": minor
---

Runtime protection additions in the shared detection core.

- **DLP redaction of tool input:** a tenant `redact` rule now returns `allow` with `Verdict.transformedInput`, but only for connectors that set `ToolEvaluationContext.supportsInputRewrite`. The redacted input has to keep every parameter name and pass a clean rescan, or the call is denied. Other connectors still deny. Redacted allows are audited as `dlp_redacted` with the rule and label only.
- **Prompt protection:** a new `prompt_protection` config (secrets `block`, PII `warn` by default) and `scanPrompt()` combine the secret and PII detectors with tenant DLP. Results carry kinds and counts only.
- **Operator approvals:** an out-of-band approval store (`~/.singularity-aidr/approvals.json`, HMAC-signed, single-use, 15-minute default, bound to the tool and artifacts). `guardToolCall` records each `ask` and releases the identical retry once an operator approves it. The agent cannot approve its own block. New self-defense rule CLT-SELF-007.
- **Output DLP precision:** tool-output quarantine now fires only on high-precision secret and PII findings. A common-PII baseline follows the tenant's reserved `pii-<type>` rules and exceptions. Local mode can load an optional, unsigned `~/.singularity-aidr/dlp-policy.json`. An invalid file is skipped and shown as a degraded health check.
- **Shell argv inspection:** argv-array shell commands (`bash -lc`, `sh -c`, `env`, `cmd /c`, `pwsh -Command`/`-EncodedCommand`) are normalised and inspected. A command that is neither a string nor valid argv is denied as `malformed_command`.
- **Fail-closed initialisation helpers:** `initFailureCode()` and `formatInitFailureMessage()` for in-process connectors.
- **Posture:** the plugin scanner gains whole-file skill-scan rules (the AI-Infra-Guard T01-T09 taxonomy) and orphan bytecode detection. New posture event builders and an enrolled posture upload.
- The health URL probe uses the configured endpoint and makes no request when the URL leg is disabled.
