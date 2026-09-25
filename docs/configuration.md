# Configuration

Singularity AIDR reads configuration from `~/.singularity-aidr/config.json`.
Development builds apply defaults to omitted fields; signed commercial packages
have the artifact-trust requirement described below.

Source and development builds **enforce locally by default** against the shipped
threat rules without requiring an account or network connection for the local
heuristics. This does not mean they are offline by default: enabled URL, file,
and package checks can make outbound requests. Signed
commercial connector packages are intentionally stricter: before first start,
provision `config.json` with the independently delivered Ed25519 artifact
verification public key produced by the deployment flow. They fail closed when
that trust configuration, signed manifest, or a covered runtime file is missing
or changed. The release signing private key never belongs in this file.

For source/development builds, managed mode is an **opt-in additive layer**
(dashboard telemetry, signed intel packs, remote policy, seat enforcement).
Commercial builds force managed mode and signed artifact/entitlement checks.
Missing enrollment does not disable the local evaluator, but missing or invalid
artifact trust can stop commercial startup. Do not describe an unenrolled
commercial package as a ready managed installation.

## Example Config

This example is not a list of defaults. Provider-backed URL, file, and package
reputation checks are disabled by default; setting their `enabled` fields opts
in to those external data flows. See the tables below and [privacy data
flows](privacy.md) before enabling network features.

```json
{
  "mode": "local",
  "control_plane": {
    "enabled": true,
    "endpoint": "https://aidr.example.com",
    "timeout_seconds": 0.5,
    "send_audit_logs": false,
    "send_clean_verdicts": false,
    "sync_incidents": false,
    "grace_period_hours": 72,
    "redact_mode": "hash"
  },
  "policy": {
    "enabled": false,
    "filesystem": {
      "enabled": false,
      "allowed_write_roots": [],
      "deny_write_patterns": [],
      "outside_root_action": "require_approval"
    },
    "network": {
      "enabled": false,
      "allow_domains": [],
      "deny_domains": [],
      "deny_private_ips": true,
      "deny_action": "block",
      "outside_allow_action": "require_approval"
    },
    "shell": {
      "enabled": false,
      "deny_patterns": [],
      "deny_action": "block"
    }
  },
  "intel": {
    "enabled": false,
    "url_denylist_path": "~/.singularity-aidr/intel/url_denylist.txt"
  },
  "response": {
    "emit_incidents": true
  },
  "url_check": {
    "timeout_seconds": 5,
    "enabled": true
  },
  "file_check": {
    "timeout_seconds": 5,
    "enabled": true
  },
  "package_check": {
    "enabled": true,
    "timeout_seconds": 5
  },
  "amsi_check": {
    "enabled": true
  },
  "prompt_protection": {
    "secrets": "block",
    "pii": "warn"
  },
  "toxic_flow": {
    "enabled": true,
    "action": "auto",
    "window_minutes": 60
  },
  "version_check": {
    "enabled": false
  },
  "heuristics_enabled": true,
  "cache": {
    "enabled": true,
    "ttl_malicious_seconds": 3600,
    "ttl_clean_seconds": 86400,
    "path": "~/.singularity-aidr/cache.json"
  },
  "allowlist": {
    "path": "~/.singularity-aidr/allowlist.json"
  },
  "logging": {
    "enabled": true,
    "log_clean": false,
    "path": "~/.singularity-aidr/audit.jsonl",
    "max_bytes": 5242880,
    "max_files": 3
  },
  "sensitivity": "balanced",
  "disabled_threats": []
}
```

## Options

### `mode`

One of `"local"` or `"managed"`. Default: `"local"`.

- `local`: no managed control-plane enrollment or telemetry. Heuristics, policy,
  allowlist, cache, audit log, plugin scan, and integrity verification run
  in-process. This is the source/development default and requires no account;
  URL, file, and package reputation checks can still contact external services.
- `managed`: additionally enables the control plane (dashboard telemetry, agent
  seat enforcement), signed intel packs, remote policy and server-signed
  entitlements. Requires `control_plane.enabled` plus an `api_key` or
  `enrollment_token`, **and a deployed control plane**.

Commercial builds force `managed`; setting `local` does not bypass their
artifact trust or entitlement requirements. If a managed installation has no
valid enrollment credentials, managed-only features stay disabled and local
detection continues. An enrolled commercial installation with invalid signed
entitlement can instead return a blocking review verdict. The runtime reports
these states rather than presenting an unverified check as clean.

> **Deployment requirement:** no control plane is currently deployed, so `managed`
> cannot complete enrollment. Leave `mode` at its `local` default unless your
> deployment provides the `/v1/device-start`, `/v1/device-poll`, `/v1/enroll`,
> `/v1/ingest` and `/v1/revocations` endpoints.

### `auth`

| Field | Default | Description |
|-------|---------|-------------|
| `api_key` | (none) | API key for managed control plane services (telemetry + licensing). |
| `enrollment_token` | (none) | Optional one-time token for bootstrapping managed mode (support/fallback path). |

### `control_plane`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Allow control-plane integration in managed mode; local mode does not sync. A deployed endpoint is still required. |
| `endpoint` | empty | Base URL for a deployed control plane; no built-in deployment is provided. |
| `timeout_seconds` | `0.5` | Request timeout for control plane calls |
| `send_audit_logs` | `true` | In managed mode with enrollment, send runtime verdict events for the dashboard; local mode does not sync. |
| `send_clean_verdicts` | `false` | Also send `allow` events (higher volume) |
| `sync_incidents` | `false` | Also send incident events (when emitted) |
| `grace_period_hours` | `72` | Offline grace window for managed mode |
| `redact_mode` | `"hash"` | Remote minimisation: `"hash"` replaces summaries/artifacts with SHA-256 digests; `"full"` omits them; `"none"` is debug-only and still receives mandatory credential/query redaction. |

### `policy`

Local policy engine to enforce workspace boundaries and basic egress/command restrictions.

- Filesystem policy: allow write roots, deny write regexes, and outside-root action.
- Network policy: allow/deny domains, private IP blocking, and outside-allow action.
- Shell policy: deny regexes for commands (tool: `Bash`).
- MCP server and tool identifiers are exact and case-sensitive. A simple tool rule may use the legacy `server.tool` string when neither name contains a period. For dotted names, use the structured selector so the pair cannot collide:

  ```yaml
  condition:
    mcp_tool:
      server: "com.example"
      tool: "read.file"
  ```

  The compiled runtime selector is the JSON tuple `["com.example","read.file"]`; direct `allow_tools`, `deny_tools`, and `require_approval_tools` entries use that same JSON string. Do not lowercase MCP names: MCP tool names are case-sensitive.

### `intel`

Offline intel packs used by the policy layer.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Enable local intel packs |
| `url_denylist_path` | `~/.singularity-aidr/intel/url_denylist.txt` | Plaintext denylist (one URL or domain per line, `#` comments allowed) |

### `response`

| Field | Default | Description |
|-------|---------|-------------|
| `emit_incidents` | `true` | Emit incident entries (used by managed dashboards) |

### `url_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Explicit opt-in to send URLs without credentials, query, or fragment to the reputation provider. Withheld/disabled lookups require review; they are not reported clean. |
| `endpoint` | (built-in) | Optional override for the URL reputation endpoint (use this for self-hosted deployments) |
| `include_query_parameters` | `false` | Explicit opt-in to send URL query parameters. URLs containing queries are otherwise withheld and require review. User info and fragments are never sent. |
| `timeout_seconds` | `5` | Request timeout |

Example (Supabase Edge Function):

```json
{
  "url_check": {
    "endpoint": "https://YOUR_PROJECT.supabase.co/functions/v1/url-check"
  }
}
```

### `file_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Explicit opt-in to send file SHA-256 hashes to the reputation provider |
| `endpoint` | (built-in) | Optional override for the file reputation endpoint (use this for self-hosted deployments) |
| `timeout_seconds` | `5` | Request timeout |

Example (Supabase Edge Function):

```json
{
  "file_check": {
    "endpoint": "https://YOUR_PROJECT.supabase.co/functions/v1/file-check"
  }
}
```

### `package_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Explicit opt-in to send package names to npm/PyPI. Disabled package operations are marked unverified and require review. |
| `timeout_seconds` | `5` | Request timeout |

### `version_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `false` | Opt in to automatic startup/extension version checks. Sends version, runtime, OS/architecture, installation ID and, if enrolled, an Authorization bearer key to the update service. Direct API callers of `checkForUpdate()` are separate. |

### `amsi_check`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable AMSI (Antimalware Scan Interface) scanning on Windows and WSL |

When enabled, Singularity AIDR scans tool inputs (commands, file content, edits) through the Windows AMSI API before execution. This integrates with any installed antimalware provider (Windows Defender, etc.) to detect malicious content. AMSI scanning is automatically skipped on unsupported platforms (macOS, non-WSL Linux). See [AMSI Scanning](amsi-scanning.md) for details.

### `prompt_protection`

Inspects the user's prompt before the agent sends it to the model, on every connector whose
host exposes a pre-model prompt hook. All connectors share one engine (`scanPrompt` and the
`inspectUserPrompt` runner in `@singularityrd/aidr-core`), so the same prompt gets the same
decision everywhere.

| Field | Default | Description |
|-------|---------|-------------|
| `secrets` | `"block"` | Tokens, API keys, AWS keys, private keys, password assignments. `"block"`, `"warn"` or `"off"`. |
| `pii` | `"warn"` | Email addresses, formatted phone numbers and SSNs, Luhn-valid card numbers, Turkish ID numbers (TC Kimlik, checksum-validated), IBANs (mod-97) and TR/international phone numbers. `"block"`, `"warn"` or `"off"`. |

Per-connector support:

| Connector | Host hook | Block | Warn (personal data) | Audit `tool_name` | Deadline (host timeout) |
|-----------|-----------|-------|----------------------|-------------------|-------------------------|
| Claude Code | `UserPromptSubmit` (`hooks/hooks.json`) | `decision: "block"` + reason, shown to the user only | `systemMessage` to the user, `additionalContext` to the model | `UserPromptSubmit` | 7 s (10 s) |
| Cursor | `beforeSubmitPrompt` (managed `~/.cursor/hooks.json`, `failClosed: true`) | `continue: false` + `user_message` | Prompt is sent; notice in `user_message` (Cursor documents it for blocked prompts) and in the audit log. The event has no model-context field. | `beforeSubmitPrompt` | 20 s (30 s) |
| VS Code (Local agent hooks) | `UserPromptSubmit` (managed `.claude/settings.json`, needs `chat.useClaudeHooks`) | `continue: false` + `stopReason` | `systemMessage` to the user; the event has no documented model-context field | `UserPromptSubmit` | 20 s (30 s) |
| Codex CLI | `UserPromptSubmit` (register `aidr-codex-hook` under `[[hooks.UserPromptSubmit]]`, then trust it) | `decision: "block"` + non-empty reason; exit 2 + stderr on internal failure | `systemMessage` to the user, `additionalContext` to the model | `UserPromptSubmit` | 7 s (the documented `timeout = 10`) |
| OpenCode | `chat.message` plugin hook | Text parts replaced with the block notice, TUI toast, and the hook throws so the prompt is not stored or sent | Prompt is sent; TUI toast, and a notice attached to that message for the model (`experimental.chat.messages.transform`, not persisted) | `chat.message` | 10 s (in-process) |
| OpenClaw | `before_agent_run` gate (embedded and CLI runners) | `{ outcome: "block", message }`; OpenClaw keeps only the replacement text in the transcript | Notice prepended for the model through `before_prompt_build`, asking it to tell the user | `before_agent_run` | 10 s (15 s, fail-closed) |

Connector notes:

- **Cursor**: attachments listed in the `beforeSubmitPrompt` payload are not inspected, only
  the prompt text.
- **VS Code**: only the Local agent harness runs these hooks; Agent Host sessions (Copilot,
  Claude, Codex) use their own hook systems. The same `.claude/settings.json` entry is also
  honoured by Claude Code, which reads the same file.
- **Codex**: Codex runs `UserPromptSubmit` hooks without a matcher and fails open when the
  hook is untrusted, crashes, times out or returns malformed output. Register it next to the
  `PreToolUse` handler (see [packages/codex/README.md](../packages/codex/README.md)).
- **OpenCode**: only the user's own text parts are inspected; `synthetic` parts that OpenCode
  generates (for example the contents of an attached file) are not. If the plugin fails to
  initialise, prompts get the uninspected-prompt policy below.
- **OpenClaw**: `before_agent_run` is not an input gate for OpenClaw's Codex or Copilot
  harnesses, and a host without the hook ignores the registration. A non-bundled plugin
  needs `plugins.entries.aidr-openclaw.hooks.allowConversationAccess: true` for
  `before_agent_run` and `before_prompt_build`.
- Host acceptance: the Cursor, VS Code, Codex, OpenCode and OpenClaw paths are verified
  against the hosts' published hook contracts and by tests that drive the built connector
  bundles; no named real-host acceptance record exists yet
  (`deploy/native/interception-matrix.json`, `pre-prompt` rows).

Behaviour common to all connectors:

- `block` stops the prompt and shows the reason to the user. The reason names the kind of
  data found (for example "GitHub token"), never the value.
- `warn` sends the prompt, shows the user a notice where the host can display one and gives
  the model a context note not to repeat or copy the data where the host can deliver one
  (see the table).
- An operator-provisioned tenant DLP policy is also applied to the prompt and cannot be
  turned off here. A prompt cannot be rewritten, so any tenant action other than `allow`
  (including `redact`, and an uninspectable prompt) blocks.
- Audit entries (`tool_name` per the table) record the kinds and counts found, never the
  prompt.
- Failure policy: if the hook cannot inspect the prompt (unreadable input, an oversized
  payload — over 2 MiB on Claude Code, over 1 MiB on the Cursor/VS Code hook — or an internal
  error) it blocks only when `secrets` is `"block"`. With `"warn"` or `"off"` the prompt is
  sent with a visible "not inspected" notice. A provisioned tenant policy that cannot be
  verified always blocks. A hook process that is killed before it writes a response cannot
  block on Claude Code, VS Code or Codex (host limitations); the managed Cursor hook requests
  `failClosed: true` (host enforcement not yet verified), and OpenClaw's `before_agent_run`
  gate blocks on a thrown error or timeout. A hook that fails before it
  reads the payload (for example a failed artifact integrity check) answers with a
  combined deny-and-stop response on Cursor/VS Code, exit 2 on Codex, and a block on
  OpenClaw.
- Deadline: each connector answers before its host's hook timeout (see the table). A prompt
  it could not finish inspecting by then is blocked when `secrets` is `"block"` or a tenant
  DLP policy is provisioned; otherwise it is sent with a visible "not fully inspected"
  notice. Override with `AIDR_USER_PROMPT_SUBMIT_DEADLINE_MS` on Claude Code (an integer
  from 100 to 9000) and `AIDR_PROMPT_INSPECTION_DEADLINE_MS` on the other connectors (from
  100 to 28000 on Cursor/VS Code, 9000 on Codex, 13000 on OpenClaw, 60000 on OpenCode);
  anything else uses the default. Inspection cost is linear in the prompt size (a 1.5 MB
  prompt takes well under a second), and once a secret is found in `"block"` mode the scan
  stops there, so the block reports the first secret found rather than a full count.

#### DLP redaction of tool input

When a tenant DLP rule's action is `redact`, the outcome depends on whether the connector
can execute a rewritten tool input:

| Connector | Redact outcome |
|-----------|----------------|
| Claude Code | Allowed with the redacted input via PreToolUse `updatedInput` (no `permissionDecision`, so the user's normal permission flow still applies). Verified against Claude Code 2.1.282. |
| OpenCode | Allowed; `output.args` is rewritten in place before the tool runs. A failed rewrite blocks. |
| Codex | Denied. Codex 0.141.0 runs the original input when it rejects a rewrite, and a competing hook's rewrite can replace ours. |
| OpenClaw, Cursor / VS Code, CLI, SDK | Denied (no supported input-rewrite path). |

A redaction is only applied when the redacted input keeps every parameter name and a
rescan under the same policy finds nothing left to act on; otherwise the call is denied.
The audit log records the rule and label (`category: "dlp_redacted"`), not the values.

Because the rewritten input is executed, its replacement tokens are shell-inert words:
`REDACTED` for the default label token and `REDACTED_<TYPE>` otherwise (for example
`REDACTED_IP_ADDRESS` for a detector match, or `REDACTED_EMPLOYEE_ID` for an operator token
`[EMPLOYEE ID]`). Display placeholders such as `[REDACTED]` are shell globs
(`rm ./tmp/[REDACTED]` matches single-character file names), so they are used only where
the text is shown, never in a rewritten tool input. The rewritten input is also re-run
through the local threat rules; if it matches a rule the original did not (and that match
would not be allowed on its own), the call is denied as `dlp_redaction_unsafe`.

### `toxic_flow`

Session toxic-flow ("lethal trifecta") and behavioral chain detection. Every connector that
uses the shared evaluator (Claude Code, Cursor / VS Code, OpenClaw, OpenCode, Codex and the
MCP gateway) gets it. See [Toxic-flow detection](toxic-flow.md) for the model.

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Track private-data access, untrusted-content exposure and external communication per agent session. |
| `action` | `"auto"` | What a completed chain does: `"auto"` asks in `balanced`/`relaxed` and denies in `paranoid`; `"ask"`, `"deny"`, or `"monitor"` (allow, but record the finding in the audit log as `toxic_flow_monitor`). |
| `window_minutes` | `60` | How long a step keeps counting toward a chain (1-1440). Also the lifetime of a session record. |
| `bulk_sensitive_threshold` | `5` | Distinct sensitive files / credential stores in the window that trigger `bulk_sensitive_access` (2-64). |
| `trusted_domains` | `[]` | Extra destination domains (suffix match) for which a plain request is not external communication. Package registries and source hosts are built in. A request that carries a payload (body, upload, piped data) still counts. |
| `trusted_mcp_servers` | `[]` | MCP server ids whose output is not untrusted content. `policy.mcp.allow_servers` is also honoured. |
| `trusted_git_remotes` | `["origin"]` | Git remote names a push to is not external communication. A push to a URL or any other remote counts. |

- Chains: `lethal_trifecta` (`AIDR-FLOW-001`), `exfil_chain` (`AIDR-FLOW-002`),
  `injection_to_action` (`AIDR-FLOW-003`), `bulk_sensitive_access` (`AIDR-FLOW-004`). The verdict
  category is `toxic_flow` and the reason names the chain, the earlier steps (tool plus a redacted
  target summary and age) and this call.
- An `ask` is a block pending out-of-band approval like any other (`aidr pending` /
  `aidr approve <actionId>` on soft-gated connectors, the native dialog in Claude Code).
- Calls the operator allowlisted are recorded but never escalated.
- Failure policy: a state file that cannot be read or written is a skipped signal; the call is
  evaluated by every other layer and an `allow` is marked `toxic_flow_unavailable` in the audit
  log (never a clean result). A state file that fails its integrity check is treated as
  tampering: the session is assumed to have exercised all three capabilities for the rest of
  the window, so its next egress needs approval.

### `secure_code`

Advisory checks on the code an agent writes (TLS verification disabled, SQL/command
injection, `eval` on request input, `chmod 777`, wildcard CORS with credentials, exposed debug
servers, disabled CSRF, weak crypto, hard-coded credentials). Only the lines a call adds are
inspected, gated by file language. See [Secure-code guardrails](secure-code-guardrails.md).

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Turn the guardrails on or off |
| `action` | `"warn"` | `"warn"`: the write goes through with a notice and an audit entry; `"ask"`: the write is held for review |

### `ai_supply_chain`

Trusted model sources for the AI model supply-chain rules (unsafe model loading and unvetted
model downloads). These lists add to the shipped `allowlists/model-sources/*.yaml`. See
[AI model supply-chain safety](ai-supply-chain-safety.md).

| Field | Default | Description |
|-------|---------|-------------|
| `trusted_model_orgs` | `[]` | Extra Hugging Face organisations whose repositories are trusted (exact, case-insensitive) |
| `trusted_model_hosts` | `[]` | Extra HTTPS hosts trusted for direct model-weight downloads (suffix match on a dot boundary) |

### `heuristics_enabled`

Boolean, default `true`. Set to `false` to disable all local pattern matching.

### `cache`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable verdict caching |
| `ttl_malicious_seconds` | `3600` | Cache TTL for malicious verdicts (1 hour) |
| `ttl_clean_seconds` | `86400` | Cache TTL for clean verdicts (24 hours) |
| `path` | `~/.singularity-aidr/cache.json` | Cache file location (must remain under `~/.singularity-aidr`) |

### `allowlist`

| Field | Default | Description |
|-------|---------|-------------|
| `path` | `~/.singularity-aidr/allowlist.json` | Allowlist file location (must remain under `~/.singularity-aidr`) |

The allowlist stores user overrides for false positives. When Singularity AIDR returns an `ask` verdict and the user proceeds, the artifact can be allowlisted for future sessions. Manage it with `aidr allowlist list`, `aidr allowlist add <url|command|file_path> <value>` (operator-only, interactive confirmation) and `aidr allowlist remove <type> <value>`; commands are stored as a SHA-256 of the command text, so `list` shows the hash and `remove` accepts either the text or a unique hash prefix.

### `logging`

| Field | Default | Description |
|-------|---------|-------------|
| `enabled` | `true` | Enable JSONL audit logging |
| `log_clean` | `false` | Also log `allow` verdicts |
| `path` | `~/.singularity-aidr/audit.jsonl` | Log file location (must remain under `~/.singularity-aidr`) |
| `max_bytes` | `5242880` | Rotate log when it exceeds this size |
| `max_files` | `3` | Number of rotated backups to keep |

Relative `path` values are resolved under `~/.singularity-aidr`. Paths that escape that directory (or resolve to the `~/.singularity-aidr` directory itself) are ignored and fall back to defaults.

Audit entries are scrubbed before they are written. The regular logger rotates
and expires records according to the values above. For signed/tamper-evident
response evidence, use `ResponseAuditor` with `{ signEntries: true }`; see
[`docs/privacy.md`](privacy.md#local-audit-retention-and-deletion-semantics)
for checkpoint, deletion-manifest and external-archive requirements.

### `sensitivity`

One of `"paranoid"`, `"balanced"`, or `"relaxed"`. Default: `"balanced"`. See [How It Works](how-it-works.md#sensitivity-presets).

In `paranoid` mode, `ask` verdicts are promoted to `deny` on OpenClaw, OpenCode and Codex, and a deny can never be released by an operator approval. Those connectors cannot open a host-native approval dialog, so an `ask` verdict stays blocked until a human approves it out of band with `aidr approve` (see [Operator approvals](#operator-approvals)); the agent cannot approve its own action. Claude Code supports a host approval UI. Cursor `preToolUse` does not support an enforceable `ask` response, so its adapter maps `ask` to an explicit deny. See the [OpenClaw](../packages/openclaw/README.md#approving-a-flagged-action) and [OpenCode](../packages/opencode/README.md#approval-flow) connector notes.

### `operator_approvals`

`key_storage`: `"os-vault"` (default) or `"file"`. Where the operator approval
key and the single-use ledger live. With `"os-vault"` and no OS credential vault,
operator approvals are disabled and asks stay blocked; `"file"` is an explicit,
reduced-protection opt-in that `aidr doctor` warns about. Overridden by
`AIDR_OPERATOR_APPROVAL_KEY_STORAGE`. See [Key custody](#key-custody).

`dashboard_only`: `false` (default) or `true`. **Managed mode only.** When `true`,
an `ask` can be released only by a [dashboard approval](#managed-mode-dashboard-approvals):
the guard does not record or consume `aidr approve` approvals, and Claude Code and
the VS Code / Cursor hooks block the call instead of opening their native
confirmation dialog. Ignored in local mode.

### `disabled_threats`

Array of threat IDs to skip during heuristic matching. Default: `[]`.

Use this to permanently suppress specific rules that don't apply to your workflow. Threat IDs are listed in the YAML files under `threats/` (e.g. `CLT-CMD-001`).

```json
{
  "disabled_threats": ["CLT-CMD-001", "CLT-FILE-003"]
}
```

## DLP policy

DLP (data loss prevention) evaluates the serialized tool input against a
`DlpPolicySchema` document (labels, keyword/regex rules with `block`, `ask` or
`redact` actions, and time-bounded exceptions). Where the policy comes from
depends on [`mode`](#mode):

| Mode | Source | Signature |
|------|--------|-----------|
| `managed` | `~/.singularity-aidr/detectors/<runtime>.json`, issued by the control plane | Ed25519-signed and bound to the verified managed entitlement; an unsigned or tampered bundle blocks tool calls |
| `local` | `~/.singularity-aidr/dlp-policy.json` (override with `AIDR_DLP_POLICY_PATH`) | Unsigned; written by the machine's own operator |

Local mode behaviour:

- **Missing file** — local DLP is off. Nothing else changes.
- **Valid file** — the policy is enforced on every connector exactly like a
  managed policy (`tenantId` in the file is only a label for rule and exception
  ownership). A `redact` rule behaves exactly as it does under a managed policy
  (see [DLP redaction of tool input](#dlp-redaction-of-tool-input)): Claude Code and
  OpenCode run the redacted input, while connectors without a supported
  input-rewrite path (Codex, OpenClaw, Cursor / VS Code, CLI, SDK) enforce it as a
  deny. The mode does not change this; only the connector's rewrite support does.
- **Invalid file** (unreadable, not JSON, or failing schema validation) — the
  policy is skipped, a single warning is written to stderr, and the extended
  health check `local_dlp_policy` (for example
  `aidr-claude-code health --check local_dlp_policy --json`) reports `degraded`
  with `enforced: false`. It is never reported as an enforced, clean policy. Error
  messages list only the failing field paths, never policy values.
- The unsigned file is ignored in `managed` mode; managed installs accept DLP
  policy only from signed bundles. If a signed bundle is installed in local
  mode, it is still validated and refused (tool calls are blocked) rather than
  silently replaced by the local file.

Minimal example:

```json
{
  "version": 1,
  "tenantId": "local",
  "labels": [
    { "id": "internal", "tenantId": "local", "name": "Internal", "sensitivity": "restricted" }
  ],
  "rules": [
    {
      "id": "project-codename",
      "tenantId": "local",
      "labelId": "internal",
      "name": "Unreleased project codename",
      "action": "block",
      "directions": ["input"],
      "matchers": [{ "type": "keyword", "values": ["PROJECT-ORION"] }]
    }
  ]
}
```

### Built-in common-PII baseline

While any DLP policy is active (managed or local), tool input is also checked
for six built-in PII types (`COMMON_PII_TYPES` in `packages/core/src/pii-baseline.ts`):

| Type | Reserved rule id | What is matched |
|------|------------------|-----------------|
| SSN | `pii-ssn` | Dashed `123-45-6789` form |
| Payment card | `pii-credit_card` | Luhn-valid numbers from a known card network |
| Email | `pii-email` | Email addresses |
| Phone | `pii-phone` | `+` international prefix or separated NANP `555-123-4567` layout |
| TC Kimlik | `pii-tc_kimlik` | Turkish national ID numbers from the AIDR Privacy rules (checksum-validated) |
| IBAN | `pii-iban` | IBANs from the AIDR Privacy rules (mod-97 checksum-validated) |

Bare digit runs such as epoch timestamps, order ids, IP addresses and hashes are
not treated as PII.

Each type is governed by its reserved rule id, so the policy stays in control:

- No rule with that id: the baseline blocks the call.
- A rule with that id and `"enabled": false`, or whose `directions` omit
  `"input"`: the baseline is off for that type.
- A rule with that id: its `action` applies to the baseline finding (`ask`
  asks for out-of-band approval; `block` and `redact` deny, because the baseline
  itself never rewrites input; a baseline deny also takes precedence over a
  tenant-rule redaction of the same call). Its matchers also run as an ordinary
  rule, extending the baseline.
- An active exception whose `ruleId` is the reserved id suppresses matches:
  `scope: "rule"` for every match, `scope: "match"` for one value (fingerprint
  `sha256(tenantId + "\0" + ruleId + "\0" + value)`), `scope: "content"` for one
  exact serialized payload (`sha256(tenantId + "\0" + content)`).

For example, to allow email addresses while keeping every other baseline type
blocking, add this rule:

```json
{
  "id": "pii-email",
  "tenantId": "local",
  "labelId": "internal",
  "name": "Email addresses (allowed)",
  "enabled": false,
  "action": "block",
  "matchers": [{ "type": "keyword", "values": ["unused"] }]
}
```

### Tool-output quarantine

Independently of DLP policy, connectors that inspect tool output quarantine a
result only for high-precision findings: credentials (AWS keys, PEM private
keys with key material, GitHub/GitLab/Slack/npm/Hugging Face tokens, OpenAI and
Anthropic keys, verified JWTs, bearer tokens and generated-looking values
assigned to secret-named keys), Luhn-valid payment cards, and SSNs that are
explicitly labelled. Contact data such as `git log` author emails is not a
quarantine reason.

## Operator approvals

In managed mode an `ask` can also be approved out of band by an owner or admin
in the dashboard (AAL2, signed single-use token verified by the connector); see
[Dashboard approvals](control-plane.md#dashboard-approvals-managed-mode) and
[contracts/dashboard-approvals.md](contracts/dashboard-approvals.md). The
control plane needs the Edge secret `AIDR_APPROVAL_SIGNING_WRAP_KEY_B64` for it.

OpenClaw, OpenCode and Codex cannot show a host-native confirmation dialog, so
their `ask` verdicts go through a file-backed, operator-only approval channel:

This is the approval channel in **local mode**. In managed mode an `ask` is also
sent to the AIDR dashboard for an administrator to approve — see
[Managed mode: dashboard approvals](#managed-mode-dashboard-approvals).

1. When a connector blocks an `ask`, it records a **pending ask** in
   `~/.singularity-aidr/approvals.json`: the `actionId` (a SHA-256 of tool, input
   and session), a digest of the exact artifact set, the tool, the connector, a
   redacted summary and a one-hour expiry. Raw artifact values and the session id
   are not stored — only digests and redacted previews. Every text field the
   agent could influence is stored with C0/C1 control characters and Unicode
   bidi/format controls (U+200B–U+200F, U+202A–U+202E, U+2066–U+2069, U+FEFF, …)
   rendered as visible escapes (`\x1b`, `‮`), and a cut field ends with
   `…(truncated)`. The record also keeps the total artifact count, so
   `aidr pending` says "showing 16 of 40 (truncated)" when a call had more
   artifacts than are previewed. The CLI escapes again at display time.
2. The operator reviews open asks with `aidr pending` and approves one with
   `aidr approve <actionId>`. The CLI prints what will be released and requires
   the operator to type `approve` in an interactive terminal. For automation it
   accepts `--yes` only when `AIDR_OPERATOR_NONINTERACTIVE=1` is also set.
3. The approval records `{actionId, artifactDigest, tool, approvedAt, expiresAt,
   approver}`. It expires after 15 minutes (`--ttl <minutes>`, 1–1440) and is
   **single-use**: the first retry of the identical call (same tool, same
   artifacts, same session) spends it, and later retries are blocked again. A
   different command, tool or session is never released by it, and a `deny` —
   including a paranoid-promoted `ask` — is never released at all.
4. `aidr approve <actionId> --permit-allowlist` additionally lets the agent's
   `aidr_allowlist_add` tool turn each approved artifact into one permanent
   allowlist entry. Without that flag the agent cannot allowlist anything.

| CLI | Purpose |
|-----|---------|
| `aidr pending [--json]` | List asks waiting for a decision (and say so when approvals are disabled) |
| `aidr approve <actionId> [--ttl <min>] [--permit-allowlist] [--yes]` | Approve one retry (operator only) |
| `aidr allowlist list\|add\|remove` | Manage permanent exceptions (`add` is operator only) |
| `aidr audit tail [-n N] [--json]` | Show recent audit entries, re-redacted |
| `aidr audit export [--since 24h\|ISO] [--format jsonl\|csv] [-o file]` | Export redacted entries, including rotated files; the session id is replaced by a digest and CSV cells are neutralised against spreadsheet formulas |
| `aidr doctor [--json]` | Check hosts, hook registration, rule count, core version, mode, DLP policy, the approval store and key custody, and the last verdict; exits non-zero on problems |

### Key custody

Every pending ask and approval carries an HMAC-SHA256 under a per-install key.
Where that key lives is set by `operator_approvals.key_storage`:

```json
{
  "operator_approvals": { "key_storage": "os-vault" }
}
```

| `key_storage` | Key and single-use ledger | Without it |
|---------------|---------------------------|------------|
| `"os-vault"` (default) | OS credential vault only — Windows DPAPI, macOS Keychain, or libsecret `secret-tool` — under the ids `aidr-operator-approval-key` and `aidr-operator-approval-ledger` | **Approvals are disabled.** Asks stay blocked (fail closed), the block message tells the user the ask could not be recorded, and `aidr pending`, `aidr approve` and `aidr doctor` say why. There is no silent fallback to a file. |
| `"file"` (explicit opt-in) | Owner-only files `~/.singularity-aidr/operator-approval.key` and `operator-approval-ledger.json` | — |

`AIDR_OPERATOR_APPROVAL_KEY_STORAGE=os-vault|file` overrides the config.
Anything other than an explicit `file` means the vault; `AIDR_SECRET_STORE=file-acl`
does **not** opt approvals into the key file — it only means "no vault", which
disables approvals. `aidr doctor` warns loudly whenever the file storage is in use:
any process running as the same user — including a compromised agent with shell
access — can read a key file and forge approvals.

Under the vault storage the provider never reads a key file, whatever
`operator-approval-key.json` (an informational record of where the key lives)
says: planting `{"store":"file"}` plus a key of one's choosing does not create a
signing key. A key file left over from an earlier file-storage install is removed
when the vault key is created.

A hand-edited record (later expiry, different digest, reset use counter) or one
signed with another key fails verification and is refused. The store is written
atomically with mode `0600` under an exclusive lock, bounded to 200 pending asks
and 200 approvals, and a symlinked or oversized store is not used. Any store, key
or ledger failure keeps the call blocked. Rotating the key (deleting the vault
entry or key file) invalidates every outstanding record.

### Single use against rollback

The HMAC proves that a record was written by a key holder, not that it is the
latest one: restoring an earlier copy of the whole `approvals.json` (taken before
an approval was spent) brings back a validly signed, unspent approval. Single use
is therefore anchored outside the store: every spend is written to the
**consumption ledger** (`aidr-operator-approval-ledger` in the same OS vault as
the key), read back to confirm it persisted, and checked on every consume. A
restored store then yields `already_used`. Allowlist grants
(`--permit-allowlist`) are spent through the same ledger. If the ledger cannot be
read or written — no vault, a corrupt entry, a write that does not persist, or
more than 1024 unexpired spends — nothing is released and `aidr approve` refuses
to create approvals that could not be spent. Entries expire with the approval they
record. Under the `file` storage the ledger is a file in the same directory, so it
stops a rollback of `approvals.json` alone but not a rollback of both files; on
Windows the DPAPI-sealed vault entry is itself a file under
`~/.singularity-aidr/secrets`, so sealing prevents forging it but not restoring an
older copy of it.

### Self-defense rules

The approval channel is protected by hard-deny rules (never `ask`, which would
hand the agent an actionId to have approved):

- `CLT-SELF-007` — an agent command that runs `aidr approve`, `aidr pending`,
  `aidr allowlist add`, or sets `AIDR_OPERATOR_NONINTERACTIVE`.
- `CLT-SELF-008` — any agent reference to the AIDR state directory
  `.singularity-aidr`, in a shell command, a file-tool path, a Write/Edit body or
  an MCP argument.
- `CLT-SELF-009` — the vault entries and key/ledger file names
  (`singularity-aidr-cli`, `aidr-operator-approval-*`, `operator-approval*.key|json`).

They match the **shell-normalized** view of the text (`match_on:
command_normalized`, `file_path_normalized`, `content_normalized`), in which
quotes and backslash escapes are removed (including nested ones), `$'…'` is
decoded, `$(which aidr)` / `` `command -v aidr` `` become `aidr`, variables
assigned in the same command are substituted, literal string concatenations
(`'/.singular' + 'ity-aidr'`) are joined, and globs that would expand to the
state directory (`~/.singul*`, `.s?ngularity-aidr`, `~/.{singularity-aidr,x}`,
`~/.*`) are resolved to its name. So `aidr 'approve' <id>`, `"aidr" approve`,
`aidr ap\prove`, `$(which aidr) approve`, `npx @singularityrd/aidr-cli approve`,
`script -qc "aidr 'approve' <id>" /dev/null`, `expect`/`unbuffer` wrappers,
`pty.spawn(['aidr','approve',…])`, `cat ~/.singularity-aidr/*.key` and
`cd ~ && cat .s*/operator-approval.key` are all denied. AIDR's read-only
diagnostics — `aidr doctor`, `aidr status`, `aidr audit tail`,
`aidr allowlist list` — are not matched; there is no agent-facing exception for
reading the directory itself. Because these rules deny any mention of
`.singularity-aidr`, an agent editing files or docs that contain that path (for
example, while developing AIDR itself) is blocked too; that is deliberate.

### Residual risk

This channel is designed to stop a prompt-injected agent from approving its own
block through the tools it is given. It is **not** a boundary against code that
already runs as the same OS user with unrestricted shell access. The normalized
view cannot see a path computed at run time (assembled by arithmetic, decoded
from base64, fetched, or read from another file), and such code can:

- query the OS vault as that user — macOS Keychain and libsecret release an item
  to any process of the user once the keychain is unlocked, unless the item's
  access control requires a per-access prompt;
- mint a valid record with the key it read, or write the ledger;
- allocate a pseudo-terminal to satisfy the TTY check, or set
  `AIDR_OPERATOR_NONINTERACTIVE`.

The mitigations are layered, not absolute: vault custody keeps the key out of
files the agent's file tools can read; agent tool calls normally have no TTY; the
self-defense rules above deny the direct and obfuscated routes; and every release
is written to the audit log as a user override.

**Recommended deployment:** keep `key_storage` at `"os-vault"` and configure the
vault item to prompt on every access (Keychain Access → the
`singularity-aidr-cli` item → Access Control → "Ask for Keychain password"; each
recorded ask and each approval then shows a prompt), or run the agent under a
separate OS account from the operator, so its shell cannot open the operator's
vault at all. In managed mode, [dashboard approvals](#managed-mode-dashboard-approvals)
with `operator_approvals.dashboard_only: true` remove the local same-user approval
path entirely.

### Managed mode: dashboard approvals

In **local mode** nothing changes: the only approval channel is the operator CLI
described above, and no approval ever leaves the machine.

In **managed mode** (enrolled: an API key and an active, ed25519-verified
entitlement), every `ask` from every connector — OpenClaw, OpenCode, Codex, Claude
Code and the Cursor / VS Code hook — is additionally submitted to the AIDR
dashboard, where an administrator can approve or deny it:

1. **Request.** The connector sends `POST {endpoint}/v1/approval-requests` with the
   installation id, connector, `actionId`, `sha256:`-prefixed artifact-set digest,
   tool, matched threat ids, a redacted and control-character-escaped summary (at
   most 512 characters; raw artifact values are never sent) and an expiry of
   25 minutes. The request is idempotent on tenant, installation and `actionId`.
   The call stays blocked, and the block reason tells the user
   `Approval requested in the AIDR dashboard: <request_id>`. The request id is
   remembered in `~/.singularity-aidr/dashboard-approval-requests.json`, so the
   next hook process (Claude Code and Codex start one per call) finds it.
2. **Decision.** An owner or admin approves it in the dashboard (AAL2 / MFA
   session). The control plane signs an approval token with the tenant's Ed25519
   approval key, which never leaves the server.
3. **Release.** On the identical retry the connector polls the request. An
   approved token is released only if **all** of these hold, otherwise the call
   stays blocked and the reason is logged and audited:
   - the Ed25519 signature verifies under a key whose `key_id` is listed in
     `approval_public_keys` of the **signed entitlement** (an unknown key id, or
     an entitlement without approval keys, is a rejection — the keys are never
     read from config, the network response or any unsigned file);
   - `tenant_id`, installation id, `actionId`, artifact digest and tool match the
     pending ask exactly, and the decision is `approve`;
   - it is unexpired, was issued no more than 15 minutes before it expires, and
     was not issued in the future;
   - its nonce has not been spent. The nonce is spent in the same consumption
     ledger as operator approvals (OS vault by default, read back after writing),
     so one approval releases **exactly one** call, across processes and even if
     `dashboard-approval-requests.json` or `approvals.json` is rolled back. With
     no usable ledger nothing is released.

   The release is audited twice: a `runtime_verdict` with `source:
   "dashboard_approval"` and `user_override: true`, and `dashboard_approval`
   entries for each step (`requested`, `denied`, `expired`, `rejected` with its
   reason, `consumed` with the approver id). Tokens and the API key are never
   logged.

Every control-plane call on the hook path is bounded (1.5 s each, 3 s in total),
so a slow or unreachable control plane cannot hold the hook past its deadline; a
failure keeps the call blocked and says the request could not be sent.

**Why this is stronger than the CLI channel.** The approver is a different,
authenticated human on a different device, not whoever runs as the agent's OS
user. The only thing on the endpoint that can make a token valid is the
control plane's signing key, which the endpoint does not have: the verification
keys arrive inside the entitlement the licensing key signs, so neither the agent
nor any same-user process can mint an approval, re-bind one to another call, or
replay one. What remains local is *which* request to poll, and tampering with that
only ever results in a block.

By default the local operator channel keeps working alongside the dashboard (and
Claude Code / VS Code keep their native dialog). Set
`operator_approvals.dashboard_only: true` to make the dashboard the **only**
channel: `aidr approve` approvals are ignored, native dialogs become blocks, and if
the dashboard is unavailable (not enrolled, no signed entitlement, control plane
unreachable) the call stays blocked with the reason in the message.

## Files on Disk

| Path | Purpose |
|------|---------|
| `~/.singularity-aidr/config.json` | Configuration |
| `~/.singularity-aidr/threats/` | Custom threat rules (YAML, optional) |
| `~/.singularity-aidr/cache.json` | Verdict cache |
| `~/.singularity-aidr/allowlist.json` | User allowlist |
| `~/.singularity-aidr/audit.jsonl` | Audit log |
| `~/.singularity-aidr/approvals.json` | Operator approval store: pending asks and `aidr approve` approvals (HMAC-protected, `0600`) |
| `~/.singularity-aidr/operator-approval.key` | Approval HMAC key, only with the explicit `operator_approvals.key_storage: "file"` opt-in (`0600`) |
| `~/.singularity-aidr/operator-approval-ledger.json` | Single-use consumption ledger, only with the `file` key storage (`0600`); otherwise it lives in the OS vault |
| `~/.singularity-aidr/operator-approval-key.json` | Informational record of where the approval key lives; never makes AIDR read a key file |
| `~/.singularity-aidr/dashboard-approval-requests.json` | Managed mode: which dashboard approval request to poll for which pending ask (`0600`); grants nothing by itself |
| `~/.singularity-aidr/session-flow/` | Per-session toxic-flow records (`<digest>.json`, HMAC-protected, `0600`, pruned after `toxic_flow.window_minutes`) and their per-install key `.flow-key` (`0600`) |
| `~/.singularity-aidr/installation-id` | Random UUID identifying this installation |
| `~/.singularity-aidr/managed.json` | Managed-mode state (seat status, backoff windows) |
| `~/.singularity-aidr/pending-approvals.json` | Pending approval state (transient, managed by PreToolUse hook) |
| `~/.singularity-aidr/consumed-approvals.json` | Consumed approvals for MCP allowlist flow (10-min TTL entries) |
| `~/.singularity-aidr/intel/` | Optional offline intel packs |
| `~/.singularity-aidr/dlp-policy.json` | Optional unsigned DLP policy (local mode only; override with `AIDR_DLP_POLICY_PATH`) |
| `~/.singularity-aidr/detectors/<runtime>.json` | Signed tenant detector bundle (managed mode) |
