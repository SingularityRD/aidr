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

Claude Code only (`UserPromptSubmit` hook, `packages/claude-code/dist/user-prompt-submit.cjs`).
Inspects the user's prompt before Claude Code sends it to the model.

| Field | Default | Description |
|-------|---------|-------------|
| `secrets` | `"block"` | Tokens, API keys, AWS keys, private keys, password assignments. `"block"`, `"warn"` or `"off"`. |
| `pii` | `"warn"` | Email addresses, formatted phone numbers and SSNs, Luhn-valid card numbers. `"block"`, `"warn"` or `"off"`. |

- `block` stops the prompt; Claude Code shows the reason to the user only. The reason names
  the kind of data found (for example "GitHub token"), never the value.
- `warn` sends the prompt, shows the user a notice and gives the model a context note not to
  repeat or copy the data.
- An operator-provisioned tenant DLP policy is also applied to the prompt and cannot be
  turned off here. A prompt cannot be rewritten, so any tenant action other than `allow`
  (including `redact`, and an uninspectable prompt) blocks.
- Audit entries (`tool_name: "UserPromptSubmit"`) record the kinds and counts found, never
  the prompt.
- Failure policy: if the hook cannot inspect the prompt (unreadable or oversized input over
  2 MiB, or an internal error) it blocks only when `secrets` is `"block"`. With `"warn"` or
  `"off"` the prompt is sent with a visible "not inspected" notice. A provisioned tenant
  policy that cannot be verified always blocks. A hook process that is killed before it
  writes a response cannot block; that is a Claude Code host limitation.

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

The allowlist stores user overrides for false positives. When Singularity AIDR returns an `ask` verdict and the user proceeds, the artifact can be allowlisted for future sessions.

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

In `paranoid` mode, `ask` verdicts are promoted to `deny` on OpenClaw and OpenCode. Those plugins cannot open a host-native approval dialog, so an `ask` verdict stays blocked until a human approves out of band; the agent cannot approve its own action. Claude Code supports a host approval UI. Cursor `preToolUse` does not support an enforceable `ask` response, so its adapter maps `ask` to an explicit deny. See the [OpenClaw](../packages/openclaw/README.md#approving-a-flagged-action) and [OpenCode](../packages/opencode/README.md#approval-flow) connector notes.

### `disabled_threats`

Array of threat IDs to skip during heuristic matching. Default: `[]`.

Use this to permanently suppress specific rules that don't apply to your workflow. Threat IDs are listed in the YAML files under `threats/` (e.g. `CLT-CMD-001`).

```json
{
  "disabled_threats": ["CLT-CMD-001", "CLT-FILE-003"]
}
```

## Files on Disk

| Path | Purpose |
|------|---------|
| `~/.singularity-aidr/config.json` | Configuration |
| `~/.singularity-aidr/threats/` | Custom threat rules (YAML, optional) |
| `~/.singularity-aidr/cache.json` | Verdict cache |
| `~/.singularity-aidr/allowlist.json` | User allowlist |
| `~/.singularity-aidr/audit.jsonl` | Audit log |
| `~/.singularity-aidr/installation-id` | Random UUID identifying this installation |
| `~/.singularity-aidr/managed.json` | Managed-mode state (seat status, backoff windows) |
| `~/.singularity-aidr/pending-approvals.json` | Pending approval state (transient, managed by PreToolUse hook) |
| `~/.singularity-aidr/consumed-approvals.json` | Consumed approvals for MCP allowlist flow (10-min TTL entries) |
| `~/.singularity-aidr/intel/` | Optional offline intel packs |
