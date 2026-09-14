# Codex CLI Hooks — Verified Protocol Reference for **0.141.0**

Scope: `codex-cli 0.141.0` (verified installed binary at
`%LOCALAPPDATA%\Programs\OpenAI\Codex\bin\codex.exe`, 313,418,032 bytes).
Primary evidence is pinned to the release tag **`rust-v0.141.0`** in `openai/codex`,
plus the generated JSON Schemas shipped at that tag, plus direct string/config probes
of the installed binary.

## 0. Read this first — three things that will silently break a security hook

1. **`PreToolUse` in Codex 0.141.0 has no fail-closed path.** Every failure mode
   (timeout, crash, unparseable output, unsupported field, unknown exit code,
   untrusted hook) results in the tool call **proceeding**. Only an explicit,
   well-formed `deny` or `exit 2` **with non-empty stderr** blocks.
2. **An untrusted or modified hook is not registered at all** — it is skipped
   silently apart from a startup warning. Untrusted == not enforced == fail-open.
3. **`permissionDecision: "ask"` is unsupported** and fails open, as does a bare
   `permissionDecision: "allow"`. A three-decision `allow|deny|ask` engine cannot be
   mapped 1:1 onto Codex `PreToolUse`.

Also: the published docs at `learn.chatgpt.com/docs/hooks` describe a **newer build
than 0.141.0**. `SessionEnd`, `Interrupt`, `async`, `additionalContextLimit`, and the
`hooks.json` top-level `description` field are all documented there but **do not work
in 0.141.0** (details in §2, §5, §8).

---

## 1. Configuration schema — VERIFIED

There is **no** `[[hooks]]` table with an `event = "..."` key. Hooks are nested by
event name. Two equivalent forms are discovered per active config layer:

- `hooks.json` (JSON, everything wrapped in a top-level `"hooks"` object)
- inline `[hooks]` tables in `config.toml`

Locations: `~/.codex/hooks.json`, `~/.codex/config.toml`, `<repo>/.codex/hooks.json`,
`<repo>/.codex/config.toml`. If a layer has **both**, Codex merges them and warns at
startup. Multiple sources all load; higher-precedence layers do not replace lower ones.

Source: `codex-rs/config/src/hook_config.rs`, `codex-rs/hooks/src/engine/discovery.rs`
at tag `rust-v0.141.0`.

### 1.1 `~/.codex/config.toml` (inline form)

```toml
# Optional: hooks are ON by default in 0.141.0 ("hooks  stable  true").
# [features]
# hooks = false          # canonical key
# codex_hooks = false    # deprecated alias — VERIFIED still works in 0.141.0

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "/usr/bin/python3 /abs/path/pre_tool_use_policy.py"
timeout = 10
statusMessage = "AIDR: checking Bash command"
# commandWindows = 'py -3 C:\abs\path\pre_tool_use_policy.py'   # Windows-only override
```

### 1.2 `~/.codex/hooks.json` (JSON form)

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "^Bash$",
        "hooks": [
          {
            "type": "command",
            "command": "/usr/bin/python3 /abs/path/pre_tool_use_policy.py",
            "timeout": 10,
            "statusMessage": "AIDR: checking Bash command"
          }
        ]
      }
    ]
  }
}
```

**Trap:** `HooksFile` is declared `#[serde(deny_unknown_fields)]` and has exactly one
field, `hooks`. A top-level `"description"` key — which the current official docs
advertise — makes the **whole file fail to parse** in 0.141.0. The failure is reported
only as a warning (`failed to parse hooks config <path>: ...`) and the hooks are simply
not loaded. Do not put `description` in `hooks.json` on 0.141.0.

### 1.3 Event table names (exact, case-sensitive)

`PreToolUse`, `PermissionRequest`, `PostToolUse`, `PreCompact`, `PostCompact`,
`SessionStart`, `UserPromptSubmit`, `SubagentStart`, `SubagentStop`, `Stop`

### 1.4 Matcher group and handler fields

Matcher group: `matcher` (optional regex string), `hooks` (array of handlers).

Command handler (`type = "command"`):

| TOML / JSON key | Alias | Type | Default | Notes |
| --- | --- | --- | --- | --- |
| `type` | — | `"command"` | required | internally tagged enum tag |
| `command` | — | string | required | run via shell; empty command is skipped |
| `commandWindows` | `command_windows` | string | — | Windows-only override |
| `timeout` | — | u64 seconds | `600` | clamped to minimum `1` |
| `async` | — | bool | `false` | **0.141.0: `true` causes the hook to be SKIPPED** |
| `statusMessage` | — | string | — | UI text while running |

`type = "prompt"` and `type = "agent"` parse but are skipped with a warning.

**Not supported in 0.141.0:** `additionalContextLimit` is **silently ignored** — the
handler enum does not use `deny_unknown_fields`, so an unknown key is dropped without
error. `ConfiguredHandler` at this tag has no `additional_context_limit` field.

### 1.5 Trust / enablement state table (config.toml only)

```toml
[hooks.state."/home/u/.codex/config.toml:pre_tool_use:0:0"]
enabled = true
trusted_hash = "<opaque>"
```

`hooks.state` exists only in `config.toml` (it is part of `HooksToml`, not `HooksFile`).
See §6.

---

## 2. Supported hook events in 0.141.0 — VERIFIED

Exactly **10** events (`HOOK_EVENT_NAMES: [&str; 10]`,
`codex-rs/hooks/src/lib.rs@rust-v0.141.0`; also `HookEventsToml` has exactly 10 fields;
`codex-rs/hooks/schema/generated/` at that tag contains 20 files = 10 events x
input+output).

**NOT present in 0.141.0:**

| Event | Evidence |
| --- | --- |
| `SessionEnd` | Not in `HOOK_EVENT_NAMES`, no `hook_event_key_label` arm, no `session-end.*.schema.json`, and the literal string `SessionEnd` is **entirely absent** from the installed binary. |
| `Interrupt` | Not in `HOOK_EVENT_NAMES`, no `hook_event_key_label` arm, no `interrupt.*.schema.json`. (The bare token `Interrupt` does appear in the binary from unrelated code; it is not a hook event here.) |

Unknown event names in `[hooks]` / `hooks.json` are **silently ignored** (no
`deny_unknown_fields` on the events struct), so a `SessionEnd` block from the newer
docs will be accepted by the parser and never fire.

`matcher` is honored for: `PreToolUse`, `PermissionRequest`, `PostToolUse`,
`PreCompact`, `PostCompact`, `SessionStart`, `SubagentStart`, `SubagentStop`.
`matcher` is ignored for: `UserPromptSubmit`, `Stop`.

### Tool coverage for PreToolUse / PostToolUse

| Tool path | Matcher name | `tool_input` shape |
| --- | --- | --- |
| Shell commands | `Bash` | `{"command": "..."}` |
| Unified exec (`exec_command`) | `Bash` | `{"command": "..."}` |
| `apply_patch` (file edits) | `apply_patch`, or alias `Edit` / `Write` | `{"command": "<patch text>"}` |
| MCP tools | `mcp__server__tool` | resolved JSON arguments |
| Other local function tools | function name (e.g. `update_plan`) | its arguments |
| Hosted tools (`WebSearch`) | **not hooked at all** | — |

Official docs caveat, quoted: *"Some specialized tool paths can opt out of the default
hook path. Treat tool hooks as a useful guardrail, not a complete enforcement boundary."*
A `write_stdin` poll does not re-run `PreToolUse`.

---

## 3. Input protocol — VERIFIED

One JSON object on stdin. Field set is exact: the generated input schemas declare
`"additionalProperties": false`.

`pre-tool-use.command.input` (0.141.0):

```json
{
  "session_id": "thr_abc123",
  "turn_id": "turn_456",
  "transcript_path": "/home/u/.codex/sessions/rollout-2026-01-01.jsonl",
  "cwd": "/home/u/project",
  "hook_event_name": "PreToolUse",
  "model": "gpt-5.1-codex",
  "permission_mode": "default",
  "tool_name": "Bash",
  "tool_input": { "command": "rm -rf /" },
  "tool_use_id": "call_9f8e7d6c"
}
```

| Field | Type | Required | Notes |
| --- | --- | --- | --- |
| `session_id` | string | yes | Codex thread id. Docs example format `thr_123` |
| `turn_id` | string | yes | Codex extension; active turn id |
| `transcript_path` | string \| null | yes | **not a stable interface** (official docs) |
| `cwd` | string | yes | also the hook's process working directory |
| `hook_event_name` | string | yes | const `"PreToolUse"` |
| `model` | string | yes | Codex extension, active model slug |
| `permission_mode` | string | yes | enum: `default`, `acceptEdits`, `plan`, `dontAsk`, `bypassPermissions` |
| `tool_name` | string | yes | canonical name (`Bash`, `apply_patch`, `mcp__fs__read`) |
| `tool_input` | any JSON | yes | see tool coverage table |
| `tool_use_id` | string | yes | tool-call id for this invocation |
| `agent_id` | string | optional | only present for subagent-originated calls |
| `agent_type` | string | optional | only present for subagent-originated calls |

`PostToolUse` input is the same plus a required `tool_response` (any JSON).

**Note:** `tool_name` reports the *canonical* name (`apply_patch`) even when the matcher
matched via the alias `Edit`/`Write`. Aliases are used only for handler selection.

---

## 4. Output protocol — VERIFIED

For `PreToolUse`, JSON on stdout. Parsing logic is
`codex-rs/hooks/src/engine/output_parser.rs@rust-v0.141.0`.

### 4.1 Block (deny) — the canonical shape (identical to Claude Code)

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "deny",
    "permissionDecisionReason": "Destructive command blocked by hook."
  }
}
```

`permissionDecisionReason` must be **non-empty after trimming**. If it is missing or
whitespace-only, the hook run is marked **Failed** and the tool call **proceeds**.

### 4.2 Block (deny) — legacy Codex shape, also accepted

```json
{ "decision": "block", "reason": "Destructive command blocked by hook." }
```

`reason` must be non-empty, else Failed + fail-open.

### 4.3 Block via exit code

`exit 2` **and non-empty stderr** → blocked; the trimmed stderr becomes the reason.
`exit 2` with **empty/whitespace stderr** → Failed, and the tool call **PROCEEDS**.

### 4.4 Allow with rewrite

```json
{
  "hookSpecificOutput": {
    "hookEventName": "PreToolUse",
    "permissionDecision": "allow",
    "updatedInput": { "command": "echo rewritten" }
  }
}
```

`updatedInput` is only valid together with `permissionDecision: "allow"`. For Bash and
`apply_patch` it must contain a string `command`. Competing rewrites resolve by
**completion order** (last to finish wins); blocking always wins over rewriting.

### 4.5 Non-blocking context

```json
{ "hookSpecificOutput": { "hookEventName": "PreToolUse", "additionalContext": "..." } }
```
plus optional top-level `systemMessage`.

### 4.6 Enum values (from generated output schema)

- `decision`: `"approve"` | `"block"`
- `hookSpecificOutput.permissionDecision`: `"allow"` | `"deny"` | `"ask"`
- `PermissionRequest` → `hookSpecificOutput.decision.behavior`: `"allow"` | `"deny"` (+ optional `message`)

### 4.7 Full PreToolUse outcome table

| Hook result | Effect on the tool call |
| --- | --- |
| exit 0, stdout empty | allow, run Completed |
| exit 0, valid JSON `deny` | **BLOCK** |
| exit 0, valid JSON legacy `decision:"block"` | **BLOCK** |
| exit 0, valid JSON `allow` + `updatedInput` | allow, input rewritten |
| exit 0, `allow` **without** `updatedInput` | Failed (`unsupported permissionDecision:allow`) → **allow** |
| exit 0, `permissionDecision:"ask"` | Failed (`unsupported permissionDecision:ask`) → **allow** |
| exit 0, `decision:"approve"` | Failed (`unsupported decision:approve`) → **allow** |
| exit 0, `deny` with empty reason | Failed → **allow** |
| exit 0, `continue:false` / `stopReason` / `suppressOutput` | Failed → **allow** |
| exit 0, `updatedInput` without `permissionDecision:"allow"` | Failed → **allow** |
| exit 0, plain text stdout (not `{`/`[`) | **ignored**, run Completed → **allow** |
| exit 0, malformed JSON-looking stdout | Failed (`invalid pre-tool-use JSON output`) → **allow** |
| exit 2, non-empty stderr | **BLOCK** |
| exit 2, empty stderr | Failed → **allow** |
| any other exit code (1, 3, …) | Failed → **allow** |
| no exit status (killed by signal) | Failed → **allow** |
| spawn failure / stdin write failure | Failed → **allow** |
| timeout | Failed → **allow** |
| hook skipped (untrusted / `async:true`) | never runs → **allow** |

When several handlers match, blocking is `any(should_block)` — a single deny wins.

A plain-text `BLOCKED` message on stdout with exit 0 does **not** block. Do not rely on it.

---

## 5. Timeout and failure semantics — VERIFIED

- Default timeout: **600 seconds** (`timeout_sec.unwrap_or(600).max(1)`).
- Configured with `timeout` (seconds). Minimum enforced value is 1.
- On timeout the child is killed (`kill_on_drop(true)`) and the run is recorded as
  `Failed` with `hook timed out after Ns`. The tool call **proceeds**.
- Failure modes that all fail **open** for `PreToolUse`: timeout, spawn error, stdin
  write failure, crash/non-zero-non-2 exit, signal death, unparseable stdout,
  unsupported-but-parseable output fields.
- Consequence for a security hook: set `timeout` strictly larger than your worst-case
  latency. A reputation lookup that overruns the timeout becomes a **silent allow**,
  not a block.
- `async = true` in 0.141.0 emits `skipping async hook in <path>: async hooks are not
  supported yet` and the handler is dropped. A security hook marked `async` will
  **never run**.

This is the opposite of the AIDR connector convention of failing closed; the fail-open
behaviour is Codex's, not something a hook can override.

---

## 6. Trust / safety gating — VERIFIED

Hooks are gated on a persisted trust hash. Mechanism:

1. Each discovered handler gets a key:
   `{key_source}:{event_label}:{group_index}:{handler_index}`
   - `key_source` = config file path for file hooks, e.g.
     `/home/u/.codex/config.toml:pre_tool_use:0:0`
   - plugin hooks: `{plugin_id}:{source_relative_path}:{event_label}:{g}:{h}`, e.g.
     `demo@test:hooks/hooks.json:pre_tool_use:0:0`
   - `event_label` is snake_case: `pre_tool_use`, `permission_request`, `post_tool_use`,
     `pre_compact`, `post_compact`, `session_start`, `user_prompt_submit`,
     `subagent_start`, `subagent_stop`, `stop`
2. `current_hash` = a versioned hash (`version_for_toml`) over the **normalized TOML
   identity** of the handler (event + matcher group + command/timeout/statusMessage).
   It is *not* a plain SHA-256 of the command string, so it cannot be trivially
   hand-computed.
3. Trust status:
   - `Managed` — system / MDM / `requirements.toml` sources: trusted by policy
   - `Trusted` — persisted `trusted_hash` == `current_hash`
   - `Modified` — persisted hash differs
   - `Untrusted` — no persisted hash
4. **Enforcement gate** (`discovery.rs::append_matcher_groups`): a handler is registered
   only if `enabled && (bypass_hook_trust || Managed || Trusted)`. Otherwise it is
   dropped. **Untrusted or Modified hooks simply do not exist at runtime** → the tool
   call proceeds uninspected.
5. Enable/disable: `enabled` defaults to true unless explicitly set `false` in
   `[hooks.state."<key>"]`. Only `User` and `SessionFlags` config layers may write
   `hooks.state`.

### Startup warning

Exact strings extracted from the 0.141.0 binary:

- `1 hook needs review before it can run.`
- `N hooks need review before they can run.`

There is a trust-review TUI (strings present for a notes/submit prompt: `tab to add
note`, `enter to submit`, `ctrl + p / ctrl + n change question`). The current docs
describe a `/hooks` command for this; I verified the warning text and the review UI
strings in 0.141.0 but **did not interactively confirm the literal slash-command name**.
`HookTrustStatus` labels present in the binary: `Untrusted`, `Trusted`, `Modified`.

### Bypass

`--dangerously-bypass-hook-trust` is present in the installed 0.141.0 binary and in
`codex --help`:

> Run enabled hooks without requiring persisted hook trust for this invocation.
> DANGEROUS. Intended only for automation that already vets hook sources

It bypasses the trust check only; an explicitly `enabled = false` handler stays disabled.

### Managed / enterprise

`requirements.toml` may define `[hooks]` plus `managed_dir` /
`windows_managed_dir`; `allow_managed_hooks_only = true` skips user, project, session
and plugin hooks while still loading managed ones. Pin `[features] hooks = true` in
`requirements.toml` to enforce managed hooks even when a user disabled hooks locally.

---

## 7. Differences from Claude Code hooks (porting notes)

**What carries over unchanged:**

- The 3-level shape: event → matcher group → handler list.
- `matcher` as a regex on tool name; `"*"` / `""` / omitted = match all.
- Handler `{"type":"command","command":"..."}`.
- The JSON wrapper for the JSON file form (`{"hooks": {...}}`).
- `exit 2` + stderr = block.
- **The exact Claude Code deny payload works as-is:**
  `{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"..."}}`
- Plugin env compat: Codex sets both `PLUGIN_ROOT`/`PLUGIN_DATA` **and**
  `CLAUDE_PLUGIN_ROOT`/`CLAUDE_PLUGIN_DATA`. The engine type is literally named
  `ClaudeHooksEngine` — the format is deliberately Claude-Code-shaped.

**Differences that will break a straight port:**

| # | Difference | Impact |
| --- | --- | --- |
| 1 | `permissionDecision: "ask"` is unsupported → Failed → **fail-open** | AIDR's `ask` decision is unenforceable via Codex `PreToolUse`. Map `ask` to `deny` (with the `actionId` in the reason) if you need it enforced. |
| 2 | Bare `permissionDecision: "allow"` → Failed → fail-open | `allow` is only meaningful with `updatedInput`. Emit `{}` / no output for a plain allow. |
| 3 | `continue:false` / `stopReason` / `suppressOutput` on `PreToolUse` → Failed → fail-open | Never emit these on PreToolUse. |
| 4 | Codex *also* accepts legacy `{"decision":"block","reason":"..."}` | Extra shape available; harmless to ignore. |
| 5 | Input adds `model`, `permission_mode`, `turn_id`; optional `agent_id`, `agent_type` | Input schema is strict (`additionalProperties:false` on the input contract) — don't emit extra fields, and don't assume Claude's field set. |
| 6 | File edits: Codex `apply_patch` puts the **patch text in `tool_input.command`**; Claude Code `Edit`/`Write` use `tool_input.file_path` / `old_string` / `new_string` | Matcher alias `Edit\|Write` works, but the extractor must special-case the payload shape or it will extract nothing. |
| 7 | Untrusted hooks are silently skipped | Claude Code plugin hooks run once installed; Codex needs an explicit trust step (or `--dangerously-bypass-hook-trust`). |
| 8 | No `SessionEnd`, no `Interrupt` in 0.141.0 | Claude-Code-only events; guard the config. |
| 9 | `hooks.json` top-level `description` rejected | Whole file fails to parse → no hooks load. |
| 10 | `additionalContextLimit` silently ignored | Oversized `additionalContext` is spilled to disk instead of capped. |
| 11 | `async: true` → handler **skipped** in 0.141.0 | Never mark a PreToolUse policy hook async. |
| 12 | Hosted tools (e.g. `WebSearch`) bypass the hook path | Cannot be a complete enforcement boundary. |

---

## 8. What I did NOT verify (explicit gaps)

- **No end-to-end run through a live Codex session.** Exercising a real tool call
  requires model credentials. All protocol claims come from release-tagged source,
  release-tagged generated schemas, the installed binary's strings/config surface, and
  the official docs — not from an observed tool-call round trip.
- **Exact `session_id` string format.** Docs show `thr_123`; treat as an opaque string.
- **The literal 0.141.0 slash-command name for the trust browser.** I verified the
  startup warning text and trust-review UI strings; the `/hooks` name comes from the
  (newer) official docs.
- **`trusted_hash` computation.** It is `version_for_toml` over a normalized TOML
  structure; I did not reverse-engineer the exact algorithm, so **programmatically
  pre-seeding trust is not something I can give you a recipe for.** Use the trust UI or
  the bypass flag.
- **PostToolUse / permission-event details** were read from the same tagged source but
  are less exhaustively enumerated here than `PreToolUse`.
- Official docs at `learn.chatgpt.com/docs/hooks` describe newer behaviour
  (`SessionEnd`, `Interrupt`, `async`, `additionalContextLimit`, `description`); treat
  that page as a forward-looking reference, not as 0.141.0 behaviour.

---

## Sources

- Official docs (markdown): https://learn.chatgpt.com/docs/hooks.md
- Official docs (rendered): https://learn.chatgpt.com/docs/hooks
- `hooks` marked stable: https://github.com/openai/codex/commit/23afa173f4edb981f828b4b3587034ff99f7e223
- Generated wire schemas @ 0.141.0: https://github.com/openai/codex/tree/rust-v0.141.0/codex-rs/hooks/schema/generated
  - `pre-tool-use.command.input.schema.json`, `pre-tool-use.command.output.schema.json`, `post-tool-use.command.input.schema.json`
- Source @ `rust-v0.141.0`:
  - https://github.com/openai/codex/blob/rust-v0.141.0/codex-rs/hooks/src/lib.rs
  - https://github.com/openai/codex/blob/rust-v0.141.0/codex-rs/hooks/src/engine/discovery.rs
  - https://github.com/openai/codex/blob/rust-v0.141.0/codex-rs/hooks/src/engine/output_parser.rs
  - https://github.com/openai/codex/blob/rust-v0.141.0/codex-rs/hooks/src/engine/command_runner.rs
  - https://github.com/openai/codex/blob/rust-v0.141.0/codex-rs/hooks/src/events/pre_tool_use.rs
  - https://github.com/openai/codex/blob/rust-v0.141.0/codex-rs/hooks/src/config_rules.rs
  - https://github.com/openai/codex/blob/rust-v0.141.0/codex-rs/config/src/hook_config.rs
- Claude Code hooks (for the port): https://docs.claude.com/en/docs/claude-code/hooks
