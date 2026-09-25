# Data and Context Poisoning Protection

AI coding agents take their standing orders from files and stores they re-read
in every session: instruction files such as `CLAUDE.md`, `AGENTS.md` and
`.cursorrules`, agent memory, agent and IDE settings, MCP server configuration
and tool descriptions, and memory or vector stores behind MCP tools. One
poisoned write to any of them turns a one-off prompt injection into a permanent
one, and a poisoned tool description or document can steer the agent before the
user types anything.

Singularity AIDR protects that context at four points: when the agent **writes**
it, when the agent **reads** it, when an MCP server **describes its tools**, and
when the agent **installs a package** whose name it may have invented.

It addresses OWASP LLM04 (Data and Model Poisoning), OWASP Agentic ASI06
(Memory and Context Poisoning) and the tool and package parts of ASI04
(Agentic Supply Chain).

## At a glance

| Situation | Decision |
|-----------|----------|
| Agent edits `README.md` or source code | allow (not affected) |
| Agent writes ordinary content to `CLAUDE.md`, `.cursorrules`, `.claude/settings.json`, `.mcp.json`, `.vscode/tasks.json`, a git hook or `~/.bashrc` | **ask**: blocked until an operator approves out of band |
| The written content hides instructions (invisible Unicode tag characters, bidirectional controls, zero-width characters) | **deny** |
| The written content overrides instructions, hides actions from the user, sends secrets to an external destination, reads private keys, plants chat-template role tokens or pipes a remote script into a shell | **deny** |
| A settings write turns on auto-approval, skips permissions, disables hooks, auto-starts all project MCP servers, allows every shell command or auto-runs a task when the folder opens | **deny** |
| The agent reads a file or page with hidden tag-character text or zero-width payloads | tool output is **blocked** from the model with an explanation |
| The agent reads content that tells it to persist rules into `CLAUDE.md` or memory, read `~/.ssh` first, or shadow other tools | the model receives a **notice** to treat it as untrusted |
| An MCP tool description or schema carries hidden or injected instructions (MCP gateway) | every request to that server is **refused** |
| An approved MCP server changes its tool list or descriptions (rug pull) | **refused** until an operator approves the new signed toolset |
| An MCP memory or vector-store write carries injected instructions | **deny**; a standing behaviour change for future sessions: **ask** |
| `npm install` of a package that does not exist | **deny** |
| A package first published recently with little adoption (possible slopsquatting) | **ask** |

`ask` is never an approval the agent can grant itself: it is a block pending an
out-of-band operator action (`aidr pending` / `aidr approve` in the operator's
own terminal). No connector exposes an approval tool to the agent.

### Why a benign `CLAUDE.md` edit asks instead of allowing or denying

Instruction and memory files are legitimate to change, so a clean edit is not
denied. But the file is re-read by every future session, so whether the change
is wanted is a human decision, not something the content can prove. A benign
edit therefore **asks**, and only content with a concrete poisoning signal is
**denied**. Teams that edit these files constantly can set
`poisoning_protection.agent_control_files` to `off` (content is still scanned)
or allowlist a specific file path; teams that never want agents to touch them
can set it to `deny`.

## 1. Instruction and memory file integrity (write time)

Runs in the shared evaluator, so it applies identically to Claude Code, Cursor,
VS Code, OpenClaw, OpenCode, Codex and the MCP gateway (the SDK security client
uses its own lighter pipeline and does not include it). It follows the
operation, not the tool name: `Write`, `Edit`, `MultiEdit`, `apply_patch` (every
file in the patch), deletes, MCP file-system writers, and shell writes
(redirects, `tee`, `cp`/`mv`/`ln`/`install` destinations, `sed -i`, `dd of=`,
`curl -o`, PowerShell content cmdlets and interpreter one-liners such as
`open(..., "w")`). Reading a file never asks.

Protected files (`threats/context-poisoning.yaml`, rules `CTX-PATH-001` to `CTX-PATH-007`):

| Rule | Files |
|------|-------|
| `CTX-PATH-001` | `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `CLAUDE.local.md` (any directory), `.cursorrules`, `.windsurfrules`, `.clinerules`, `.github/copilot-instructions.md`, `.github/instructions/`, `.cursor/rules/`, `.windsurf/rules/` and similar rule directories |
| `CTX-PATH-002` | Agent memory: `MEMORY.md`, `memory-bank/`, `.claude/memory/`, Claude Code project memory, `.codex/memories/`, Windsurf memories, OpenClaw workspace files |
| `CTX-PATH-003` | Agent configuration: `.claude/settings*.json`, `.claude/hooks|commands|agents|skills/`, `.cursor/hooks.json`, `.codex/config.toml`, `.gemini/settings.json`, OpenClaw and OpenCode configuration |
| `CTX-PATH-004` | MCP configuration: `.mcp.json`, `mcp.json` (including `.cursor/` and `.vscode/`), `claude_desktop_config.json`, other MCP settings files |
| `CTX-PATH-005` | IDE automation: `.vscode/tasks.json`, `settings.json`, `launch.json`, `extensions.json`, dev container definitions, `*.code-workspace` |
| `CTX-PATH-006` | Repository hooks: `.git/hooks/`, `.git/config`, `.husky/`, `.githooks/` |
| `CTX-PATH-007` | Shell start-up files: `.bashrc`, `.zshrc`, `.profile` and relatives, fish and PowerShell profiles, `/etc/profile.d/` |

Content written into these files is scanned by rules `CTX-HIDE-*` (invisible
Unicode), `CTX-INJ-*` (injected directives) and `CTX-CFG-001` (permission
widening). Emoji, emoji flags and the zero-width joiners that Persian and Indic
scripts need are not flagged.

## 2. Poisoned context at read time

Claude Code, Cursor, VS Code, OpenClaw, OpenCode, the MCP gateway and the SDK
output guard inspect tool output with one shared scanner. That inspection now
also recognises:

| Rule | Finding | Effect |
|------|---------|--------|
| `OUT-HIDE-001` | Text hidden in Unicode tag characters; the hidden text is decoded and scanned too | block (critical) |
| `OUT-HIDE-002` | A run of 8 or more zero-width characters (an encoded payload) | block (critical) |
| `OUT-HIDE-003` | Bidirectional control characters | notice |
| `OUT-POISON-001` | Instructions to send secrets or credentials to an external destination | block (critical) |
| `OUT-POISON-002` | Instructions to read private keys or credential files first | notice |
| `OUT-POISON-003` | Requests to persist rules into `CLAUDE.md`, `AGENTS.md`, memory or the system prompt | notice |
| `OUT-POISON-004` | `<IMPORTANT>`-style pseudo-markup, tool shadowing, "do not tell the user" | notice |

"Block" follows each connector's output-inspection behaviour: Claude Code
returns a PostToolUse block with the reason (the tool already ran and cannot be
undone), OpenClaw and OpenCode quarantine or replace the output, the MCP gateway
refuses the response, and the SDK output guard reports it. Findings never echo
the hidden text back to the model. Codex does not let a hook inspect tool output
before the model reads it, so on Codex this layer is not available; write-time
protection (section 1) still applies there.

## 3. MCP tool poisoning and rug pulls

MCP tool names, descriptions and input schemas are part of the model's context.
The MCP gateway scans every observed tool list with rules `CTX-MCP-001` to
`CTX-MCP-003` plus the hidden-Unicode and injected-directive rules:

- orders to read local secrets or agent configuration before using a tool,
- descriptions that override or redirect other tools (cross-tool shadowing,
  "all emails must also be sent to ..."),
- model-directed pseudo-markup and tool substitution,
- invisible Unicode in any name, description, enum or default.

A blocking finding refuses every request to that server with
`tool_metadata_poisoned`, even when the toolset is signed and operator-approved:
a signature proves who published a description, not that it is safe. Review-level
findings are recorded in the gateway's audit events.

Pinning: the gateway only serves a toolset whose hash (names, descriptions,
input and output schemas, annotations) matches an Ed25519-signed manifest that an
operator approved out of band with `aidr-mcp-approve`. If the live server
changes a single description after approval, every request is refused with
`toolset_drift`. A re-signed, changed toolset is quarantined until an operator
approves it again. Approval is never an MCP tool or HTTP endpoint.

MCP discovery (`discoverMcpServers` and session start) scans the tools of every
supplied signed manifest the same way and reports the result per server as
`tool_metadata`.

## 4. Memory and RAG write poisoning

MCP tools that write to agent memory or a vector store are recognised by their
server and tool names (for example `memory`, `mem0`, `qdrant`, `chroma`,
`pinecone` with verbs such as `add`, `store`, `upsert`, `create_entities`,
`add_observations`) and, through the MCP gateway, by their descriptions. Their
arguments are scanned before the write:

- hidden Unicode, instruction overrides, concealment, exfiltration and
  secret-reading directives, role tokens and remote-script execution: **deny**;
- a standing order to fetch, run or send something (`CTX-MEM-001`): **deny**;
- an instruction that changes how the agent behaves in future sessions
  ("in future sessions the assistant should ...", `CTX-MEM-002`): **ask**.

Ordinary facts ("the user prefers tabs over spaces") are allowed.

Written content (instruction files, memory writes, MCP tool metadata) is matched
both as written and as the model reads it: compatibility forms are folded
(`ｉｇｎｏｒｅ` → `ignore`), invisible fillers such as soft hyphens are dropped,
and Cyrillic/Greek letters drawn like Latin ones are mapped to Latin, so an
instruction spelled with them is still recognised.

## Slopsquatting

AI assistants sometimes invent plausible package names, and attackers register
them. With package checks enabled (`package_check.enabled`), AIDR:

- **denies** a package that does not exist on npm or PyPI, or a requested
  version that was never published;
- holds for review (**ask**) a package first published fewer than
  `new_package_days` days ago (default 30) whose adoption is low: fewer than
  `low_adoption_weekly_downloads` npm downloads last week, or, when downloads are
  unavailable (PyPI, or the npm downloads API did not answer), at most
  `low_adoption_max_versions` published versions. Packages younger than 7 days
  are always held.

Package checks send package names to the public registries, so they are off by
default. While they are off, or when a registry cannot be reached, these signals
do not run and the install is reported as **unverified**, never as clean.

## Configuration

```json
{
  "poisoning_protection": {
    "enabled": true,
    "agent_control_files": "ask",
    "content_scan": true,
    "memory_write_scan": true
  },
  "package_check": {
    "enabled": true,
    "new_package_days": 30,
    "low_adoption_weekly_downloads": 1000,
    "low_adoption_max_versions": 3,
    "adoption_lookup": true
  }
}
```

All poisoning switches are on by default. Individual rules can be turned off
with `disabled_threats` (for example `["CTX-PATH-005"]` for teams whose agents
routinely edit `.vscode/settings.json`). A user allowlist entry for a file path
removes the review for that file but never the content findings. See
[Configuration](configuration.md#poisoning_protection).

Read-time inspection is part of tool-output inspection and is always on.
The MCP gateway's tool-metadata scan is always on and fails closed: if its rules
cannot be loaded, requests are refused with `detection_unavailable`.

## Limits

- Detection is pattern-based. A paraphrased instruction without any of the
  covered signals is not recognised; the path-based review on protected files
  is what catches those, which is why a benign edit still asks.
- Shell writes are recognised lexically. Writes hidden behind variables built at
  run time or inside scripts the agent runs later are not attributed to a file;
  the script contents themselves are still inspected by the command rules.
- Tool descriptions are only visible where tool lists pass through AIDR: the MCP
  gateway and supplied signed manifests. A host that talks to an MCP server
  directly shows AIDR only the tool calls, not the tool list.
- Read-time findings on Claude Code cannot undo a tool call that already ran;
  they stop the output from being trusted by the model. Codex has no read-time
  layer (host limitation).
- On Codex, `ask` is enforced as `deny` (Codex has no working ask), so a benign
  instruction-file edit is blocked until the operator approves it with
  `aidr approve`.
- The npm downloads lookup is an extra request to `api.npmjs.org` for young
  packages only; PyPI has no official download-count API, so the release count
  is used as the adoption signal there.
