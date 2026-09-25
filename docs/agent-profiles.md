# Agent permission profiles

An agent permission profile is a least-privilege declaration of what one AI
agent may do: which kinds of tools it may use, which command prefixes, file
paths, network domains and MCP servers or tools are in scope, and what happens
to anything the profile does not cover. You scope each profile to connectors
(Claude Code, Cursor, VS Code, OpenClaw, OpenCode, Codex, the MCP gateway) and,
optionally, to repositories.

Profiles are a **restriction layer on top of threat detection**:

- Threat rules, DLP and every other detector still run on every call.
- The profile outcome and the detection verdict are merged with
  `deny > ask > allow`. A profile can turn an allowed call into `ask` or `deny`;
  a profile `allow` never overrides a threat `deny` or `ask`.
- An allowlist entry is a false-positive exception to threat detection, not a
  permission. It does not lift a profile restriction.
- `ask` is a block pending out-of-band operator approval (`aidr pending` /
  `aidr approve`), exactly like a threat `ask`. No agent-callable approval
  exists. A profile `deny` cannot be approved.

## Where profiles come from

| Source | Location | Trust |
|--------|----------|-------|
| Local | `~/.singularity-aidr/agent-profiles.json` (override with `AIDR_AGENT_PROFILES_PATH`), JSON or YAML | Written by the machine's operator. Applies in local **and** managed mode. |
| Managed | `agent_profiles` section of the signed tenant detector bundle `~/.singularity-aidr/detectors/<runtime>.json` | Ed25519-signed and bound to the verified managed entitlement, like the tenant DLP policy. |
| MCP gateway | `agentProfiles` in the gateway configuration file | The gateway operator's private configuration. |

When both a managed and a local document apply, **both are evaluated and the
stricter outcome wins**. A managed profile therefore always holds: the local
document can narrow it (for example deny one more command) but can never widen
it.

## Failure behaviour

| Situation | Result |
|-----------|--------|
| No profile document | No profile restriction; threat detection alone decides. |
| Local document invalid (unreadable, bad JSON/YAML, schema error) | **Refused**: it is not loaded and nothing in it is enforced. A warning is logged once, `aidr doctor` reports the `agent_profiles` check as failed, and `aidr profile validate` lists the errors by location. |
| Managed `agent_profiles` section invalid | **Fail closed**: every call on that connector is denied with a reason naming the problem (category `agent_profile_invalid`) until a valid bundle is installed. |
| Signed bundle tampered, expired or for another tenant | The whole bundle is refused and every call on that connector is blocked (existing detector-bundle behaviour). |
| MCP gateway `agentProfiles` invalid, or a client bound to a missing profile | The gateway refuses to start. |
| Unexpected error while evaluating a profile | The call is denied. |

## Document format

```json
{
  "version": 1,
  "default_profile": "standard-developer",
  "profiles": [
    {
      "name": "payments-repo",
      "description": "Agents working in the payments service",
      "applies_to": {
        "connectors": ["claude-code", "cursor"],
        "repositories": ["~/work/payments", "/srv/checkouts/payments-*"]
      },
      "default": "ask",
      "tools": {
        "shell": "allow",
        "file_read": "allow",
        "file_write": "allow",
        "web_fetch": "ask",
        "mcp": "allow",
        "other": "allow"
      },
      "tool_overrides": { "Task": "deny" },
      "commands": {
        "allow_prefixes": ["git", "npm test", "npm run lint"],
        "deny_prefixes": ["git push", "npm publish"],
        "unmatched": "ask"
      },
      "files": {
        "read_roots": ["${workspace}"],
        "write_roots": ["${workspace}/src", "${workspace}/test"],
        "deny": ["**/.env", "*.pem", "~/.ssh", "~/.aws"],
        "outside_roots": "deny"
      },
      "network": {
        "allow_domains": ["github.com", "registry.npmjs.org"],
        "deny_domains": ["pastebin.com"],
        "unmatched": "ask"
      },
      "mcp": {
        "servers": { "github": "allow", "jira": "ask" },
        "tools": { "github": { "delete_repository": "deny" } },
        "unmatched": "deny"
      }
    }
  ]
}
```

Every field except `name` and `default` is optional. Unknown fields are
rejected.

### Selecting a profile

A profile applies to a call when every selector it sets matches:

- `applies_to.connectors` — the connector serving the call (`claude-code`,
  `cursor`, `vscode`, `openclaw`, `opencode`, `codex`, `mcp-gateway`).
- `applies_to.repositories` — path globs matched against the agent session's
  working directory **or any of its ancestors**, so `~/work/payments` covers
  every directory inside that checkout.

Among the matching profiles, the most specific selector wins: repository scope,
then connector scope, then an unscoped profile. Profiles with equally specific
selectors all apply and the stricter outcome wins (`aidr profile validate`
flags profiles whose selectors are identical). When nothing matches, `default_profile` applies if the
document names one; otherwise the call has no profile restriction.

The working directory is the one the host reports with the call (Claude Code
and Codex `cwd`, Cursor/VS Code `cwd` or the first workspace root). OpenClaw and
OpenCode use the plugin process's working directory.

### How one profile decides

Each call is checked in two layers and the strictest result wins:

1. **Tool gate.** `tool_overrides[<tool name>]` if present, otherwise
   `tools.<class>`, otherwise `default`.
2. **Scope rules** for what the call touches (below). Each rule family only
   restricts when it is configured.

| Class | Tools (host vocabularies are normalized first) |
|-------|-------|
| `shell` | Bash / shell / exec / run_terminal_cmd, BashOutput, KillShell, `exec_command` |
| `file_read` | Read, Glob, Grep, LS, list/search tools, NotebookRead |
| `file_write` | Write, Edit, MultiEdit, apply_patch, NotebookEdit, Delete |
| `web_fetch` | WebFetch, WebSearch, fetch/browser tools |
| `mcp` | `mcp__<server>__<tool>` and the host's generic MCP call |
| `other` | Everything else (Task, TodoWrite, custom tools) |

Because the two layers combine, an allow list inside a class needs that class
to be allowed: `commands.allow_prefixes` has no effect when `tools.shell`
resolves to `deny` (validation reports this as a `no_effect` diagnostic).

**Commands** (`shell` class):

- `deny_prefixes` — any segment of the command that starts with the prefix
  (at a word boundary) is denied. Segments are split on `;`, `&&`, `||`, `|`,
  `&` and newlines, and are also checked with quotes removed, with leading
  `VAR=value` assignments and wrappers such as `sudo`, `env`, `nohup`,
  `timeout` and `xargs` stripped, with the executable's directory removed
  (`/bin/rm`), and inside `$(…)` and backticks.
- `allow_prefixes` — when present, the command is allowed only if **every**
  segment starts with an allowed prefix, uses no command or process
  substitution and does not redirect output into a file (`> /dev/null` and
  `2>&1` are fine). Anything else gets `unmatched` (default: the profile
  `default`). An empty list means "no command is allowed".

**Files:**

- `deny` — glob patterns; any path any tool names (including MCP arguments and
  the words of a shell command) that matches, or that lies inside a matching
  directory, is denied. A pattern without `/` (`*.pem`, `.env`) matches a file
  or directory name anywhere.
- `read_roots` / `write_roots` — directories. A `file_read` / `file_write` call
  whose target resolves (following symlinks) outside every root gets
  `outside_roots` (default: the profile `default`). A write whose target cannot
  be determined is treated as outside. A search tool without a path searches
  the working directory.
- Paths may start with `/`, `~/`, a drive letter, or `${workspace}` (the
  session's working directory). Relative paths in tool calls are resolved
  against the working directory. `**` matches across directories, `*` within
  one name, `?` one character; other characters are literal. Matching is
  case-insensitive on Windows and macOS.

**Network** (`shell`, `web_fetch`, `mcp` and `other` classes; URLs inside file
content being written are not treated as requests):

- `deny_domains` — the host or any subdomain is denied.
- `allow_domains` — when present, any other host (or a URL whose host cannot be
  read) gets `unmatched`. `example.com` covers its subdomains; `*.example.com`
  covers only subdomains; IP addresses match exactly. An empty list means "no
  destination is allowed".

**MCP** (`mcp` class): the most specific entry decides —
`tools[server][tool]`, then `servers[server]`, then `unmatched` (default: the
profile `default`). When neither `servers` nor `tools` is set, only the tool
gate applies. A call whose server and tool cannot be identified gets
`unmatched`.

## What the agent and the operator see

A profile decision is a normal verdict with `source: "agent_profile"`, category
`agent_profile` (or `agent_profile_invalid`) and a rule-family id in
`matched_threat_id`: `AGENT-PROFILE-TOOL`, `-COMMAND`, `-FILE`, `-NETWORK`,
`-MCP`, `-SELECTION` or `-INVALID`. The reason names the profile, its source and
the rule, for example:

```
Agent permission profile "payments-repo" (managed) denied this call:
rule commands.deny_prefixes["git push"] — the command runs "git push", which this profile denies.
```

Reasons never include the command text or file contents, only the profile's
own rule values, host names and paths. Profile decisions are written to the
local audit log and, for enrolled managed agents, reported to the control plane
like other verdicts; the dashboard's Policy page shows them under **Recent
profile decisions**.

## Templates

Four templates ship with the product. Print one as a ready-to-edit document
with `aidr profile show <name> --template`:

| Template | Intent |
|----------|--------|
| `read-only-reviewer` | Read the workspace and git history; no writes, network or MCP. Shell limited to read-only prefixes. |
| `standard-developer` | Read/write inside the workspace (and `/tmp`), run commands, fetch docs; privileged and destructive commands denied; MCP needs approval; writes elsewhere need approval. |
| `ci-agent` | Unattended builds: allowed build/test prefixes only, writes inside the workspace (not `.github/workflows` or `.git/config`), package registries only. Nothing asks. |
| `locked-down` | Read files inside the workspace; everything else denied. |

All templates deny credential locations (`.env` files, keys, `~/.ssh`,
`~/.aws`, cloud CLI configs, `~/.npmrc`, `~/.netrc`, the AIDR state directory).
Templates carry no `applies_to`; add one before using several profiles in one
document.

## CLI

| Command | Purpose |
|---------|---------|
| `aidr profile list [--json]` | Local profiles (or why the file was refused), managed profiles per connector, and templates. Exits non-zero when a document is invalid. |
| `aidr profile show <name> [--template]` | Print one local or managed profile, or a template document. |
| `aidr profile validate [file] [--json]` | Validate a document (default: the local file) and print errors by location and diagnostics. |
| `aidr profile test '<tool-call-json>' [--connector c] [--cwd dir] [--file doc]` | Dry-run one call — `{"tool_name":"Bash","tool_input":{"command":"git push"}}`, or `@call.json` — against the installed profiles (or `--file`). Prints the selected profiles, decision and deciding rule. Threat detection is not run. |
| `aidr doctor` | Includes an `agent_profiles` check. |

## Publishing a signed (managed) profile

Managed profiles use the same signed distribution as the tenant DLP policy.
On the publishing host, for each connector runtime:

```sh
aidr profile validate agent-profiles.json
node scripts/provision-agent-profiles.mjs \
  --tenant <tenant-id> --runtime <claude-code|cursor|vscode|openclaw|opencode|codex> \
  --profiles agent-profiles.json --expires-at <UTC timestamp within 24h> \
  --private-key <publisher-ed25519.pem> --output-dir ~/.singularity-aidr/detectors
```

The script validates the document, keeps any DLP, behavioural or feed section
already signed for the same tenant (only when that bundle verifies against the
same key; otherwise it refuses), signs the new payload and installs it
atomically. Publishing DLP with `scripts/provision-dlp-detector.mjs` keeps a
verified profile section the same way. The agent accepts the bundle only with
a verified managed entitlement for the same tenant; confirm with
`aidr doctor` or `aidr profile list` on the agent.

## Limits

- Command prefixes are a coarse control over what a shell runs. A program an
  allowed prefix starts (for example a build script) can do anything that
  program does; threat detection still inspects every command.
- Shell words are checked against `files.deny` lexically (symlinks are not
  resolved for them); file tool paths are resolved.
- Repository selection follows the working directory the host reports. Where an
  agent can change that directory, prefer connector-scoped profiles for strict
  controls, or make every profile that could match restrictive.
- The dashboard shows templates and reported decisions; it does not store or
  sign profiles.
