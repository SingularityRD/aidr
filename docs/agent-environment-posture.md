# Agent environment and autonomy posture

AIDR inspects each tool call an agent makes. How much damage a missed call can do also
depends on how the agent host itself is configured. An agent that never asks before
running commands, has its sandbox turned off, runs as root or inherits cloud credentials
can do far more harm than one that doesn't. The agent environment posture checks report
those settings.

The checks are **static**: they read local configuration files and the current process
environment. They never start an agent host or run a command. The result is a posture
snapshot of this machine and user, not proof of how a given agent session was actually
launched: a command-line flag can override a config file.

## Running it

```bash
aidr doctor                        # one "agent_environment" line: warns, never fails the doctor
aidr discover --agents             # MCP inventory plus every agent finding with its fix
aidr discover --agents --json      # adds an "agent_environment" object to the JSON report
aidr discover --agents --upload    # also sends the findings to the dashboard Posture page
```

`aidr discover --agents` exits non-zero when an agent configuration file exists but cannot
be parsed. That file is a coverage gap, not a clean result.

## Checks

| Check id | Host | Severity | What is read | Fix |
|----------|------|----------|--------------|-----|
| `permission_bypass_mode` | Claude Code | critical | `permissions.defaultMode: "bypassPermissions"` in `~/.claude/settings.json`, `<project>/.claude/settings.json`, `<project>/.claude/settings.local.json` | Use `"default"` or `"acceptEdits"` |
| `broad_shell_allow_rule` | Claude Code | high | `permissions.allow` entries `Bash`, `Bash(*)`, `Bash(:*)`, `Bash(*:*)` or `*` | Use specific prefixes such as `Bash(npm run test:*)` |
| `hooks_disabled` | Claude Code | critical | `disableAllHooks: true` (AIDR then never runs) | Remove the key |
| `approval_policy_never` | Codex | high | `approval_policy = "never"` in `~/.codex/config.toml` (root table and every `[profiles.<name>]`) | `"on-request"` or `"untrusted"` |
| `sandbox_full_access` | Codex | critical | `sandbox_mode = "danger-full-access"` (root and profiles) | `"workspace-write"` or `"read-only"` |
| `permission_allow_all` | OpenCode | high | `permission.bash` / `permission.edit` set to the string `"allow"` in `opencode.json` (user and project) | `"ask"` or per-command patterns |
| `aidr_hook_missing` | Claude Code, Cursor, VS Code, Codex, OpenCode, OpenClaw | high | Host detected but no AIDR registration found (same measurement as `aidr status`) | `aidr setup` and the host's platform guide |
| `no_aidr_connector` | Windsurf, JetBrains AI Assistant / Junie, Cline, Roo Code, GitHub Copilot CLI, Gemini CLI, Aider, Amazon Q Developer, Kiro, Zed | medium | The tool's own directory (`~/.codeium/windsurf`, `~/.junie`, `~/.copilot`, `~/.gemini`, `~/.aider.conf.yml`, `~/.aws/amazonq`, `~/.kiro`, `~/.config/zed`, `%APPDATA%\Zed`, ...), its editor extension (`saoudrizwan.claude-dev-*`, `rooveterinaryinc.roo-cline-*`), its JetBrains plugin (`ml-llm`, `junie`) or its executable on `PATH` exists (`packages/core/src/unprotected-agents.ts`; nothing is executed). AIDR has no connector for these tools: their commands, file changes and web requests are **not inspected**. `aidr status`, `aidr coverage`, the session banner and the first-run notice name them as unprotected | Route through the AIDR MCP gateway or restrict by policy |
| `no_devcontainer` | environment | low | Cursor or VS Code detected, the project has no `.devcontainer/devcontainer.json` and the process is not in a container | Add a devcontainer |
| `running_as_root` | environment | high | Effective uid is 0 | Run agents as an unprivileged user |
| `docker_socket_writable` | environment | high | `/var/run/docker.sock` is writable (equivalent to root on the host) | Rootless Docker or remove the user from the docker group |
| `cloud_credentials_in_env` | environment | medium | Names of `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CREDENTIALS`, `AZURE_CLIENT_SECRET`, `AZURE_CLIENT_CERTIFICATE_PATH`, `ARM_CLIENT_SECRET`, `DIGITALOCEAN_ACCESS_TOKEN`, `KUBECONFIG` when set | Use short-lived, least-privilege credentials |
| `mcp_plaintext_secret` | environment | high | Literal credential values in MCP server `env`, `environment`, `headers` or `args` in the MCP config files `aidr discover` inventories. Uses the same secret detector as prompt protection, plus secret-named keys with a literal value; `${VAR}`, `$VAR`, `{env:VAR}`, `env:`, `op://`, `vault:` and `secret:` references are not flagged | Reference an environment variable or secret manager and rotate the value |

### What is deliberately not checked

Only config keys whose format is documented in this repository (installers, platform
guides and the skill-scan rules) are checked. Where a key could not be verified, AIDR skips
it rather than guess and possibly report a false "safe" or a false alarm:

- **Cursor** auto-run / "YOLO" mode and **VS Code** chat tool auto-approval are not read.
  Cursor and VS Code are reported for hook coverage and the devcontainer check only.
- **OpenClaw** sandbox and exec-approval settings are not read. It is reported for hook
  coverage only.
- **Gemini CLI** and **Aider** are detected only, to report that AIDR has no connector for
  them. Their autonomy settings are not read.
- The cloud-credential check reports that credentials are present. It cannot tell whether
  they carry admin rights.

## What is uploaded

`aidr discover --agents --upload` sends one `agent_posture_finding` event per finding
through the same identifiers-only posture pipeline as the MCP inventory and skill scans.
Each event carries:

- the host (`claude-code`, `cursor`, `vscode`, `codex`, `opencode`, `openclaw`,
  `gemini-cli`, `aider`, `windsurf`, `jetbrains-ai`, `cline`, `roo-code`, `copilot-cli`,
  `amazon-q`, `kiro`, `zed` or `environment`; the last eight were added in
  `supabase/migrations/20261014003300_approval_notify_unprotected_hosts_fp_reports.sql`)
- the check id from the table above
- the severity
- a count (rules, variables or servers, from 0 to 10,000)

Config paths, key names, environment variable names and all values stay on the machine.
The client telemetry boundary, the ingest function and the database projection each
re-validate those fields against fixed lists and drop anything else
(`packages/core/src/posture-events.ts`, `supabase/functions/ingest/posture.ts`,
`supabase/migrations/20260927004000_agent_environment_posture.sql`). Rows land in
`posture_findings` with `source = 'agent_environment'`. They follow the same RLS,
retention cascade and offboarding guard as the other posture sources.

The dashboard **Posture** page shows an "Agent environment and autonomy" table: host,
check, severity, the number of installations currently reporting it, the item count and
when it was last seen. An empty table means nothing was uploaded, not that agents are
configured safely.
