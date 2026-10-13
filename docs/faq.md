# FAQ

## What is the fastest way to set it up?

Install a supported connector and validate its local decision path. Browser
device authorization requires a deployed and configured control plane; without
one, it cannot provide a working verification URL. See [Device Auth](device-auth.md).

## Is Singularity AIDR always running?

On Claude Code, yes - it loads automatically via hooks on every session. On Cursor/VS Code, you need to explicitly enable protection via the command palette. On OpenClaw, it runs once installed as a plugin.

## What happens if Singularity AIDR encounters an error?

Failure behavior depends on the operation. An unavailable enabled reputation
check is reported as incomplete and can require review rather than being called
clean; invalid commercial artifact trust can block startup. See
[How It Works](how-it-works.md) and [Configuration](configuration.md).

## Does Singularity AIDR send my code to the cloud?

Local heuristics do not upload source files, but enabled URL reputation sends
the extracted full URL; package checks can send names, versions, registry
metadata and file hashes. Managed telemetry, deep scans and diagnostics have
separate outbound paths. See [Privacy](privacy.md) before using customer data.

## How do I handle false positives?

Approval depends on the connector. Claude Code supports its host approval UI. Cursor `preToolUse` cannot enforce an `ask` response, so AIDR maps it to an explicit deny. OpenClaw and OpenCode do not expose a human approval dialog through these plugins, so an `ask` verdict remains blocked for that session; the agent cannot approve its own action. After reviewing the artifact out of band, a human can add that exact artifact to `~/.singularity-aidr/allowlist.json` (or use a trusted approval channel already connected to the `ApprovalStore`). Avoid asking the agent to approve or permanently allowlist a suspicious action. See the [OpenClaw](../packages/openclaw/README.md#approving-a-flagged-action) and [OpenCode](../packages/opencode/README.md#approval-flow) connector notes.

## Can I disable a specific threat rule?

Yes. Add its ID to `disabled_threats` in `~/.singularity-aidr/config.json`. Threat IDs are in the YAML files under `threats/`. See [Configuration](configuration.md#disabled_threats).

## Can I add custom threat rules?

Yes. Place valid YAML rule files in `~/.singularity-aidr/threats/`; they are loaded during evaluation. A custom rule with the same ID as a built-in rule overrides it, so prefer unique IDs unless that replacement is intentional. See [Threat Rules](threat-rules.md#custom-user-threats) for the schema and behavior.

## Does Singularity AIDR work offline?

Partially. Local heuristics can run offline; URL/file/package checks are
enabled by default in source/development builds and may use network access.
If an enabled reputation leg is unavailable, the result can require review;
it is not a verified clean result. Disable those legs for an offline pilot and
verify egress. Commercial builds force managed mode.

## What about MCP tool calls?

MCP-aware policy paths exist, but coverage depends on the connector and host
interception point. Direct calls that bypass an installed hook/gateway are not
protected. Validate the selected host and tool methods before including MCP
coverage in a pilot.

## How do I disable Singularity AIDR temporarily?

- **Any connector:** `aidr uninstall --host <id> --keep-data` removes it and keeps your configuration (see [Uninstall](getting-started.md#uninstall))
- **Claude Code:** `/plugin uninstall aidr@aidr` (a development `--plugin-dir` install: run Claude without `--plugin-dir`)
- **Cursor/VS Code:** Run `Singularity AIDR: Disable Protection` from the command palette
- **OpenClaw:** Uninstall the plugin via `openclaw plugins uninstall aidr-openclaw`

You can also disable individual features in `~/.singularity-aidr/config.json` (e.g. set `url_check.enabled` to `false`).

## How do I prevent the agent from auto-approving flagged actions on OpenClaw or OpenCode?

OpenClaw and OpenCode do not register an agent-callable approval tool, and their plugins cannot open a host-native human approval dialog. An `ask` verdict therefore stays blocked until a human approves it out of band; the agent cannot proceed by approving its own action. Claude Code supports its host approval UI; Cursor `preToolUse` maps `ask` to an explicit deny. For OpenClaw/OpenCode, use `"sensitivity": "paranoid"` to turn `ask` verdicts into hard denials when that is the desired policy. See the [OpenClaw](../packages/openclaw/README.md#approving-a-flagged-action) and [OpenCode](../packages/opencode/README.md#approval-flow) connector notes.

See [Configuration](configuration.md#sensitivity) for sensitivity settings.

## Why does OpenClaw flag Singularity AIDR as "potential-exfiltration"?

This is a false positive. OpenClaw's `code_safety` audit fires when `readFile` and `fetch` coexist in the same bundle. Singularity AIDR reads local files (config, cache, YAML) and may also make network calls for first-party reputation checks or managed sync. No file contents cross the network.
