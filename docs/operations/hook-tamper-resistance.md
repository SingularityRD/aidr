# Hook tamper resistance and connector heartbeat

AIDR enforces through hooks that each AI tool (agent host) loads. `aidr setup`
registers those hooks in the user's own files (`~/.claude/settings.json`,
`~/.codex/hooks.json`, the editor's hooks file). A user can delete those entries,
set Claude Code's `disableAllHooks`, run the editor command
"Singularity AIDR: Disable protection", or never trust the Codex hook. Until now
nobody was told.

A per-machine install closes as much of that as each host allows, and reports the
rest:

1. **System-wide hooks.** The hooks go where the host reads organisation policy,
   which only an administrator can change (`aidr machine-hooks install`).
2. **Protection lock.** Machine policy `protection_locked` makes the Cursor /
   VS Code extension refuse "Disable protection" and put back hooks a user
   deleted. It also takes local relaxations away from anything running as the
   user, the agent included: the hooks ignore the local allowlist
   (`~/.singularity-aidr/allowlist.json`) and local detection exceptions, and
   the CLI refuses `aidr allowlist add`, `aidr exception add`, a weakening
   `aidr config -s` and `aidr uninstall` before any prompt, so no terminal trick
   can confirm them. Exceptions for a locked fleet come from the control plane
   (signed managed policy), which the device cannot write.
3. **Heartbeat and alerts.** `aidr heartbeat` measures every host on the device
   once an hour and reports one state per connector. The control plane raises
   `agent.unprotected` when a protected connector stops being protected, and
   `agent.offline` when the heartbeat itself stops.

None of this changes a host's own behaviour for a hook that crashes, times out or
is killed before it answers: Claude Code and Codex then let the call through. A
local administrator can also change machine policy; the heartbeat is what makes
that visible.

## What each host supports

| Host | System-wide location AIDR writes | Users can remove or disable it? | "Only managed hooks" switch | Verified against |
| --- | --- | --- | --- | --- |
| Claude Code | `/etc/claude-code/managed-settings.d/50-singularity-aidr.json` (Linux, WSL); `C:\Program Files\ClaudeCode\managed-settings.d\50-singularity-aidr.json` (Windows) | No. A user's `disableAllHooks` does not turn managed hooks off; only managed settings can | `allowManagedHooksOnly: true` (written with `--lock-other-hooks`) | code.claude.com/docs/en/managed-settings and /docs/en/settings-reference, read 2026-10-14 |
| Codex | `/etc/codex/hooks.json`; `%ProgramData%\OpenAI\Codex\hooks.json` | No. Hooks from the system config layer are managed: trusted without `/hooks` review, and a user's per-hook `enabled = false` does not apply to them | `allow_managed_hooks_only = true` in the system `requirements.toml` (written with `--lock-other-hooks`, added as the first line, never over an administrator's own value) | codex-rs source at tag `rust-v0.141.0`: `hooks/src/engine/discovery.rs` (`ConfigLayerSource::System` is managed), `config/src/loader/mod.rs` (system paths), `config/src/config_requirements.rs` |
| Cursor | Not written. Cursor reads an enterprise `/etc/cursor/hooks.json` (Linux), but AIDR's Cursor hook runner ships inside the per-user extension, so there is no machine-wide command to register yet | Yes, unless `protection_locked` is set (the extension then refuses and restores) | — | Linux path: Cursor's own log output quoted on forum.cursor.com. Windows path `C:\ProgramData\Cursor\hooks.json` appears only in third-party guides |
| VS Code | None exists. VS Code Local hooks (`chat.useClaudeHooks`) read the Claude settings files | Yes, unless `protection_locked` is set | — | A third-party extension cannot register a VS Code policy: extension setting policies live in the VS Code distribution's `product.json` (microsoft/vscode `add-policy` skill) |
| OpenCode, OpenClaw | None. Their plugins are per-user | Yes | — | — |

What could not be verified here, and must be checked on the customer's versions
before it is sold as a control:

- **No real host was run.** The Claude Code paths and semantics come from the
  current public documentation; the Codex behaviour comes from reading its source
  at `rust-v0.141.0` (the version `packages/codex` was accepted against), not from
  running it. Repeat on the Claude Code and Codex versions in use.
- **Claude Code source precedence.** By default Claude Code takes policy from the
  first admin source that has any: server-managed settings, then MDM / the
  `HKLM\SOFTWARE\Policies\ClaudeCode` registry value, then the managed settings
  files and drop-ins. If the customer already deploys Claude Code policy through
  server-managed settings, MDM or HKLM, the AIDR drop-in is skipped. Add AIDR's
  hooks to that source, or set `managedSourcesBehavior: "merge"` there (Claude
  Code 2.1.242 or later). `aidr machine-hooks install` prints this note.
- **WSL.** `/etc/claude-code` inside WSL is writable by the WSL user, so it is not
  tamper resistant there.
- **Windows ACLs.** `aidr machine-hooks status` measures owner and mode on Linux
  only. On Windows check that `C:\Program Files\ClaudeCode` and
  `%ProgramData%\OpenAI\Codex` are writable by administrators only (by default
  `%ProgramData%` subfolders let Users create files; tighten the ACL of
  `%ProgramData%\OpenAI\Codex` with your device management tool).
- **Cursor enterprise hooks on Windows** and Cursor's merge semantics were not
  confirmed from Cursor's own documentation.
- **macOS** is not a supported endpoint yet. The fleet PKG/Jamf templates use
  the paths listed in code and the hooks read `/etc/singularity-aidr/managed.json`
  there too, but none of it has been run on a Mac.

## Deploying it

### Linux (.deb / .rpm)

The package's maintainer script runs as root and, unless `AIDR_MACHINE_HOOKS=0`
is set, calls:

```bash
aidr machine-hooks install --heartbeat          # AIDR_LOCK_OTHER_HOOKS=1 adds --lock-other-hooks
```

That writes the Claude Code drop-in, merges AIDR's three handlers into
`/etc/codex/hooks.json` (other handlers are kept), and installs
`/etc/systemd/user/aidr-heartbeat.{service,timer}` enabled for every user session
(`systemctl --global enable`). Final removal runs
`aidr machine-hooks remove --heartbeat`; an upgrade keeps everything.

Set the protection lock in the machine policy file (W1 contract,
`/etc/singularity-aidr/managed.json`, root-owned, mode 0644):

```json
{ "protection_locked": true }
```

A policy file that is not owned by root, or that group or others can write, is
ignored.

### Windows (MSI, per-machine)

The MSI runs `aidr.exe machine-hooks install --heartbeat` as a deferred, elevated
action (not impersonated) for a per-machine install, including an install in the
system context (Intune, SCCM, GPO). Public properties:

| Property | Default | Effect |
| --- | --- | --- |
| `AIDR_MACHINE_HOOKS` | `1` | `0` skips the system-wide hooks and the heartbeat task |
| `AIDR_LOCK_OTHER_HOOKS` | unset | `1` adds `--lock-other-hooks` (only managed hooks run in Claude Code and Codex) |
| `AIDR_PROTECTION_LOCKED` | unset | `1` writes `HKLM\SOFTWARE\Policies\Singularity AIDR\protection_locked = 1` (DWORD) |

```powershell
msiexec /i aidr.msi ALLUSERS=1 AIDR_PROTECTION_LOCKED=1 AIDR_LOCK_OTHER_HOOKS=1 /qn
```

The heartbeat is the scheduled task `\Singularity AIDR\Heartbeat` (hourly and at
logon, for whichever member of `BUILTIN\Users` is logged on). Final removal runs
`machine-hooks remove --heartbeat`; a per-user install changes nothing
system-wide.

### Linux and macOS fleet scripts (Jamf, configuration management)

`deploy/fleet/unix/aidr-fleet.sh` (behind `deploy/fleet/linux/*.sh`, the macOS
PKG postinstall and `deploy/fleet/macos/jamf-policy.sh`) verifies a signed
standalone bundle, stages it in a root-owned release store, writes
`managed.json` (`--control-plane-url`, `--enrollment-key-file`,
`--protection-locked`) and runs the release's own `aidr machine-hooks install`
(`--lock-other-hooks`, `--heartbeat` on Linux), with upgrade, rollback and
uninstall. No Node.js is needed. See `deploy/fleet/unix/README.md`.

`aidr machine-hooks install` refuses a bundle whose files do not match its
manifest, or whose manifest signatures do not verify against the release key
next to it (`<prefix>/config/release-public.pem`), before writing anything.

### By hand or from a configuration-management tool

```bash
sudo aidr machine-hooks install --heartbeat [--lock-other-hooks]
aidr machine-hooks status            # registered? other hooks blocked? admin-only file?
sudo aidr machine-hooks remove --heartbeat
```

`aidr setup` notices a system-wide registration and leaves the user's own files
alone for that host, so a call is not inspected twice.

### Lock "only managed hooks" with care

`--lock-other-hooks` stops every user, project and plugin hook in Claude Code
(including the AIDR Claude Code plugin, if a user installed it) and every
non-managed hook in Codex. That is what an organisation that wants nothing else
to run asks for, but it also stops any other hook the developers rely on. In
Claude Code it also disables plugins with a `command` source and the `/goal`
command.

## A crashed hook blocks (POSIX registrations)

Claude Code and Codex run a call whose hook crashed, was killed or could not be
found (exit 1/126/127/137) and block on exit 2 (Codex only with a reason on
stderr). `aidr setup` and `aidr machine-hooks install` therefore register POSIX
hook commands as `<cmd> || { [ $? -eq 2 ] || echo "<reason>" >&2; exit 2; }`
(packages/cli/src/utils/standalone.ts `failClosedHookCommand`). The real-host
scenario `crashed-hook-wrapped-fails-closed` proves the block on Claude Code
2.1.302 and Codex 0.141.0; `crashed-hook-observed` keeps recording the hosts'
own fail-open for an unwrapped hook.

Not wrapped yet:

- **Windows registrations.** Claude Code runs a shell-form hook through Git Bash
  on Windows, or PowerShell when Git Bash is not installed
  (code.claude.com/docs/en/hooks, "Exec form and shell form", read 2026-10-17);
  PowerShell cannot parse the wrapper. Codex runs Windows hooks through its own
  shell. Both need a real-host run on Windows before a wrapped form ships there.
- **The Claude Code plugin's `hooks/hooks.json`.** It is one file for every
  platform, so it keeps the plain `node "${CLAUDE_PLUGIN_ROOT}/…"` command until
  the Windows behaviour above is verified. Enterprise fleets should use the
  machine-wide hooks, which are wrapped on Linux and macOS.

## The protection lock (Cursor, VS Code)

With `protection_locked` set in machine policy, the extension:

- hides "Singularity AIDR: Disable protection" from the command palette, and
  refuses it when invoked another way, with a message that the attempt was
  recorded;
- on every start, puts its hooks back in the configured scope if they were
  deleted by hand (shown to the user);
- counts refused attempts, restorations and (when not locked) user disables in
  `~/.singularity-aidr/protection-events.json`, which the heartbeat reports.

The VS Code setting `chat.useClaudeHooks` stays the user's choice; AIDR does not
change editor settings. `aidr heartbeat` reports VS Code as `hook_missing` when
its hook entries are gone.

## Heartbeat

`aidr heartbeat` (managed mode) sends, for each host present on the device:

| Field | Values |
| --- | --- |
| `connector` | `claude-code`, `cursor`, `vscode`, `openclaw`, `opencode`, `codex` |
| `state` | `protected`, `hook_missing`, `hook_disabled`, `hook_untrusted`, `hook_broken` |
| `enforcement` | `machine_policy`, `user_config`, `none` |
| `protection_locked` | boolean (editors) |
| `disable_attempts` | count of refused "Disable protection" attempts (editors) |

No paths, commands, user names or hostnames are sent. Codex is `hook_untrusted`
when an AIDR handler in the user's Codex home has no trust record (Codex then
skips it without a word) and `hook_disabled` when Codex has it switched off.
`aidr doctor` reports the same Codex trust state as the `codex_hook_trust` check.
AIDR does not recompute Codex's trust hash, so a recorded trust is reported as
"trust recorded", not as proven.

The control plane (`connector-heartbeat` Edge Function, migration
`20261014000205_connector_heartbeats.sql`) stores the latest state per agent and
connector in `connector_heartbeats`, refreshes the agent's `last_seen`, and queues
`agent.unprotected` to every alert channel that watches agent health (the
`agent_offline` filter in Settings → Notifications) when:

- a connector last reported `protected` reports any other state (one alert per
  agent, connector, state and episode), or
- the count of refused "Disable protection" attempts rises
  (`connector_state: disable_attempted`).

A connector first reported unprotected is a coverage gap, shown on the device,
not an alert, so a rollout does not page anyone. A device whose heartbeat stops
(task removed, machine off, AIDR uninstalled) raises `agent.offline` after the
channel's threshold. The event format is in
[docs/contracts/notifications.md](../contracts/notifications.md).

## Needs a person

- Run the MSI and the .deb on real Windows and Linux machines, then confirm with
  `/status` in Claude Code ("Enterprise managed settings (drop-ins)") and with
  Codex's `/hooks` list (the AIDR hooks shown as managed) that both hosts load
  the system-wide hooks.
- Decide per customer whether to turn on `--lock-other-hooks` and
  `protection_locked`.
- Tighten the ACL of `%ProgramData%\OpenAI\Codex` on Windows fleets.
