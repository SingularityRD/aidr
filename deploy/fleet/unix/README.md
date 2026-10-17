# Unix fleet lifecycle manager

`aidr-fleet.sh` is the one lifecycle manager behind the Linux scripts
(`../linux/`), the macOS PKG postinstall and the Jamf policy (`../macos/`). It
runs as root (`id -u` 0); every action takes the same lifecycle lock.

```
aidr-fleet.sh verify|install|upgrade|rollback|uninstall|status [options]
```

## Scopes

| | Machine (default) | User (`--user NAME`) |
| --- | --- | --- |
| Artifact | signed standalone (SEA) bundle: `aidr-sea/` from `packages/claude-code/scripts/build-sea.mjs`, as `.tgz` | signed npm connector package (`package/`) |
| Hosts | Claude Code and Codex, for every user, through their system-wide policy (`aidr machine-hooks install`) | Claude Code, in that user's `~/.claude/settings.json` |
| User can remove it | No (managed settings / Codex system layer) | Yes |
| Node.js on the endpoint | Not needed | Required |
| State | `<state root>/machine` | `<state root>/users/<hex name>` |

Cursor, VS Code, OpenCode and OpenClaw remain per-user connectors (each user's
`aidr setup`); set `protection_locked` so the editors refuse "Disable
protection" (`docs/operations/hook-tamper-resistance.md`).

## Machine scope

1. **Verify.** The artifact must match `--sha256` and its detached OpenSSL
   signature must verify against the root-owned, pinned `--public-key`. The
   archive is checked for traversal, links, special entries and size before
   extraction (unchanged from the per-user path).
2. **Stage.** The bundle is extracted into
   `<install root>/releases/<sha256>/bundle` (root-owned, files `0644`, the
   multi-call `bin/aidr` `0755`). `--bundle-public-key` (the Ed25519 release key,
   root-owned like the pinned key) is copied to
   `releases/<sha256>/config/release-public.pem`. A retained release is reused
   only after both the candidate and the retained archive verify again, and only
   with the same bundle key.
3. **Policy.** `--control-plane-url https://…`, `--enrollment-key-file FILE`
   (one `aidr_fleet_…` line; the key never appears in a process list) and
   `--protection-locked true|false` write `/etc/singularity-aidr/managed.json`
   (root-owned, `0644`) from exactly the given values, keeping the replaced file
   as `managed.json.previous`. Values are validated before anything is staged.
   With no policy option an existing file is kept; manage other keys
   (proxy, CA, licensing keys) by writing that file yourself.
4. **Register.** The release's own `bin/aidr machine-hooks install --bundle-root
   <release>/bundle` re-verifies every bundle file against the bundle manifest,
   and the manifest signatures against the copied key (a release build must be
   signed), before writing any host policy. `--lock-other-hooks` makes the hosts
   run only managed hooks; `--heartbeat` (Linux) schedules the hourly
   `aidr heartbeat`. Both choices are remembered in `<state root>/machine/options`
   and reapplied on upgrade and rollback until changed with
   `--no-lock-other-hooks` / `--no-heartbeat`.
5. **Record.** `release-state` gets `current` and `previous`;
   `<install root>/bin/aidr` launches the active release;
   `/etc/singularity-aidr/mdm-managed` makes `aidr update` leave updates to the
   fleet tool. A run interrupted after staging leaves `pending`, which makes
   `status` and `fleet-health.mjs` report unhealthy until a run completes.

`rollback` re-verifies the previous release's retained archive and registers it
again. `uninstall` runs `aidr machine-hooks remove` from the active release,
removes the launcher and keeps the releases, the machine policy and every
per-user connector. `status` uses `fleet-health.mjs` when Node.js is present,
otherwise it prints the machine state and `aidr machine-hooks status`.

Hook commands point at the immutable digest directory, so upgrade and rollback
are one atomic rewrite of each host's policy file. Nothing here changes a host's
own behaviour for a hook that crashes or is killed (see the tamper-resistance
document); a local administrator can still change machine policy.

## Tests

`pnpm verify:fleet:unix` runs `scripts/verify-unix-fleet-delivery.mjs`
(per-user lifecycle), `aidr-fleet-lock.test.mjs` (lock recovery) and
`aidr-fleet-machine.test.mjs` (machine scope, macOS PKG postinstall rendering
and the Jamf parameter mapping) in the script's test-root mode, which refuses
uid 0: run it as an unprivileged account. The machine tests use a stand-in
`bin/aidr`; the real command's verification and host writes are covered by
`packages/cli/src/__tests__/machine-hooks.test.ts`.
