# Canary credentials (honeytokens)

Canary credentials are decoy secrets that Singularity AIDR plants on a developer
machine. No legitimate task ever uses them. An AI agent that opens one, searches
its contents, or sends its value anywhere is almost certainly following injected
instructions, so AIDR blocks the action and records a high-severity
`canary_triggered` incident.

## Operator commands

```bash
aidr canary deploy [--path <dir>] [--kinds aws,github,openai,env,ssh-config,db-url] [--json]
aidr canary list [--json]
aidr canary remove <id> | --all [--json]
aidr canary status [--json]
```

- **deploy** creates one decoy file per requested kind (default: all six). Home
  decoys go under your home directory; project decoys (`env`, `db-url`) go under
  `--path` (default: the current directory). It runs again safely: a kind that is
  already deployed under the same root is skipped.
- **list** shows each decoy's id, kind, path and whether the file is still
  `intact`, `missing`, `modified` or `not_regular`.
- **remove** deletes the chosen decoys and drops them from the registry. A decoy
  whose content changed since deployment is left in place and reported, so a
  file you edited is never deleted. Directories that deploy created are removed
  when they are empty again.
- **status** reports registry health, decoy states and the number of triggers in
  the local audit log. It exits non-zero when the registry is unusable or a decoy
  is missing or changed.

These commands are operator-only. An agent that runs `aidr canary …` is blocked
by threat rule `CLT-CANARY-001`: listing the decoys would tell a hijacked agent
which files to avoid, and removing them would disarm the tripwire.

## What is planted

| Kind | Location (first free name is used) | Content |
|------|-------------------------------------|---------|
| `aws` | `~/.aws/credentials.old`, `.bak`, `.backup`, `credentials-2023.bak` | INI profile with an access key ID and secret key |
| `github` | `~/.git-credentials.old`, `.bak`, `.backup` | `https://user:ghp_…@github.com` credential line |
| `openai` | `~/.config/openai/api_key.old`, `.bak`, `~/.openai_api_key.bak` | `OPENAI_API_KEY=sk-proj-…` |
| `env` | `<project>/.env.backup`, `.env.production.bak`, `.env.old`, `.env.local.backup` | application secrets and an API key |
| `ssh-config` | `~/.ssh/config.old`, `.bak`, `.backup` | a bastion `Host` entry with a unique host name |
| `db-url` | `<project>/.env.database.bak`, `database.url.bak`, `.db-credentials.old` | `DATABASE_URL=postgres://user:password@…` |

Guarantees:

- **Never overwrites.** Each file is created with `O_CREAT|O_EXCL|O_NOFOLLOW` and
  mode `0600`. A candidate name that already exists in any form (a file, a
  directory or a symlink) is skipped; when every name for a kind exists, nothing
  is written for that kind.
- **Never valid.** Every value is freshly random. AWS access key IDs contain a
  character that is outside AWS's key-ID alphabet, so no AWS account can ever
  have issued one. The other values are random strings no provider issued, and
  host names sit under the non-public `.internal` domain.
- **Keep project decoys out of version control.** `deploy` prints a reminder; add
  the project decoy names to `.gitignore`. AIDR never edits your `.gitignore`.

## The registry

`~/.singularity-aidr/canary/registry.json` (directory `0700`, file `0600`)
records, per decoy, its id, kind, path, creation time, the SHA-256 digest of the
file as written, the directories deploy created, and the SHA-256 digest and
length of each token value. **Raw token values are never stored** anywhere but in
the decoy file itself.

The registry is inside the AIDR state directory, which self-defense rule
`CLT-SELF-008` puts out of every agent's reach: any tool call (shell command,
file tool, search tool, MCP argument) that names `.singularity-aidr` is a hard
block.

## Detection

Detection runs in the shared core, so Claude Code, Cursor, VS Code, OpenClaw,
OpenCode and Codex all enforce it before a tool runs, and every connector plus the
SDK output guard checks tool output.

**Before a tool runs** (first check in the evaluator, ahead of allowlists,
approvals, caches and any reputation lookup, so no external service ever sees a
decoy value), a call is denied when:

- it names a decoy path: absolute, `~/…` or `$HOME/…`, `file://…`, `@path`
  arguments, or a relative path whose segments are a suffix of the decoy's path
  (`cat .env.backup`, `grep KEY project/.env.database.bak`). In file bodies and
  free-text fields only absolute and home-relative paths count, so a README that
  mentions `.env.backup` is not a trigger; or
- any string in its input (command, URL, file content, edit, MCP arguments)
  contains a registered token value, including percent-encoded, `\u`-escaped and
  base64-encoded forms. Candidate strings are hashed and compared with the
  registry digests.

The verdict is `deny`, category `canary_triggered`, severity `critical`, source
`canary`, rule `AIDR-CANARY-001` (token value) or `AIDR-CANARY-002` (decoy
path). Its artifacts name the canary id only; the tool input is omitted from the
audit entry so the decoy value never lands in a log.

**After a tool runs**, the shared output scanner reports finding
`OUT-CANARY-001` (critical) when tool output contains a decoy value, for example
after a recursive `grep` that swept over a decoy. Every connector that uses the
output scanner quarantines that output. The Claude Code PostToolUse hook also
writes the audit entry and incident.

**Prompts.** The Claude Code UserPromptSubmit hook blocks a prompt that carries a
decoy value and records the trigger.

**Incidents.** Every trigger writes a `runtime_verdict` audit entry with
`category: "canary_triggered"`. In managed mode it also opens an incident and
sends both events through the existing control-plane ingest path, where the
dashboard's Incidents page labels them **Canary triggered** (recognised by
`source: canary` / `AIDR-CANARY-*`). No migration is needed.

## Failure policy

Canary detection is a detection-internal signal. When the registry cannot be
read or parsed, or a tool input is too large to walk completely, the signal is
skipped and logged, and the call is **not** reported as clean: an otherwise clean
allow carries category `canary_unavailable` with a reason saying the canary check
did not run, and it is written to the audit log. `aidr canary status` reports an
unusable registry and exits non-zero. Connector entry points keep failing closed
exactly as before.

## Browser Guard

Browser Guard does not read the local registry (a browser extension has no access
to it), so it cannot tell a canary value from any other credential and does not
count canaries separately: the counts-only telemetry contract
(`docs/contracts/privacy-telemetry.md`) allows only the fixed privacy entity
types, and adding a `canary` key would change that contract. Browser Guard's
existing secret detection already classifies the decoy AWS key IDs, GitHub and
OpenAI keys, `.env` secrets and database URLs as `SECRET`, so a prompt carrying
one is handled like any other secret under the site policy.

## Limits

- A value that is split, reversed or encrypted before use is not recognised; a
  base64 encoding is recognised only when the value starts at the beginning of the
  encoded run.
- Directory-wide actions (`grep -r`, `find -exec cat`) are not blocked in advance
  when they do not name a decoy; the decoy content is caught in the tool output.
- A relative path is matched by its trailing segments, because the agent's
  working directory is not known to the evaluator.
