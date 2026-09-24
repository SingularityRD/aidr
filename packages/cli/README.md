# AIDR CLI

The `aidr` command provides local setup and diagnostics for AIDR connectors. It
does not deploy a control plane or create a cloud account.

This is not a one-command customer download. The release operator must first
grant access to a signed, approved version in the private registry. `aidr setup`
only configures local AIDR state and prints connector setup guidance; it does
not install or activate the connector.

Install the exact approved version from the private registry using
[Package Installation](../../docs/package-installation.md), then inspect the
available commands:

```sh
aidr --help
```

Run `aidr setup` only after the operator has supplied the approved runtime
configuration and selected a supported secret store. It may write local
configuration and record detected runtime state; it does not install hooks or
activate the connector, and it is not a substitute for the customer acceptance
procedure.

## Commands

| Command | What it does |
|---------|--------------|
| `aidr setup` | Write local configuration and print connector setup guidance |
| `aidr status [--json]` | Measured installation state (detection self-test, connectors, data loss) |
| `aidr doctor [--json]` | Hosts detected, hooks registered, rule count, core version, mode, DLP policy status, approval store and last verdict; exits `1` when any check fails |
| `aidr pending [--json]` | Blocked agent actions (`ask` verdicts) waiting for an operator decision |
| `aidr approve <actionId>` | **Operator only.** Approve one retry of exactly that call; 15-minute default (`--ttl <minutes>`), single-use, `--permit-allowlist` to also let the agent allowlist it once |
| `aidr allowlist list [--json]` | Show allowlist entries (commands appear as hashes) |
| `aidr allowlist add <url\|command\|file_path> <value>` | **Operator only.** Add a permanent exception |
| `aidr allowlist remove <type> <value>` | Remove an entry (command text or hash prefix) |
| `aidr audit tail [-n N] [--json]` | Most recent audit entries, re-redacted |
| `aidr audit export [--since 24h\|ISO] [--format jsonl\|csv] [-o file]` | Redacted export across rotated log files |
| `aidr config`, `aidr scan`, `aidr collect`, `aidr discover`, `aidr uninstall` | See `aidr <command> --help` |

### Operator-only commands

`aidr approve` and `aidr allowlist add` widen what an agent may do, so they are
out-of-band, human-only actions. They print what will be allowed and require the
operator to type a confirmation word (`approve` / `allow`) in an interactive
terminal. Automation may pass `--yes`, which is honoured only when
`AIDR_OPERATOR_NONINTERACTIVE=1` is also set. Approvals are HMAC-protected with a
per-install key kept in the OS credential vault where available. This stops a
prompt-injected agent from approving its own block through its tools; it is not
a boundary against code running as the same OS user with full shell access. The
self-defense rule `CLT-SELF-007` blocks an agent that tries to run these commands.
See [Operator approvals](../../docs/configuration.md#operator-approvals) for the
flow, the on-disk format and the residual risk.
