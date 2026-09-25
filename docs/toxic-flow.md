# Toxic-flow detection

Single-call rules look at one tool call at a time. Many real attacks on coding agents only
show up as a sequence. The agent reads a credential file, later fetches a web page that
carries an injected instruction, and then "posts a summary" to an external URL. Each step
looks ordinary on its own. Together they are data exfiltration.

Singularity AIDR tracks what each agent session has done and flags the call that would
complete a dangerous combination.

## The model

The approach follows the widely discussed **"lethal trifecta"** idea: an agent that has all three
of the following in one session can be turned against its user by anyone who controls
the untrusted content:

| Capability | Examples AIDR observes |
|------------|------------------------|
| **A. Private data access** | Reads of credential stores and secret files (`~/.ssh/id_*`, `~/.aws/credentials`, `.env*`, `.npmrc`, `.netrc`, kubeconfig, key material, browser credential stores, `/etc/shadow`), secret-printing commands (`env`, `gh auth token`, `aws secretsmanager get-secret-value`, `kubectl get secret`, `security find-generic-password`), database dumps (`pg_dump`, `mysqldump`, `*dump*.sql`), secrets or personal data found in tool output |
| **B. Untrusted content exposure** | Web fetches and searches, browser/scraper tools, output of MCP servers not marked trusted, reading or executing a file downloaded in this session (`curl -o`, `wget`, `git clone`), tool output flagged by prompt-injection inspection |
| **C. External communication** | Network egress to a non-trusted destination (HTTP clients, raw sockets, interpreter one-liners), uploads (`curl -d/-F/-T`, `scp`/`rsync` to a remote host), `git push` to a remote other than `origin`, email (`sendmail`, `mail`, `swaks`), MCP tools that send data out (`send_message`, `create_issue`, `post`, `upload`, and so on), paste, file-drop, request-capture and chat-webhook services, DNS lookups built from command output |

A step keeps counting for `toxic_flow.window_minutes` (default 60).

## Chains

| Chain | Threat id | Fires when |
|-------|-----------|------------|
| `lethal_trifecta` | `AIDR-FLOW-001` | This call would give the session all three capabilities (A + B + C). It fires on the call that first completes the set, and after that on every call that is itself external communication. |
| `exfil_chain` | `AIDR-FLOW-002` | Secret-grade material was read (earlier in the window or in this call), and this call sends a payload out: a request body, an upload, piped data, a paste service, an email, a push or an MCP send tool. It does not need untrusted content. |
| `injection_to_action` | `AIDR-FLOW-003` | Untrusted content entered the session, and this call runs a destructive command: `rm -r` of a broad target (`/`, `~`, `*`, `.git`, a top-level directory), `git push --force`, `git reset --hard`, `git clean -f`, `find -delete`, `mkfs`/`dd of=/dev/…`, SQL `DROP`/`TRUNCATE`, `terraform destroy`, `kubectl delete`, recursive bucket deletes, and similar. |
| `bulk_sensitive_access` | `AIDR-FLOW-004` | Distinct sensitive files or credential stores accessed in the window reach `toxic_flow.bulk_sensitive_threshold` (default 5). |

When several chains fire, the strongest is reported and the others are listed under "Also matched".

### What the agent and the user see

The verdict category is `toxic_flow`. The reason names the chain, the earlier steps and this
call, for example:

```text
Toxic flow "exfil_chain": this call sends data to an external destination after secret
material was read in this session. Earlier steps: [private data] Read: Read
~/.aws/credentials (cloud credentials) (4m ago). This call: [external communication]
Bash: curl → collector.example (carries data).
```

Step summaries name a tool and a target: a path, a host or a remote name. They never
contain request bodies, query strings, command arguments that could carry the data, or
file contents. The telemetry redactor is also applied to them.

### Actions

`toxic_flow.action` decides what a completed chain does:

- `auto` (default): `ask` in `balanced` and `relaxed`, `deny` in `paranoid`.
- `ask` / `deny`: fixed.
- `monitor`: the call is allowed. The finding is recorded in the audit log (`toxic_flow_monitor`) so you can tune the settings before you enforce them.

An `ask` blocks the call until a human approves it out of band, as every other `ask`
does. In Claude Code the native permission dialog asks the user. In OpenClaw, OpenCode and
Codex the operator approves it with `aidr approve <actionId>` in their own terminal. The
agent cannot approve its own block.

Other layers still decide first. A call that another layer denied is not recorded, because
it never ran. If another layer required a DLP rewrite, a chain denies the call instead of
asking: an approved ask would run the original, unredacted input. Calls on the operator
allowlist are recorded but never escalated.

## What does not trigger

These flows never touch a capability, so they are never flagged:

- `npm install`, reading `package.json`, editing source files, running tests.
- `git push`, `git push origin …`, and requests to package registries or source hosts.
- Requests to `localhost` and private addresses.
- Reading `.env.example` or public keys.
- Writing to `.env`. Reading a secret is private-data access; writing one is not.

A plain request to a trusted domain (package registries, language docs, `github.com`, plus
`toxic_flow.trusted_domains`) is not external communication. A request that carries a
payload still is.

## Where the signal comes from

- **Before each call.** The shared evaluator classifies the call and checks it against the
  session record. It runs after all other detection layers, so every connector gets it:
  Claude Code, Cursor / VS Code, OpenClaw, OpenCode, Codex and the MCP gateway.
- **After each call.** Where a connector inspects tool output after execution, the
  findings are added to the session: secrets become private data, and prompt-injection
  payloads become untrusted content. This happens in Claude Code (`PostToolUse`), OpenClaw
  (`after_tool_call`), OpenCode (`tool.execute.after`) and the Cursor / VS Code tool-output
  hooks. Codex's `PostToolUse` path only publishes an observation and does not inspect
  output. The MCP gateway blocks flagged results before they reach the model.
- **Session identity.** Each connector passes its host's session or conversation id. If a
  host sends none, a stable key is built from the connector, the parent process and the
  process working directory (never from a `cwd` argument of the tool call, which the model
  chooses). The MCP gateway uses one session per MCP session (`Mcp-Session-Id`), or
  for a stateless server one per client, server and gateway process, never one per client
  credential across sessions (see `docs/agent-safety.md`); chains that span two MCP servers
  are therefore not correlated by the gateway.

## State, tamper resistance and failure policy

- Each session has one small JSON record in `~/.singularity-aidr/session-flow/`, with at
  most 64 steps and 32 tracked downloads. Records are written atomically under a short
  per-session lock. They are pruned after the window, with at most 512 session records.
- The directory is inside the AIDR state directory. Self-defense rule `CLT-SELF-008` blocks
  any agent access to that directory from a shell, a file tool or an MCP argument. Every
  record also carries an HMAC-SHA256 under a per-install key (`.flow-key`, `0600`) and is
  bound to its own session digest. A hand-edited, truncated, symlinked or swapped record
  fails verification.
- **A record that fails verification is treated as tampering, not as a clean slate.**
  The session is assumed to have all three capabilities for the rest of the window, so its
  next egress needs approval. The reason says that the integrity check failed.
- **A record that cannot be read or written** (permissions, I/O) is a skipped detection
  signal. The call is still evaluated by every other layer, the failure is logged, and an
  `allow` is recorded as `toxic_flow_unavailable`, never as a clean result. Connector
  entry points stay fail-closed as before.
- Residual risk: like the operator approval store, this is not a boundary against arbitrary
  code that already runs as the same OS user with full shell access. It makes tampering
  detectable and turns it into a stricter posture.

## Cost

Classification is pure and runs on every call. The session record is read only when a call
contributes a capability, reads a file or runs a destructive command. It is written only
when the record changes. Evaluating a call against a full 64-step record takes microseconds.
The file-backed path costs one small read and at most one small atomic write. The
performance test in `packages/core/src/__tests__/toxic-flow.test.ts` checks both.

## Limitations

- Classification is heuristic. It follows `bash -c`, `eval`, argv arrays and common
  command prefixes one level deep. It does not model every way a program can reach the
  network. A custom binary that uploads data is not recognised as external communication.
- The capability patterns are built into `packages/core/src/toxic-flow-classify.ts`. They
  are not threat-rule YAML. Tune them with the `toxic_flow` settings above.
- Taint is tracked per session. It does not follow data from one agent session to another.
- Downloads are matched by path. A downloaded file that is moved or renamed is no longer
  tracked.
