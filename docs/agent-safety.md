# AI safety guardrails for autonomous agents

Coding agents are increasingly left to work on their own: they run commands, edit code, open
pull requests and talk to cloud accounts for minutes or hours without a person watching every
step. Most of what goes wrong in that setting is not malware. It is an agent that gets stuck,
an agent that "passes" by weakening the checks it is graded by, an agent that hands itself
more autonomy, or an agent that does something that cannot be undone.

Singularity AIDR adds four guardrails for these cases. They run in the same shared engine as
every other AIDR check, so they apply to every supported connector (Claude Code, Cursor,
VS Code, OpenClaw, OpenCode, Codex) and to the MCP gateway, in local mode, with no account or
network access.

| Guardrail | What it catches | Decision |
|-----------|-----------------|----------|
| [Runaway and budget guardrails](#1-runaway-and-budget-guardrails) | Loops, a command failing again and again, tool-call rate spikes, optional per-session budgets | `ask` (the session pauses for a person) |
| [Reward hacking and sabotage](#2-reward-hacking-and-sabotage) | Skipped tests, removed assertions, bypassed git hooks, disabled CI, lowered coverage, blanket lint/type suppressions, erased logs or history, force-pushes to protected branches | `ask` |
| [Autonomy escalation](#3-autonomy-escalation) | An agent launching another agent (or itself) with approvals or sandbox switched off, or detached in the background | `deny` (balanced and paranoid), `ask` (relaxed) |
| [Irreversible actions](#4-irreversible-actions) | Database drops, infrastructure teardown, cloud deletions, publishing, production deploys, sending messages or payments | `ask`, labelled "Irreversible action" |

An `ask` is a block pending human approval, exactly like every other AIDR `ask`: Claude Code,
Cursor and VS Code show their native confirmation dialog; OpenClaw, OpenCode and Codex keep the
call blocked until an operator approves the exact call out of band (`aidr pending`,
`aidr approve <actionId>`) or, in managed mode, in the dashboard. The agent is never given a
way to approve its own block. Every verdict names the specific reason, for example
*"Test skipped or disabled in a test file (it.skip / xit / @pytest.mark.skip / t.Skip /
@Disabled)"* or *"Runaway guard paused this session for human review: The same tool call was
repeated 9 times in a row (limit 8)."*

## 1. Runaway and budget guardrails

A stuck agent keeps doing the same thing: re-running the same failing build, re-reading the
same file, retrying an edit that never applies. One that has gone off the rails does a lot of
it very fast. None of those calls is harmful on its own, so the runaway guard looks at the
session instead of the call. When a threshold is exceeded the call becomes an `ask`.

| Signal | Id | Default |
|--------|----|---------|
| The same call back-to-back, nothing else in between | `CLT-AGENT-RUN-001` | more than 8 in a row |
| The same call anywhere in the window | `CLT-AGENT-RUN-002` | more than 25 in 10 minutes |
| Near-identical calls (only numbers, ids or spacing differ, e.g. a polling loop) | `CLT-AGENT-RUN-003` | more than 50 in 10 minutes |
| The same call failed repeatedly with no file edited in between | `CLT-AGENT-RUN-004` | the retry after 3 failures |
| Tool-call rate spike | `CLT-AGENT-RUN-005` | more than 120 calls in 60 seconds |
| Session budget: tool calls | `CLT-AGENT-RUN-006` | off |
| Session budget: minutes | `CLT-AGENT-RUN-007` | off |
| Session budget: distinct files written | `CLT-AGENT-RUN-008` | off |

The defaults are deliberately generous: an agent that edits and re-runs its tests is not a
loop (any other call breaks a back-to-back streak, and editing a file resets the failure count).
Budgets are off until you set them. Configure everything under `agent_safety.runaway` in
`~/.singularity-aidr/config.json`:

```json
{
  "agent_safety": {
    "runaway": {
      "max_consecutive_identical_calls": 8,
      "max_calls_per_minute": 120,
      "max_tool_calls": 500,
      "max_session_minutes": 120,
      "max_files_written": 100
    }
  }
}
```

Once a budget is exceeded, every further call in that session asks until the session ends (or
you raise the budget). See the [configuration reference](configuration.md#agent_safety) for all
fields.

**Failure outcomes.** Repeated-failure detection uses the outcome the host reports, and only
explicit failure markers count (an unknown result shape is never a failure):

| Connector | Failure signal |
|-----------|----------------|
| Claude Code | `PostToolUse` result with `is_error: true` or a non-zero `exit_code` |
| OpenClaw | `after_tool_call` with an `error` |
| OpenCode | `tool.execute.after` with bash `metadata.exit` other than 0, or a raw MCP result with `isError: true` (a tool that throws never reaches this hook) |
| Cursor | `postToolUse` whose `tool_output` (JSON) carries a non-zero `exitCode`/`exit_code` or `is_error`/`isError: true` |
| VS Code | `PostToolUse` whose `tool_response` carries the same markers |
| Codex | not available: codex-cli 0.141.0 runs `PostToolUse` only for calls that succeeded, and `Bash` results carry no exit code |

The post-tool call is normalized the way the connector's pre-tool hook normalized it (Cursor
shell commands as evaluated at `beforeShellExecution`), so the retry is recognised as the same
call. Where no outcome is reported, the loop, rate and budget signals still apply.

**State and privacy.** Each session's record lives in `~/.singularity-aidr/agent-safety/`
(next to the active `config.json`): counters, short fingerprints of recent calls, digests of
written paths and timestamps. It never stores command text, file paths, file contents or the
session id itself. Records are owner-only, written atomically, bounded in size and number
(`max_sessions`, oldest pruned first) and expire after `state_ttl_hours`. Each record carries an
HMAC keyed by a random per-install key; a record that has been edited, replayed from another
session, or replaced by a symlink is not trusted. Sessions are keyed the same way as toxic-flow
detection, so a host that sends no real session id does not merge unrelated agents.

**MCP gateway sessions.** The gateway serves many clients, so it never keys a session by the
client credential alone. A server that issues an `Mcp-Session-Id` gets one record per MCP
session (keyed by a digest of the id, bound to the tenant, client and server). A stateless
server has no conversation id, so its record covers one client's calls to that server through
one gateway process: one MCP connection for a stdio bridge (each bridge runs its own gateway),
and every stateless call from that client to that server until restart for a shared HTTP
gateway. Issue one client credential per agent to keep agents apart there. Records never carry
over into a later gateway run or another bridge process.

The agent cannot reach this state: the self-defense rules deny it any access to
`~/.singularity-aidr` (reading, listing, deleting or rewriting), so it cannot reset its own
counters.

**Failure policy.** The runaway guard is a detection signal. If its state cannot be read,
written or trusted, the signal is skipped and logged, and an otherwise clean call is recorded in
the audit log as `runaway_guard_unavailable` — never as a clean result. A tampered record is
reset. Connector entry points remain fail-closed as always.

## 2. Reward hacking and sabotage

An agent that is told "make the tests pass" can do it by weakening the tests. These rules catch
an agent changing the checks it is supposed to satisfy, or destroying the record of what it did.

**Diff-aware file edits.** For `Write`, `Edit`, `MultiEdit`, `apply_patch` and file deletions,
AIDR compares the lines the edit adds with the lines it removes (for a `Write`, against the file
currently on disk) and considers what kind of file it is. Only the *change* counts: editing a
test that was already skipped, rewording an assertion, or moving lines is not flagged, and a
skip written outside a test file is not a test skip.

| Id | Flags |
|----|-------|
| `CLT-AGENT-RH-101` | A test skipped or disabled in a test file: `it.skip`, `test.todo`, `xit`, `describe.skip`, `@pytest.mark.skip`/`xfail`, `@unittest.skip`, `pytest.skip()`, Go `t.Skip()`, JUnit `@Disabled`/`@Ignore`, Rust `#[ignore]`, xUnit `Skip =`, PHPUnit `markTestSkipped` |
| `CLT-AGENT-RH-102` | Test focus added (`it.only`, `fdescribe`): the rest of the file stops running |
| `CLT-AGENT-RH-103` | Assertions removed or commented out (net fewer assertions in a test file) |
| `CLT-AGENT-RH-104` | Tautological assertions added (`expect(true).toBe(true)`, `assert True`) |
| `CLT-AGENT-RH-105` | A test file deleted, or rewritten so it no longer contains any test |
| `CLT-AGENT-RH-106` | A CI check made non-blocking or disabled: `continue-on-error: true`, `allow_failure`, `if: false`, `\|\| true` after a test/lint command |
| `CLT-AGENT-RH-107` | A test, lint or type-check step removed from CI or a git hook |
| `CLT-AGENT-RH-108` / `-109` | A coverage threshold lowered or removed (`lines`, `branches`, `fail_under`, `--cov-fail-under`, Codecov `target`) |
| `CLT-AGENT-RH-110` | A file-wide suppression added: `// @ts-nocheck`, bare `/* eslint-disable */`, `# pylint: skip-file`, `# mypy: ignore-errors`, `#![allow(warnings)]` |
| `CLT-AGENT-RH-111` | A burst of line-level suppressions in one edit (5 or more `@ts-ignore`, `# type: ignore`, `# noqa`, `eslint-disable-next-line`, `# nosec`) |
| `CLT-AGENT-RH-112` | Lint/type/test configuration weakened: TypeScript `strict` off, a whole source or test tree ignored, a no-op or `\|\| true` test script, `--passWithNoTests` |

**Shell commands.**

| Id | Flags |
|----|-------|
| `CLT-AGENT-RH-001` | Git hooks bypassed: `--no-verify`, `git commit -n`, `core.hooksPath=/dev/null` |
| `CLT-AGENT-RH-002` | Hook managers switched off: `HUSKY=0`, `LEFTHOOK=0`, `SKIP=... git commit` |
| `CLT-AGENT-RH-003` | Force-push to `main`, `master`, `trunk`, `release/*`, `production`, `develop` (not to feature branches) |
| `CLT-AGENT-RH-004` | Shell history erased: `history -c`, `unset HISTFILE`, `HISTSIZE=0`, deleting `~/.bash_history` |
| `CLT-AGENT-RH-005` | Git history rewritten or a protected branch deleted: `git reflog expire`, `filter-branch`, `filter-repo`, `push --delete main` |
| `CLT-AGENT-RH-006` | Log or audit files truncated or deleted: `truncate -s 0`, `: > app.log`, `rm /var/log/...` |
| `CLT-AGENT-RH-007` | System audit logging disabled: `auditctl -e 0`, stopping `auditd`, `journalctl --vacuum-*` |
| `CLT-AGENT-RH-008` | Test files deleted or emptied from the shell (`rm src/x.test.ts`, `rm -rf tests`, `find -name '*.spec.js' -delete`) |
| `CLT-AGENT-RH-009` | Tests edited in place to skip them or strip assertions (`sed -i 's/it(/it.skip(/'`, `sed '/expect/d'`) |
| `CLT-AGENT-RH-010` | Branch protection or a repository ruleset removed through the GitHub API |

All of these `ask`, so legitimate changes (deleting an obsolete test, a planned history
rewrite) go ahead once a person confirms them.

## 3. Autonomy escalation

An agent that starts another coding agent — or a copy of itself — with its approvals or sandbox
switched off escapes the human-in-the-loop entirely. These rules match the launch command (also
through quoting and other shell tricks) and **deny** it at the `balanced` and `paranoid`
sensitivity; at `relaxed` it becomes an `ask`.

| Id | Flags |
|----|-------|
| `CLT-AGENT-AUTO-001` | Claude Code with `--dangerously-skip-permissions` or `--permission-mode bypassPermissions` |
| `CLT-AGENT-AUTO-002` | Codex with `--dangerously-bypass-approvals-and-sandbox`, `--full-auto`, `--yolo`, `-a never`, `--sandbox danger-full-access` |
| `CLT-AGENT-AUTO-003` | Gemini CLI / Qwen Code with `--yolo`, `-y` or `--approval-mode yolo` |
| `CLT-AGENT-AUTO-004` | Cursor Agent with `--force` |
| `CLT-AGENT-AUTO-005` | Aider with `--yes-always` |
| `CLT-AGENT-AUTO-006` | Other agent CLIs with all approvals off (`--dangerously-skip-permissions`, `--dangerously-allow-all`, `--skip-permissions-unsafe`, `--trust-all-tools`, `--allow-all-tools`, `--yolo`) |
| `CLT-AGENT-AUTO-007` | A coding agent spawned detached: `nohup`, `setsid`, `screen -dm`, `tmux new -d`, `Start-Process`, or a trailing `&` |

An agent that is launched normally (with its own permission prompts) is not affected. Changes to
an agent's permission *settings files* are covered by AIDR's data and context-poisoning
protections.

## 4. Irreversible actions

Some actions are legitimate when a person means them and disastrous when an agent does them on
its own. These always `ask` (never deny) and the reason starts with **"Irreversible action:"**.

| Id | Flags | Not flagged (examples) |
|----|-------|------------------------|
| `CLT-AGENT-IRR-001` | `DROP DATABASE/SCHEMA/TABLE`, `TRUNCATE`, `DELETE FROM` without `WHERE` through `psql`, `mysql`, `sqlite3`, `sqlcmd` and other SQL clients | `DELETE ... WHERE id=1`, `SELECT` |
| `CLT-AGENT-IRR-002` | Framework drops and resets: `rails db:drop`, `prisma migrate reset`, `manage.py flush`, `dropdb`, `redis-cli FLUSHALL` | `rails db:migrate` |
| `CLT-AGENT-IRR-003` | `terraform destroy`, `apply -auto-approve`, `pulumi destroy`, `pulumi up --yes`, `cdk destroy` | `terraform plan`, interactive `terraform apply` |
| `CLT-AGENT-IRR-004` | `kubectl delete namespace`, `--all`, persistent volumes; `helm uninstall` | `kubectl delete pod <name>` |
| `CLT-AGENT-IRR-005` - `-007` | AWS, Google Cloud and Azure resource deletion (`aws s3 rb --force`, `terminate-instances`, `delete-db-instance`, `gcloud ... delete`, `az group delete`) | `aws s3 ls`, deleting a single object |
| `CLT-AGENT-IRR-008` | Hosted apps, projects, repositories or releases destroyed (`heroku apps:destroy`, `gh repo delete`, `npm unpublish`) | |
| `CLT-AGENT-IRR-009` | `gh pr merge --admin` (bypasses branch protection), making a repository public | `gh pr merge --squash` |
| `CLT-AGENT-IRR-010` | Publishing: `npm publish`, `twine upload`, `cargo publish`, `gem push`, `nuget push`, `mvn deploy`, `gh release create` | `--dry-run`, `publishToMavenLocal` |
| `CLT-AGENT-IRR-011` | `docker push` to a public registry (Docker Hub, ghcr.io, quay.io, public ECR) | Pushes to a private registry or `localhost` |
| `CLT-AGENT-IRR-012` | Email, SMS or chat messages on your behalf: `sendmail`, `mail -s`, `aws ses send-email`, `aws sns publish`, Slack/Teams/Discord webhooks | |
| `CLT-AGENT-IRR-013` | Payments, refunds and payouts through the Stripe CLI or API | `stripe listen`, `stripe trigger` |
| `CLT-AGENT-IRR-014` | Production deploys: `vercel --prod`, `firebase deploy`, `fly deploy`, `gcloud run deploy`, `git push heroku`, `kubectl apply` to a prod context | `vercel dev`, staging namespaces |

Deletions of files by path (the whole filesystem, home directory, `.git`, database files) were
already covered by AIDR's destructive-command rules and are not duplicated here.

## Tuning

- Switch any rule or runaway signal off with `disabled_threats` (for example
  `["CLT-AGENT-IRR-014"]` if your agents are expected to deploy).
- Raise or lower the runaway thresholds and budgets under `agent_safety.runaway`, or set
  `agent_safety.runaway.enabled` to `false`.
- A call you approve once can be made permanent with the operator allowlist (`aidr allowlist
  add`), exactly as for any other AIDR finding.
- Every finding is written to the audit log with its rule id, so you can see which guardrails
  your agents actually trip before tightening them.

## Limits

- Shell rules see the command line, not what a script it runs does; heredoc bodies and SQL in
  separate files are not parsed.
- Diff-aware checks read the previous version of a written file from disk (regular files up to
  1 MiB); a file that cannot be read is treated as new.
- A force-push without an explicit branch name cannot be tied to a protected branch.
- Repeated-failure detection depends on the host reporting failures (see above); it is not
  available on Codex. Cursor and VS Code markers are read from the result the hook receives;
  a host build that reports failures differently is under-counted, never over-counted.
