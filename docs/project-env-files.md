# Project `.env` files

This page states how Singularity AIDR treats the developer's own environment
files, the `.env` files of the project the agent is working in. Before this
policy the handling was inconsistent: `cat .env` asked for approval, while
`source .env`, `grep KEY .env` and `printenv`, which expose the same values,
were allowed. A handful of `.env` variants in one repository could also use up
the session's sensitive-file threshold and raise a "bulk sensitive access"
finding during ordinary work.

## What counts as a project environment file

A path is a *project environment file* when all of these hold:

- Its name is `.env` or `.env.<name>`, such as `.env.local`, `.env.test` or
  `.env.development`. Template names hold no live secrets and are not
  sensitive at all: `.env.example`, `.env.sample`, `.env.template`,
  `.env.dist`, `.env.default(s)`.
- It is inside the session's working directory. That means a relative path
  without a `..` escape (`.env`, `./config/.env.test`) or an absolute path
  under that directory.
- It is written literally. A path with `~`, `$VAR`, `%VAR%`, a glob or a
  command substitution does not qualify.
- It is not a link to somewhere else. A `.env` that is a symbolic link to a
  file outside the project, or a dangling link, does not qualify.
- The command does not change directory first (`cd`, `pushd`,
  `Set-Location`, …). After a directory change the relative path no longer
  points into the project.
- The working directory is a project. When the agent runs in the filesystem
  root or in the home directory, nothing qualifies.

## Policy

| Action | Project environment file | Any other `.env`, `~/.aws`, `~/.ssh`, other credential stores |
|---|---|---|
| Load it into a process (`source .env`, `dotenv -e .env`, `docker --env-file .env`) or print the environment (`printenv`) | allow | unchanged (rules apply) |
| Read it into the agent's context: `cat`, `head`, `less`, the Read tool | ask by default; **allow** with the opt-in `project_env_reads: "auto"` (balanced/relaxed) or `"allow"` | ask, as before |
| Copy, move, archive or encode it (`cp .env /tmp/x`, `tar … .env`, `$(base64 .env)`) | ask, as before | ask, as before |
| Write or append to it, or delete it | ask, as before | ask, as before |
| Send it anywhere (`cat .env \| curl -d @- …`, or a later upload in the same session) | **exfiltration chain: ask or deny** | exfiltration chain: ask or deny |

Reading and loading the project's own configuration is everyday development
work; an administrator who accepts that can opt in to treating a read like a
load (`project_env_reads: "auto"`). The default still asks. Moving the file elsewhere or sending it
out is still caught. Every read is still recorded in the session flow as
secret-grade material. A later call that sends data out, such as
`curl -d @notes.txt https://…`, `scp` or an MCP "send" tool, is therefore an
`exfil_chain` toxic-flow finding (see [toxic-flow](toxic-flow.md)), whether it
comes in the same call or later in the session.

Exactly three rules are affected, and only when every `.env` reference in the
call is a project environment file:

- `CLT-CRED-004`, reading a secret file from the shell.
- `CLT-FILE-008` and `LLM-FILE-001`, a file tool on a secret file.

For a shell command the rule is re-checked with the project `.env` references
neutralised. `cat .env ~/.aws/credentials` therefore still asks, because the
second path still matches.

### Configuration

`project_env_reads` sets the read behaviour:

- `"ask"` (default): always ask.
- `"auto"` (opt-in): allow, except under `sensitivity: "paranoid"`.
- `"allow"` (opt-in): always allow.

Exfiltration tracking does not depend on this setting.

## Session threshold

The bulk-sensitive-access chain (`toxic_flow.bulk_sensitive_threshold`,
default 5) counts *distinct* credential stores read within the flow window. All
of a project's environment files now count as **one** store. Reading `.env`,
`.env.local`, `.env.test` and `config/.env.test`, by any spelling of the path,
contributes one entry. A sweep across real credential stores is still caught:
the project's environment files plus `~/.netrc`, `~/.pgpass`, `~/.kube/config`
and `~/.aws/credentials` reach the threshold.

## Implementation

- `packages/core/src/project-env.ts`: the definition above and the rule
  filter.
- `packages/core/src/toxic-flow-classify.ts`: groups the project's
  environment files into one flow target.
- Tests: `packages/core/src/__tests__/project-env.test.ts`.
