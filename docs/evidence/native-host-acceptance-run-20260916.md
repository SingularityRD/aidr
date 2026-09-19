# Native extension-host acceptance run — 2026-09-16

Real installed IDE hosts running the packaged, built AIDR extension in an
isolated profile. Both runs are the repository's own E2E suite
(`packages/extension/src/__tests__/e2e-suite/index.js`), executed by the
vendor's extension host directly — not by a Vitest worker, because the Vitest
worker fork dies on this Windows host before test bodies run
(`[vitest-pool]: Worker forks emitted error`, exit 3221226505).

## Result

| Host | Executable | Version | Cases | Exit |
|---|---|---|---|---|
| Cursor | `%LOCALAPPDATA%\Programs\cursor\Cursor.exe` | 3.19.7 | **8/8 pass** | 0 |
| VS Code | `%LOCALAPPDATA%\Programs\Microsoft VS Code\Code.exe` | 1.137.0 | **8/8 pass** | 0 |

Raw per-case JSON: `cursor-host-e2e-results.json`, `vscode-host-e2e-results.json`.

Cases exercised in both hosts:

- `configure-workspace-scope` — the extension's own `aidr.<host>.scope` setting
  is written through the real settings API.
- `extension-activates` — activation event fires in a real host.
- `commands-registered` — commands are registered on the real command palette.
- `enable-protection-writes-hooks` — enabling protection writes the managed hook
  file to the workspace (Cursor `.cursor/hooks.json`, VS Code
  `.claude/settings.json`) with the host's managed marker.
- `hook-health-command` — health command runs without error.
- `dangerous-write-blocked` — a dangerous Write payload is blocked by the
  installed managed hook.
- `hook-response-shape-consistent` — hook output shape matches the host contract.
- `disable-protection-removes-hooks` — disabling removes exactly the managed
  entries.

## What this evidence does and does not prove

**Proves:** the packaged extension loads and activates in the real Cursor 3.19.7
and VS Code 1.137.0 extension hosts, registers its commands and settings, writes
and removes its managed hooks, and returns a blocking decision for a dangerous
Write payload through the installed hook.

**Does not prove:** that a real model-driven agent turn had its file side effect
prevented. No agent turn was run here, because no model provider is
authenticated on this machine. `dangerous-write-blocked` exercises the hook
decision path with a fixture payload; it is hook-decision evidence, not
observed side-effect-prevention evidence in a live agent session. This is a
`native_host`-level result for host load/registration/hook wiring, and it does
**not** close `18-native-host`, which additionally requires named QA/Endpoint/
Support acceptance records.

## Isolation

Both runs used an isolated `--user-data-dir`, `--extensions-dir` and (for
VS Code) an isolated `HOME`/`USERPROFILE`, so no normal user profile,
extension set or settings file was read or modified.

## How to reproduce

```powershell
$sandbox = ".release-evidence/native-host-tools-20260916/ide-acceptance/sandboxes/cursor"
$env:AIDR_E2E_HOST = "cursor"
$env:AIDR_E2E_EXTENSION_ID = "singularityrd.aidr-cursor"
$env:AIDR_E2E_SCOPE_SETTING_KEY = "aidr.cursor.scope"
$env:AIDR_E2E_MANAGED_MARKER = "--managed-by aidr-cursor"
$env:AIDR_E2E_HOOK_MODE = "cursor"
$env:AIDR_E2E_HOOKS_RELATIVE_PATH = ".cursor/hooks.json"
$env:AIDR_E2E_HOOK_RUNNER_PATH = "$PWD\packages\extension\dist\aidr-hook.cjs"
$env:AIDR_E2E_RESULTS_FILE = "$sandbox\aidr-e2e-results.json"
& "$env:LOCALAPPDATA\Programs\cursor\Cursor.exe" `
  "--extensionDevelopmentPath=$sandbox/extensions/singularityrd.aidr-cursor-0.6.0" `
  "--extensionTestsPath=$PWD\packages\extension\src\__tests__\e2e-suite\index.js" `
  "$PWD\packages\extension\test-workspace" `
  "--user-data-dir=$sandbox/user-data" "--extensions-dir=$sandbox/extensions" `
  --disable-extensions --disable-workspace-trust --skip-welcome --skip-release-notes `
  --disable-updates --disable-gpu --log error
```

For VS Code use `aidr.vscode.scope`, `--managed-by aidr-vscode`,
`AIDR_E2E_HOOK_MODE=vscode`, `AIDR_E2E_HOOKS_RELATIVE_PATH=.claude/settings.json`
and the VS Code executable. The `AIDR_E2E_*` values are the ones
`HOST_METADATA` in `packages/extension/src/__tests__/e2e.test.ts` supplies to the
same runner; passing a different value fails the suite for the wrong reason.
