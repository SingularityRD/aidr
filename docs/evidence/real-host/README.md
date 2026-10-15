# Real-host evidence records

`claude-code.json`, `codex.json`, `opencode.json` and `openclaw.json` are the
records `pnpm test:e2e:real-host` (`scripts/real-host-e2e/run.mjs`) writes: the
real, unmodified host program with AIDR installed from the development build in
a disposable HOME, driven by a scripted loopback mock model. Each record names
the platform it ran on; it is evidence for that platform only.
`deploy/native/interception-matrix.json` cites them and
`deploy/native/support-matrix.json` pins their SHA-256.

## Windows

The records above were made on Linux x64. Windows evidence comes from the
opt-in workflow **Windows Real-Host E2E**
(`.github/workflows/windows-real-host-e2e.yml`, `workflow_dispatch` only) on a
GitHub-hosted `windows-latest` runner:

| Job | What it runs | Writes |
|---|---|---|
| `real-host` (`claude-code`) | Claude Code (pinned 2.1.282, Bash tool through Git Bash) with AIDR's hooks from this checkout | `windows/claude-code.json` |
| `real-host` (`codex`) | Codex CLI (pinned 0.141.0, shell commands in PowerShell) with AIDR's `PreToolUse` hook | `windows/codex.json` |
| `vscode` | the VS Code extension in a real VS Code Extension Host (pinned VS Code download) | `windows/vscode-extension.junit.xml` |

The records are uploaded as workflow artifacts. A person reviews them (every
scenario, the host versions, the attribution controls) and commits them under
`docs/evidence/real-host/windows/`; only then may the support and interception
matrices cite Windows. A failing scenario is a finding to fix, not a record to
commit.

### What still needs a human on Windows

- **The first runs and their review.** The Windows code paths of the harness
  (profile folders, Git Bash, PowerShell commands for Codex, `.js` entry points)
  were written without a Windows machine; the first run may expose harness
  issues rather than product issues.
- **Cursor.** Cursor's installer and sign-in cannot run unattended on a hosted
  runner; the Cursor extension and Cursor's `agent` CLI need a Windows machine
  with a signed-in Cursor.
- **A real model and interactive sessions.** The tier uses a scripted mock model
  and one non-interactive turn per scenario; approval dialogs, long sessions and
  real model behaviour are a manual acceptance on a Windows workstation.
- **OpenCode and OpenClaw on Windows** are not in the workflow.
- **The signed MSI on clean Windows 10/11 machines**: install, Active Setup for a
  second user, uninstall and the per-user cleanup at the next sign-in, SmartScreen
  and Defender behaviour, Intune/SCCM delivery in the system context.
