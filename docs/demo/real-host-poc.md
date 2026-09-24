# Real OpenCode host, offline AIDR acceptance

This is a reproducible **real-host / fake-model** check, not a cloud or real-LLM demonstration. It runs the installed OpenCode binary with the existing AIDR plugin and core `dist` files in a disposable profile and workspace. A deterministic OpenAI-compatible provider listens only on `127.0.0.1`; the test sends no prompt to an external model or cloud service and never reads the user's OpenCode profile.

On the Windows test machine with OpenCode 1.18.32 installed:

```powershell
pnpm verify:opencode-host-offline 'C:\Users\anill\AppData\Roaming\npm\node_modules\opencode-ai\bin\opencode.exe'
```

Supply the absolute path to another installed `opencode.exe` if needed. Existing `packages/opencode/dist/index.js`, `packages/core/dist/index.js`, and the local `@opencode-ai/plugin` dependency must already be present; the verifier does not build or install them. A pass requires OpenCode's own `tool_use` events and file side effects, not a direct call to the AIDR plugin:

| Synthetic tool call through OpenCode | Required observation |
| --- | --- |
| Write a synthetic `.env` file | AIDR-attributed host error; file absent |
| Write example-only AWS/DB credential text to a neutral file | AIDR-attributed host error; file absent |
| Write a harmless note | Host tool completed; file content matches exactly |

The script prints one `PASS` line per case, exits nonzero on any mismatch, and removes its checked temporary directory. It also checks that the tool call came from the loopback fake model. No destructive shell command is executed.

This proves local OpenCode host dispatch and two tool-boundary denials in an isolated fixture. It does **not** prove actual model behaviour, coverage of every attack, customer policy configuration, cloud event delivery, dashboard display, or a releasable signed candidate. A cloud-hosted PoC requires a separately enrolled managed installation, an isolated pilot, a freshly deployed signed candidate, and an end-to-end check of the cloud intake acknowledgement and Events row. Do not describe this offline test as that cloud proof.
