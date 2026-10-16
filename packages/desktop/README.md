# Singularity AIDR desktop app (Windows)

`@singularityrd/aidr-desktop` is an Electron app that shows and changes the AIDR
protection of one Windows user, using the product's own code paths.

| Page | What it does | Where the facts come from |
|---|---|---|
| Status (Durum) | AIDR version, rules loaded by the engine, enforcement mode, per-connector state (installed, hook registered, hook program present), last verdict | `detectConnectorStatuses` (CLI, what `aidr status` prints) and the shipped `aidr.exe status --json` |
| Connect / Disconnect Claude Code | Preview (diff of `~/.claude/settings.json`), then `aidr setup --host claude-code` / `aidr uninstall --hooks-only` | The CLI's own `standaloneClaudeSettings` for the preview; the supported CLI paths for the change (backup, idempotent, AIDR-marked hooks only, installation receipt) |
| Prove it works (Çalıştığını kanıtla) | Runs the registered PreToolUse hook exactly as Claude Code does (JSON on stdin) with `ls -la` (expect allow) and a never-executed `curl … \| bash` canary (expect deny); shows verdicts, rule and latency | The hook command in the settings, split into program + arguments and run without a shell |
| Logs (Kayıtlar) | Every audit record type, live: tool calls, prompt checks (UserPromptSubmit), tool-output findings (PostToolUse), plugin scans, incidents, response actions, approvals, exceptions; decision and type filters, search; JSONL/CSV export | `audit.jsonl` in the AIDR data folder and its rotated files (read with the CLI's audit reader); export through `aidr audit export` (redacted, session ids digested) |
| Incidents (Olaylar) | Correlated incidents with severity, status (open/closed), session, connector, first/last seen, event count; severity/status filters; detail with each linked verdict (rule, reason, masked artifact, time); live | `incident_record` entries of the audit log (core's correlator), latest snapshot per incident, events joined to their verdict records by session and time |
| Browser Guard | Chrome/Edge detection of the extension and of the optional native helper; the shipped extension is staged automatically on every start (a stable per-user folder, refreshed when the app updates) and the page opens the browser's extensions page for the one-time "Load unpacked" | Browser profile preference files (read only), `reg query` of the native-messaging keys |
| Settings | Language (Turkish by default on a Turkish system), theme, deny notifications, start at sign-in (off by default) | `preferences.json` in the app's user-data folder |

A tray icon shows protected / not protected. Closing the window keeps the app in the tray
(the audit feed and deny notifications keep running); "Quit" exits.

Test traffic is labelled and never mixed with agent activity: records of the app's
self-test (`öz-test` / `self-test`) and of the canary `aidr setup` sends to a hook before
registering it (`kurulum testi` / `setup canary`).

Everything except Connect, Disconnect, the "Also record allowed calls" toggle
(`logging.log_clean`) and Browser Guard staging is read-only.

## AIDR Privacy ships with the app

AIDR Privacy is installed with the app, nothing extra to download:

- **Browser Guard** (TR/EN personal data and secret masking before a prompt reaches an AI
  chat site) is bundled and staged to `%USERPROFILE%\.singularity-aidr\desktop\browser-guard\chrome`
  on every start. Load that folder once in Chrome or Edge (Browser Guard page → open the
  extensions page → "Load unpacked"); after an app update the browser picks up the new build
  on its next restart. Fleet-wide force-install with a fixed extension ID goes through
  enterprise policy instead (`deploy/browser-guard/`).
- **The AIDR Privacy engine** is part of the bundled `aidr.exe`:
  `aidr privacy-engine [--json] [--redact] < input` masks TCKN, IBAN (mod-97), card numbers
  (Luhn), phones, e-mail addresses and secrets locally and prints the decision as JSON
  (exit 2 when the input must be blocked). A copy or hard link of `aidr.exe` named
  `aidr-privacy.exe` runs the same engine. `aidr privacy scan <file>` remains the
  file-oriented report.

## How the hooks are installed

The app ships the standalone AIDR runtime (`packages/claude-code/scripts/build-sea.mjs`:
one multi-call `aidr.exe` serving the CLI and every hook, plus the rules). On "Connect" it
copies the runtime to a per-user, digest-addressed folder
(`<home>\.singularity-aidr\desktop\runtime\<version>-<manifest digest>\`), verifies every
file against the bundle manifest and runs `aidr setup --host claude-code` from that copy.
The hooks therefore read

```
"C:/Users/<you>/.singularity-aidr/desktop/runtime/<id>/bin/aidr.exe" hook pre-tool-use
```

and keep working when the app is closed, updated or uninstalled. Disconnect runs
`aidr uninstall --hooks-only --yes --json` (with `AIDR_OPERATOR_NONINTERACTIVE=1`, after the
confirmation dialog in the app), which removes only the AIDR-marked hooks and keeps a backup.

## Commands

```powershell
pnpm install; pnpm build                                    # workspace build (core, connectors, CLI)
pnpm --filter @singularityrd/aidr-desktop build             # app code -> dist/
pnpm --filter @singularityrd/aidr-desktop build:runtime     # AIDR runtime + Browser Guard -> build/runtime/
pnpm --filter @singularityrd/aidr-desktop dev               # build, stage if missing, start
pnpm --filter @singularityrd/aidr-desktop dist              # release/: NSIS installer + portable exe
pnpm --filter @singularityrd/aidr-desktop icons             # regenerate assets/icons from branding/singularity-mark.svg
pnpm --filter @singularityrd/aidr-desktop test:smoke        # Electron smoke test (see below)
```

`dist` writes `release/SingularityAIDR-Setup-<version>.exe` (per-user NSIS, no elevation,
`asInvoker`) and `release/SingularityAIDR-Portable-<version>.exe`. Electron fuses are
hardened: no `RunAsNode`, no `NODE_OPTIONS`, no `--inspect`, asar integrity, app only from
the asar.

## Tests

- Unit tests (`src/__tests__`, part of the root `pnpm test`): IPC payload validation and
  exclusivity, the settings-merge preview, runtime copy/verification, the CLI calls for
  connect/disconnect, the self-test against a really spawned hook, audit parsing of every
  record type, tailing and rotation, incident snapshots and verdict joins, protocol path
  containment, Browser Guard detection, TR/EN key parity.
- Smoke test (`e2e/smoke.mjs`, Playwright `_electron`) in a temporary HOME/USERPROFILE:
  connect -> self-test (allow + deny) -> logs -> type filter -> export -> incidents and
  detail -> Browser Guard -> settings -> disconnect -> settings restored. It fails if the
  real `~/.claude/settings.json` changes. Options:
  - `--lang en` (default `tr`)
  - `--real-claude`: drives the real Claude Code CLI against the repository's scripted
    loopback model (`scripts/real-host-e2e`) and checks the block in the CLI and in the feed
  - `--packaged <exe>`: runs against a packaged build. The hardened fuses forbid
    `--inspect`, so build a test package first:
    `npx electron-builder --win dir --config electron-builder.yml -c.directories.output=release-smoke -c.electronFuses.enableNodeCliInspectArguments=true`
  - `--keep`: keep the temporary folder
- Screenshots: `docs/screenshots/<lang>/`.

## Security model

- `contextIsolation` on, `nodeIntegration` off, `sandbox` on.
- One preload exposing two functions (`invoke`, `on`) restricted to the typed channel list
  in `src/shared/contract.ts`; every payload is validated again in the main process and only
  accepted from `app://aidr` pages.
- Pages are served from the app's own `app://` scheme with
  `default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'none'`; every
  non-`app:` request is cancelled (no remote content). No navigation, no new windows, no
  permissions except clipboard write.
- Programs are started with argument arrays, never through a shell. No elevation.

## Signing

Builds here are unsigned. `scripts/sign-windows.cjs` is electron-builder's signer and does
nothing unless `AIDR_DESKTOP_SIGN=1`; then it signs each file through
`scripts/windows-authenticode-signer.ps1` (pfx, Azure Key Vault or jsign HSM backends,
pinned thumbprint and RFC 3161 timestamp checks; `docs/operations/windows-code-signing.md`).
The AIDR runtime under `resources/runtime/` is skipped there because the hooks verify it
against its manifest: sign `aidr.exe` before staging, rewrite the manifests with
`build-sea.mjs --remanifest <dir>`, and for a release use `--flavor release` with
Ed25519-signed manifests.

## Known limits

- The bundled runtime is the development flavour (unsigned manifests); release bundles come
  from the release pipeline.
- Hook latency is about 1.5-2 s per call (up to about 5 s on a cold start): the standalone
  runtime falls back to the PowerShell AMSI backend because core's koffi loader looks for
  `vendor/koffi` next to `bin/` instead of in `dist/` (`packages/core/src/clients/amsi.ts`).
- Browser Guard is not in the Chrome/Edge stores yet and is loaded unpacked. Its native
  helper is registered by an administrator (`packages/browser-guard/docs/native-host.md`);
  the app only reports it.
- "Last verdict" is per audit log, not per connector: audit records do not name the
  connector that wrote them.
