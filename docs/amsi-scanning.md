# AMSI Scanning

Singularity AIDR integrates with the Windows [Antimalware Scan Interface (AMSI)](https://learn.microsoft.com/en-us/windows/win32/amsi/antimalware-scan-interface-portal) to detect malware in tool call content. When a Bash command, file write, or file edit is intercepted, the content is passed to the locally installed antimalware provider (e.g. Windows Defender) for scanning before execution.

## Supported Platforms

| Platform | Support |
|----------|---------|
| Windows 10/11 | Supported (koffi FFI or PowerShell) |
| WSL (Windows Subsystem for Linux) | Supported (PowerShell only) |
| macOS | Not available (skipped at runtime) |
| Linux (non-WSL) | Not available (skipped at runtime) |

AMSI is a Windows API. On macOS and non-WSL Linux the check is silently skipped and has no effect on verdicts. Under WSL, Singularity AIDR detects the WSL environment and uses the PowerShell backend via WSL interop to call the Windows-side AMSI API.

## How It Works

1. When a tool call arrives, Singularity AIDR extracts scannable content from the tool input
2. The content is passed to the AMSI API via the locally installed antimalware provider
3. The provider returns a numeric result indicating whether the content is clean, blocked by admin policy, or detected as malware
4. The result is fed into the decision engine alongside heuristic, URL, and package signals

### What Gets Scanned

| Tool | Content Scanned |
|------|----------------|
| Bash | Command string |
| Write | File content being written |
| Edit | New string content |

Content longer than 1 MB is truncated before scanning.

### Backends

The AMSI client uses two backends with automatic fallback:

1. **Koffi FFI (primary)** - Calls `amsi.dll` directly via the `koffi` (3.x) native FFI package. Fast, but requires the optional `koffi` dependency. Bundled connectors (Claude Code, Cursor/VS Code hook runner, OpenClaw) ship a manifest-covered copy in `dist/vendor/koffi` staged by `scripts/stage-windows-koffi.mjs`: koffi's loader plus the `win32_x64`, `win32_arm64` and `win32_ia32` builds taken from koffi 3's `@koromix/koffi-win32-*` packages. The root `pnpm.supportedArchitectures` setting installs those three packages on every build host.
2. **PowerShell P/Invoke (fallback)** - Spawns PowerShell with embedded C# P/Invoke bindings to the same AMSI API. No extra dependencies required (PowerShell is built into Windows).

On native Windows, the client probes the koffi backend first. If it is unavailable (e.g. `koffi` not installed), it falls back to PowerShell. Under WSL, the koffi backend is skipped (it cannot load Windows DLLs from Linux userspace) and only the PowerShell backend is tried. Hosts without AMSI (macOS, Linux outside WSL) skip the leg entirely, and setting `amsi_check.enabled` to `false` turns it off explicitly.

The PowerShell fallback checks `$ExecutionContext.SessionState.LanguageMode` before it compiles its interop type. Under AppLocker or WDAC, PowerShell runs in `ConstrainedLanguage`, `Add-Type` is refused, and the fallback reports that explicitly instead of failing on `Add-Type`.

### When AMSI is unavailable

Two different situations are kept apart. Neither is ever reported as a clean scan.

| Situation | Example | Verdict of an otherwise-allowed call |
|---|---|---|
| **AMSI cannot run on this host at all**: no backend could be established | koffi missing or blocked, and PowerShell in `ConstrainedLanguage` | Default (`amsi_check.unavailable_action: "annotate"`): stays `allow`, category `amsi_not_available`, with the reason "content was NOT scanned by AMSI; local threat rules still inspected it; not a clean AMSI result". With `"ask"`: `ask`, category `amsi_unavailable`. |
| **A scan failed on a working backend** | PowerShell process died or timed out mid-scan; start-up threw | Always `ask`, category `amsi_unavailable` (source `amsi`). |

This follows the failure policy for optional detection signals: an unavailable signal is skipped, logged and surfaced, never shown as clean. A `deny` or `ask` from another layer is never weakened; it only gains the note.

**Host state record.** A hook is a new process per tool call. So that a host where AMSI cannot run does not pay a PowerShell start (and a warning) on every call, the outcome of the start-up attempt is kept in `~/.singularity-aidr/amsi-state.json`:

- `unavailable` records skip the start-up attempt until they expire: after 24 hours for a `ConstrainedLanguage` refusal, after 1 hour for any other failure, and immediately when the AIDR version or the host changes.
- `available` records only document the backend in use; every call still initialises AMSI and scans.
- The warning "AMSI is unavailable on this host" is logged when the state changes, not on every call.
- The record can only ever make AIDR say "not scanned"; it can never make content look scanned or clean. Like the rest of `~/.singularity-aidr`, it is protected from the agent by the self-defense rules.

**Session start and health.** The Claude Code session-start hook probes AMSI once (in parallel with the plugin scan) and, when AMSI cannot run, shows one notice for the session (English and Turkish): commands and file writes are still checked by local rules but are NOT scanned by AMSI, and `aidr doctor` is the next step. The extended health check reports `amsi` as `degraded` with the recorded reason, `healthy` with the backend, or `not_configured` (no AMSI on the platform, disabled, or not probed yet).

**Latency.** With the native koffi backend a scan is in-process. Without it, every hook process starts PowerShell (about 300 to 500 ms per call). Shipping the manifest-covered koffi build in the Windows installer is therefore the supported configuration; verify it with `aidr doctor` after installation.

> **Note:** WSL-to-Windows process spawning adds overhead compared to native Windows. The PowerShell backend already spawns a new process per scan, so under WSL each scan has additional cross-boundary latency.

## Verdicts

| AMSI Result | Verdict | Confidence | Severity |
|-------------|---------|------------|----------|
| Malware detected (result >= 32768) | `deny` | 1.0 | critical |
| Blocked by admin policy (16384 <= result < 32768) | `deny` | 0.9 | critical |
| Clean (result < 16384) | No signal | - | - |

AMSI deny signals use the `malware` category and take precedence over other signal sources during merge (deny > ask > allow). Clean results produce no signal, so the verdict depends on the other detection layers.

AMSI results are not cached — each tool call triggers a fresh scan.

## Configuration

```json
{
  "amsi_check": {
    "enabled": true
  }
}
```

- `amsi_check.enabled` - set to `false` to disable AMSI scanning. Default: `true`.
- `amsi_check.unavailable_action` - `"annotate"` (default) or `"ask"`; see [When AMSI is unavailable](#when-amsi-is-unavailable).

AMSI scanning is enabled by default and runs on Windows and WSL. On other platforms the setting has no effect.

