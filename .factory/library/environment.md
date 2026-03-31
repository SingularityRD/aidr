# Environment

Environment variables, external dependencies, and setup notes.

## Environment Variables

**Tracing:**
- `TRACE_ENABLED` — Enable OpenTelemetry tracing (default: false)
- `TRACE_SAMPLING` — Sampling rate 0-1 (default: 1.0)
- `TRACE_OTLP_ENDPOINT` — OTLP collector endpoint
- `TRACE_CONSOLE_EXPORTER` — Enable console span export (default: true)
- `TRACE_PROPAGATE_W3C` — Enable W3C trace context propagation (default: true)
- `TRACE_DEBUG` — Enable debug logging (default: false)

**Sentry:**
- `SENTRY_DSN` — Sentry DSN for error tracking
- `SENTRY_ENVIRONMENT` — Environment tag (default: development)

**Rule Sync:**
- `RULE_SYNC_CDN_URL` — CDN endpoint for rule updates
- `RULE_SYNC_POLL_INTERVAL` — Polling interval in minutes (default: 5)
- `RULE_SYNC_EMERGENCY_INTERVAL` — Emergency poll interval in seconds (default: 30)

**E2E Testing:**
- `ANTHROPIC_API_KEY` — Required for Claude Code E2E tests
- `OPENCLAW_GATEWAY_TOKEN` — Override for OpenClaw auth token
- `AIDR_CURSOR_PATH` — Override Cursor executable path
- `AIDR_VSCODE_PATH` — Override VS Code executable path

## External Dependencies

**Runtime:**
- Node.js 18+ (no runtime dependencies for core)

**Build:**
- pnpm 10+
- TypeScript 5.0+

**Optional (for specific features):**
- Docker (for containerized deployment)
- pre-commit (for git hooks)

## Platform Notes

**Windows:**
- Uses PowerShell for some scripts
- Path separators handled by Node.js path module

**macOS/Linux:**
- Full bash script support
- Native binary building via SEA

## What Belongs Here

**Yes:** Required env vars, external API keys/services, dependency quirks, platform-specific notes.

**No:** Service ports/commands (use `.factory/services.yaml`).
