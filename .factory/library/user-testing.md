# Singularity AIDR - Testing Surface Documentation

## Test Tiers

| Tier | Scope | Files | Requires |
|------|-------|-------|----------|
| 1 — Unit | Core library functions | `packages/core/src/__tests__/*.test.ts` | pnpm dev deps |
| 2 — Integration | Hook/plugin entry points | `packages/claude-code/src/__tests__/`, `packages/openclaw/src/__tests__/e2e-integration.test.ts`, `packages/opencode/src/__tests__/integration.test.ts` | pnpm dev deps |
| 3 — E2E (Claude Code) | Full plugin in Claude CLI | `packages/claude-code/src/__tests__/e2e.test.ts` | `claude` CLI + `ANTHROPIC_API_KEY` |
| 3 — E2E (OpenClaw) | Full plugin in OpenClaw gateway | `packages/openclaw/src/__tests__/e2e.test.ts` | OpenClaw gateway + `OPENCLAW_GATEWAY_TOKEN` |
| 3 — E2E (OpenCode) | OpenCode CLI smoke test | `packages/opencode/src/__tests__/e2e.test.ts` | OpenCode CLI executable |
| 3 — E2E (Cursor extension) | Singularity AIDR extension in Cursor Extension Host | `packages/extension/src/__tests__/e2e.test.ts` | Installed Cursor executable |
| 3 — E2E (VS Code extension) | Singularity AIDR extension in VS Code Extension Host | `packages/extension/src/__tests__/e2e.test.ts` | Installed VS Code executable |

## Running Tests

### Unit and Integration Tests (Tier 1-2)

```bash
pnpm test                                    # Run all unit + integration tests
pnpm test -- --reporter=verbose              # Verbose output
pnpm test -- packages/core/src/__tests__/extractors.test.ts  # Single test file
pnpm test -- -t "test name"                  # Run tests matching name
```

### E2E Tests (Tier 3)

```bash
pnpm test:e2e                                # All E2E tests
pnpm test:e2e:claude                         # Claude Code E2E only
pnpm test:e2e:openclaw                       # OpenClaw E2E only
pnpm test:e2e:opencode                       # OpenCode E2E only
pnpm test:e2e:cursor                         # Cursor extension E2E only
pnpm test:e2e:vscode                         # VS Code extension E2E only
```

## E2E Prerequisites

### Claude Code E2E

**Requirements:**
- `claude` CLI in PATH
- Valid `ANTHROPIC_API_KEY`
- Singularity AIDR **not** installed via Claude Code marketplace (conflicts with `--plugin-dir`)

### OpenClaw E2E

**Requirements:**
- Running OpenClaw gateway with Singularity AIDR installed
- Auth token in `~/.openclaw/openclaw.json` (or `OPENCLAW_GATEWAY_TOKEN` env var)

**Gateway Setup:**

```bash
# Build Singularity AIDR first
pnpm build

# Set the mount and run setup
export OPENCLAW_EXTRA_MOUNTS="AIDR_PROJECT_DIR/packages/openclaw:/home/node/.openclaw/extensions/aidr:ro"
./docker-setup.sh

# Restart gateway
docker compose up -d
```

**Optional Environment Variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCLAW_GATEWAY_TOKEN` | from `~/.openclaw/openclaw.json` | Override auth token |
| `OPENCLAW_E2E_HOST` | `http://localhost:18789` | Gateway URL |
| `OPENCLAW_E2E_MODEL` | `claude-3-5-haiku-latest` | Model to use |

### OpenCode E2E

**Requirements:**
- OpenCode CLI executable available

### Cursor Extension E2E

**Requirements:**
- Installed Cursor executable
- For headless agent sub-suite: `agent` CLI in PATH + valid auth

**Optional Environment Variables:**

| Variable | Description |
|----------|-------------|
| `AIDR_E2E_ENABLE_IDE_HOST=1` | Enable real IDE Extension Host E2E suites |
| `AIDR_CURSOR_PATH` | Absolute path to Cursor executable |
| `AIDR_AGENT_PATH` | Absolute path to `agent` CLI |

**Running:**

```bash
AIDR_E2E_ENABLE_IDE_HOST=1 pnpm test:e2e:cursor
```

### VS Code Extension E2E

**Requirements:**
- Installed VS Code executable

**Optional Environment Variables:**

| Variable | Description |
|----------|-------------|
| `AIDR_E2E_ENABLE_IDE_HOST=1` | Enable real IDE Extension Host E2E suites |
| `AIDR_VSCODE_PATH` | Absolute path to VS Code executable |
| `VSCODE_EXECUTABLE_PATH` | Alternate VS Code executable override |

**Running:**

```bash
AIDR_E2E_ENABLE_IDE_HOST=1 pnpm test:e2e:vscode
```

## Test Configuration

- **Unit/Integration:** `vitest.config.ts`
- **E2E:** `vitest.e2e.config.ts`
- **Coverage:** Built-in via `@vitest/coverage-v8`

## Coverage

```bash
pnpm test:coverage                           # Run tests with coverage report
```

## Test Conventions

- Tests auto-build via `globalSetup` before running
- E2E tests are excluded from default `pnpm test` run
- Extension hooks always exit with code `0` during tests
- Tests use fail-open behavior matching production
