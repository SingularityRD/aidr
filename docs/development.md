# Development

## Setup

```bash
git clone https://github.com/singularityrd/aidr
cd aidr
git checkout pre-release
pnpm install
pnpm build
```

Development happens on the `pre-release` branch. The `main` branch is the distribution channel (what users install). See [CONTRIBUTING.md](../CONTRIBUTING.md#branch-policy) for details.

Requires Node.js >= 22.12.0 and pnpm >= 9.

## Commands

| Command | Description |
|---------|-------------|
| `pnpm build` | Build all packages (tsc + esbuild) |
| `pnpm build:release` | Release build (no sourcemaps in `dist/`) |
| `pnpm test` | Run unit + integration tests (builds automatically) |
| `pnpm test -- --reporter=verbose` | Verbose test output |
| `pnpm test -- <file>` | Run a single test file |
| `pnpm test -- -t "name"` | Run tests matching name |
| `pnpm test:types:core-changed` | Type-check the core tests changed in the current hardening pass |
| `pnpm test:coverage:core` | Run the isolated core suite and enforce its package coverage floor |
| `pnpm test:e2e` | All E2E tests (Claude Code + OpenClaw + OpenCode + Cursor + VS Code) |
| `pnpm test:e2e:negative` | Negative credential control: proves missing credentials cannot produce a green E2E run |
| `pnpm test:e2e:claude` | Claude Code E2E tests only |
| `pnpm test:e2e:openclaw` | OpenClaw E2E tests only |
| `pnpm test:e2e:opencode` | OpenCode E2E tests only |
| `pnpm test:e2e:cursor` | Cursor extension E2E tests only |
| `pnpm test:e2e:vscode` | VS Code extension E2E tests only |
| `pnpm build:sea` | Build standalone SEA binaries |
| `pnpm lint` | Lint with Biome |
| `pnpm lint:fix` | Lint + auto-fix |
| `pnpm check` | Type check all packages |
| `node scripts/check-no-sourcemaps.mjs` | Verify built `dist/` artifacts contain no sourcemaps |
| `pnpm changeset` | Create a changeset for your changes |
| `pnpm run version` | Apply changesets: bump versions, generate changelogs, sync manifests |

## Test Tiers

| Tier | Scope | Files | Requires |
|------|-------|-------|----------|
| Unit | Core library | `packages/core/src/__tests__/*.test.ts` | dev deps only |
| Integration | Hook/plugin entry points | `packages/claude-code/src/__tests__/`, `packages/openclaw/src/__tests__/e2e-integration.test.ts`, `packages/opencode/src/__tests__/integration.test.ts` | dev deps only |
| E2E (Claude Code) | Full plugin in Claude CLI | `packages/claude-code/src/__tests__/e2e.test.ts` | `claude` CLI + `ANTHROPIC_API_KEY` |
| E2E (OpenClaw) | Full plugin in OpenClaw gateway | `packages/openclaw/src/__tests__/e2e.test.ts` | OpenClaw gateway + `OPENCLAW_GATEWAY_TOKEN` |
| E2E (OpenCode) | OpenCode CLI smoke test | `packages/opencode/src/__tests__/e2e.test.ts` | OpenCode CLI executable |
| E2E (Cursor extension) | Singularity AIDR extension in Cursor Extension Host | `packages/extension/src/__tests__/e2e.test.ts` | Installed Cursor executable (`agent` CLI required for headless Cursor-agent sub-suite) |
| E2E (VS Code extension) | Singularity AIDR extension in VS Code Extension Host | `packages/extension/src/__tests__/e2e.test.ts` | Installed VS Code executable |

`pnpm test` runs unit and integration tests. E2E is excluded — run separately with `pnpm test:e2e` (all), `pnpm test:e2e:claude`, `pnpm test:e2e:openclaw`, `pnpm test:e2e:opencode`, `pnpm test:e2e:cursor`, or `pnpm test:e2e:vscode`.

The isolated core coverage gate currently prevents regression below 83% lines, 80% statements, 72% branches, and 84% functions. On the current tree the isolated run measures about 83.7% lines, 80.2% statements, 72.6% branches, and 84.7% functions; raise the enforced floors as coverage improves rather than lowering or bypassing the gate.

**Claude Code E2E prerequisites:** `claude` CLI in PATH, valid `ANTHROPIC_API_KEY`, and Singularity AIDR must **not** be installed via the Claude Code marketplace (duplicate-plugin conflict with `--plugin-dir`).

### Release E2E gate and evidence

`pnpm test:e2e` is fail-closed. The capability inventory is versioned in [`scripts/e2e-release-manifest.json`](../scripts/e2e-release-manifest.json); it declares each connector, its expected test count, the source test file, capabilities and prerequisites. The runner rejects missing or unexpected test files, test-count mismatches, zero collected tests, skipped/pending/todo assertions, failed assertions, failed Vitest processes, or missing JSON/JUnit evidence.

Every run writes machine-readable evidence to `.e2e-artifacts/release/`:

- `summary.json` — manifest-to-result mapping with collected, executed, passed, failed, pending and todo counts plus failure reasons.
- `<suite>.json` — Vitest assertion evidence.
- `<suite>.xml` — JUnit evidence for CI and investor/customer validation packets.

An exit code of `0` means every manifest assertion was collected, executed and passed. A zero exit code from Vitest alone is not sufficient because Vitest considers skipped suites successful. A missing host, binary, gateway or model credential is therefore an intentional release `NO-GO`, never an automatic pass. Run `pnpm test:e2e:negative` to verify the missing-credential control.

#### Negative credential control vocabulary

`pnpm test:e2e:negative` proves that the release gate refuses to run with credentials
removed. It never treats an unavailable environment as a product defect, and it never
turns a genuinely accepted negative case into a skip. Every scenario is classified into
this fixed vocabulary in `.e2e-artifacts/negative-credentials/summary.json`:

| Status | Meaning |
|--------|---------|
| `PASS` | The negative case was correctly refused, and the host/inputs the suite needs are present, so the refusal is attributable to the input the control removed. |
| `FAIL` | The negative case was wrongly accepted (at least one assertion executed). A product defect; always exits non-zero. |
| `HOST_UNAVAILABLE` | The host binary or extension host is not installed on this machine. An environment blocker. |
| `BLOCKED_EXTERNAL` | A credential, gateway or customer input is missing. An environment blocker. |
| `UNSUPPORTED` | The scenario is not advertised for this platform/architecture. |
| `SETUP_FAILURE` | The control could not be exercised (missing build artifacts, unreadable evidence, no refusal evidence). Exits non-zero: an unusable control never reports `PASS`. |

Exit code `0` means no negative case was wrongly accepted. When the only non-`PASS`
scenarios are `HOST_UNAVAILABLE`/`BLOCKED_EXTERNAL`/`UNSUPPORTED`, the summary reports
`decision: "NO-GO"`, `status: "blocked"` and the exact hosts and inputs that are missing:
the control observed no product defect, and the release gate `pnpm test:e2e` remains the
fail-closed `NO-GO` for that environment. Any `FAIL` or `SETUP_FAILURE` exits `1`.

### Cursor / VS Code E2E Setup

The extension E2E tests run inside a real Extension Host process using installed IDE binaries. They do not download IDEs.

**Prerequisites:**

- Cursor E2E: installed Cursor executable
- Cursor headless agent E2E: `agent` CLI in `PATH` (or `AIDR_AGENT_PATH`), authenticated via `agent login` or `CURSOR_API_KEY`
- VS Code E2E: installed VS Code executable
- Extension must be built (handled by Vitest `globalSetup`)
- IDE extension-host E2E is opt-in: set `AIDR_E2E_ENABLE_IDE_HOST=1`

**Optional executable overrides:**

| Variable | Description |
|----------|-------------|
| `AIDR_E2E_ENABLE_IDE_HOST` | Set to `1` to enable real IDE Extension Host E2E suites |
| `AIDR_CURSOR_PATH` | Absolute path to the Cursor executable |
| `AIDR_AGENT_PATH` | Absolute path to the `agent` CLI used by Cursor headless E2E |
| `AIDR_VSCODE_PATH` | Absolute path to the VS Code executable |
| `VSCODE_EXECUTABLE_PATH` | Alternate VS Code executable override |

For direct developer commands, an unavailable host executable or agent is represented as a skipped suite. The release command (`pnpm test:e2e`) treats that same skip as a hard failure. Cursor's release capability includes the authenticated headless agent; VS Code's capability intentionally excludes it.
Extension hooks always exit with code `0`; the host reads the JSON response from stdout to determine the verdict.

**Running the tests:**

```bash
AIDR_E2E_ENABLE_IDE_HOST=1 pnpm test:e2e:cursor
AIDR_E2E_ENABLE_IDE_HOST=1 pnpm test:e2e:vscode
```

### OpenClaw E2E Setup

The OpenClaw E2E tests connect to a running OpenClaw gateway with Singularity AIDR installed.

**Prerequisites:** The tests read `~/.openclaw/openclaw.json` for the auth token and check that the chat completions endpoint is enabled. Direct developer runs skip when either is missing; the release runner records that as `NO-GO`.

Enable the endpoint in `~/.openclaw/openclaw.json`:

```json
{
  "gateway": {
    "http": {
      "endpoints": {
        "chatCompletions": { "enabled": true }
      }
    }
  }
}
```

**Optional environment variables:**

| Variable | Default | Description |
|----------|---------|-------------|
| `OPENCLAW_GATEWAY_TOKEN` | read from `~/.openclaw/openclaw.json` | Override the gateway auth token |
| `OPENCLAW_E2E_HOST` | `http://localhost:18789` | Gateway URL |
| `OPENCLAW_E2E_MODEL` | `claude-3-5-haiku-latest` | Model to use |

**Running the gateway with Docker:**

Use OpenClaw's `OPENCLAW_EXTRA_MOUNTS` to mount the built Singularity AIDR plugin into the gateway container. Set the variable before running `docker-setup.sh`, which generates `docker-compose.extra.yml` with the mount:

```bash
# Build Singularity AIDR first
pnpm build

# Set the mount and run setup (generates docker-compose.extra.yml)
export OPENCLAW_EXTRA_MOUNTS="AIDR_PROJECT_DIR/packages/openclaw:/home/node/.openclaw/extensions/aidr:ro"
./docker-setup.sh

# If the gateway is already set up, re-run docker-setup.sh to regenerate
# the extra compose file, then restart:
docker compose up -d
```

This mounts the built `packages/openclaw/` directory (containing `dist/`, `resources/`, `package.json`, and `openclaw.plugin.json`) into the gateway's extensions directory where plugin discovery finds it. See the [OpenClaw Docker guide](https://docs.openclaw.ai/install/docker) for details.

**Tip:** Disable the security awareness skill on the gateway agent during E2E testing. The skill teaches the model to recognise dangerous patterns, which can cause it to self-refuse commands instead of calling the tool and letting Singularity AIDR's `before_tool_call` hook handle them.

**Running the tests:**

```bash
pnpm test:e2e:openclaw
```

## Project Layout

```
aidr/
├── packages/
│   ├── core/           @singularityrd/aidr-core - detection engine
│   ├── claude-code/    @singularityrd/aidr-claude-code - Claude Code hooks
│   ├── openclaw/       @singularityrd/aidr-openclaw - OpenClaw connector
│   ├── opencode/       @singularityrd/aidr-opencode - OpenCode plugin
│   └── extension/      Cursor and VS Code extensions
├── threats/            YAML threat definitions
├── allowlists/         Trusted domain allowlists
├── hooks/              hooks.json for Claude Code
├── skills/             Security awareness skill
├── scripts/            Build utilities
└── doc/                Internal specs and plans
```

## Tooling

| Tool | Version | Purpose |
|------|---------|---------|
| Node.js | >= 22.12.0 | Runtime |
| pnpm | >= 9 | Workspace management |
| TypeScript | ^5.9 | Type checking |
| esbuild | ^0.25 | Bundle hooks into single CJS files |
| Biome | ^1.9 | Linting + formatting |
| vitest | ^4.0 | Test runner |
| zod | ^3.24 | Schema validation |
| yaml | ^2.7 | YAML parsing |

## Conventions

- **Naming split:** YAML/JSON data uses `snake_case` (`threat_id`, `source_file`). TypeScript uses `camelCase` (`threatId`, `sourceFile`). Conversion functions handle the boundary.
- **Failure policy is per layer, not a blanket fail-open:**
  - *Detection internals* (a threat rule that errors, an optional reputation lookup, cache/intel/policy load) skip that signal, log it and continue. This must never be reported to the user as a clean result.
  - *Connector entry points* fail **closed**: Claude Code, OpenClaw, OpenCode, Codex and the Cursor/VS Code hook return a deny (or block) on an internal error rather than silently allowing the call. Extension hooks always exit with code `0` and emit a deny verdict.
  - *Security controls* (auth, tenant isolation, rate limits, webhook signatures, approval) fail closed.
- **Detection patterns are data.** No hardcoded patterns - all rules live in `threats/*.yaml`.
- **Versioning:** See [Versioning](#versioning) below.

## Versioning

This project uses [Changesets](https://github.com/changesets/changesets) with **linked mode** — all five packages (`@singularityrd/aidr-core`, `@singularityrd/aidr-claude-code`, `@singularityrd/aidr-openclaw`, `@singularityrd/aidr-opencode`, `aidr-cursor`) sync versions when released together, but individual packages can be bumped independently.

**Workflow:**

1. Make your changes
2. Run `pnpm changeset` — select affected packages and bump type (patch/minor/major)
3. Commit the generated `.changeset/*.md` file alongside your code changes
4. When ready to release: `pnpm run version` — applies all pending changesets, bumps `package.json` versions, generates per-package changelogs, and syncs non-standard manifests (`plugin.json`, `marketplace.json`, `openclaw.plugin.json`)
5. Commit the version bumps and changelog updates

**Non-standard manifest sync:** Changesets only knows about `package.json` files. The `pnpm run version` script automatically runs `scripts/sync-manifests.mjs` after `changeset version` to propagate versions to `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, and `packages/openclaw/openclaw.plugin.json`.

**Pre-commit hook:** A `changeset-check` pre-commit hook warns when staged files affect shipped artifacts (source code, threat definitions, allowlists, hooks, skills, plugin manifests) without a corresponding changeset. Bypass with `git commit --no-verify`.

## Standalone Binaries (SEA)

`pnpm build:sea` runs `packages/claude-code/scripts/build-sea.mjs`, which builds
Node.js [single executable applications](https://nodejs.org/api/single-executable-applications.html)
for the Claude Code hooks on Linux, macOS and Windows:

| Output (`bin/`, gitignored) | Entry bundle |
|---|---|
| `aidr-pre-tool-use` (`.exe` on Windows) | `packages/claude-code/dist/pre-tool-use.cjs` |
| `aidr-session-start` (`.exe` on Windows) | `packages/claude-code/dist/session-start.cjs` |

The script uses the documented flow, which works on every supported Node
(>= 22.12; it does not depend on `node --build-sea`):

1. bundle the entry points with `esbuild.config.js`;
2. write `dist/sea-config-<entry>.json` and run `node --experimental-sea-config` to produce the blob (code cache disabled);
3. copy `process.execPath` to the output binary;
4. inject the blob with the locally pinned `postject` devDependency (no `npx`/network), using the
   `NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2` sentinel. On macOS the signature is removed
   first, the blob goes into the `NODE_SEA` Mach-O segment, and the binary is re-signed ad hoc.

It fails fast when the running Node is older than 20, is a shared-libnode build, or lacks the
SEA sentinel fuse (Homebrew builds) — use the official binary from nodejs.org, nvm/fnm/volta,
or `actions/setup-node` in CI. Windows binaries are unsigned (postject prints
`warning: The signature seems corrupted!`, which is expected); sign them with `signtool`
before distribution. Smoke test:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"ls"},"session_id":"t","hook_event_name":"PreToolUse","cwd":"."}' | ./bin/aidr-pre-tool-use
```

## Building the Extension

See [Building the Extension](../doc/build_extension.md) for Cursor/VS Code VSIX packaging instructions.

---

**Internal team:** See the private internal repo for leak prevention setup, release sync workflows, and pre-release audit instructions.
