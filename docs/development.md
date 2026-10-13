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
| `pnpm ci:local` | Run every `ci.yml` gate locally with a summary table (see [Running CI locally](#running-ci-locally)); `pnpm ci:local:quick` for the fast subset |
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
| `pnpm test:e2e:real-host` | Real Claude Code / Codex / OpenCode / OpenClaw binaries against a scripted mock model (no API keys) |
| `pnpm build:sea` | Build the relocatable, unsigned SEA hook directory (`bin/aidr-sea/`) |
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
| E2E (real host, mock model) | Real host binaries with AIDR installed in a disposable HOME, tool calls scripted by a loopback mock model | `scripts/real-host-e2e/` | `claude` on PATH; network on first run to install the pinned Codex, OpenCode, OpenClaw and Node 24 |

`pnpm test` runs unit and integration tests. E2E is excluded — run separately with `pnpm test:e2e` (all), `pnpm test:e2e:claude`, `pnpm test:e2e:openclaw`, `pnpm test:e2e:opencode`, `pnpm test:e2e:cursor`, `pnpm test:e2e:vscode`, or `pnpm test:e2e:real-host`.

### Real-host E2E with a scripted mock model

`pnpm test:e2e:real-host` (scripts/real-host-e2e/) runs the **real, unmodified host
programs** — Claude Code, Codex CLI 0.141.0, OpenCode 1.18.32 and OpenClaw 2026.9.6
(the last three installed, pinned, into `.ci-local/real-host` on first run, plus a
sha256-verified Node.js 24 for OpenClaw) — with AIDR installed from this checkout's
`pnpm build` output in a disposable HOME. Only the model is replaced: a loopback server
(`mock-llm-server.mjs`) speaks the Anthropic Messages, OpenAI Responses and Chat
Completions streaming protocols and answers each turn with a predetermined tool call,
then a final text. No API key, account or outbound model traffic is involved, and the
host processes get a minimal environment (no proxy, no credentials, no operator HOME).

Each scenario is one non-interactive turn, and the assertions read what the host did,
not what AIDR returned:

| Scenario | Asserted on the host |
|---|---|
| `benign-tool-executes` | the command ran (marker file), its output went back to the model, the connector receipt says `allow` |
| `malicious-tool-blocked` | `curl … \| sh` to a TEST-NET address never ran, AIDR's denial went back to the model, the audit log has the `CLT-CMD-001` deny |
| `malicious-tool-runs-without-aidr` | the same call **does** run with AIDR absent (attribution control; also the `disabled-hook` observation) |
| `credential-canary-read-blocked` | a private-key canary never appears in any model request |
| `secret-prompt-blocked` | a prompt carrying a token never reaches the model; the audit entry has kinds only |
| `secret-tool-output-quarantined` | a token in tool output reaches the model only as AIDR's quarantine notice (Claude Code, OpenCode, OpenClaw) |
| `internal-error-fails-closed` | with AIDR's own integrity check failing (`AIDR_COMMERCIAL=1` against the unsigned build) nothing runs |
| `tool-hook-deadline-fails-closed` | Claude Code: the connector's inspection deadline at its 100 ms floor denies the call |
| `crashed-hook-observed` | Claude Code, Codex: a hook process SIGKILLed before its verdict — the host's policy is recorded (both fail open) |

Each host writes one record (default `.release-evidence/real-host/<connector>.json`).
`--evidence-dir docs/evidence/real-host` refreshes the committed records that
`deploy/native/interception-matrix.json` cites; the support matrix pins their sha256,
so update `acceptanceEvidence` there in the same change. Useful flags: `--host
claude-code,codex`, `--scenario <id>`, `--hosts-dir <dir>` (or `AIDR_REAL_HOST_DIR`),
`--keep` (keep the sandboxes). A selected host that cannot be found fails the run.

What this tier does **not** prove: real model behaviour or detection breadth (the
tool call is scripted), a signed commercial artefact (it loads the development
build), interactive approval dialogs, or any platform other than the one it ran on.
Cursor and VS Code are not covered (their installers could not be fetched in the
environment the records were produced in).

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

### Node.js versions in CI

`.github/workflows/ci.yml` pins every Node line it tests in its top-level `env`:

| Line | Where it runs | Why |
|------|---------------|-----|
| `NODE_VERSION` 22.12.0 | Quality gate (lint, types, every unit/integration suite, release build), Browser Guard, Helm, workflow lint | Minimum supported engine (`engines.node` in the root `package.json`) |
| `NODE_24_VERSION` 24.21.0 | Second leg of the core build + test matrix; the on-prem deployment job | On-prem runtime line: the dashboard image is `node:24.21.0`, esbuild targets `node24`, and `deployment-doctor.mjs` refuses hosts older than Node 24 |
| `PRIVACY_NODE_VERSION` 22.16.0 | `packages/privacy` build/tests and the privacy rule drift gate | `engines.node` floor of `@singularityrd/aidr-privacy` |

The core matrix (`core-node-matrix`) runs the same build and suite on 22.12.0 and
24.21.0, so a change that only works on one line fails CI. Raise a floor by
changing the `env` value, the matrix literal and the `engines` field together;
`scripts/ci-workflows.test.mjs` fails when they disagree.

Every job that runs tests records the agent configuration files an installer can
write under the runner's real home (`~/.claude/settings.json`, `~/.cursor/hooks.json`,
`~/.codex/*`, ...) before the tests and fails if any of them changed afterwards
(`scripts/verify-real-home-untouched.mjs`). Tests must stub `HOME` and
`USERPROFILE` to a temporary directory, as the hook-installer suites do.

## Running CI locally

GitHub Actions is disabled for this organisation, so `.github/workflows/ci.yml` is
not the gate: `pnpm ci:local` is. It runs every gate `ci.yml` runs on your
machine, in one command, and ends with a summary table.

```bash
pnpm ci:local                      # everything; stops at the first failing required step
pnpm ci:local --keep-going         # run everything, then summarise (use before pushing)
pnpm ci:local:quick                # fast subset: lint, tsc, static/contract/readiness/drift gates
pnpm ci:local --list               # groups, steps, commands, timeouts, prerequisites
pnpm ci:local --only helm,privacy  # groups or step ids (repeatable); --skip works the same way
pnpm ci:local --fetch-tools        # provision missing pinned tools into .ci-local/tools first
pnpm ci:local:release --keep-going # release sign-off: every step must PASS (= --release)
```

| Option | Effect |
|--------|--------|
| `--only <group\|id>[,...]` | Run only these groups/steps. The only way to select the opt-in `real-host-e2e` group, which CI also runs only on manual dispatch. |
| `--skip <group\|id>[,...]` | Leave these out (listed under "Not selected" in the summary). |
| `--quick` | Keep steps marked quick: no builds, full suites, coverage, Docker or network. |
| `--keep-going` | Do not stop after the first failing required step. |
| `--fetch-tools` | Download or build missing pinned tools into `.ci-local/tools`, verified exactly as `ci.yml` verifies them: gitleaks, promtool and actionlint from the URL and sha256 pinned in `ci.yml`; Helm through the `ci.yml` install step (GPG signature + checksum), falling back to `go install helm.sh/helm/v3/cmd/helm@<pinned>` (module checksum database) when get.helm.sh is unreachable; Node 24 from nodejs.org checked against `SHASUMS256.txt`. Nothing is committed. |
| `--allow-dirty` | Report the clean-checkout step as SKIPPED instead of failing it when the tree has uncommitted changes. |
| `--strict` | Exit non-zero when any selected step is SKIPPED (full-parity machines). |
| `--release` | Release sign-off profile. Selects every non-opt-in step plus the release-only full-history secret scan (`pnpm verify:secrets`), implies `--strict`, refuses `--only`, `--skip`, `--quick` and `--allow-dirty`, and exits non-zero unless every selected step PASSED (a SKIPPED, NOT RUN or advisory failure fails it). Only `claim-evidence-refresh`, which needs a candidate assembled after this gate, is left out, with that reason in the summary. |
| `--json [file]` | Also write the machine-readable report to `file`; it is always written to `.ci-local/report.json`. |

**Groups**, in execution order: `guards` (real-HOME record/verify and a working-tree
mutation check, wrapped around the whole run), `install`, `hygiene` (clean checkout +
vendored AIG source, repo hygiene, gitleaks secret scan), `lint` (Biome with 0 errors,
knip, jscpd), `check` (tsc), `static` (the `quality:static` node gates, AIG freshness,
Cloudflare Worker contract), `readiness` (validate-backlog, verify-feature-acceptance,
check-generator-determinism, investor metrics), `commercial` (commercial surface,
compliance, claim inventory and evidence freshness), `docs-facts` (brochure and
feature-guide fact tests), `workflows` (ci-workflows contract, actionlint, this runner's
drift test), `supabase` (migration contract, pinned Deno Edge typecheck, the Postgres
container suites), `audit`, `build`, `test` (`pnpm test`), `coverage`, `core-matrix`,
`privacy` (`pnpm test:privacy`, `verify:privacy-rules`), `mcp-gateway`, `browser-guard`
(pin check, build, unit, real-browser E2E, release zips), `onprem` (deployment/air-gap/
customer-kit/license/offline-pack/onprem-* suites, bootstrap/upgrade/backup/config
reference, promtool, compose models, image builds), `helm`, `aig-bridge` (pip-audit +
pytest in `.ci-local/venv/aig-bridge`), `release` (release build, built-artifact
enforcement `verify:enforcement` + `verify:codex`, release signing/provenance contracts,
fleet lifecycles, packed-artifact install, dashboard route smoke, evidence boundary) and the opt-in
`real-host-e2e`.

**How it stays equal to `ci.yml`.** The plan (`scripts/lib/ci-local-plan.mjs`) is an
explicit step catalog with a drift test rather than a mechanical translation, because
a third of the CI steps download tools into `$RUNNER_TEMP`, need a Docker daemon or
assert runner specifics, and would fail or silently no-op on a workstation; an
explicit catalog can say why a step did not run. Where a CI step is self-contained
shell, the local step *is* that step: `ci: [job, step]` executes the literal `run:`
block read from `ci.yml` at run time, with its `env:` and `working-directory:`
(`$RUNNER_TEMP` points into `.ci-local/runner-temp/`). The remaining steps are explicit
commands that name the CI steps they cover, and `pnpm quality:gate` is run as its
individual components so a failure names the gate. `scripts/ci-local.test.mjs` (run by
`ci:local` itself, step `ci-local-drift`) fails when `ci.yml` gains a job or `run:`
step with no local step, when a reference goes stale, when an explicitly covered CI
step starts calling a root script or repo file the local command does not, or when
`quality:gate`/`quality:static` gain a component. It also fails when
`.github/workflows/release-rc.yml` runs a root script (`pnpm <script>`, with
`quality:*` chains expanded) that no local step runs, so a release-only contract cannot
rot between releases. When you add a CI step, add or extend a step in the catalog (or
list it in `CI_ONLY_STEPS` with a reason; release-only scripts go in
`RELEASE_ONLY_SCRIPTS` with a reason).

**Prerequisites and SKIPPED.** A step whose prerequisite is missing is reported as
`SKIPPED` with the exact prerequisite and the fix, in the table and in a separate
SKIPPED section - never as PASS and never silently. Only required failures make the
exit code non-zero (`--strict` also fails on skips; `--release` fails on anything but PASS).

**Step dependencies (NOT RUN).** `package-install` and `route-smoke` consume what
`build-release` writes (the release `dist/` trees and the dashboard build). In `ci.yml`
a failed `pnpm quality:gate` ends the job before they run, so with `--keep-going` they
are reported `NOT RUN` ("needs build-release") when `build-release` failed in the same
run, instead of failing a second time on missing or stale development artefacts.
Selected on their own (`--only route-smoke`), they run against whatever is on disk.

**Unsigned release builds and signed-release evidence.** `pnpm build:release` (and
therefore `ci.yml`'s quality gate and `ci:local`) writes unsigned `dist/` manifests.
The package-level `packages/claude-code/aidr-artifact.manifest.json` and every
`aidr-artifact.manifest.sig` are written only by the signing workflow
(`release-rc.yml`). `pnpm verify:package-install` therefore checks everything else in
an unsigned build and reports the absent signed-release evidence as an explicit
`SKIPPED_WITH_REASON` line (never a pass); shipping only part of that set still fails.
Signed-release mode (`node scripts/verify-package-install.mjs --require-signed`, also
on whenever `AIDR_SIGNING_PUBLIC_KEY_PEM_PATH` is set, as in the release-rc
clean-consumer gate) requires every declared signature and package manifest.

| Prerequisite | Steps | Without it |
|--------------|-------|------------|
| Docker CLI + compose v2 | `onprem-compose` | SKIPPED |
| Docker daemon | `supabase-postgres`, `postgres-gates`, `onprem-dashboard-image`, `onprem-aig-bridge-image` | SKIPPED (the static Supabase checks still run) |
| Network (registry.npmjs.org) | audits, Deno Edge typecheck, Postgres suites, image builds, aig-bridge | SKIPPED |
| gitleaks 8.30.1, promtool, actionlint, Helm 3 | `secret-scan`, `onprem-promtool`, `actionlint`, `helm` | SKIPPED; `--fetch-tools` provisions them |
| Node 24 | `core-node24`; preferred by the `onprem` steps | the Node 24 leg is SKIPPED with a warning; on-prem steps run on the current Node with a WARNING note |
| Python 3.12 | `aig-bridge-*` | SKIPPED |
| PowerShell 7 (`pwsh`) | `fleet-windows` (GitHub's Ubuntu runners ship it) | SKIPPED; `fleet-unix` still runs |
| A non-root user | `fleet-unix` (the installer refuses its test-root mode for uid 0) | SKIPPED |
| Playwright Chromium for the pinned `playwright-core` | `bg-playwright-pin`, `bg-e2e` | SKIPPED; set `PLAYWRIGHT_BROWSERS_PATH` or populate `/opt/pw-browsers` |

Everything else runs on the current Node (the `core-node22` leg records which version
it used; CI pins 22.12.0). Differences from hosted CI that remain: steps run
sequentially in one checkout, `CI` is not set (so artifact manifests do not claim a CI
build host; `AIDR_CI_LOCAL=1` is set instead), and artifacts are not uploaded. Each
step's full output is in `.ci-local/logs/`, and `.ci-local/` is gitignored. The runner
needs bash (Linux, macOS, WSL or Git Bash).

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
4. When ready to release: `pnpm run version` — applies all pending changesets, bumps `package.json` versions, generates per-package changelogs, and syncs non-standard manifests (`plugin.json`, `marketplace.json`, `openclaw.plugin.json`, the Helm `Chart.yaml`)
5. Commit the version bumps and changelog updates

**Non-standard manifest sync:** Changesets only knows about `package.json` files. The `pnpm run version` script automatically runs `scripts/sync-manifests.mjs` after `changeset version` to propagate versions to `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `packages/openclaw/openclaw.plugin.json` and `deploy/helm/aidr/Chart.yaml`. The chart `appVersion` follows the dashboard package version (it is the default tag of every first-party image the chart deploys), and the chart `version` moves with it: a product patch bumps the chart patch, a product minor or major bumps the chart minor; chart majors are reserved for breaking values changes and are made by hand. `pnpm verify:manifests` (part of `quality:static`) fails when any of these manifests disagrees with its package.

**Pre-commit hook:** A `changeset-check` pre-commit hook warns when staged files affect shipped artifacts (source code, threat definitions, allowlists, hooks, skills, plugin manifests) without a corresponding changeset. Bypass with `git commit --no-verify`.

**Browser Guard releases** are versioned separately from the connector packages.
Pushing a protected, PGP-signed annotated tag `browser-guard-vX.Y.Z` (matching
`packages/browser-guard/package.json`) runs `.github/workflows/release-browser-guard.yml`:
unit tests, the real-browser E2E, two release builds that must produce identical
zips, `SHA256SUMS`, a build-provenance attestation and a **draft** GitHub release.
The workflow reads only the tag-signing secrets (`RELEASE_TAG_PGP_PUBLIC_KEY`,
`RELEASE_TAG_PGP_FINGERPRINT`) from the `browser-guard-release` environment; store
submission (Chrome Web Store, Edge Add-ons, AMO) stays a manual step with no store
credentials in CI.

## SEA Binaries (relocatable directory)

`pnpm build:sea` runs `packages/claude-code/scripts/build-sea.mjs`, which builds
Node.js [single executable applications](https://nodejs.org/api/single-executable-applications.html)
for every Claude Code hook and bin entry point on Linux, macOS and Windows. A SEA
blob holds one script, but the hooks read their threat rules, allowlists, the
response worker and the native koffi addon from disk, relative to the binary. The
output is therefore a directory that must be shipped and installed as a whole; a
single binary copied on its own loads no rules and asks on every call:

| Path under `bin/aidr-sea/` (gitignored) | Content |
|---|---|
| `bin/aidr-pre-tool-use`, `aidr-post-tool-use`, `aidr-session-start`, `aidr-user-prompt-submit` (`.exe` on Windows) | `packages/claude-code/dist/<entry>.bundle.cjs` |
| `bin/aidr-health`, `bin/aidr-mcp-server` | `packages/claude-code/dist/health.cjs`, `mcp-server.cjs` |
| `dist/resources/threats`, `dist/resources/allowlists` | the shipped rules and allowlists |
| `dist/response-worker.cjs`, `dist/vendor/`, `dist/native/` | runtime files the bundles load |
| `aidr-artifact.manifest.json` | sha256 of every file above (connector manifest schema) |

The script uses the documented flow, which works on every supported Node
(>= 22.12; it does not depend on `node --build-sea`):

1. bundle the entry points with `esbuild.config.js --release` (no source maps);
2. write `dist/sea-config-<entry>.json` and run `node --experimental-sea-config` to produce the blob (code cache disabled);
3. copy `process.execPath` to the output binary;
4. inject the blob with the locally pinned `postject` devDependency (no `npx`/network), using the
   `NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2` sentinel. On macOS the signature is removed
   first, the blob goes into the `NODE_SEA` Mach-O segment, and the binary is re-signed ad hoc.

It then writes the manifest, copies the directory to a temporary location and runs the relocated
`aidr-pre-tool-use` with an isolated HOME: a pipe-to-shell command must be denied from the
shipped rules and `ls -la` allowed, or the build fails. Because the manifest uses the connector
schema, the relocated hooks also check every rule and allowlist file they read against it. To
re-check a copied distribution:

```bash
node packages/claude-code/scripts/build-sea.mjs --verify /opt/aidr-sea
```

It fails fast when the running Node is older than 20, is a shared-libnode build, or lacks the
SEA sentinel fuse (Homebrew builds) — use the official binary from nodejs.org, nvm/fnm/volta,
or `actions/setup-node` in CI. The output is **unsigned**: sign `aidr-artifact.manifest.json`
with `scripts/sign-artifact-manifest.mjs` (and configure the public key in
`integrity.public_keys_pem` so the rule check is signature-verified) and the binaries with
`codesign`/`signtool` before distribution (postject prints
`warning: The signature seems corrupted!` on Windows, which is expected). No release workflow
builds or ships the SEA directory; the supported distribution is the signed npm/plugin package.

## Building the Extension

See [Building the Extension](../doc/build_extension.md) for Cursor/VS Code VSIX packaging instructions.

---

**Internal team:** See the private internal repo for leak prevention setup, release sync workflows, and pre-release audit instructions.
