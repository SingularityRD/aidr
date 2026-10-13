/**
 * Pure planning layer for `pnpm ci:local` (scripts/ci-local.mjs).
 *
 * GitHub Actions is disabled for this organisation, so every gate that
 * .github/workflows/ci.yml would run has to be runnable on a workstation with
 * one command. This module holds everything that does not touch the machine:
 * the step catalog, step selection, prerequisite evaluation, ci.yml resolution,
 * the drift check against ci.yml and the summary / exit-code logic. The runner
 * (scripts/ci-local.mjs) probes the host, provisions tools and executes.
 *
 * ## How the local plan relates to ci.yml (hybrid, drift-tested)
 *
 * A step is one of:
 *
 *   - `ci: [job, step]` - the command IS the literal `run:` block of that ci.yml
 *     step, read at run time and executed with the step's `env:` and
 *     `working-directory:`. Used wherever the CI shell is self-contained, so the
 *     local run cannot drift from CI for those steps.
 *   - `run: "<shell>"` - an explicit command, with `covers:` naming the ci.yml
 *     steps it stands in for. Used where the CI shell cannot run locally as
 *     written: it downloads a tool into $RUNNER_TEMP on every run (gitleaks,
 *     promtool, actionlint, Helm), asserts an exact runner Node patch version
 *     (core matrix), or is the `pnpm quality:gate` chain, which is decomposed
 *     into its components so a failure names the gate that failed.
 *   - `internal` - implemented by the runner (Playwright pin check, tree guard).
 *
 * `computeDrift` then fails (via scripts/ci-local.test.mjs, which ci:local runs
 * itself) when ci.yml gains a job or a `run:` step with no local counterpart,
 * when a `covers:`/`ci:` reference goes stale, when an explicitly covered CI
 * step starts calling a root script or repo file the local command does not,
 * or when `quality:gate` / `quality:static` gain a component. Deriving the
 * whole plan mechanically was rejected: a third of the CI steps download
 * tools, need a Docker daemon or assert runner specifics, and would either fail
 * or silently no-op on a workstation; an explicit catalog can say *why* a step
 * is skipped instead.
 */

import { CANDIDATE_DIGEST_SOURCE } from "../generate-v8-evidence-index.mjs";

export const CI_WORKFLOW_PATH = ".github/workflows/ci.yml";
export const LOCAL_DIR = ".ci-local";
export const REPORT_PATH = `${LOCAL_DIR}/report.json`;
const REPORT_SCHEMA = "aidr.ci-local.report/v1";

/** CI step that runs the decomposed root-script chain. */
const DECOMPOSED_CI_STEP = Object.freeze({
	job: "quality-gate",
	step: "Type, lint, audit, tests, coverage and release build",
	script: "quality:gate",
});

/** Root scripts that are pure `&&` chains and are expanded into their components. */
const CHAIN_SCRIPT = /^quality:/u;

/**
 * ci.yml `run:` steps deliberately without a local counterpart. An entry needs a reason.
 * @type {ReadonlyArray<{job: string, step: string, reason: string}>}
 */
export const CI_ONLY_STEPS = Object.freeze([
	{
		job: "privacy-platform",
		step: "Provision isolated real parser dependencies",
		reason:
			"Runner provisioning: installs apt packages with sudo and a hash-locked parser venv into RUNNER_TEMP; a developer host supplies its own AIDR_PYTHON instead of ci:local mutating the system.",
	},
	{
		job: "posture-scanner-supply-chain",
		step: "govulncheck the vendored Go module (pinned)",
		reason:
			"Needs the Go toolchain (GOTOOLCHAIN-fetched go1.27.2) and vuln.go.dev; locally run it from vendor/ai-infra-guard with the same GOTOOLCHAIN and go run golang.org/x/vuln/cmd/govulncheck@<GOVULNCHECK_VERSION> ./...",
	},
	{
		job: "posture-scanner-supply-chain",
		step: "Trivy scan and SBOM of the vendored tree (pinned)",
		reason:
			"Downloads the sha256-pinned Trivy release and its vulnerability DB into RUNNER_TEMP; ci:local provisions no Trivy. Run the step's trivy fs commands by hand with the same pinned release.",
	},
	{
		job: "fleet-windows",
		step: "Build native Claude fleet payload",
		reason:
			"Windows-runner build preparation for the native lifecycle gate; locally the same release bytes come from the build-release step.",
	},
]);

const MIN = 60_000;
const DEFAULT_TIMEOUT_MS = 10 * MIN;

/**
 * Prerequisites a step can declare. `fix` is printed verbatim when the
 * prerequisite is missing, so it must say exactly what to install or set.
 */
export const REQUIREMENTS = Object.freeze({
	"docker-cli": {
		label: "docker CLI with the compose v2 plugin",
		fix: "Install Docker Engine or Docker Desktop; `docker compose version` must succeed.",
	},
	"docker-daemon": {
		label: "a reachable Docker daemon",
		fix: "Start Docker (dockerd / Docker Desktop); `docker info` must succeed for the current user.",
	},
	network: {
		label: "outbound HTTPS (https://registry.npmjs.org/ reachable)",
		fix: "Connect to the network or set HTTPS_PROXY; these gates query registries or pull images.",
	},
	helm: {
		label: "Helm 3 (ci.yml pins v3.19.0)",
		fix: "Put helm on PATH or set HELM_BIN, or rerun with --fetch-tools (signed get.helm.sh release, falling back to a checksum-DB-verified `go install` build) into .ci-local/tools.",
	},
	gitleaks: {
		label: "gitleaks (ci.yml pins v8.30.1)",
		fix: "Put gitleaks on PATH or set GITLEAKS_BIN, or rerun with --fetch-tools (downloads the ci.yml-pinned, sha256-verified release into .ci-local/tools).",
	},
	promtool: {
		label: "promtool (ci.yml pins Prometheus 3.14.0)",
		fix: "Put promtool on PATH or set PROMTOOL_BIN, or rerun with --fetch-tools (downloads the ci.yml-pinned, sha256-verified release into .ci-local/tools).",
	},
	actionlint: {
		label: "actionlint (ci.yml pins v1.7.7)",
		fix: "Put actionlint on PATH or set ACTIONLINT_BIN, or rerun with --fetch-tools (downloads the ci.yml-pinned, sha256-verified release into .ci-local/tools).",
	},
	node24: {
		label: "Node.js 24 (ci.yml NODE_24_VERSION)",
		fix: "Set AIDR_NODE24_BIN=/path/to/node24, install Node 24 with nvm, or rerun with --fetch-tools (downloads the ci.yml-pinned version from nodejs.org, checked against SHASUMS256.txt, into .ci-local/tools).",
	},
	"node-privacy-floor": {
		label: "Node.js at or above the privacy engine floor (ci.yml PRIVACY_NODE_VERSION)",
		fix: "Run ci:local on a newer Node.js 22 or 24 release.",
	},
	"non-root": {
		label: "a non-root user (GitHub runners run as the unprivileged runner user)",
		fix: "Run ci:local as an ordinary user; the Unix fleet installer refuses its test-root mode for uid 0 on purpose.",
	},
	pwsh: {
		label: "PowerShell 7 (pwsh), preinstalled on GitHub's Ubuntu runners",
		fix: "Install PowerShell 7 so `pwsh` is on PATH (https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux).",
	},
	python312: {
		label: "Python 3.12 (ci.yml pins 3.12.8)",
		fix: "Install python3.12 (with the venv module) or set AIDR_PYTHON312_BIN; the runner creates .ci-local/venv/aig-bridge from it.",
	},
	chromium: {
		label: "Playwright Chromium matching the pinned playwright-core revision",
		fix: "Set PLAYWRIGHT_BROWSERS_PATH to a directory holding chromium-<revision> (or populate /opt/pw-browsers): PLAYWRIGHT_BROWSERS_PATH=<dir> node packages/browser-guard/node_modules/playwright-core/cli.js install --no-shell chromium",
	},
	"ci-secrets": {
		label: "the secrets this ci.yml step reads, exported as environment variables",
		fix: "Export every variable named in the reason (the real-host suites refuse to run without them).",
	},
	"release-candidate": {
		label: "a local release-candidate inventory under .release-evidence/",
		fix: "Build a release candidate first (node scripts/build-release-candidate.mjs); .release-evidence/ is gitignored and never exists on a fresh checkout.",
	},
});

/**
 * Group order is execution order. `guards` is special: its `pre` steps run
 * first and its `post` steps run last, even after a failure.
 */
export const GROUPS = Object.freeze([
	["guards", "Real-HOME and working-tree guards around the whole run"],
	["install", "Frozen lockfile install"],
	["hygiene", "Clean checkout, vendored AIG source, repo hygiene, secret scan"],
	["lint", "Biome lint (0 errors), knip, duplicate detection"],
	["check", "TypeScript type check of every package"],
	["static", "quality:static node gates, AIG freshness, Cloudflare Worker contract"],
	["readiness", "Readiness record validators"],
	["commercial", "Commercial surface, compliance and claim checks"],
	["docs-facts", "Brochure and feature-guide fact tests"],
	["workflows", "Workflow contract, actionlint and this runner's drift test"],
	["supabase", "Supabase migration contract, Edge typecheck, Postgres suites"],
	["audit", "Production and build dependency audits"],
	["build", "Workspace build"],
	["test", "Full Vitest suite (pnpm test)"],
	["coverage", "Coverage runs (workspace and isolated core floors)"],
	["core-matrix", "Core build and suite on Node 22 and Node 24"],
	["privacy", "Privacy package tests and rule drift"],
	["mcp-gateway", "MCP gateway tests"],
	["browser-guard", "Browser Guard build, unit, real-browser E2E and packaging"],
	["onprem", "On-prem deployment kit contracts, monitoring and compose models"],
	["helm", "Helm chart lint and render"],
	["aig-bridge", "AIG bridge Python dependency audit and tests"],
	["release", "Release build, fleet lifecycles, package install, route smoke"],
	["real-host-e2e", "Provisioned real-host connector E2E (manual opt-in, as in CI)"],
]);

/** Patterns for local-only on-prem suites that ci.yml does not name (see selectExtraSuites). */
export const ONPREM_EXTRA_SUITE_PATTERNS = Object.freeze([
	/^deployment-[\w-]+\.test\.mjs$/u,
	/^airgap-[\w-]+\.test\.mjs$/u,
	/^customer-kit[\w-]*\.test\.mjs$/u,
	/^license[\w-]*\.test\.mjs$/u,
	/^import-offline-pack[\w-]*\.test\.mjs$/u,
	/^onprem-[\w-]+\.test\.mjs$/u,
]);

/** pip through a proxy on a loaded machine needs more than the 15 s default read timeout. */
const PIP_ENV = Object.freeze({ PIP_DEFAULT_TIMEOUT: "120", PIP_RETRIES: "5" });

const step = (definition) => Object.freeze({ required: true, quick: false, timeoutMs: DEFAULT_TIMEOUT_MS, requires: [], ...definition });

/**
 * The local plan. Order within the array is execution order inside a group.
 * @type {ReadonlyArray<Readonly<Record<string, any>>>}
 */
export const STEPS = Object.freeze([
	// ── guards (pre) ────────────────────────────────────────────────────────
	step({
		id: "guard-home-record",
		group: "guards",
		phase: "pre",
		name: "Record real-HOME agent configuration",
		run: `node scripts/verify-real-home-untouched.mjs --record ${LOCAL_DIR}/real-home.json`,
		covers: [["*", "Record real-HOME agent configuration before tests"]],
		quick: true,
		timeoutMs: MIN,
	}),

	// ── install ─────────────────────────────────────────────────────────────
	step({
		id: "install",
		group: "install",
		name: "Frozen install without postinstall mutation",
		run: "pnpm install --frozen-lockfile --ignore-scripts",
		covers: [
			["*", "Frozen install without postinstall mutation"],
			["real-host-e2e", "Frozen install"],
		],
		quick: true,
		timeoutMs: 15 * MIN,
	}),

	// ── hygiene ─────────────────────────────────────────────────────────────
	step({
		id: "clean-checkout",
		group: "hygiene",
		name: "Clean checkout and vendored AIG source",
		ci: ["quality-gate", "Verify clean checkout and vendored AIG source"],
		dirtySensitive: true,
		quick: true,
		timeoutMs: MIN,
	}),
	step({
		id: "repo-hygiene",
		group: "hygiene",
		name: "Repository hygiene gate and its tests",
		run: "pnpm verify:repo-hygiene && node --test scripts/verify-repo-hygiene.test.mjs",
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({
		id: "secret-scan",
		group: "hygiene",
		name: "Current-worktree secret scan (gitleaks)",
		run: "pnpm verify:secrets:current",
		covers: [["quality-gate", "Current-worktree secret scan (pinned)"]],
		requires: ["gitleaks"],
		quick: true,
		timeoutMs: 5 * MIN,
	}),

	// ── lint ────────────────────────────────────────────────────────────────
	step({ id: "lint", group: "lint", name: "Biome lint (0 errors)", run: "pnpm lint", quick: true, timeoutMs: 5 * MIN }),
	step({ id: "knip", group: "lint", name: "knip unused files/exports/dependencies", run: "pnpm knip", quick: true, timeoutMs: 10 * MIN }),
	step({ id: "duplicates", group: "lint", name: "jscpd duplicate detection", run: "pnpm duplicates", timeoutMs: 10 * MIN }),

	// ── check ───────────────────────────────────────────────────────────────
	step({ id: "check", group: "check", name: "Type check all packages (tsc)", run: "pnpm check", quick: true, timeoutMs: 20 * MIN }),

	// ── static ──────────────────────────────────────────────────────────────
	step({
		id: "aig-freshness",
		group: "static",
		name: "Strict AIG verification and generated-data freshness",
		ci: ["quality-gate", "Strict AIG verification and generated-data freshness"],
		quick: true,
		timeoutMs: 5 * MIN,
	}),
	step({
		id: "cloudflare-worker",
		group: "static",
		name: "Cloudflare Worker contract",
		ci: ["quality-gate", "Cloudflare Worker contract"],
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({ id: "package-install-gate", group: "static", name: "Package install gate tests", run: "pnpm test:package-install-gate", quick: true, timeoutMs: 5 * MIN }),
	step({ id: "benchmarks", group: "static", name: "Benchmark harness tests", run: "pnpm benchmark:test", quick: true, timeoutMs: 5 * MIN }),
	step({ id: "mandatory-skips", group: "static", name: "Undeclared test skip gate", run: "node scripts/check-mandatory-skips.mjs", quick: true, timeoutMs: 3 * MIN }),
	step({ id: "demo-preflight", group: "static", name: "Demo preflight (static)", run: "node scripts/demo-preflight.mjs --static", quick: true, timeoutMs: 3 * MIN }),
	step({ id: "monthly-sli", group: "static", name: "Monthly SLI report tests and verification", run: "pnpm test:monthly-sli && pnpm verify:monthly-sli", quick: true, timeoutMs: 3 * MIN }),
	step({ id: "load-contract", group: "static", name: "Load-test harness tests and verification", run: "node --test scripts/load-test.test.mjs && pnpm verify:load", quick: true, timeoutMs: 5 * MIN }),

	// ── readiness ───────────────────────────────────────────────────────────
	step({ id: "validate-backlog", group: "readiness", name: "READINESS_BACKLOG invariants", run: "node scripts/validate-backlog.mjs && node --test scripts/validate-backlog.test.mjs", quick: true, timeoutMs: 3 * MIN }),
	step({ id: "feature-acceptance", group: "readiness", name: "Feature acceptance record", run: "node scripts/verify-feature-acceptance.mjs && node --test scripts/verify-feature-acceptance.test.mjs", quick: true, timeoutMs: 3 * MIN }),
	step({ id: "generator-determinism", group: "readiness", name: "Inventory generator determinism", run: "node scripts/check-generator-determinism.mjs && node --test scripts/check-generator-determinism.test.mjs", quick: true, timeoutMs: 3 * MIN }),
	step({ id: "investor-metrics", group: "readiness", name: "Investor metric dictionary", run: "pnpm verify:investor-metrics && pnpm test:investor-metrics", quick: true, timeoutMs: 3 * MIN }),

	// ── commercial ──────────────────────────────────────────────────────────
	step({ id: "commercial-surface", group: "commercial", name: "Commercial surface contract", run: "node scripts/check-commercial-surface.mjs", quick: true, timeoutMs: 3 * MIN }),
	step({ id: "commercial-compliance", group: "commercial", name: "Commercial compliance templates and tests", run: "node scripts/verify-commercial-compliance.mjs && pnpm test:commercial-compliance", quick: true, timeoutMs: 3 * MIN }),
	step({
		id: "commercial-readiness",
		group: "commercial",
		name: "Commercial readiness, gate-receipt and candidate-bound production GO checks",
		run: "node scripts/check-commercial-readiness.mjs && node --test scripts/check-commercial-readiness.test.mjs scripts/verify-commercial-gate-receipts.test.mjs scripts/verify-production-go.test.mjs scripts/stage-verified-artifact-roots.test.mjs docs/scripts/claim-check.test.mjs",
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({
		id: "claim-inventory",
		group: "commercial",
		name: "Claim inventory scan and claim-evidence freshness",
		run: "node docs/scripts/claim-check.mjs --mode=inventory && node scripts/check-claim-evidence-freshness.mjs && node --test scripts/check-claim-evidence-freshness.test.mjs",
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({
		id: "claim-evidence-refresh",
		group: "commercial",
		name: "Claim-evidence refresh helper against a local release candidate",
		run: "node --test scripts/refresh-claim-evidence.test.mjs",
		requires: ["release-candidate"],
		requiresFile: CANDIDATE_DIGEST_SOURCE,
		timeoutMs: 3 * MIN,
	}),

	// ── docs-facts ──────────────────────────────────────────────────────────
	step({
		id: "docs-facts",
		group: "docs-facts",
		name: "Brochure facts and feature-guide renderer tests",
		run: "node --test scripts/brochure-facts.test.mjs scripts/render-feature-guide.test.mjs",
		quick: true,
		timeoutMs: 3 * MIN,
	}),

	// ── workflows ───────────────────────────────────────────────────────────
	step({
		id: "ci-workflows",
		group: "workflows",
		name: "Parse every workflow and enforce the CI contract",
		ci: ["workflow-lint", "Parse every workflow and enforce the CI contract"],
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({
		id: "ci-local-drift",
		group: "workflows",
		name: "ci:local runner tests and ci.yml drift check",
		run: "node --test scripts/ci-local.test.mjs",
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({
		id: "actionlint",
		group: "workflows",
		name: "actionlint (pinned)",
		run: "actionlint -color -shellcheck= -pyflakes=",
		covers: [["workflow-lint", "actionlint 1.7.7 (pinned)"]],
		requires: ["actionlint"],
		quick: true,
		timeoutMs: 3 * MIN,
	}),

	// ── supabase ────────────────────────────────────────────────────────────
	step({ id: "supabase-static", group: "supabase", name: "Supabase migration contract", ci: ["quality-gate", "Supabase migration contract"], quick: true, timeoutMs: 5 * MIN }),
	step({ id: "supabase-edge-contracts", group: "supabase", name: "Supabase Edge contracts", run: "node scripts/check-supabase-edge-contracts.mjs", quick: true, timeoutMs: 3 * MIN }),
	step({
		id: "supabase-edge-typecheck",
		group: "supabase",
		name: "Pinned Deno Edge typecheck",
		ci: ["quality-gate", "Pinned Deno Edge typecheck (security-critical slice)"],
		requires: ["network"],
		timeoutMs: 15 * MIN,
	}),
	step({
		id: "supabase-postgres",
		group: "supabase",
		name: "Pinned local Supabase schema contract (Postgres suites)",
		ci: ["quality-gate", "Pinned local Supabase schema contract"],
		cleanup: ["quality-gate", "Stop pinned local Supabase stack"],
		requires: ["docker-daemon", "network"],
		timeoutMs: 45 * MIN,
	}),
	step({
		id: "postgres-gates",
		group: "supabase",
		name: "Blocking reputation, offboarding and retention PostgreSQL gates",
		ci: ["quality-gate", "Blocking reputation, offboarding and retention PostgreSQL gates"],
		requires: ["docker-daemon", "network"],
		timeoutMs: 30 * MIN,
	}),

	// ── audit ───────────────────────────────────────────────────────────────
	step({ id: "audit-prod", group: "audit", name: "Production dependency audit", run: "pnpm audit:prod", requires: ["network"], timeoutMs: 5 * MIN }),
	step({ id: "audit-build", group: "audit", name: "Build dependency audit", run: "pnpm audit:build", requires: ["network"], timeoutMs: 5 * MIN }),
	step({
		id: "audit-vendored",
		group: "audit",
		name: "Vendored posture scanner audit and image base pin contract",
		ci: ["posture-scanner-supply-chain", "Vendored frontend audit, Go toolchain and image base pin contract"],
		requires: ["network"],
		timeoutMs: 5 * MIN,
	}),

	// ── build ───────────────────────────────────────────────────────────────
	step({ id: "build", group: "build", name: "Build all packages", run: "pnpm build", timeoutMs: 30 * MIN }),

	// ── test ────────────────────────────────────────────────────────────────
	step({ id: "vitest", group: "test", name: "Full Vitest suite (pnpm test)", run: "pnpm test", timeoutMs: 60 * MIN }),

	// ── coverage ────────────────────────────────────────────────────────────
	step({ id: "coverage", group: "coverage", name: "Workspace coverage run", run: "pnpm test:coverage", timeoutMs: 60 * MIN }),
	step({ id: "coverage-core", group: "coverage", name: "Isolated core coverage floor", run: "pnpm test:coverage:core", timeoutMs: 20 * MIN }),

	// ── core-matrix ─────────────────────────────────────────────────────────
	step({
		id: "core-node22",
		group: "core-matrix",
		name: "Core build and suite on the current Node (CI leg 22)",
		run: "pnpm --filter @singularityrd/aidr-core run build && pnpm exec vitest run --config packages/core/vitest.config.ts --reporter=dot",
		covers: [["core-node-matrix", "Build core and run the core suite"]],
		nodeLeg: "current",
		timeoutMs: 20 * MIN,
	}),
	step({
		id: "core-node24",
		group: "core-matrix",
		name: "Core build and suite on Node 24 (CI leg 24)",
		run: "pnpm --filter @singularityrd/aidr-core run build && pnpm exec vitest run --config packages/core/vitest.config.ts --reporter=dot",
		covers: [["core-node-matrix", "Build core and run the core suite"]],
		nodeLeg: "24",
		requires: ["node24"],
		timeoutMs: 20 * MIN,
	}),

	// ── privacy ─────────────────────────────────────────────────────────────
	step({
		id: "privacy",
		group: "privacy",
		name: "Build and test packages/privacy",
		ci: ["privacy", "Build and test packages/privacy"],
		requires: ["node-privacy-floor"],
		timeoutMs: 20 * MIN,
	}),
	step({
		id: "privacy-rules",
		group: "privacy",
		name: "Privacy rule drift gate",
		ci: ["privacy-rules-drift", "Verify privacy rules have not drifted"],
		requires: ["node-privacy-floor"],
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({
		id: "privacy-platform",
		group: "privacy",
		name: "Private privacy platform build, complete Node suite and installed signed MCP",
		ci: ["privacy-platform", "Map-free private build, complete Node suite and installed signed MCP"],
		requires: ["node-privacy-floor"],
		timeoutMs: 30 * MIN,
	}),
	step({
		id: "privacy-sdk-mtls",
		group: "privacy",
		name: "Mandatory SDK ESM and CJS mTLS input and output gate",
		ci: ["privacy-platform", "Mandatory SDK ESM and CJS mTLS input and output gate"],
		requires: ["node-privacy-floor"],
		timeoutMs: 15 * MIN,
	}),

	// ── mcp-gateway ─────────────────────────────────────────────────────────
	step({
		id: "mcp-gateway",
		group: "mcp-gateway",
		name: "MCP gateway tests",
		ci: ["quality-gate", "MCP gateway tests"],
		timeoutMs: 15 * MIN,
	}),

	// ── browser-guard ───────────────────────────────────────────────────────
	step({
		id: "bg-playwright-pin",
		group: "browser-guard",
		name: "playwright-core pin and Chromium revision",
		internal: "playwright-pin",
		display: "internal: playwright-core must be an exact pin, installed == pinned, chromium-<revision> present",
		covers: [["browser-guard", "Install Chromium pinned to the browser-guard playwright-core version"]],
		ciDeviations: {
			"packages/browser-guard/node_modules/playwright-core/cli.js":
				"ci:local never installs Chromium or its apt dependencies (--with-deps needs root); it resolves the pinned revision from PLAYWRIGHT_BROWSERS_PATH or /opt/pw-browsers.",
		},
		requires: ["chromium"],
		timeoutMs: MIN,
	}),
	step({ id: "bg-build", group: "browser-guard", name: "Build the extension", ci: ["browser-guard", "Build the extension"], timeoutMs: 10 * MIN }),
	step({ id: "bg-unit", group: "browser-guard", name: "Browser Guard unit tests", ci: ["browser-guard", "Unit tests"], timeoutMs: 15 * MIN }),
	step({
		id: "bg-e2e",
		group: "browser-guard",
		name: "Browser Guard real-browser E2E (hermetic fixtures)",
		ci: ["browser-guard", "Real-browser E2E (hermetic fixtures)"],
		requires: ["chromium"],
		timeoutMs: 20 * MIN,
	}),
	step({ id: "bg-package", group: "browser-guard", name: "Package release zips and checksums", ci: ["browser-guard", "Package release zips and checksums"], timeoutMs: 10 * MIN }),

	// ── onprem (CI runs this job on Node 24) ────────────────────────────────
	step({
		id: "onprem-contracts",
		group: "onprem",
		name: "Deployment, ingress, monitoring, air-gap and customer-kit contracts",
		ci: ["onprem-deploy", "Deployment, ingress, monitoring, air-gap and customer-kit contracts"],
		nodeLeg: "prefer-24",
		quick: true,
		timeoutMs: 10 * MIN,
	}),
	step({
		id: "onprem-extra",
		group: "onprem",
		name: "Other on-prem node suites (license, offline pack, onprem-*, deployment-*)",
		expand: "onprem-extra",
		nodeLeg: "prefer-24",
		quick: true,
		timeoutMs: 10 * MIN,
	}),
	step({
		id: "onprem-lifecycle",
		group: "onprem",
		name: "Bootstrap, upgrade, backup, restore-drill and config-reference gates",
		ci: ["onprem-deploy", "Bootstrap, upgrade, backup, restore-drill and config-reference gates"],
		nodeLeg: "prefer-24",
		quick: true,
		timeoutMs: 10 * MIN,
	}),
	step({
		id: "onprem-promtool",
		group: "onprem",
		name: "Prometheus alert contract (promtool)",
		run: "cd deploy/monitoring && promtool check rules prometheus-alerts.yml && promtool test rules prometheus-alerts.test.yml",
		covers: [["quality-gate", "Prometheus alert contract (promtool 3.14.0, pinned)"]],
		requires: ["promtool"],
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({
		id: "onprem-compose",
		group: "onprem",
		name: "Posture scanner compose model fails closed and validates with placeholders",
		ci: ["onprem-deploy", "Posture scanner compose model fails closed and validates with placeholders"],
		requires: ["docker-cli"],
		quick: true,
		timeoutMs: 3 * MIN,
	}),
	step({
		id: "onprem-dashboard-image",
		group: "onprem",
		name: "Build the prepared dashboard image",
		ci: ["onprem-deploy", "Build the prepared dashboard image"],
		nodeLeg: "prefer-24",
		requires: ["docker-daemon", "network"],
		timeoutMs: 30 * MIN,
	}),
	step({
		id: "onprem-aig-bridge-image",
		group: "onprem",
		name: "Build the AIG bridge image",
		ci: ["onprem-deploy", "Build the AIG bridge image"],
		requires: ["docker-daemon", "network"],
		timeoutMs: 30 * MIN,
	}),

	// ── helm ────────────────────────────────────────────────────────────────
	step({
		id: "helm",
		group: "helm",
		name: "Lint and render the Helm chart",
		run: "pnpm verify:helm",
		covers: [
			["helm", "Lint and render the chart"],
			["helm", "Install Helm 3.19.0 (pinned, signature and checksum verified)"],
		],
		requires: ["helm"],
		timeoutMs: 10 * MIN,
	}),

	// ── aig-bridge (Python, in .ci-local/venv/aig-bridge) ───────────────────
	step({
		id: "aig-bridge-deps",
		group: "aig-bridge",
		name: "Install pinned bridge tooling and dependencies",
		ci: ["aig-bridge", "Install pinned bridge tooling and dependencies"],
		venv: "aig-bridge",
		env: PIP_ENV,
		requires: ["python312", "network"],
		timeoutMs: 15 * MIN,
	}),
	step({
		id: "aig-bridge-tests",
		group: "aig-bridge",
		name: "Audit and test the AIG bridge",
		ci: ["aig-bridge", "Audit and test bridge"],
		venv: "aig-bridge",
		env: PIP_ENV,
		requires: ["python312", "network"],
		timeoutMs: 15 * MIN,
	}),

	// ── release ─────────────────────────────────────────────────────────────
	step({ id: "build-release", group: "release", name: "Release build", run: "pnpm build:release", timeoutMs: 30 * MIN }),
	// Split so a host without PowerShell still runs the Unix leg (GitHub's Ubuntu runners ship pwsh).
	step({
		id: "fleet-windows",
		group: "release",
		name: "Windows fleet lifecycle (PowerShell fixtures)",
		ci: ["fleet-windows", "Verify Windows fleet lifecycle"],
		requires: ["pwsh"],
		timeoutMs: 10 * MIN,
	}),
	step({
		id: "fleet-windows-response",
		group: "release",
		name: "Windows response actions and worker lifecycle",
		ci: ["fleet-windows", "Verify Windows response actions and worker lifecycle"],
		requires: ["pwsh"],
		timeoutMs: 10 * MIN,
	}),
	step({
		id: "fleet-unix",
		group: "release",
		name: "Unix fleet lifecycle",
		run: "pnpm verify:fleet:unix",
		covers: [["quality-gate", "Verify Unix fleet lifecycle"]],
		// deploy/fleet/unix/aidr-fleet.sh refuses its test-root mode for uid 0 by design.
		requires: ["non-root"],
		timeoutMs: 10 * MIN,
	}),
	// Both consume what build-release writes (release tarball contents, the
	// dashboard's dist/). In ci.yml a failed `pnpm quality:gate` ends the job
	// before they run; here they are reported NOT RUN when build-release failed
	// in the same run instead of failing again on missing or stale artefacts.
	step({ id: "package-install", group: "release", name: "Install every packed consumer artifact", ci: ["quality-gate", "Install every packed consumer artifact"], after: ["build-release"], timeoutMs: 20 * MIN }),
	step({ id: "route-smoke", group: "release", name: "Dashboard static route smoke", ci: ["quality-gate", "Dashboard static route smoke"], after: ["build-release"], timeoutMs: 10 * MIN }),
	step({ id: "evidence-boundary", group: "release", name: "CI evidence upload boundary", ci: ["quality-gate", "Verify CI evidence upload boundary"], quick: true, timeoutMs: 3 * MIN }),

	// ── real-host-e2e (manual opt-in in CI, opt-in here) ────────────────────
	step({
		id: "real-e2e-deps",
		group: "real-host-e2e",
		name: "Install pinned bridge E2E dependencies",
		ci: ["real-host-e2e", "Install pinned bridge E2E dependencies"],
		venv: "aig-bridge",
		env: PIP_ENV,
		optIn: true,
		requires: ["python312", "network"],
		timeoutMs: 15 * MIN,
	}),
	step({
		id: "real-e2e",
		group: "real-host-e2e",
		name: "Positive and negative connector suites",
		ci: ["real-host-e2e", "Run positive and negative connector suites"],
		optIn: true,
		requires: ["ci-secrets"],
		timeoutMs: 90 * MIN,
	}),
	step({
		id: "real-e2e-evidence",
		group: "real-host-e2e",
		name: "Connector evidence upload boundary",
		ci: ["real-host-e2e", "Verify connector evidence upload boundary"],
		optIn: true,
		timeoutMs: 3 * MIN,
	}),
	// Local-only (no ci.yml counterpart): real Claude Code / Codex / OpenCode /
	// OpenClaw binaries against a scripted loopback mock model. Needs no secrets,
	// but installs the pinned hosts (and Node.js 24 for OpenClaw) on first run.
	// It rebuilds first: the tier loads the development build, and the earlier
	// build-release step leaves commercial-flavoured, unsigned dist/ output.
	step({
		id: "real-host-mock-model",
		group: "real-host-e2e",
		name: "Real host binaries with a scripted mock model (local-only)",
		run: "pnpm build && pnpm test:e2e:real-host",
		optIn: true,
		requires: ["network"],
		timeoutMs: 45 * MIN,
	}),

	// ── guards (post) ───────────────────────────────────────────────────────
	step({
		id: "guard-home-verify",
		group: "guards",
		phase: "post",
		name: "Assert tests never wrote the real HOME",
		run: `node scripts/verify-real-home-untouched.mjs --verify ${LOCAL_DIR}/real-home.json`,
		covers: [["*", "Assert tests never wrote the runner's real HOME"]],
		quick: true,
		timeoutMs: MIN,
	}),
	step({
		id: "guard-tree-unchanged",
		group: "guards",
		phase: "post",
		name: "Verification did not mutate the working tree",
		internal: "tree-unchanged",
		display: "internal: git diff --check, and git status/diff identical to the snapshot taken before the first step",
		covers: [["quality-gate", "Enforce clean diff after verification/build"]],
		quick: true,
		timeoutMs: MIN,
	}),
]);

// ─── argument parsing ─────────────────────────────────────────────────────

export const USAGE = `Usage: pnpm ci:local [options]      (pnpm ci:local:quick = --quick)

Runs every gate .github/workflows/ci.yml runs, locally, and prints a summary.

  --list                 List groups and steps (command, timeout, prerequisites) and exit
  --only <g|id>[,...]    Run only these groups or step ids (repeatable; selects opt-in groups)
  --skip <g|id>[,...]    Skip these groups or step ids (repeatable)
  --quick                Fast subset: static, contract and drift gates; no builds or suites
  --keep-going           Do not stop after the first failing required step
  --fetch-tools          Download/build missing pinned tools (gitleaks, promtool, actionlint,
                         Helm, Node 24) into .ci-local/tools, verified as ci.yml verifies them
  --allow-dirty          Skip the clean-checkout step when the tree has uncommitted changes
  --strict               Exit non-zero when any selected step is SKIPPED
  --json [file]          Also write the machine-readable report to <file>
                         (it is always written to ${REPORT_PATH})
  -h, --help             Show this help`;

/**
 * @param {string[]} argv
 * @returns {{help: boolean, list: boolean, only: string[], skip: string[], quick: boolean, keepGoing: boolean, fetchTools: boolean, allowDirty: boolean, strict: boolean, json: string | null}}
 */
export function parseArgs(argv) {
	const options = { help: false, list: false, only: [], skip: [], quick: false, keepGoing: false, fetchTools: false, allowDirty: false, strict: false, json: null };
	const flags = { "--list": "list", "--quick": "quick", "--keep-going": "keepGoing", "--fetch-tools": "fetchTools", "--allow-dirty": "allowDirty", "--strict": "strict" };
	for (let index = 0; index < argv.length; index += 1) {
		const arg = argv[index];
		if (arg === "--") continue;
		if (arg === "-h" || arg === "--help") options.help = true;
		else if (flags[arg]) options[flags[arg]] = true;
		else if (arg === "--only" || arg === "--skip") {
			const value = argv[index + 1];
			if (!value || value.startsWith("-")) throw new Error(`${arg} needs a group or step id`);
			index += 1;
			const target = arg === "--only" ? options.only : options.skip;
			target.push(...value.split(",").map((part) => part.trim()).filter(Boolean));
		} else if (arg.startsWith("--only=") || arg.startsWith("--skip=")) {
			const [flag, value] = arg.split("=", 2);
			(flag === "--only" ? options.only : options.skip).push(...value.split(",").map((part) => part.trim()).filter(Boolean));
		} else if (arg === "--json") {
			const value = argv[index + 1];
			if (value && !value.startsWith("-")) {
				options.json = value;
				index += 1;
			} else options.json = REPORT_PATH;
		} else if (arg.startsWith("--json=")) options.json = arg.slice("--json=".length) || REPORT_PATH;
		else throw new Error(`unknown option: ${arg}`);
	}
	return options;
}

// ─── selection ────────────────────────────────────────────────────────────

/**
 * Decide which steps run. Returns the selected steps in execution order and a
 * reason for every step that was left out (so nothing disappears silently).
 *
 * Rules: `--only` restricts to the named groups/ids (and is the only way to
 * select an opt-in group); `--skip` removes; `--quick` keeps `quick` steps
 * unless a step is named in `--only`; guard steps are added whenever any other
 * step is selected, unless `guards` (or the guard id) is skipped.
 */
export function selectSteps(steps, { only = [], skip = [], quick = false } = {}) {
	const known = new Set(steps.flatMap((entry) => [entry.id, entry.group]));
	const unknown = [...only, ...skip].filter((name) => !known.has(name));
	if (unknown.length > 0) throw new Error(`unknown group or step id: ${unknown.join(", ")} (see --list)`);

	const named = (entry, list) => list.includes(entry.id) || list.includes(entry.group);
	const reasonFor = (entry) => {
		if (named(entry, skip)) return "--skip";
		if (only.length > 0 && !named(entry, only)) return "not in --only";
		if (entry.optIn && !named(entry, only)) return `opt-in, as in CI (select with --only ${entry.group})`;
		if (quick && !entry.quick && !named(entry, only)) return "not part of --quick";
		return null;
	};

	const chosen = new Set();
	const notSelected = [];
	for (const entry of steps) {
		if (entry.group === "guards") continue;
		const reason = reasonFor(entry);
		if (reason) notSelected.push({ id: entry.id, group: entry.group, reason });
		else chosen.add(entry.id);
	}
	for (const entry of steps.filter((candidate) => candidate.group === "guards")) {
		const explicitly = only.length > 0 && named(entry, only);
		if (named(entry, skip)) notSelected.push({ id: entry.id, group: entry.group, reason: "--skip" });
		else if (chosen.size > 0 || explicitly) chosen.add(entry.id);
		else notSelected.push({ id: entry.id, group: entry.group, reason: "no other step selected" });
	}

	const phaseRank = (entry) => (entry.phase === "pre" ? 0 : entry.phase === "post" ? 2 : 1);
	const groupRank = new Map(GROUPS.map(([name], index) => [name, index]));
	const selected = steps
		.map((entry, index) => ({ entry, index }))
		.filter(({ entry }) => chosen.has(entry.id))
		.sort((a, b) => phaseRank(a.entry) - phaseRank(b.entry) || (groupRank.get(a.entry.group) ?? 99) - (groupRank.get(b.entry.group) ?? 99) || a.index - b.index)
		.map(({ entry }) => entry);
	return { selected, notSelected };
}

// ─── prerequisites ────────────────────────────────────────────────────────

/**
 * @param {Record<string, any>} entry step
 * @param {{available: Record<string, boolean>, detail?: Record<string, string>}} facts
 * @returns {{ok: true} | {ok: false, requirement: string, reason: string, fix: string}}
 */
export function evaluateRequirements(entry, facts) {
	for (const requirement of entry.requires ?? []) {
		const key = requirement === "ci-secrets" || requirement === "release-candidate" ? `${requirement}:${entry.id}` : requirement;
		if (facts.available[key]) continue;
		const spec = REQUIREMENTS[requirement];
		const detail = facts.detail?.[key];
		return {
			ok: false,
			requirement,
			reason: `${spec?.label ?? requirement} not available${detail ? ` (${detail})` : ""}`,
			fix: spec?.fix ?? "",
		};
	}
	return { ok: true };
}

// ─── ci.yml resolution ────────────────────────────────────────────────────

/** Find a ci.yml step by job id and step name. */
export function findCiStep(workflow, jobId, stepName) {
	const job = workflow?.jobs?.[jobId];
	if (!job) return null;
	return (job.steps ?? []).find((candidate) => candidate.name === stepName) ?? null;
}

const EXPRESSION = /\$\{\{\s*([^}]*?)\s*\}\}/gu;

/**
 * Substitute the GitHub expressions a local run can honour: `env.X` (workflow,
 * job, then step env), `matrix.X` and `secrets.X` (read from the local
 * environment). Anything else is an error - the drift test proves every
 * literal step resolves.
 */
export function substituteExpressions(text, { env = {}, matrix = {}, secrets = {} } = {}) {
	return String(text).replace(EXPRESSION, (whole, expression) => {
		const match = /^(env|matrix|secrets)\.([A-Za-z_][\w-]*)$/u.exec(expression);
		if (!match) throw new Error(`unsupported expression ${whole}`);
		const [, context, name] = match;
		const source = context === "env" ? env : context === "matrix" ? matrix : secrets;
		if (context === "secrets") return source[name] ?? "";
		if (!(name in source)) throw new Error(`unresolved expression ${whole}`);
		return String(source[name]);
	});
}

/** Names of `${{ secrets.X }}` referenced by a ci.yml step's env. */
export function referencedSecrets(ciStep) {
	const names = new Set();
	for (const value of Object.values(ciStep?.env ?? {})) {
		for (const match of String(value).matchAll(/\$\{\{\s*secrets\.([A-Za-z_]\w*)\s*\}\}/gu)) names.add(match[1]);
	}
	return [...names].sort();
}

/**
 * Resolve a literal ci.yml step into something the runner can execute.
 * @returns {{run: string, env: Record<string, string>, workingDirectory: string | null}}
 */
export function resolveCiStep(workflow, [jobId, stepName], { matrix = {}, secrets = {} } = {}) {
	const ciStep = findCiStep(workflow, jobId, stepName);
	if (!ciStep) throw new Error(`ci.yml has no step "${stepName}" in job "${jobId}"`);
	if (typeof ciStep.run !== "string") throw new Error(`ci.yml step "${jobId} / ${stepName}" has no run: block`);
	const job = workflow.jobs[jobId];
	const env = {};
	for (const layer of [workflow.env ?? {}, job.env ?? {}]) {
		for (const [name, value] of Object.entries(layer)) env[name] = substituteExpressions(value, { env, matrix, secrets });
	}
	for (const [name, value] of Object.entries(ciStep.env ?? {})) env[name] = substituteExpressions(value, { env, matrix, secrets });
	const run = substituteExpressions(ciStep.run, { env, matrix, secrets });
	return { run, env, workingDirectory: ciStep["working-directory"] ?? null };
}

// ─── drift ────────────────────────────────────────────────────────────────

/** Root scripts and repo files a CI `run:` block calls; the local command must call them too. */
export function ciRunTokens(run) {
	const tokens = new Set();
	for (const match of String(run).matchAll(/(?:^|[\s;&|(])pnpm (?:run )?(?!-|exec\b|install\b|dlx\b|run\b)([a-z][\w:-]*)/gmu)) tokens.add(`pnpm ${match[1]}`);
	for (const match of String(run).matchAll(/(?:^|[\s"'=])((?:scripts|deploy|docs|packages|supabase|services)\/[\w./-]+\.(?:mjs|cjs|js|ts|sql|ya?ml|json))/gmu)) tokens.add(match[1]);
	return [...tokens].sort();
}

/** Expand a root script into its `&&` leaves, recursing into `quality:*` chains. */
export function expandScriptChain(name, rootScripts, seen = new Set()) {
	if (seen.has(name)) throw new Error(`script chain cycle at ${name}`);
	seen.add(name);
	const body = rootScripts[name];
	if (typeof body !== "string") throw new Error(`root package.json has no script "${name}"`);
	return body
		.split("&&")
		.map((part) => part.trim())
		.flatMap((part) => {
			const nested = /^pnpm (?:run )?([\w:-]+)$/u.exec(part);
			return nested && CHAIN_SCRIPT.test(nested[1]) ? expandScriptChain(nested[1], rootScripts, seen) : [part];
		});
}

const commandParts = (run) => String(run ?? "").split("&&").map((part) => part.trim());

/**
 * Every problem that makes the local plan diverge from ci.yml. Empty = in sync.
 * @param {Record<string, any>} workflow parsed ci.yml
 * @param {ReadonlyArray<Record<string, any>>} steps local plan
 * @param {{rootScripts: Record<string, string>, ciOnly?: ReadonlyArray<{job: string, step: string, reason: string}>}} context
 * @returns {string[]}
 */
export function computeDrift(workflow, steps, { rootScripts, ciOnly = CI_ONLY_STEPS }) {
	const problems = [];
	const jobs = workflow?.jobs ?? {};
	/** @type {Map<string, Array<{entry: Record<string, any>, literal: boolean}>>} */
	const coverage = new Map();
	const key = (jobId, name) => `${jobId}\u0000${name}`;
	const addCoverage = (jobId, name, entry, literal) => {
		const list = coverage.get(key(jobId, name)) ?? [];
		list.push({ entry, literal });
		coverage.set(key(jobId, name), list);
	};

	for (const entry of steps) {
		const references = [];
		if (entry.ci) references.push({ ref: entry.ci, literal: true });
		if (entry.cleanup) references.push({ ref: entry.cleanup, literal: true });
		for (const ref of entry.covers ?? []) references.push({ ref, literal: false });
		for (const { ref, literal } of references) {
			const [jobId, name] = ref;
			const targets = jobId === "*" ? Object.keys(jobs).filter((id) => findCiStep(workflow, id, name)) : [jobId];
			if (targets.length === 0 || targets.some((id) => !findCiStep(workflow, id, name))) {
				problems.push(`stale reference: local step "${entry.id}" points at ci.yml "${jobId} / ${name}", which does not exist`);
				continue;
			}
			for (const id of targets) {
				const ciStep = findCiStep(workflow, id, name);
				if (literal && typeof ciStep.run !== "string") problems.push(`local step "${entry.id}" executes ci.yml "${id} / ${name}", which has no run: block`);
				addCoverage(id, name, entry, literal);
			}
		}
	}

	const exempt = new Set(ciOnly.map(({ job, step: name }) => key(job, name)));
	for (const { job, step: name, reason } of ciOnly) {
		if (!findCiStep(workflow, job, name)) problems.push(`stale CI_ONLY_STEPS entry: ci.yml has no "${job} / ${name}"`);
		if (!reason) problems.push(`CI_ONLY_STEPS entry "${job} / ${name}" needs a reason`);
	}

	for (const [jobId, job] of Object.entries(jobs)) {
		let represented = false;
		for (const ciStep of job.steps ?? []) {
			if (typeof ciStep.run !== "string") continue;
			const covering = coverage.get(key(jobId, ciStep.name)) ?? [];
			if (exempt.has(key(jobId, ciStep.name))) {
				represented = true;
				continue;
			}
			if (jobId === DECOMPOSED_CI_STEP.job && ciStep.name === DECOMPOSED_CI_STEP.step) {
				// Covered component by component; the chain check below proves each one.
				represented = true;
				if (ciStep.run.trim() !== `pnpm ${DECOMPOSED_CI_STEP.script}`) {
					problems.push(`ci.yml "${jobId} / ${ciStep.name}" must stay exactly "pnpm ${DECOMPOSED_CI_STEP.script}" (ci:local runs its components individually)`);
				}
				continue;
			}
			if (covering.length === 0) {
				problems.push(`ci.yml "${jobId} / ${ciStep.name}" has no local step (add one to scripts/lib/ci-local-plan.mjs or list it in CI_ONLY_STEPS with a reason)`);
				continue;
			}
			represented = true;
			if (covering.some(({ literal }) => literal)) continue;
			const localText = covering.map(({ entry }) => entry.run ?? "").join("\n");
			const deviations = Object.assign({}, ...covering.map(({ entry }) => entry.ciDeviations ?? {}));
			for (const token of ciRunTokens(ciStep.run)) {
				const present = token.startsWith("pnpm ") ? localText.includes(token) || localText.includes(token.replace(/^pnpm /u, "pnpm run ")) : localText.includes(token);
				if (!present && !deviations[token]) {
					problems.push(`ci.yml "${jobId} / ${ciStep.name}" runs "${token}" but the covering local step(s) ${covering.map(({ entry }) => entry.id).join(", ")} do not`);
				}
			}
		}
		if (!represented) problems.push(`ci.yml job "${jobId}" has no local counterpart`);
	}

	if (!findCiStep(workflow, DECOMPOSED_CI_STEP.job, DECOMPOSED_CI_STEP.step)) {
		problems.push(`stale DECOMPOSED_CI_STEP: ci.yml has no "${DECOMPOSED_CI_STEP.job} / ${DECOMPOSED_CI_STEP.step}"`);
	}
	const covered = new Set(steps.flatMap((entry) => commandParts(entry.run)));
	let leaves = [];
	try {
		leaves = expandScriptChain(DECOMPOSED_CI_STEP.script, rootScripts);
	} catch (error) {
		problems.push(String(error.message));
	}
	for (const leaf of leaves) {
		if (!covered.has(leaf)) problems.push(`"${DECOMPOSED_CI_STEP.script}" component "${leaf}" is not run by any local step`);
	}
	return problems;
}

// ─── pinned tools ─────────────────────────────────────────────────────────

/** ci.yml steps whose pinned download (URL + sha256 + archive member) `--fetch-tools` reuses. */
export const TOOL_SOURCES = Object.freeze({
	gitleaks: ["quality-gate", "Current-worktree secret scan (pinned)"],
	promtool: ["quality-gate", "Prometheus alert contract (promtool 3.14.0, pinned)"],
	actionlint: ["workflow-lint", "actionlint 1.7.7 (pinned)"],
});

/**
 * Read the pin out of a ci.yml download step, so ci.yml stays the single source
 * of truth for tool versions and checksums.
 * @returns {{url: string, sha256: string, member: string, strip: number}}
 */
export function parsePinnedTarball(run) {
	const url = /https:\/\/github\.com\/\S+?\.tar\.gz/u.exec(run)?.[0];
	const sha256 = /echo "([0-9a-f]{64}) {2}\$\{archive\}"/u.exec(run)?.[1];
	const tar = /tar -xzf "\$\{archive\}" -C "\$\{\w+\}"(?: --strip-components=(\d+))? (\S+)/u.exec(run);
	if (!url || !sha256 || !tar) throw new Error("ci.yml step no longer has the url / sha256 / tar shape --fetch-tools reads");
	return { url, sha256, member: tar[2], strip: Number(tar[1] ?? 0) };
}

/** Semver-ish "a.b.c" >= "x.y.z". */
export function versionAtLeast(actual, floor) {
	const a = String(actual).replace(/^v/u, "").split(".").map(Number);
	const b = String(floor).replace(/^v/u, "").split(".").map(Number);
	for (let index = 0; index < 3; index += 1) {
		if ((a[index] ?? 0) !== (b[index] ?? 0)) return (a[index] ?? 0) > (b[index] ?? 0);
	}
	return true;
}

// ─── extra suites ─────────────────────────────────────────────────────────

/**
 * Local-only suites: files under scripts/ matching `patterns`, minus Postgres
 * suites (they need a database container and are run by the supabase group)
 * and minus anything already named in `coveredText` (ci.yml commands plus the
 * root scripts they call), so nothing runs twice.
 */
export function selectExtraSuites(fileNames, patterns, coveredText) {
	return fileNames
		.filter((name) => patterns.some((pattern) => pattern.test(name)))
		.filter((name) => !/postgres/u.test(name))
		.filter((name) => !coveredText.includes(`scripts/${name}`))
		.sort()
		.map((name) => `scripts/${name}`);
}

// ─── results ──────────────────────────────────────────────────────────────

export const STATUS = Object.freeze({ PASS: "PASS", FAIL: "FAIL", SKIPPED: "SKIPPED", NOT_RUN: "NOT RUN" });

/**
 * The id of a step listed in `entry.after` that already ran in this run and did
 * not produce its output (FAIL or NOT RUN), or null. A dependency that was not
 * selected, or that was SKIPPED for a missing prerequisite, does not block: the
 * step then runs against whatever is on disk and reports its own failure.
 * @param {{after?: string[]}} entry
 * @param {Array<{id: string, status: string}>} results
 */
export function blockingDependency(entry, results) {
	for (const id of entry.after ?? []) {
		const dependency = results.find((result) => result.id === id);
		if (dependency && (dependency.status === STATUS.FAIL || dependency.status === STATUS.NOT_RUN)) return id;
	}
	return null;
}

/**
 * @param {Array<{status: string, required: boolean}>} results
 * @param {{strict?: boolean, interrupted?: boolean}} options
 */
export function summarize(results, { strict = false, interrupted = false } = {}) {
	const counts = { PASS: 0, FAIL: 0, SKIPPED: 0, "NOT RUN": 0 };
	for (const result of results) counts[result.status] = (counts[result.status] ?? 0) + 1;
	const failedRequired = results.filter((result) => result.status === STATUS.FAIL && result.required);
	const failedAdvisory = results.filter((result) => result.status === STATUS.FAIL && !result.required);
	const skipped = results.filter((result) => result.status === STATUS.SKIPPED);
	let exitCode = 0;
	if (failedRequired.length > 0) exitCode = 1;
	else if (strict && skipped.length > 0) exitCode = 1;
	if (interrupted) exitCode = 130;
	return { counts, failedRequired, failedAdvisory, skipped, exitCode };
}

export function formatDuration(ms) {
	if (!Number.isFinite(ms) || ms <= 0) return "-";
	if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
	const minutes = Math.floor(ms / 60_000);
	const seconds = Math.round((ms % 60_000) / 1000);
	return `${minutes}m${String(seconds).padStart(2, "0")}s`;
}

const pad = (text, width) => (text.length >= width ? text : text + " ".repeat(width - text.length));

/** Plain-text summary table followed by the SKIPPED and FAILED sections. */
export function formatSummary(results, { notSelected = [], strict = false, interrupted = false } = {}) {
	const { counts, failedRequired, failedAdvisory, skipped, exitCode } = summarize(results, { strict, interrupted });
	const rows = results.map((result) => {
		const status = result.status === STATUS.FAIL && !result.required ? "FAIL (advisory)" : result.status;
		const detail = result.status === STATUS.SKIPPED ? result.reason ?? "" : result.note ?? "";
		return [status, formatDuration(result.durationMs), result.group, result.id, detail];
	});
	const header = ["STATUS", "DURATION", "GROUP", "STEP", "DETAIL"];
	const widths = header.map((title, column) => Math.max(title.length, ...rows.map((row) => row[column].length)));
	widths[4] = header[4].length;
	const line = (cells) => cells.map((cell, column) => (column === 4 ? cell : pad(cell, widths[column]))).join("  ").trimEnd();
	const out = [line(header), line(widths.map((width, column) => "-".repeat(column === 4 ? 6 : width))), ...rows.map(line)];
	out.push("");
	out.push(`Totals: ${counts.PASS} passed, ${counts.FAIL} failed, ${counts.SKIPPED} skipped, ${counts["NOT RUN"]} not run (of ${results.length} selected)`);
	if (skipped.length > 0) {
		out.push("");
		out.push(`SKIPPED (${skipped.length}) - these CI gates did NOT run here; missing prerequisite and fix:`);
		for (const result of skipped) {
			out.push(`  - ${result.id}: ${result.reason}`);
			if (result.fix) out.push(`      fix: ${result.fix}`);
		}
	}
	if (failedRequired.length + failedAdvisory.length > 0) {
		out.push("");
		out.push(`FAILED (${failedRequired.length} required, ${failedAdvisory.length} advisory):`);
		for (const result of [...failedRequired, ...failedAdvisory]) out.push(`  - ${result.id}: ${result.note ?? "failed"}${result.log ? ` (log: ${result.log})` : ""}`);
	}
	const notRun = results.filter((result) => result.status === STATUS.NOT_RUN);
	const blocked = notRun.filter((result) => result.blockedBy);
	const stoppedCount = notRun.length - blocked.length;
	if (stoppedCount > 0) {
		out.push("");
		out.push(`NOT RUN (${stoppedCount}) after the first required failure; rerun with --keep-going to run them.`);
	}
	if (blocked.length > 0) {
		out.push("");
		out.push(`NOT RUN (${blocked.length}) because a step they consume did not complete in this run:`);
		for (const result of blocked) out.push(`  - ${result.id}: needs ${result.blockedBy}`);
	}
	if (notSelected.length > 0) {
		out.push("");
		const reasons = new Map();
		for (const { id, reason } of notSelected) reasons.set(reason, [...(reasons.get(reason) ?? []), id]);
		out.push(`Not selected (${notSelected.length}):`);
		for (const [reason, ids] of reasons) out.push(reason === "not in --only" ? `  - ${reason}: ${ids.length} step(s)` : `  - ${reason}: ${ids.join(", ")}`);
	}
	out.push("");
	out.push(exitCode === 0 ? "RESULT: PASS (exit 0)" : `RESULT: FAIL (exit ${exitCode})${strict && failedRequired.length === 0 && skipped.length > 0 ? " - --strict and steps were skipped" : ""}`);
	return out.join("\n");
}

/** Machine-readable report written to .ci-local/report.json. */
export function buildReport(results, { startedAt, finishedAt, options, environment, notSelected = [], strict = false, interrupted = false }) {
	const { counts, exitCode } = summarize(results, { strict, interrupted });
	return {
		schema: REPORT_SCHEMA,
		startedAt,
		finishedAt,
		durationMs: Date.parse(finishedAt) - Date.parse(startedAt),
		exitCode,
		interrupted,
		counts,
		options,
		environment,
		steps: results.map((result) => ({
			id: result.id,
			group: result.group,
			name: result.name,
			status: result.status,
			required: result.required,
			durationMs: result.durationMs ?? 0,
			command: result.command ?? null,
			exitCode: result.exitCode ?? null,
			timedOut: Boolean(result.timedOut),
			reason: result.reason ?? null,
			fix: result.fix ?? null,
			note: result.note ?? null,
			log: result.log ?? null,
			outputTail: result.outputTail ?? null,
		})),
		notSelected,
	};
}
