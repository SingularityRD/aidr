import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

/**
 * Artifacts the test suites load directly from disk.
 *
 * The connectors' tests execute the BUILT bundles (that is the point - they test
 * what ships), so the build has to exist before any test file is imported.
 */
const REQUIRED_ARTIFACTS = [
	"packages/core/dist/index.js",
	"packages/claude-code/dist/pre-tool-use.cjs",
	"packages/claude-code/dist/pre-tool-use.bundle.cjs",
	"packages/claude-code/dist/health.cjs",
	"packages/openclaw/dist/index.cjs",
	"packages/opencode/dist/index.js",
	"packages/extension/dist/cursor_extension.js",
];

/**
 * Build the workspace once, in dependency order.
 *
 * ## Why this is a single command and not one build per package
 *
 * Each connector's own `build` script starts with `pnpm -C ../core build`, whose
 * first action is `rmrf dist`. Running the per-package builds separately (or on
 * every Vitest process) therefore means several processes delete and recreate the
 * same `packages/core/dist` tree concurrently. Anything importing
 * `@singularityrd/aidr-core` during that window fails with
 * "Failed to resolve entry for package @singularityrd/aidr-core" - a red suite
 * that has nothing to do with the code under test (tracked as AIDR-014).
 *
 * `pnpm build` runs the packages in workspace order with core first, so there is
 * exactly one core build and no overlap.
 */
function buildOnce() {
	try {
		execSync("pnpm build", { stdio: "inherit" });
	} catch (error) {
		if (process.env.AIDR_E2E_RELEASE === "1") {
			throw new Error(
				`[global-setup] release build failed: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
		throw error;
	}
}

export function setup() {
	const root = resolve(process.cwd());
	const missing = REQUIRED_ARTIFACTS.filter((relativePath) => !existsSync(resolve(root, relativePath)));

	// Release E2E must execute against the immutable build prepared by the release
	// pipeline. A missing artifact is a real release failure and must fail closed
	// instead of being rebuilt.
	if (process.env.AIDR_E2E_RELEASE === "1") {
		if (missing.length > 0) {
			throw new Error(
				`[global-setup] release artifacts are missing; run the immutable release build first: ${missing.join(", ")}`,
			);
		}
		return;
	}

	// `pnpm test:ci` builds once and then sets this flag, so the correctness gate
	// never rebuilds under itself and a missing artifact is reported instead of
	// being papered over.
	if (process.env.AIDR_TEST_NO_BUILD === "1") {
		if (missing.length > 0) {
			throw new Error(
				`[global-setup] AIDR_TEST_NO_BUILD=1 but required artifacts are missing: ${missing.join(", ")}. ` +
					"Run the build first (pnpm test:ci does this).",
			);
		}
		return;
	}

	// Developer `pnpm test` from a clean checkout: build once, in order.
	console.log(
		missing.length > 0
			? `[global-setup] building workspace (missing: ${missing.join(", ")})`
			: "[global-setup] artifacts present; building once to ensure they match the working tree",
	);
	buildOnce();
}
