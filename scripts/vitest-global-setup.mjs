import { execSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";

function tryRun(cmd, cwd) {
	try {
		execSync(cmd, { stdio: "inherit", cwd });
	} catch (error) {
		if (process.env.AIDR_E2E_RELEASE === "1") {
			throw new Error(
				`[global-setup] release build failed for "${cmd}": ${error instanceof Error ? error.message : String(error)}`,
			);
		}
		// Developer E2E may use an already-built dist/ tree. Release E2E is fail-closed above.
		console.error(`[global-setup] warning: "${cmd}" failed, continuing...`);
	}
}

export function setup() {
	// Release E2E must execute against the immutable build prepared by the
	// release pipeline.  Building here is unsafe: the runner starts one
	// Vitest process per suite and each process would concurrently delete and
	// recreate the shared core/dist tree.  That race causes false setup errors
	// such as missing @singularityrd/aidr-core imports.  A missing artifact is a
	// real release failure and must fail closed instead of being rebuilt.
	if (process.env.AIDR_E2E_RELEASE === "1") {
		const root = resolve(process.cwd());
		const required = [
			"packages/core/dist/index.js",
			"packages/claude-code/dist/health.cjs",
			"packages/openclaw/dist/index.cjs",
			"packages/opencode/dist/index.js",
			"packages/extension/dist/cursor_extension.js",
		];
		const missing = required.filter((relativePath) => !existsSync(resolve(root, relativePath)));
		if (missing.length > 0) {
			throw new Error(
				`[global-setup] release artifacts are missing; run the immutable release build first: ${missing.join(", ")}`,
			);
		}
		return;
	}

	// Build core first (needed by all other packages)
	tryRun("pnpm --filter @singularityrd/aidr-core run build");
	// Build claude-code and openclaw (no corepack dependency)
	tryRun(
		"pnpm --filter @singularityrd/aidr-claude-code --filter @singularityrd/aidr-openclaw run build",
	);
	// Build extension manually (its build script uses corepack which may not be available)
	tryRun("node scripts/sync-assets.mjs", "packages/extension");
	tryRun("node esbuild.config.cjs", "packages/extension");
	// Build opencode plugin bundle used by integration tests
	tryRun("pnpm --filter @singularityrd/aidr-opencode run build");
}
