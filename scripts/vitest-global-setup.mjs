import { execSync } from "node:child_process";

function tryRun(cmd, cwd) {
	try {
		execSync(cmd, { stdio: "inherit", cwd });
	} catch {
		// Fail open — tests may still work if dist/ is already built
		console.error(`[global-setup] warning: "${cmd}" failed, continuing...`);
	}
}

export function setup() {
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
