import { execSync } from "node:child_process";

const run = (cmd, cwd) => execSync(cmd, { stdio: "inherit", cwd });

export function setup() {
	// Build core first (needed by all other packages)
	run("pnpm --filter @singularityrd/aidr-core run build");
	// Build claude-code and openclaw (no corepack dependency)
	run(
		"pnpm --filter @singularityrd/aidr-claude-code --filter @singularityrd/aidr-openclaw run build",
	);
	// Build extension manually (its build script uses corepack which may not be available)
	run("node scripts/sync-assets.mjs", "packages/extension");
	run("node esbuild.config.cjs", "packages/extension");
	// Build opencode plugin bundle used by integration tests
	run("pnpm --filter @singularityrd/aidr-opencode run build");
}
