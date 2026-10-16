import { fileURLToPath } from "node:url";
import { defineProject } from "vitest/config";

// Same safety net as the root config: a fresh HOME per test file (tests delete
// ~/.claude, ~/.config and ~/.singularity-aidr under HOME) and English output.
const isolatedHome = fileURLToPath(new URL("../../scripts/vitest-isolated-home.mjs", import.meta.url));

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

export default defineProject({
	root: repoRoot,
	test: {
		setupFiles: [isolatedHome],
		env: { AIDR_LOCALE: "en" },
		name: "core",
		environment: "node",
		include: ["packages/core/src/**/__tests__/**/*.test.ts"],
		maxWorkers: 1,
		pool: "forks",
		hookTimeout: 60_000,
		testTimeout: 60_000,
		coverage: {
			provider: "v8",
			reportsDirectory: "coverage/core",
			include: ["packages/core/src/**/*.ts"],
			exclude: [
				"packages/core/src/**/__tests__/**",
				"packages/core/src/typings/**",
			],
			thresholds: {
				lines: 83,
				statements: 80,
				branches: 72,
				functions: 84,
			},
		},
	},
});
