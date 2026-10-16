import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

// Same safety net as the root config: a fresh HOME per test file (tests delete
// ~/.claude, ~/.config and ~/.singularity-aidr under HOME) and English output.
const isolatedHome = fileURLToPath(new URL("../../scripts/vitest-isolated-home.mjs", import.meta.url));

export default defineConfig({
	test: {
		setupFiles: [isolatedHome],
		env: { AIDR_LOCALE: "en" },
		include: ["src/**/__tests__/**/*.test.ts"],
		environment: "node",
		pool: "forks",
		maxWorkers: 1,
	},
});
