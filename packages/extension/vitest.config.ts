import { fileURLToPath } from "node:url";
import { configDefaults, defineProject } from "vitest/config";

// Same safety net as the root config: a fresh HOME per test file (tests delete
// ~/.claude, ~/.config and ~/.singularity-aidr under HOME) and English output.
const isolatedHome = fileURLToPath(new URL("../../scripts/vitest-isolated-home.mjs", import.meta.url));

export default defineProject({
	test: {
		setupFiles: [isolatedHome],
		env: { AIDR_LOCALE: "en" },
		name: "extension",
		environment: "node",
		exclude: [...configDefaults.exclude, "src/__tests__/e2e.test.ts"],
	},
});
