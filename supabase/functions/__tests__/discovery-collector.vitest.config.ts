import { defineConfig } from "vitest/config";

// Collector auth contract tests avoid connector-wide global build setup.
export default defineConfig({
	test: {
		environment: "node",
		include: ["supabase/functions/__tests__/discovery-collector-credential.test.ts"],
		maxWorkers: 1,
		pool: "forks",
	},
});
