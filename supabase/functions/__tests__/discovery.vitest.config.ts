import { defineConfig } from "vitest/config";

// Discovery contract tests avoid the connector-wide build global setup.
export default defineConfig({
	test: {
		environment: "node",
		include: ["supabase/functions/__tests__/discovery.test.ts"],
		maxWorkers: 1,
		pool: "forks",
	},
});
