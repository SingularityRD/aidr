import { defineConfig } from "vitest/config";

// Focused Edge handler tests do not need the connector bundle build required by
// the repository-wide Vitest global setup.
export default defineConfig({
	test: {
		include: ["supabase/functions/**/__tests__/**/*.test.ts"],
		environment: "node",
		testTimeout: 60_000,
	},
});
