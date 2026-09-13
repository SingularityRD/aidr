import { defineConfig } from "vitest/config";

// Focused pure/SQL-contract suite without the workspace connector build.
// The repository-wide test gate still uses the root Vitest configuration.
export default defineConfig({
	test: {
		include: ["supabase/functions/revocations/__tests__/*.test.ts"],
		environment: "node",
		maxWorkers: 1,
	},
});
