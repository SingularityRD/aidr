import { defineConfig } from "vitest/config";

// Focused server/core contracts: deliberately no connector build/globalSetup.
export default defineConfig({
	test: {
		environment: "node",
		include: [
			"supabase/functions/__tests__/dlp-policy-store.test.ts",
			"supabase/functions/__tests__/policy-management-contract.test.ts",
			"packages/core/src/__tests__/dlp/custom-policy.test.ts",
		],
		maxWorkers: 1,
		pool: "forks",
	},
});
