import { defineConfig } from "vitest/config";

// Edge-handler contracts use injected clients; no connector build or live fleet.
export default defineConfig({
	test: {
		environment: "node",
		include: [
			"supabase/functions/__tests__/policy-contract.test.ts",
			"supabase/functions/__tests__/policy-management-contract.test.ts",
			"supabase/functions/__tests__/policy-ack-contract.test.ts",
			"supabase/functions/__tests__/api-key-auth.test.ts",
		],
		maxWorkers: 1,
	},
});
