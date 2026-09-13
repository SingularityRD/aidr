import { defineConfig } from "vitest/config";

/** Isolated Edge contract tests do not require connector build artifacts. */
export default defineConfig({
	test: {
		include: ["supabase/functions/invoice-entitlement/__tests__/*.test.ts"],
		environment: "node",
	},
});
