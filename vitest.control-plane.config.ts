import { defineConfig } from "vitest/config";

/**
 * Supabase/control-plane contract tests intentionally run without the
 * connector global setup. Live tenant/RLS evidence is a separate external
 * manifest suite; this config covers deterministic function contracts only.
 */
export default defineConfig({
	test: {
		environment: "node",
		include: [
			"supabase/functions/__tests__/security-flow.test.ts",
			"supabase/functions/__tests__/identity-security.test.ts",
		],
		maxWorkers: 1,
		pool: "forks",
	},
});
