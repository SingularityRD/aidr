import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globalSetup: ["./scripts/vitest-global-setup.mjs"],
		// This repo is a pnpm monorepo, but we run unit tests as a single Vitest project
		// to keep `pnpm test` simple and deterministic across environments.
		include: [
			"packages/**/src/**/__tests__/**/*.test.ts",
			"supabase/functions/**/__tests__/**/*.test.ts",
		],
		exclude: ["**/node_modules/**", "**/*.e2e.test.ts", "**/*e2e-integration*", "**/src/__tests__/e2e.test.ts"],
		environment: "node",
		reporters: ["verbose", "json"],
		outputFile: { json: "./coverage/test-results.json" },
		coverage: {
			provider: "v8",
			reporter: ["text", "lcov"],
			exclude: [
				"**/node_modules/**",
				"**/dist/**",
				"**/.next/**",
				"**/coverage/**",
				"landing/**",
				"threats/**",
				"packages/**/resources/**",
				"packages/core/src/evaluator.ts",
				"packages/core/src/managed.ts",
				"packages/core/src/policy.ts",
				"packages/core/src/session-start.ts",
				"packages/core/src/session-start-scan.ts",
				"packages/core/src/clients/control-plane.ts",
				"packages/core/src/integrity/index.ts",
				"packages/core/src/integrity/runtime.ts",
				"packages/core/src/intel/semver.ts",
			],
			thresholds: {
				lines: 70,
				functions: 70,
				branches: 60,
				statements: 70,
			},
		},
	},
});
