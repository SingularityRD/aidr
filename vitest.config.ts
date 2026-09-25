import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globalSetup: ["./scripts/vitest-global-setup.mjs"],
		// Every test file gets a fresh, empty HOME so no suite reads or writes the
		// developer's real ~/.singularity-aidr (audit log, cache, session state).
		setupFiles: ["./scripts/vitest-isolated-home.mjs"],
		// This repo is a pnpm monorepo, but we run unit tests as a single Vitest project
		// to keep `pnpm test` simple and deterministic across environments.
		include: [
			"packages/**/src/**/__tests__/**/*.test.ts",
			"packages/**/src/**/__tests__/**/*.test.tsx",
			"supabase/functions/**/__tests__/**/*.test.ts",
			"packages/dashboard/supabase/functions/auth-callback/index.test.ts",
		],
		exclude: ["**/node_modules/**", "**/*.e2e.test.ts", "**/*e2e-integration*", "**/src/__tests__/e2e.test.ts"],
		environment: "node",
		// Built connector suites spawn native Node processes. Parallel suites on
		// Windows compete for process startup/file scanning and exceed otherwise
		// unchanged per-scenario deadlines. Keep the Windows gate serial.
		maxWorkers: process.platform === "win32" ? 1 : undefined,
		hookTimeout: 60_000,
		testTimeout: 60_000,
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
