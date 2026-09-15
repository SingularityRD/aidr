import { defineConfig } from "vitest/config";

// Targeted provisioning gate. Compile core first with `pnpm -C packages/core exec tsc`.
// Unlike the workspace gate this does not rebuild unrelated connector/UI artifacts.
export default defineConfig({
	test: {
		include: [
			"packages/core/src/__tests__/detector-provisioning.test.ts",
			"packages/core/src/__tests__/behavioral-corpus.test.ts",
			"packages/core/src/__tests__/behavioral-orchestrator.test.ts",
			"packages/core/src/__tests__/behavioral-analyzer-baseline.test.ts",
			"packages/core/src/__tests__/behavioral-baseline-store.test.ts",
			"packages/core/src/__tests__/evaluator-runtime-detectors.test.ts",
			"packages/claude-code/src/__tests__/detector-provisioning.test.ts",
		],
		environment: "node",
		maxWorkers: 1,
		hookTimeout: 60_000,
		testTimeout: 60_000,
	},
});
