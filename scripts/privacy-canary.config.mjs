import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["scripts/privacy-canary.test.mjs"],
		environment: "node",
		maxWorkers: 1,
		testTimeout: 30_000,
	},
});
