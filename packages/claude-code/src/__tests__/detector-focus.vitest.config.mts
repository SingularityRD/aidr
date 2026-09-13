import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: [
			"packages/claude-code/src/__tests__/detector-provisioning.test.ts",
			"packages/claude-code/src/__tests__/pre-tool-use-empty-artifacts.test.ts",
		],
		environment: "node",
	},
});
