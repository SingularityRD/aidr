import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		globalSetup: ["./scripts/vitest-global-setup.mjs"],
		projects: ["packages/*/vitest.config.ts"],
	},
});
