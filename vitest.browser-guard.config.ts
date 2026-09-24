import { defineConfig } from "vitest/config";

// Browser Guard unit suites only: deliberately no connector build/globalSetup, so
// the CI browser-guard job does not rebuild the whole workspace. DOM suites opt in
// with a `// @vitest-environment jsdom` file header.
export default defineConfig({
	test: {
		environment: "node",
		include: ["packages/browser-guard/src/**/__tests__/**/*.test.ts"],
		hookTimeout: 60_000,
		testTimeout: 60_000,
	},
});
