import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
	resolve: {
		alias: {
			"@singularityrd/aidr-core": resolve(process.cwd(), "packages/core/src/output-scanner.ts"),
		},
	},
	test: {
		include: ["packages/claude-code/src/__tests__/tool-output-quarantine.test.ts"],
		environment: "node",
	},
});
