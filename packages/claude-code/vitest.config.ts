import { defineProject } from "vitest/config";

export default defineProject({
	test: {
		name: "claude-code",
		environment: "node",
		exclude: ["**/e2e.test.ts", "**/node_modules/**"],
	},
});
