import { fileURLToPath } from "node:url";
import { defineConfig } from "vitest/config";

export default defineConfig({
	root: fileURLToPath(new URL("../../../", import.meta.url)),
	test: {
		include: ["supabase/functions/scim/__tests__/**/*.test.ts"],
		environment: "node",
		maxWorkers: 1,
	},
});
