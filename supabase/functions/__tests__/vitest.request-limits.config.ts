// Pure Edge helper and SQL contract tests without the workspace connector build.
export default {
	test: {
		include: ["supabase/functions/__tests__/request-limits.test.ts"],
		environment: "node",
		maxWorkers: 1,
	},
};
