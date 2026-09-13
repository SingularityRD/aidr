// Run the enrollment contract tests without the workspace-wide connector build.
// The suite only imports pure Edge helpers and source/SQL contract fixtures.
export default {
	test: {
		include: [
			"supabase/functions/__tests__/enrollment-exchange.test.ts",
			"supabase/functions/enroll/__tests__/retry-outcome.test.ts",
		],
		environment: "node",
		maxWorkers: 1,
	},
};
