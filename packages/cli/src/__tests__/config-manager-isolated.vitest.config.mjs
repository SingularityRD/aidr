// Run the config-store unit suite without the repository-wide build globalSetup.
// This suite mocks the only core import (VERSION) and exercises filesystem I/O.
import { fileURLToPath } from "node:url";

export default {
	resolve: {
		alias: {
			"@singularityrd/aidr-core": fileURLToPath(
				new URL("./config-manager-core-stub.mjs", import.meta.url),
			),
		},
	},
	test: {
		include: [
			"packages/cli/src/__tests__/config-manager-private-store.test.ts",
			"packages/cli/src/__tests__/config-manager-windows-acl.test.ts",
		],
		environment: "node",
	},
};
