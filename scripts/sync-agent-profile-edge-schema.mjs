import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

// A deployable copy of the ONE engine agent-profile schema, not an
// independently maintained validator. policy-management validates dashboard-
// staged profiles with it; self-hosted kits ship functions/, not core/src.
export function agentProfileEdgeSchemaSource() {
	const core = new URL("../packages/core/src/agent-profile-schema.ts", import.meta.url);
	const require = createRequire(new URL("../packages/core/package.json", import.meta.url));
	const version = require("zod/package.json").version;
	const source = readFileSync(core, "utf8").replaceAll("\r\n", "\n");
	const dependency = 'import { type ZodIssue, z } from "zod";';
	if (!source.startsWith(dependency) || /^import /m.test(source.slice(dependency.length))) {
		throw new Error("Agent profile schema dependencies changed; review Edge compatibility");
	}
	return "// Generated from packages/core/src/agent-profile-schema.ts; do not edit.\n" +
		"// Regenerate: node scripts/sync-agent-profile-edge-schema.mjs --write\n" +
		source.replace(dependency, `import { type ZodIssue, z } from "npm:zod@${version}";`);
}

export const agentProfileEdgeSchemaPath = new URL(
	"../supabase/functions/_shared/agent-profile-schema.ts",
	import.meta.url,
);
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const expected = agentProfileEdgeSchemaSource();
	if (process.argv.includes("--write")) writeFileSync(agentProfileEdgeSchemaPath, expected);
	else if (readFileSync(agentProfileEdgeSchemaPath, "utf8").replaceAll("\r\n", "\n") !== expected) {
		throw new Error("Edge agent profile schema drift: run node scripts/sync-agent-profile-edge-schema.mjs --write");
	}
}
