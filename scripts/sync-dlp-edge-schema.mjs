import { readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";

// A deployable copy of the ONE engine schema, not an independently maintained
// validator. Self-hosted/customer-kit packages include functions/, not core/src.
export function dlpEdgeSchemaSource() {
	const core = new URL("../packages/core/src/dlp/policy.ts", import.meta.url);
	const require = createRequire(new URL("../packages/core/package.json", import.meta.url));
	const version = require("zod/package.json").version;
	const source = readFileSync(core, "utf8").replaceAll("\r\n", "\n");
	const dependency = 'import { z } from "zod";';
	if (!source.startsWith(dependency)) throw new Error("DLP schema dependency changed; review Edge compatibility");
	return "// Generated from packages/core/src/dlp/policy.ts; do not edit.\n" +
		"// Regenerate: node scripts/sync-dlp-edge-schema.mjs --write\n" +
		source.replace(dependency, `import { z } from "npm:zod@${version}";`);
}

export const edgeSchemaPath = new URL("../supabase/functions/_shared/dlp-policy-schema.ts", import.meta.url);
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const expected = dlpEdgeSchemaSource();
	if (process.argv.includes("--write")) writeFileSync(edgeSchemaPath, expected);
	else if (readFileSync(edgeSchemaPath, "utf8").replaceAll("\r\n", "\n") !== expected) {
		throw new Error("Edge DLP schema drift: run node scripts/sync-dlp-edge-schema.mjs --write");
	}
}
