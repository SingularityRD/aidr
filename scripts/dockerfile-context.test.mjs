// Every file a shipped Dockerfile COPYs must survive its .dockerignore allowlist.
// A missing entry only shows up when a customer builds the image on-prem
// (`failed to compute cache key: "/release-manifest.mjs": not found`).
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const CONTEXTS = ["deploy/dashboard"];

/** Allowlist-style .dockerignore: `*` then `!path` re-includes. */
function included(ignore, path) {
	let kept = true;
	for (const raw of ignore.split(/\r?\n/)) {
		const line = raw.trim();
		if (!line || line.startsWith("#")) continue;
		const negate = line.startsWith("!");
		const pattern = (negate ? line.slice(1) : line).replace(/\/\*\*$/, "/").replace(/\/$/, "");
		const matches = pattern === "*" || path === pattern || path.startsWith(`${pattern}/`);
		if (matches) kept = negate;
	}
	return kept;
}

for (const context of CONTEXTS) {
	test(`${context}: every COPY source is in the build context`, () => {
		const dockerfile = readFileSync(join(root, context, "Dockerfile"), "utf8");
		const ignorePath = join(root, context, ".dockerignore");
		const ignore = existsSync(ignorePath) ? readFileSync(ignorePath, "utf8") : "";
		const sources = [...dockerfile.matchAll(/^COPY\s+(?:--\S+\s+)*(\S+)\s+\S+\s*$/gm)]
			.map((m) => m[1].replace(/^\.\//, "").replace(/\/$/, ""))
			.filter((source) => !source.startsWith("--from"));
		assert.ok(sources.length > 0, "no COPY instructions parsed");
		const excluded = sources.filter((source) => !included(ignore, source));
		assert.deepEqual(excluded, [], `excluded by ${context}/.dockerignore`);
	});
}
