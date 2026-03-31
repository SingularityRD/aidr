/**
 * Best-effort leak scan for release bundles.
 *
 * Goal: catch accidental bundling of developer machine paths or internal URLs in release artifacts.
 * This is not a security boundary, but it helps reduce accidental leaks.
 */

import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";

const roots = process.argv.slice(2);
if (roots.length === 0) {
	console.error("Usage: node scripts/check-no-leaky-paths.mjs <dir> [dir...]");
	process.exit(2);
}

const PATTERNS = [
	{ id: "win_users", re: /[A-Za-z]:\\Users\\[^\\s"'<>]+/g },
	{ id: "mac_users", re: /\/Users\/[^/\s"'<>]+/g },
	{ id: "linux_home", re: /\/home\/[^/\s"'<>]+/g },
];

async function* walk(dir) {
	let ents;
	try {
		ents = await readdir(dir, { withFileTypes: true });
	} catch {
		return;
	}
	for (const e of ents) {
		const p = join(dir, e.name);
		if (e.isDirectory()) {
			// Don't scan test fixtures.
			if (e.name === "__tests__" || e.name === "__snapshots__") continue;
			yield* walk(p);
		} else if (e.isFile()) {
			yield p;
		}
	}
}

function looksTexty(path) {
	return (
		path.endsWith(".js") ||
		path.endsWith(".cjs") ||
		path.endsWith(".mjs") ||
		path.endsWith(".css") ||
		path.endsWith(".html") ||
		path.endsWith(".json") ||
		path.endsWith(".md")
	);
}

const offenders = [];

for (const root of roots) {
	try {
		const s = await stat(root);
		if (!s.isDirectory()) continue;
	} catch {
		continue;
	}

	for await (const file of walk(root)) {
		if (!looksTexty(file)) continue;
		let data;
		try {
			data = await readFile(file, "utf8");
		} catch {
			continue;
		}
		for (const p of PATTERNS) {
			if (p.re.test(data)) {
				offenders.push({ file, pattern: p.id });
				break;
			}
		}
	}
}

if (offenders.length > 0) {
	console.error("\nFound potential leak strings in release artifacts:");
	for (const o of offenders.slice(0, 200)) {
		console.error(`- ${o.file} (${o.pattern})`);
	}
	process.exit(1);
}
