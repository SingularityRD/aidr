/**
 * Prove a package's dist/ tree was built, in release mode, from the commit a
 * candidate is about to be bound to.
 *
 * dist/ is gitignored, so checking out another commit leaves an older build in
 * place behind a clean worktree. `pnpm build:release` writes
 * dist/aidr-artifact.manifest.json with the commit (`provenance.git_sha`), the
 * committed-tree digest (`provenance.source_digest`) and the sha256 of every
 * file; this check requires all three to match what is on disk now.
 */

import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";

const MANIFEST = "aidr-artifact.manifest.json";
const SIGNATURE = "aidr-artifact.manifest.sig";

function listFiles(root) {
	const out = [];
	const stack = [root];
	while (stack.length > 0) {
		const current = stack.pop();
		for (const name of readdirSync(current)) {
			const full = path.join(current, name);
			const info = statSync(full);
			if (info.isDirectory()) stack.push(full);
			else if (info.isFile()) out.push(path.relative(root, full).replace(/\\/g, "/"));
		}
	}
	return out.sort();
}

/**
 * @param {{distDir: string, label: string, commitSha: string, sourceDigest: string}} input
 * @returns {string[]} problems; empty when the tree is bound to `commitSha`
 */
export function distProvenanceProblems({ distDir, label, commitSha, sourceDigest }) {
	if (!existsSync(distDir)) return [`${label} is missing; run \`pnpm build:release\` first`];
	const files = listFiles(distDir);
	const maps = files.filter((file) => file.endsWith(".map"));
	if (maps.length > 0) {
		return [`${label} contains source maps (${maps.slice(0, 3).join(", ")}${maps.length > 3 ? ", ..." : ""}); it is not a release-mode build, run \`pnpm build:release\``];
	}
	const manifestPath = path.join(distDir, MANIFEST);
	if (!existsSync(manifestPath)) return [`${label}/${MANIFEST} is missing; run \`pnpm build:release\` on this commit`];
	let manifest;
	try {
		manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
	} catch (error) {
		return [`${label}/${MANIFEST} is not valid JSON: ${error instanceof Error ? error.message : String(error)}`];
	}
	const problems = [];
	const recordedSha = manifest?.provenance?.git_sha;
	if (recordedSha !== commitSha) {
		problems.push(`${label} was built from commit ${recordedSha ?? "<unrecorded>"}, not HEAD ${commitSha}; rerun \`pnpm build:release\``);
	}
	const recordedTree = manifest?.provenance?.source_digest;
	if (recordedTree !== sourceDigest) {
		problems.push(`${label} records source tree ${recordedTree ?? "<unrecorded>"}, not the committed tree ${sourceDigest}; rerun \`pnpm build:release\``);
	}
	const listed = new Map((Array.isArray(manifest?.files) ? manifest.files : []).map((entry) => [entry?.path, entry?.sha256]));
	const onDisk = files.filter((file) => file !== MANIFEST && file !== SIGNATURE);
	const changed = [];
	for (const file of onDisk) {
		const expected = listed.get(file);
		if (!expected) changed.push(`${file} (not in the manifest)`);
		else if (createHash("sha256").update(readFileSync(path.join(distDir, file))).digest("hex") !== expected) changed.push(`${file} (content changed)`);
	}
	const present = new Set(onDisk);
	for (const file of listed.keys()) if (!present.has(file)) changed.push(`${file} (missing)`);
	if (changed.length > 0) {
		problems.push(`${label} no longer matches its build manifest: ${changed.slice(0, 5).join(", ")}${changed.length > 5 ? `, and ${changed.length - 5} more` : ""}; rerun \`pnpm build:release\``);
	}
	return problems;
}
