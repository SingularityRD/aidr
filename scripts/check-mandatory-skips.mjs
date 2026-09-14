#!/usr/bin/env node
/**
 * check-mandatory-skips.mjs — machine gate for AIDR-063 (undeclared test skips).
 *
 * Acceptance criteria enforced here:
 *   "A test that is skipped is either impossible to run in this environment and says
 *    so in a machine-readable form, or it fails the gate. No empty skips."
 *
 * Why this exists
 * ---------------
 * `packages/claude-code/src/__tests__/integration.test.ts` carried an
 * `it.skip("denies known malicious URL via URL check ...", () => {})` — an empty
 * body, no owner and no gate that noticed. A mandatory-looking assertion could
 * therefore disappear from the suite silently. A skip is sometimes the honest
 * answer (an excluded e2e tier whose host or credential is absent), so the gate
 * does not ban skips: it requires each one to declare why it is skipped, and it
 * always rejects a skip with an empty body.
 *
 * Declaration form (a comment on the skip's own line or the line above):
 *
 *   // AIDR-SKIP: AIDR-049 qa-owner — the Cursor extension host is not installed here
 *   it.skip("...", () => { ... });
 *
 * Scope is derived from `vitest.config.ts`: only the files Vitest would actually
 * collect are scanned, so an excluded e2e tier cannot hide an undeclared skip.
 *
 * Exit codes: 0 clean, 1 violations, 2 the gate could not run.
 *
 * Usage:  node scripts/check-mandatory-skips.mjs [--json] [--repo <dir>]
 */

import { readdirSync, readFileSync, statSync } from "node:fs";
import { dirname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = resolve(MODULE_DIR, "..");

/** The globs `vitest.config.ts` collects, expressed as directory roots. */
export const INCLUDED_ROOTS = ["packages", "supabase/functions"];

/** Only files under a `__tests__` directory inside an included root are collected. */
export const TEST_DIR_SEGMENT = "__tests__";

/** `// AIDR-SKIP: <backlog-id> <owner> — <reason>` */
export const DECLARATION_PATTERN =
	/\/\/\s*AIDR-SKIP:\s*([A-Z][A-Z0-9-]*-\d+)\s+(\S+)\s*[—:-]\s*(\S.{9,})/;

/** A skip site: the call that skips, and the line index it sits on. */
const SKIP_PATTERN = /\b(?:it|test|describe)\.(?:skip|todo)\s*\(/;

const BLOCK_COMMENT = /\/\*[\s\S]*?\*\//g;

/**
 * Remove comments from a line so a `// it.skip(...)` in prose is not read as a
 * skip site. Only the first `//` outside a quoted string starts a comment, and
 * block comments are removed first so a `/* ... *\/` span cannot leave a stray
 * `//` behind.
 */
export function stripComments(line) {
	const withoutBlocks = line.replace(BLOCK_COMMENT, " ");
	let quote = null;
	for (let index = 0; index < withoutBlocks.length; index += 1) {
		const character = withoutBlocks[index];
		if (quote) {
			if (character === "\\") index += 1;
			else if (character === quote) quote = null;
			continue;
		}
		if (character === '"' || character === "'" || character === "`") {
			quote = character;
			continue;
		}
		if (character === "/" && withoutBlocks[index + 1] === "/") {
			return withoutBlocks.slice(0, index);
		}
	}
	return withoutBlocks;
}

/**
 * Files whose skips are structural rather than a coverage decision: a helper that
 * wraps an optional dependency. Each entry must carry a written reason, and the
 * gate rejects an entry without one.
 */
export const ALLOWLIST = [
	{
		path: "packages/core/src/__tests__/helpers/**",
		reason: "Shared test helper modules, not test files; they contain no skip site of their own.",
		owner: "AIDR-063",
	},
];

function walk(directory, out) {
	let entries;
	try {
		entries = readdirSync(directory, { withFileTypes: true });
	} catch {
		return out;
	}
	for (const entry of entries) {
		if (entry.name === "node_modules" || entry.name === "dist" || entry.name.startsWith(".")) {
			continue;
		}
		const full = join(directory, entry.name);
		if (entry.isDirectory()) {
			walk(full, out);
		} else if (entry.isFile() && /\.(?:test|spec)\.[cm]?[jt]sx?$/.test(entry.name)) {
			out.push(full);
		}
	}
	return out;
}

/** Collect every collected test file under the included roots. */
export function collectedTestFiles(repoRoot = REPO_ROOT) {
	const files = [];
	for (const root of INCLUDED_ROOTS) {
		const absolute = join(repoRoot, root);
		try {
			statSync(absolute);
		} catch {
			continue;
		}
		for (const file of walk(absolute, [])) {
			if (file.split(/[\\/]/).includes(TEST_DIR_SEGMENT)) {
				files.push(file);
			}
		}
	}
	return files.sort();
}

function isAllowlisted(relativePath) {
	return ALLOWLIST.some((entry) =>
		entry.path.endsWith("/**") ? relativePath.startsWith(entry.path.slice(0, -2)) : relativePath === entry.path,
	);
}

/** True when the call's argument list contains no executable body. */
export function hasEmptyBody(source, callIndex) {
	const open = source.indexOf("(", callIndex);
	if (open === -1) return false;
	let depth = 0;
	let close = -1;
	for (let index = open; index < source.length; index += 1) {
		const character = source[index];
		if (character === "(") depth += 1;
		else if (character === ")") {
			depth -= 1;
			if (depth === 0) {
				close = index;
				break;
			}
		}
	}
	if (close === -1) return false;
	const args = source.slice(open + 1, close);
	// The last argument is the body. `() => {}` and `function () {}` are empty.
	const arrow = args.match(/=>\s*\{\s*\}\s*$/);
	const fn = args.match(/function\s*\([^)]*\)\s*\{\s*\}\s*$/);
	return Boolean(arrow || fn);
}

/** Scan one file's source for skip sites and classify each. */
export function scanSource(source, relativePath) {
	const findings = [];
	const lines = source.split(/\r?\n/);
	// Track each line's character offset so the body probe starts at the call it
	// belongs to instead of at the first `(` in the file.
	let offset = 0;
	for (let index = 0; index < lines.length; index += 1) {
		const line = lines[index];
		const lineStart = offset;
		offset += line.length + 1;
		const match = SKIP_PATTERN.exec(stripComments(line));
		if (!match) continue;
		const callIndex = lineStart + match.index;
		const declarationWindow = [lines[index], lines[index - 1] ?? "", lines[index - 2] ?? ""].join("\n");
		const declared = DECLARATION_PATTERN.test(declarationWindow);
		const empty = hasEmptyBody(source, callIndex);
		findings.push({
			path: relativePath,
			line: index + 1,
			text: line.trim(),
			declared,
			empty,
		});
	}
	return findings;
}

export function checkRepo(repoRoot = REPO_ROOT) {
	const files = collectedTestFiles(repoRoot);
	const findings = [];
	for (const file of files) {
		const relativePath = relative(repoRoot, file).replace(/\\/g, "/");
		if (isAllowlisted(relativePath)) continue;
		findings.push(...scanSource(readFileSync(file, "utf8"), relativePath));
	}
	const violations = findings.filter((finding) => !finding.declared || finding.empty);
	return { files, findings, violations };
}

function main() {
	const args = process.argv.slice(2);
	const asJson = args.includes("--json");
	const repoIndex = args.indexOf("--repo");
	const repoRoot = repoIndex === -1 ? REPO_ROOT : resolve(args[repoIndex + 1]);

	const { files, findings, violations } = checkRepo(repoRoot);

	// Self-check: a silent allowlist entry is worse than no allowlist.
	for (const entry of ALLOWLIST) {
		if (!entry.reason || entry.reason.length < 24 || !entry.owner) {
			process.stderr.write(`allowlist entry ${entry.path} has no usable reason/owner\n`);
			process.exit(2);
		}
	}

	if (asJson) {
		process.stdout.write(`${JSON.stringify({ files: files.length, findings, violations }, null, 2)}\n`);
	} else {
		process.stdout.write(
			`Mandatory-skip contract: ${files.length} collected test file(s), ${findings.length} skip site(s), ${violations.length} violation(s).\n`,
		);
		for (const finding of findings) {
			process.stdout.write(
				`  ${finding.declared && !finding.empty ? "declared" : "VIOLATION"} ${finding.path}:${finding.line} ${finding.text}\n`,
			);
		}
	}

	if (violations.length > 0) {
		process.stderr.write(
			`${violations.length} undeclared or empty skip(s). Declare each one as \`// AIDR-SKIP: <backlog-id> <owner> - <reason>\` or make it a real assertion.\n`,
		);
		process.exit(1);
	}
	process.stdout.write("result: PASS\n");
}

if (process.argv[1] && resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url))) {
	main();
}
