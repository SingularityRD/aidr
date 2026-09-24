#!/usr/bin/env node
/**
 * Vendor the pure AIDR Privacy rule layer into the core DLP engine.
 *
 * Core is built before every other workspace package and is bundled into each
 * connector, so it cannot take a runtime dependency on packages/privacy without
 * reordering the workspace/release builds. Instead the browser-safe, synchronous
 * rule sources (normalization, detectors, validators, dictionary, span merging and
 * the rules.ts facade) are copied verbatim, with a generated-file header, into
 * packages/core/src/dlp/privacy-rules/. packages/privacy stays the single source of
 * truth; `--check` fails on any drift so the copy cannot be edited independently.
 *
 *   node scripts/sync-privacy-rules.mjs          # regenerate
 *   node scripts/sync-privacy-rules.mjs --check  # verify (non-zero exit on drift)
 */
import { mkdirSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
export const PRIVACY_SOURCE_DIR = join(root, "packages", "privacy", "src");
export const PRIVACY_RULES_TARGET_DIR = join(root, "packages", "core", "src", "dlp", "privacy-rules");

/** Closed dependency set of rules.ts. Every relative import must resolve inside this list. */
export const PRIVACY_RULE_FILES = Object.freeze([
	"types.ts",
	"errors.ts",
	"normalize.ts",
	"validators.ts",
	"ip.ts",
	"dictionary.ts",
	"spans.ts",
	"detectors.ts",
	"rules.ts",
]);

function header(file) {
	return (
		`// GENERATED from packages/privacy/src/${file} by scripts/sync-privacy-rules.mjs — do not edit\n` +
		"// Regenerate: pnpm sync:privacy-rules (verify: pnpm verify:privacy-rules)\n"
	);
}

/**
 * Core compiles with the same Node16 ESM + strict + noUncheckedIndexedAccess settings the
 * privacy package already uses, so no code rewriting is needed. The transform only enforces
 * that the copied graph is closed and free of Node built-ins (the rules must stay pure).
 */
export function transformPrivacyRuleSource(file, source) {
	const text = source.replaceAll("\r\n", "\n");
	for (const match of text.matchAll(/\bfrom\s+['"]([^'"]+)['"]/g)) {
		const specifier = match[1];
		if (!specifier.startsWith("./") || !specifier.endsWith(".js")) {
			throw new Error(`${file}: non-local import ${specifier} is not allowed in vendored privacy rules`);
		}
		const target = `${specifier.slice(2, -3)}.ts`;
		if (target.includes("/") || !PRIVACY_RULE_FILES.includes(target)) {
			throw new Error(`${file}: import ${specifier} escapes the vendored privacy rule set`);
		}
	}
	if (/\bimport\s*\(|\brequire\s*\(|node:/.test(text)) {
		throw new Error(`${file}: dynamic imports, require() and node: modules are not allowed`);
	}
	return header(file) + text;
}

/** Expected generated file contents keyed by file name. */
export function expectedPrivacyRuleFiles() {
	const files = new Map();
	for (const file of PRIVACY_RULE_FILES) {
		const source = readFileSync(join(PRIVACY_SOURCE_DIR, file), "utf8");
		files.set(file, transformPrivacyRuleSource(file, source));
	}
	return files;
}

/** Returns human-readable drift descriptions; empty when the vendored copy is current. */
export function privacyRulesDrift() {
	const expected = expectedPrivacyRuleFiles();
	const problems = [];
	let present = [];
	try {
		present = readdirSync(PRIVACY_RULES_TARGET_DIR).filter((name) => name.endsWith(".ts"));
	} catch {
		return [`missing directory ${PRIVACY_RULES_TARGET_DIR}`];
	}
	for (const name of present) {
		if (!expected.has(name)) problems.push(`unexpected file ${name}`);
	}
	for (const [name, content] of expected) {
		let actual;
		try {
			actual = readFileSync(join(PRIVACY_RULES_TARGET_DIR, name), "utf8").replaceAll("\r\n", "\n");
		} catch {
			problems.push(`missing file ${name}`);
			continue;
		}
		if (actual !== content) problems.push(`stale file ${name}`);
	}
	return problems;
}

export function writePrivacyRules() {
	const expected = expectedPrivacyRuleFiles();
	mkdirSync(PRIVACY_RULES_TARGET_DIR, { recursive: true });
	for (const name of readdirSync(PRIVACY_RULES_TARGET_DIR)) {
		if (name.endsWith(".ts") && !expected.has(name)) rmSync(join(PRIVACY_RULES_TARGET_DIR, name));
	}
	for (const [name, content] of expected) writeFileSync(join(PRIVACY_RULES_TARGET_DIR, name), content);
	return [...expected.keys()];
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	if (process.argv.includes("--check")) {
		const drift = privacyRulesDrift();
		if (drift.length > 0) {
			console.error(
				`Vendored privacy rules drift (${drift.join("; ")}): run pnpm sync:privacy-rules`,
			);
			process.exit(1);
		}
		console.log(`privacy rules in sync (${PRIVACY_RULE_FILES.length} files)`);
	} else {
		const written = writePrivacyRules();
		console.log(`wrote ${written.length} vendored privacy rule files to packages/core/src/dlp/privacy-rules`);
	}
}
