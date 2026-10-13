#!/usr/bin/env node
/**
 * Human-readable rule titles for the dashboard (approval cards show "what
 * was held" by title, not by rule id).
 *
 * Reads threats/*.yaml and writes packages/dashboard/src/generated/rule-titles.json
 * with each rule's English `title`, its Turkish `title_tr` when the rule has
 * one, its category and its severity. Patterns are never copied.
 *
 *   node packages/dashboard/scripts/rule-titles.mjs           # drift check (non-zero when stale)
 *   node packages/dashboard/scripts/rule-titles.mjs --write   # regenerate
 */
import { readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("../../..", import.meta.url));
const THREATS_DIR = join(root, "threats");
export const RULE_TITLES_PATH = join(
	root,
	"packages",
	"dashboard",
	"src",
	"generated",
	"rule-titles.json",
);

// `yaml` is a dependency of the core package, which parses the same files.
const { parse } = createRequire(join(root, "packages", "core", "package.json"))("yaml");

/** The generated file's exact text for the current rules. */
export function renderRuleTitles() {
	const rules = {};
	const files = readdirSync(THREATS_DIR)
		.filter((name) => name.endsWith(".yaml"))
		.sort();
	for (const file of files) {
		const records = parse(readFileSync(join(THREATS_DIR, file), "utf8"));
		if (!Array.isArray(records)) continue;
		for (const record of records) {
			if (!record || typeof record.id !== "string" || typeof record.title !== "string") continue;
			const entry = { title: record.title };
			if (typeof record.title_tr === "string" && record.title_tr.trim()) {
				entry.title_tr = record.title_tr;
			}
			if (typeof record.category === "string") entry.category = record.category;
			if (typeof record.severity === "string") entry.severity = record.severity;
			rules[record.id] = entry;
		}
	}
	const ids = Object.keys(rules).sort();
	const lines = ids.map((id) => `    ${JSON.stringify(id)}: ${JSON.stringify(rules[id])}`);
	return `{\n  "schema_version": 1,\n  "rules": {\n${lines.join(",\n")}\n  }\n}\n`;
}

function main(argv) {
	const content = renderRuleTitles();
	if (argv.includes("--write")) {
		writeFileSync(RULE_TITLES_PATH, content);
		console.log(`wrote ${RULE_TITLES_PATH}`);
		return 0;
	}
	let current = "";
	try {
		current = readFileSync(RULE_TITLES_PATH, "utf8");
	} catch {}
	if (current !== content) {
		console.error(
			"stale: packages/dashboard/src/generated/rule-titles.json\nRun `node packages/dashboard/scripts/rule-titles.mjs --write` and commit the result.",
		);
		return 1;
	}
	console.log("rule titles are up to date");
	return 0;
}

const isMain = process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) process.exitCode = main(process.argv.slice(2));
