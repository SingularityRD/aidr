/**
 * Countable facts about the shipped detection rules (threats/*.yaml), computed from the
 * rule files themselves so documentation can be checked against them instead of quoting
 * numbers that drift. Used by scripts/check-doc-claims.mjs.
 *
 * The rule files are a YAML list of mappings, one per rule, each starting with `- id:` at
 * column 0 and carrying top-level `category`, `action` and `severity` keys. Parsing is
 * line based (no YAML dependency) and asserts that every rule has those three keys, so a
 * format change fails loudly instead of producing a wrong count.
 */
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

const FIELD = /^ {2}(category|action|severity):\s*["']?([A-Za-z0-9_-]+)["']?\s*(?:#.*)?$/;

function parseRules(source, file) {
	const rules = [];
	let current = null;
	for (const line of source.split("\n")) {
		const id = line.match(/^- id:\s*["']?([^"'\s#]+)/);
		if (id) {
			current = { id: id[1], file };
			rules.push(current);
			continue;
		}
		const field = current && line.match(FIELD);
		if (field) current[field[1]] = field[2];
	}
	for (const rule of rules) {
		for (const key of ["category", "action", "severity"]) {
			if (!rule[key]) throw new Error(`${file}: rule ${rule.id} has no top-level ${key}`);
		}
	}
	return rules;
}

const tally = (values) => {
	const counts = {};
	for (const value of values) counts[value] = (counts[value] ?? 0) + 1;
	return counts;
};

/** Rule counts by file, action, severity and category for the rules under `<root>/threats`. */
export function loadRuleFacts(root) {
	const dir = path.join(root, "threats");
	const files = readdirSync(dir)
		.filter((name) => name.endsWith(".yaml"))
		.sort();
	const rules = files.flatMap((name) => parseRules(readFileSync(path.join(dir, name), "utf8"), name));
	return {
		total: rules.length,
		fileCount: files.length,
		byFile: Object.fromEntries(files.map((name) => [name, rules.filter((rule) => rule.file === name).length])),
		byAction: tally(rules.map((rule) => rule.action)),
		bySeverity: tally(rules.map((rule) => rule.severity)),
		byCategory: tally(rules.map((rule) => rule.category)),
		rules,
	};
}
