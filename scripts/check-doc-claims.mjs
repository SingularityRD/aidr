#!/usr/bin/env node
/**
 * Customer-facing documentation claims checked against the repository.
 *
 *   node scripts/check-doc-claims.mjs          # exit 1 and list every stale claim
 *   node scripts/check-doc-claims.mjs --facts  # print the computed facts
 *
 * Checks, over the customer-facing surfaces (README.md, PRODUCT_SCOPE_AND_FEATURES.md and
 * docs/ except dated or internal records; see CUSTOMER_SURFACES):
 *
 * 1. Rule counts. Any "<N> rules" / "<N> kural" total, "rules in <N> files", the action
 *    split ("219 block, 260 require approval and 28 log") and severity split sentences, the
 *    per-file rule table and the per-category rule table must match threats/*.yaml
 *    (scripts/lib/rule-facts.mjs). Numbers are never hard-coded here.
 * 2. Connector status. While deploy/native/support-matrix.json records no real-host
 *    acceptance evidence for a connector, every document that sells it must carry its
 *    preview marker (PREVIEW_MARKERS); once evidence exists the marker must go.
 * 3. Fail-closed caveat. A paragraph that says a connector, hook or entry point fails
 *    closed must, in the same paragraph, say what the host still lets through (a disabled,
 *    untrusted, killed or timed-out hook).
 *
 * Tested by scripts/check-doc-claims.test.mjs.
 */
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { loadRuleFacts } from "./lib/rule-facts.mjs";

const repositoryRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

/** Internal or dated records that describe the past on purpose and are not sold copy. */
const EXCLUDED = [
	/^docs\/(?:production-readiness|audit|evidence|strategy)\//,
	/(?:^|\/)[^/]*(?:historical|\d{8}|\d{4}-\d{2}-\d{2})[^/]*$/,
];

/** Customer-facing Markdown and HTML documents, relative to `root`. */
export function customerSurfaces(root = repositoryRoot) {
	const tracked = execFileSync("git", ["ls-files", "-z", "--", "docs", "README.md", "PRODUCT_SCOPE_AND_FEATURES.md"], {
		cwd: root,
		encoding: "utf8",
	})
		.split("\0")
		.filter((file) => /\.(?:md|html)$/.test(file));
	return tracked.filter((file) => !EXCLUDED.some((pattern) => pattern.test(file)) && existsSync(path.join(root, file)));
}

/**
 * Documents that sell or install the Cursor / VS Code connectors. Each must carry the
 * preview marker while the support matrix has no real-host evidence for them.
 */
export const PREVIEW_SURFACES = [
	"README.md",
	"docs/product/overview.md",
	"docs/getting-started.md",
	"docs/package-installation.md",
	"docs/platform-guides/cursor.md",
	"docs/compatibility-matrix.md",
	"docs/sales/one-pager.md",
	"docs/sales/pricing.md",
	"docs/sales/security-faq.md",
	"docs/sales/competitive.md",
	"docs/sales/demo-script.md",
	"docs/faq.md",
	"docs/product/features/en/01-ai-agent-security.md",
	"docs/product/features/tr/01-ai-agent-security.md",
	"docs/sales/catalog/catalog.en.html",
	"docs/sales/catalog/catalog.tr.html",
	"docs/sales/brochure/brochure.en.html",
	"docs/sales/brochure/brochure.tr.html",
];

/** The status phrase a document uses for a connector with no real-host evidence. */
export const PREVIEW_MARKERS = [/preview\s*[—-]+\s*no real-host acceptance evidence yet/i, /önizleme\s*[—-]+\s*henüz gerçek ortam kabul kanıtı yok/i];

/** Connectors whose support-matrix row has no acceptance evidence. */
export function connectorsWithoutEvidence(root = repositoryRoot) {
	const matrix = JSON.parse(readFileSync(path.join(root, "deploy/native/support-matrix.json"), "utf8"));
	return matrix.rows.filter((row) => (row.acceptanceEvidence ?? []).length === 0).map((row) => row.connector);
}

/** Visible text of an HTML document (tags, styles, scripts and entities removed). */
export function visibleText(source) {
	return source
		.replace(/<style[\s\S]*?<\/style>/g, " ")
		.replace(/<script[\s\S]*?<\/script>/g, " ")
		.replace(/<svg class="sprite"[\s\S]*?<\/svg>/, " ")
		.replace(/<!--[\s\S]*?-->/g, " ")
		.replace(/<\/(?:p|li|div|tr|h\d|section)>/g, "\n\n")
		.replace(/<[^>]+>/g, " ")
		.replace(/&nbsp;/g, " ")
		.replace(/&amp;/g, "&")
		.replace(/&#8209;/g, "-")
		.replace(/&mdash;/g, "—")
		.replace(/[ \t]+/g, " ");
}

const lineOf = (text, index) => text.slice(0, index).split("\n").length;
const num = (value) => Number(String(value).replace(/[,.]/g, ""));

/** Rule-count claims in `text`: [{line, kind, claimed, expected}] that disagree with `facts`. */
export function staleRuleClaims(text, facts) {
	const problems = [];
	const expect = (index, kind, claimed, expected) => {
		if (num(claimed) !== expected) problems.push({ line: lineOf(text, index), kind, claimed: num(claimed), expected });
	};
	const flat = text.replace(/\*\*/g, "");
	// Totals: "507 rules", "507 YAML threat rules", "507 kural", "507 tespit kuralı", "507 kuralın".
	for (const m of flat.matchAll(/(?<![\w,.+-])(\d{3,})(?![\d,.+])\s+(?:YAML\s+)?(?:threat\s+|detection\s+|shipped\s+|heuristic\s+)?rules\b/gi)) {
		expect(m.index, "rule total", m[1], facts.total);
	}
	for (const m of flat.matchAll(/(?<![\w,.+-])(\d{3,})(?![\d,.+])(?:'\S*)?\s+(?:YAML\s+)?(?:tespit\s+)?kural/gi)) {
		expect(m.index, "rule total", m[1], facts.total);
	}
	// File counts: "rules in 29 files", "rules across 29 files", "in 29 rule files", "29 dosyada", "| 29 files |".
	for (const m of flat.matchAll(/rules?\s+(?:in|across)\s+(\d+)\s+(?:rule\s+)?files|in\s+(\d+)\s+rule\s+files|(\d+)\s+dosyada\s+\d+\s+kural|\(\s*(\d+)\s+dosya\s*\)/gi)) {
		expect(m.index, "rule file count", m[1] ?? m[2] ?? m[3] ?? m[4], facts.fileCount);
	}
	// Action split, EN and TR.
	for (const m of flat.matchAll(/Of\s+the\s+\d+\s+rules,\s+(\d+)\s+block,\s+(\d+)\s+require\s+approval(?:,|\s+and)\s+(\d+)\s+(?:only\s+)?log/gi)) {
		expect(m.index, "block rules", m[1], facts.byAction.block ?? 0);
		expect(m.index, "require_approval rules", m[2], facts.byAction.require_approval ?? 0);
		expect(m.index, "log rules", m[3], facts.byAction.log ?? 0);
	}
	for (const m of flat.matchAll(/\d+\s+kuralın\s+(\d+)'\S+\s+engeller,\s+(\d+)'\S+\s+onay\s+ister,?\s+(\d+)'\S+\s+yalnızca\s+kayıt\s+tutar/gi)) {
		expect(m.index, "block rules", m[1], facts.byAction.block ?? 0);
		expect(m.index, "require_approval rules", m[2], facts.byAction.require_approval ?? 0);
		expect(m.index, "log rules", m[3], facts.byAction.log ?? 0);
	}
	// Severity split, EN and TR.
	for (const m of flat.matchAll(/(\d+)\s+are\s+critical,\s+(\d+)\s+high\s+and\s+(\d+)\s+medium/gi)) {
		expect(m.index, "critical rules", m[1], facts.bySeverity.critical ?? 0);
		expect(m.index, "high rules", m[2], facts.bySeverity.high ?? 0);
		expect(m.index, "medium rules", m[3], facts.bySeverity.medium ?? 0);
	}
	for (const m of flat.matchAll(/(\d+)'\S+\s+critical,\s+(\d+)'\S+\s+high,\s+(\d+)'\S+\s+medium/gi)) {
		expect(m.index, "critical rules", m[1], facts.bySeverity.critical ?? 0);
		expect(m.index, "high rules", m[2], facts.bySeverity.high ?? 0);
		expect(m.index, "medium rules", m[3], facts.bySeverity.medium ?? 0);
	}
	return problems;
}

const cells = (row) =>
	row
		.trim()
		.replace(/^\||\|$/g, "")
		.split("|")
		.map((cell) => cell.trim());

/**
 * The per-file and per-category rule tables. A file row names `*.yaml` files in its first
 * cell and ends with a count ("31", or "27 + 8 + 10 = 45" for a multi-file row); a category
 * row lists `category` (n) items (or one bare `category`, or `skill_*`) and ends with the
 * row total. Category counts summed over all rows must equal the repository's counts, and
 * the table totals must equal the rule total.
 */
export function staleRuleTables(text, facts) {
	const problems = [];
	const lines = text.split("\n");
	let fileTable = null;
	let categoryTable = null;
	const flush = () => {
		if (fileTable) {
			for (const [name, count] of Object.entries(facts.byFile)) {
				if (!fileTable.seen.has(name)) problems.push({ line: fileTable.line, kind: `rule file ${name} missing from the table`, claimed: 0, expected: count });
			}
		}
		if (categoryTable) {
			for (const [category, count] of Object.entries(facts.byCategory)) {
				const claimed = categoryTable.sums.get(category) ?? 0;
				if (claimed !== count) problems.push({ line: categoryTable.line, kind: `category ${category} across the table`, claimed, expected: count });
			}
		}
		fileTable = null;
		categoryTable = null;
	};
	lines.forEach((raw, index) => {
		const line = index + 1;
		if (!raw.trim().startsWith("|")) {
			flush();
			return;
		}
		const row = cells(raw.replace(/\*\*/g, ""));
		const last = row.at(-1);
		const yamlFiles = [...row[0].matchAll(/`([\w.-]+\.yaml)`/g)].map((m) => m[1]);
		if (yamlFiles.length > 0 && /^[\d\s+=]+$/.test(last)) {
			fileTable ??= { line, seen: new Set() };
			const parts = last.split("=").map((part) => part.trim());
			const addends = parts[0].split("+").map((part) => num(part.trim()));
			const total = num(parts.at(-1));
			if (addends.length !== yamlFiles.length) {
				problems.push({ line, kind: `row ${row[0]} lists ${yamlFiles.length} files and ${addends.length} counts`, claimed: addends.length, expected: yamlFiles.length });
			}
			yamlFiles.forEach((name, i) => {
				fileTable.seen.add(name);
				const expected = facts.byFile[name];
				if (expected === undefined) problems.push({ line, kind: `rule file ${name} does not exist`, claimed: addends[i], expected: 0 });
				else if (addends[i] !== expected) problems.push({ line, kind: `rules in ${name}`, claimed: addends[i], expected });
			});
			if (addends.reduce((a, b) => a + b, 0) !== total) problems.push({ line, kind: "row sum", claimed: total, expected: addends.reduce((a, b) => a + b, 0) });
			return;
		}
		const items = [...row.slice(1, -1).join(" ").matchAll(/`([a-z_]+\*?)`(?:\s*\((\d+)\))?/g)];
		if (items.length > 0 && /^\d+$/.test(last)) {
			categoryTable ??= { line, sums: new Map() };
			const rowTotal = num(last);
			let itemSum = 0;
			for (const [, name, count] of items) {
				const categories = name.endsWith("*") ? Object.keys(facts.byCategory).filter((c) => c.startsWith(name.slice(0, -1))) : [name];
				const value = count === undefined ? (items.length === 1 ? rowTotal : Number.NaN) : num(count);
				if (name.endsWith("*")) {
					const expected = categories.reduce((sum, c) => sum + facts.byCategory[c], 0);
					if (value !== expected) problems.push({ line, kind: `categories ${name}`, claimed: value, expected });
					for (const c of categories) categoryTable.sums.set(c, (categoryTable.sums.get(c) ?? 0) + facts.byCategory[c]);
				} else {
					categoryTable.sums.set(name, (categoryTable.sums.get(name) ?? 0) + value);
				}
				itemSum += value;
			}
			if (itemSum !== rowTotal) problems.push({ line, kind: `row ${row[0]} total`, claimed: rowTotal, expected: itemSum });
			return;
		}
		// Total rows: "| Total | 29 files | 507 |", "| Toplam | | 507 |".
		if (/^(?:Total|Toplam)$/i.test(row[0]) && /^\d+$/.test(last) && (fileTable || categoryTable)) {
			if (num(last) !== facts.total) problems.push({ line, kind: "table total", claimed: num(last), expected: facts.total });
			const files = row[1]?.match(/^(\d+)\s+(?:files|dosya)$/);
			if (files && num(files[1]) !== facts.fileCount) problems.push({ line, kind: "table file count", claimed: num(files[1]), expected: facts.fileCount });
		}
	});
	flush();
	return problems;
}

/**
 * A claim that connectors (their entry points or hooks) fail closed: "Connector entry points
 * fail closed", "Fail-closed connectors", "fail-closed behaviour per connector", and the
 * Turkish equivalents.
 */
const FAIL_CLOSED = /(?:connector|bağlayıcı|connector'lar|entry point|giriş noktası|hook|kanca)[^.|]{0,60}?(?:fail(?:s|ing)?[- ]\*{0,2}closed|fail-closed|kapalı kal|hata durumunda kapalı)|fail[- ]closed\s+(?:connectors?|behaviou?r\s+per\s+connector|davranışı)|hata durumunda kapalı[\s—–-]+bağlayıcı/i;
const HOST_CAVEAT = /disabled|untrusted|killed|timed[- ]out|crash|devre dışı|güvenilmeyen|öldürülen|sonlandırılan|zaman aşımı|çök/i;

/**
 * Paragraphs that claim connector fail-closed behaviour without the host caveat. Headings and
 * link texts are ignored (a heading or table-of-contents entry is followed by its section).
 */
export function failClosedWithoutCaveat(text) {
	const problems = [];
	for (const match of text.matchAll(/[^\n]+(?:\n(?!\s*\n)[^\n]*)*/g)) {
		const block = match[0]
			.split("\n")
			.filter((line) => !/^\s{0,3}#{1,6}\s/.test(line))
			.join("\n")
			.replace(/\[([^\]]*)\]\([^)]*\)/g, "");
		if (FAIL_CLOSED.test(block) && !HOST_CAVEAT.test(block)) {
			const at = Math.max(0, match[0].search(FAIL_CLOSED));
			problems.push({ line: lineOf(text, match.index + at), kind: "fail-closed claim without the host caveat", excerpt: block.trim().slice(0, 160) });
		}
	}
	return problems;
}

/** Text to check for a document: visible text for HTML, the Markdown source otherwise. */
export function documentText(file, root = repositoryRoot) {
	const source = readFileSync(path.join(root, file), "utf8");
	return file.endsWith(".html") ? visibleText(source) : source;
}

/** Every stale claim across the customer-facing surfaces. */
export function checkDocClaims(root = repositoryRoot) {
	const facts = loadRuleFacts(root);
	const problems = [];
	for (const file of customerSurfaces(root)) {
		const text = documentText(file, root);
		// Rendered HTML with a Markdown source (the feature guide) is checked through its source.
		const paragraphs = file.endsWith(".md") || file.startsWith("docs/sales/") ? failClosedWithoutCaveat(text) : [];
		for (const problem of [...staleRuleClaims(text, facts), ...staleRuleTables(text, facts), ...paragraphs]) {
			problems.push({ file, ...problem });
		}
	}
	const preview = connectorsWithoutEvidence(root).some((connector) => connector === "cursor" || connector === "vscode");
	for (const file of PREVIEW_SURFACES) {
		if (!existsSync(path.join(root, file))) {
			problems.push({ file, line: 0, kind: "preview surface is missing" });
			continue;
		}
		const text = documentText(file, root);
		const marked = PREVIEW_MARKERS.some((marker) => marker.test(text));
		if (preview && !marked) problems.push({ file, line: 0, kind: "Cursor/VS Code sold without the preview marker (support matrix has no real-host evidence)" });
		if (!preview && marked) problems.push({ file, line: 0, kind: "preview marker remains although the support matrix now records real-host evidence" });
	}
	return { facts, problems };
}

function main(argv) {
	const { facts, problems } = checkDocClaims();
	if (argv.includes("--facts")) {
		const { rules, ...summary } = facts;
		console.log(JSON.stringify(summary, null, 2));
		return;
	}
	for (const { file, line, kind, claimed, expected, excerpt } of problems) {
		const detail = excerpt ? `: ${excerpt}` : claimed !== undefined ? `: says ${claimed}, repository says ${expected}` : "";
		console.error(`${file}:${line} ${kind}${detail}`);
	}
	console.log(`Documentation claims: ${problems.length} problem(s); ${facts.total} rules in ${facts.fileCount} files.`);
	process.exitCode = problems.length === 0 ? 0 : 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
	main(process.argv.slice(2));
}
