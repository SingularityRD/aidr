#!/usr/bin/env node
/**
 * Offline licence report derived from a CycloneDX SBOM.
 *
 * Reads the SBOM produced by `scripts/generate-sbom.mjs` (no network, no
 * registry lookups) and classifies every library's declared licence against a
 * conservative procurement policy. It reports facts only: components with no
 * declared licence are listed as UNKNOWN and are never assumed permissive.
 * This is an engineering input to the COM-002 counsel review, not legal
 * approval.
 *
 * Usage:
 *   node scripts/generate-license-report.mjs [--sbom <file>] [--output <json>] [--markdown <md>] [--strict]
 *
 * `--strict` exits 1 when any component is UNKNOWN or copyleft/review-required.
 */

import { existsSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const PERMISSIVE = new Set([
	"MIT", "MIT-0", "ISC", "BSD-2-CLAUSE", "BSD-3-CLAUSE", "0BSD", "APACHE-2.0", "BLUEOAK-1.0.0",
	"PYTHON-2.0", "ZLIB", "UNLICENSE", "CC0-1.0", "CC-BY-4.0", "PSF-2.0", "WTFPL", "UPL-1.0",
]);
// Weak or strong copyleft: needs a documented distribution analysis before shipping.
const REVIEW_REQUIRED = [/^MPL/i, /^LGPL/i, /^EPL/i, /^CDDL/i, /^GPL/i, /^AGPL/i, /^SSPL/i, /^EUPL/i, /^OSL/i, /^CPAL/i, /^BUSL/i, /^CC-BY-NC/i, /^CC-BY-SA/i];

export function splitExpression(expression) {
	return String(expression)
		.replace(/[()]/g, " ")
		.split(/\s+(?:OR|AND|WITH)\s+/i)
		.map((part) => part.trim())
		.filter(Boolean);
}

function classifyId(id) {
	const upper = id.toUpperCase();
	if (REVIEW_REQUIRED.some((pattern) => pattern.test(id))) return "review-required";
	if (PERMISSIVE.has(upper)) return "permissive";
	return "other";
}

/** Classify one CycloneDX component's `licenses` array. */
export function classifyComponent(component) {
	const declared = [];
	for (const entry of component.licenses ?? []) {
		const lic = entry?.license ?? entry;
		const value = lic?.id ?? lic?.expression ?? lic?.name ?? entry?.expression;
		if (typeof value === "string" && value.trim()) declared.push(value.trim());
	}
	if (declared.length === 0) return { declared, category: "unknown" };
	const parts = declared.flatMap(splitExpression);
	const categories = parts.map(classifyId);
	const isOr = declared.some((value) => /\sOR\s/i.test(value));
	let category;
	if (categories.every((c) => c === "permissive")) category = "permissive";
	// "MIT OR GPL-3.0" can be satisfied by the permissive option.
	else if (isOr && categories.includes("permissive")) category = "permissive";
	else if (categories.includes("review-required")) category = "review-required";
	else category = "other";
	return { declared, category };
}

export function buildReport(sbom) {
	const libraries = (sbom.components ?? []).filter((component) => component.type === "library");
	const byLicense = new Map();
	const components = [];
	for (const component of libraries) {
		const { declared, category } = classifyComponent(component);
		const key = declared.length ? declared.join(" + ") : "UNKNOWN";
		byLicense.set(key, (byLicense.get(key) ?? 0) + 1);
		components.push({ name: component.name, version: component.version, purl: component.purl, licenses: declared, category });
	}
	components.sort((a, b) => `${a.purl ?? a.name}`.localeCompare(`${b.purl ?? b.name}`));
	const count = (category) => components.filter((component) => component.category === category).length;
	return {
		schema: "aidr.license-report.v1",
		sbomSerialNumber: sbom.serialNumber ?? null,
		sbomTimestamp: sbom.metadata?.timestamp ?? null,
		totals: {
			libraries: components.length,
			permissive: count("permissive"),
			reviewRequired: count("review-required"),
			other: count("other"),
			unknown: count("unknown"),
		},
		byLicense: Object.fromEntries([...byLicense.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))),
		attention: components.filter((component) => component.category !== "permissive"),
		legalStatus:
			"Engineering inventory only. UNKNOWN means no licence was declared in the SBOM; it is not assumed safe. Counsel approval (COM-002) is not implied.",
	};
}

export function renderMarkdown(report) {
	const lines = [
		"# Licence report (offline, derived from CycloneDX SBOM)",
		"",
		report.legalStatus,
		"",
		`Libraries: ${report.totals.libraries} | permissive: ${report.totals.permissive} | review-required: ${report.totals.reviewRequired} | other: ${report.totals.other} | unknown: ${report.totals.unknown}`,
		"",
		"## By declared licence",
		"",
		"| Licence | Components |",
		"|---|---|",
		...Object.entries(report.byLicense).map(([license, n]) => `| ${license} | ${n} |`),
		"",
		"## Components needing attention",
		"",
		"| Component | Declared | Category |",
		"|---|---|---|",
		...report.attention.map((c) => `| ${c.name}@${c.version} | ${c.licenses.join(", ") || "UNKNOWN"} | ${c.category} |`),
		"",
	];
	return lines.join("\n");
}

function parseArgs(argv) {
	const args = {};
	for (let i = 0; i < argv.length; i += 1) {
		if (argv[i] === "--strict") args.strict = true;
		else if (argv[i].startsWith("--")) args[argv[i].slice(2)] = argv[++i];
	}
	return args;
}

async function main() {
	const args = parseArgs(process.argv.slice(2));
	const sbomPath = path.resolve(args.sbom ?? ".release-evidence/aidr-sbom.cdx.json");
	if (!existsSync(sbomPath)) {
		console.error(`SBOM not found: ${sbomPath}. Run: node scripts/generate-sbom.mjs`);
		process.exit(2);
	}
	const report = buildReport(JSON.parse(readFileSync(sbomPath, "utf8")));
	const output = path.resolve(args.output ?? ".release-evidence/aidr-license-report.json");
	await mkdir(path.dirname(output), { recursive: true });
	await writeFile(output, `${JSON.stringify(report, null, "\t")}\n`);
	if (args.markdown) await writeFile(path.resolve(args.markdown), `${renderMarkdown(report)}\n`);
	console.log(JSON.stringify({ status: "generated", output, ...report.totals }));
	if (args.strict && (report.totals.unknown || report.totals.reviewRequired || report.totals.other)) process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
