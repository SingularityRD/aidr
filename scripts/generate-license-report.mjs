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
 * `--strict` exits 1 for UNKNOWN, review-required, other terms or unresolved flags.
 */

import { existsSync, readFileSync } from "node:fs";
import { mkdir, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { parseSpdxExpression } from "./lib/pypi-license-data.mjs";

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
	if (id === "GNU Lesser General Public License v3 (LGPLv3)") return "review-required";
	if (REVIEW_REQUIRED.some((pattern) => pattern.test(id))) return "review-required";
	if (PERMISSIVE.has(upper)) return "permissive";
	return "other";
}

function classifyDeclaration(value) {
	if (value === "GNU Lesser General Public License v3 (LGPLv3)") return classifyId(value);
	const parsed = parseSpdxExpression(value);
	if (parsed) return parsed.obligation === "permissive" ? "permissive" : "review-required";
	// Unsupported expressions remain blocked; a permissive branch cannot erase
	// an unreviewed identifier, exception, or mandatory AND obligation.
	if (/\b(?:OR|AND|WITH)\b|[()]/i.test(value)) {
		return splitExpression(value).some((id) => classifyId(id) === "review-required") ? "review-required" : "other";
	}
	return classifyId(value);
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
	const categories = declared.map(classifyDeclaration);
	let category;
	if (categories.every((c) => c === "permissive")) category = "permissive";
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
		const licenseFlags = (component.properties ?? [])
			.filter((property) => property?.name === "aidr:license-flags" && typeof property.value === "string" && property.value.trim())
			.map((property) => property.value);
		components.push({ name: component.name, version: component.version, purl: component.purl, licenses: declared, category, ...(licenseFlags.length ? { licenseFlags } : {}) });
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
		attention: components.filter((component) => component.category !== "permissive" || component.licenseFlags?.length),
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
		"| Component | Declared | Category | Flags |",
		"|---|---|---|---|",
		...report.attention.map((c) => `| ${c.name}@${c.version} | ${c.licenses.join(", ") || "UNKNOWN"} | ${c.category} | ${(c.licenseFlags ?? []).join("; ")} |`),
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
	if (args.strict && report.attention.length) process.exit(1);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
