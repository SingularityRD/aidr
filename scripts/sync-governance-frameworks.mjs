import { createHash } from "node:crypto";
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

// Governance framework control mapping (governance/frameworks/*.yaml).
//
// The YAML files are the single source of truth for how Singularity AIDR
// capabilities (product controls, not detection rules) map to NIST AI RMF,
// ISO/IEC 42001 Annex A, the EU AI Act, KVKK/GDPR, ISO/IEC 27001:2022 Annex A,
// the BDDK information systems regulation and the Presidency's Information and
// Communication Security Guide (vendor mappings, never certifications). The dashboard's
// governance scorecard embeds a projection of them at build time (the Vite
// bundle cannot read YAML), without repository paths.
//
//   node scripts/sync-governance-frameworks.mjs          validate + fail on drift
//   node scripts/sync-governance-frameworks.mjs --write  validate + regenerate
//
// Two embeds are generated: the dashboard's (scorecard, print view) and the
// compliance report's control-mapping section (supabase/functions/_shared).

const ROOT = resolve(fileURLToPath(new URL("..", import.meta.url)));
const FRAMEWORK_DIR = "governance/frameworks";
const GENERATED = "packages/dashboard/src/lib/governance-frameworks.generated.ts";
/** The compliance report's control-mapping section (Edge Functions cannot import the dashboard). */
const GENERATED_EDGE = "supabase/functions/_shared/governance-frameworks.generated.ts";
const CAPABILITIES_FILE = "capabilities.yaml";
/** Display order of the framework files. */
export const FRAMEWORK_FILES = Object.freeze([
	"nist-ai-rmf.yaml",
	"iso-iec-42001.yaml",
	"eu-ai-act.yaml",
	"kvkk-gdpr.yaml",
	"iso-iec-27001.yaml",
	"bddk-bsebh.yaml",
	"cbddo-big.yaml",
]);

export const COVERAGE_LEVELS = Object.freeze(["full", "partial", "customer-responsibility"]);
export const EVIDENCE_KINDS = Object.freeze(["table", "report_section", "function", "rpc", "file"]);
/**
 * Tenant signals the governance_scorecard RPC returns (see
 * supabase/migrations/20260927000060_governance_scorecard.sql), plus the two
 * fixed values `always` and `local_only`.
 */
export const CAPABILITY_SIGNALS = Object.freeze([
	"always",
	"local_only",
	"agents_reporting",
	"browser_guard_reporting",
	"dlp_policy_configured",
	"runtime_policy_configured",
	"human_approval_in_use",
	"acceptable_use_acknowledged",
	"mcp_inventory_reported",
	"posture_reported",
	"mfa_required",
	"retention_configured",
	"compliance_report_generated",
	"governance_digest_enabled",
]);

const CONTROL_ID_PATTERNS = {
	"nist-ai-rmf": /^(GOVERN|MAP|MEASURE|MANAGE) \d\.\d{1,2}$/,
	"iso-iec-42001": /^A\.(?:[2-9]|10)\.\d(?:\.\d)?$/,
	"eu-ai-act": /^Art\. \d{1,3}(?:\(\d{1,2}\))?$/,
	"kvkk-gdpr": /^(?:GDPR|KVKK) Art\. \d{1,3}(?:\(\d{1,2}\)(?:\([a-z]\))?)?$/,
	"iso-iec-27001": /^A\.(?:5\.(?:[1-9]|[1-3]\d)|6\.[1-8]|7\.(?:[1-9]|1[0-4])|8\.(?:[1-9]|[12]\d|3[0-4]))$/,
	// Topic codes: the mapping is made by requirement topic, not by article.
	"bddk-bsebh": /^BSEBY-[A-Z]{3,16}$/,
	"cbddo-big": /^BIG-[A-Z]{3,16}$/,
};
const ID = /^[a-z][a-z0-9-]{1,63}$/;
const EVIDENCE_ID = /^[a-z][a-z0-9_.-]{1,63}$/;

function requireYaml() {
	return createRequire(join(ROOT, "packages/core/package.json"))("yaml");
}

function readText(relative) {
	return readFileSync(join(ROOT, relative), "utf8").replaceAll("\r\n", "\n");
}

const isText = (value, min = 1) => typeof value === "string" && value.trim().length >= min;
const isIdList = (value) => Array.isArray(value) && value.every((item) => typeof item === "string");

/** Parse every framework file. Structural problems are returned, never thrown. */
export function loadGovernanceFrameworks() {
	const { parse } = requireYaml();
	const sources = [CAPABILITIES_FILE, ...FRAMEWORK_FILES].map((file) => {
		const text = readText(`${FRAMEWORK_DIR}/${file}`);
		return { file, text, data: parse(text) };
	});
	const catalog = sources[0].data ?? {};
	return {
		sources,
		capabilities: Array.isArray(catalog.capabilities) ? catalog.capabilities : [],
		evidence: Array.isArray(catalog.evidence) ? catalog.evidence : [],
		frameworks: sources.slice(1).map(({ file, data }) => ({ file, ...(data ?? {}) })),
	};
}

function migrationsText() {
	const dir = join(ROOT, "supabase/migrations");
	return readdirSync(dir)
		.filter((name) => name.endsWith(".sql"))
		.sort()
		.map((name) => readFileSync(join(dir, name), "utf8"))
		.join("\n");
}

function escapeRegExp(value) {
	return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Whether an evidence source exists in this repository. */
export function evidenceExists(item, context) {
	const ref = String(item.ref ?? "");
	switch (item.kind) {
		case "table":
			return new RegExp(`create table (?:if not exists )?public\\.${escapeRegExp(ref)}\\b`, "i").test(context.sql);
		case "rpc":
			return new RegExp(`function public\\.${escapeRegExp(ref)}\\s*\\(`, "i").test(context.sql);
		case "report_section":
			return new RegExp(`^\\s+${escapeRegExp(ref)}: `, "m").test(context.complianceReport);
		case "function":
			return /^[a-z0-9-]+$/.test(ref) && existsSync(join(ROOT, "supabase/functions", ref, "index.ts"));
		case "file":
			return !ref.startsWith("/") && !ref.includes("..") && existsSync(join(ROOT, ref));
		default:
			return false;
	}
}

/**
 * Every problem with the mapping: shape, identifiers, cross references, and
 * whether each referenced capability path and evidence source exists.
 */
export function validateGovernanceFrameworks(mapping = loadGovernanceFrameworks()) {
	const problems = [];
	const context = {
		sql: migrationsText(),
		complianceReport: readText("supabase/functions/_shared/compliance-report.ts"),
	};
	const capabilityIds = new Set();
	for (const [index, capability] of mapping.capabilities.entries()) {
		const at = `capabilities[${index}]${capability?.id ? ` (${capability.id})` : ""}`;
		if (!ID.test(capability?.id ?? "")) problems.push(`${at}: invalid id`);
		else if (capabilityIds.has(capability.id)) problems.push(`${at}: duplicate id`);
		else capabilityIds.add(capability.id);
		if (!isText(capability?.title, 8)) problems.push(`${at}: title required`);
		if (!isText(capability?.description, 20)) problems.push(`${at}: description required`);
		if (!CAPABILITY_SIGNALS.includes(capability?.signal)) problems.push(`${at}: unknown signal`);
		if (!isIdList(capability?.paths) || capability.paths.length === 0) {
			problems.push(`${at}: paths required`);
		} else {
			for (const path of capability.paths) {
				if (path.startsWith("/") || path.includes("..") || !existsSync(join(ROOT, path))) {
					problems.push(`${at}: path does not exist: ${path}`);
				}
			}
		}
	}
	const evidenceIds = new Set();
	for (const [index, item] of mapping.evidence.entries()) {
		const at = `evidence[${index}]${item?.id ? ` (${item.id})` : ""}`;
		if (!EVIDENCE_ID.test(item?.id ?? "")) problems.push(`${at}: invalid id`);
		else if (evidenceIds.has(item.id)) problems.push(`${at}: duplicate id`);
		else evidenceIds.add(item.id);
		if (!EVIDENCE_KINDS.includes(item?.kind)) problems.push(`${at}: unknown kind`);
		if (!isText(item?.ref)) problems.push(`${at}: ref required`);
		if (!isText(item?.detail, 10)) problems.push(`${at}: detail required`);
		if (EVIDENCE_KINDS.includes(item?.kind) && isText(item?.ref) && !evidenceExists(item, context)) {
			problems.push(`${at}: ${item.kind} ${item.ref} does not exist in the repository`);
		}
	}
	const usedCapabilities = new Set();
	const usedEvidence = new Set();
	for (const framework of mapping.frameworks) {
		const expectedId = framework.file.replace(/\.yaml$/, "");
		const meta = framework.framework ?? {};
		const at = framework.file;
		if (meta.id !== expectedId) problems.push(`${at}: framework.id must be ${expectedId}`);
		for (const field of ["name", "version", "reference", "scope"]) {
			if (!isText(meta[field])) problems.push(`${at}: framework.${field} required`);
		}
		const pattern = CONTROL_ID_PATTERNS[expectedId];
		const controls = Array.isArray(framework.controls) ? framework.controls : [];
		if (controls.length === 0) problems.push(`${at}: controls required`);
		const controlIds = new Set();
		for (const control of controls) {
			const where = `${at} ${control?.id ?? "<no id>"}`;
			if (typeof control?.id !== "string" || !pattern?.test(control.id)) problems.push(`${where}: invalid control id`);
			else if (controlIds.has(control.id)) problems.push(`${where}: duplicate control id`);
			else controlIds.add(control.id);
			if (expectedId === "nist-ai-rmf" && typeof control?.id === "string" && control.group !== control.id.split(" ")[0]) {
				problems.push(`${where}: group must be the AI RMF function`);
			}
			if (!isText(control?.group)) problems.push(`${where}: group required`);
			if (!isText(control?.title, 4)) problems.push(`${where}: title required`);
			if (!isText(control?.note, 40)) problems.push(`${where}: note must explain the coverage`);
			if (!COVERAGE_LEVELS.includes(control?.coverage)) problems.push(`${where}: invalid coverage`);
			if (!isIdList(control?.capabilities) || !isIdList(control?.evidence)) {
				problems.push(`${where}: capabilities and evidence must be lists`);
				continue;
			}
			if (control.coverage !== "customer-responsibility" &&
				(control.capabilities.length === 0 || control.evidence.length === 0)) {
				problems.push(`${where}: ${control.coverage} coverage needs at least one capability and one evidence source`);
			}
			for (const id of control.capabilities) {
				usedCapabilities.add(id);
				if (!capabilityIds.has(id)) problems.push(`${where}: unknown capability ${id}`);
			}
			for (const id of control.evidence) {
				usedEvidence.add(id);
				if (!evidenceIds.has(id)) problems.push(`${where}: unknown evidence source ${id}`);
			}
		}
	}
	for (const id of capabilityIds) if (!usedCapabilities.has(id)) problems.push(`capability ${id} is not mapped to any control`);
	for (const id of evidenceIds) if (!usedEvidence.has(id)) problems.push(`evidence ${id} is not referenced by any control`);
	return problems;
}

function sourceDigest(mapping) {
	const digest = createHash("sha256");
	for (const { file, text } of mapping.sources) digest.update(`${file}\n${text}\n`, "utf8");
	return digest.digest("hex");
}

/**
 * The compliance report embed: each framework's controls with capability
 * titles (not ids or paths), evidence ids, coverage and the coverage note.
 */
export function complianceControlMappingSource(mapping = loadGovernanceFrameworks()) {
	const titles = new Map(mapping.capabilities.map((capability) => [capability.id, capability.title]));
	const embedded = {
		source: FRAMEWORK_DIR,
		source_sha256: sourceDigest(mapping),
		frameworks: mapping.frameworks.map(({ framework, controls }) => ({
			id: framework.id,
			name: framework.name,
			version: framework.version,
			scope: framework.scope.trim(),
			controls: controls.map(({ id, group, title, capabilities, evidence, coverage, note }) => ({
				id,
				group,
				title,
				coverage,
				capabilities: capabilities.map((capability) => titles.get(capability) ?? capability),
				evidence,
				note: note.trim(),
			})),
		})),
	};
	return [
		"// Generated from governance/frameworks/*.yaml; do not edit.",
		"// Regenerate: node scripts/sync-governance-frameworks.mjs --write",
		"",
		"interface ComplianceMappedControl {",
		"\treadonly id: string;",
		"\treadonly group: string;",
		"\treadonly title: string;",
		'\treadonly coverage: "full" | "partial" | "customer-responsibility";',
		"\treadonly capabilities: readonly string[];",
		"\treadonly evidence: readonly string[];",
		"\treadonly note: string;",
		"}",
		"",
		"export interface ComplianceMappedFramework {",
		"\treadonly id: string;",
		"\treadonly name: string;",
		"\treadonly version: string;",
		"\treadonly scope: string;",
		"\treadonly controls: readonly ComplianceMappedControl[];",
		"}",
		"",
		"export const COMPLIANCE_CONTROL_MAPPING: {",
		"\treadonly source: string;",
		"\treadonly source_sha256: string;",
		"\treadonly frameworks: readonly ComplianceMappedFramework[];",
		`} = ${JSON.stringify(embedded, null, "\t")};`,
		"",
	].join("\n");
}

/** The dashboard embed: everything except repository paths. */
export function governanceFrameworksSource(mapping = loadGovernanceFrameworks()) {
	const embedded = {
		source: FRAMEWORK_DIR,
		source_sha256: sourceDigest(mapping),
		capabilities: mapping.capabilities.map(({ id, title, description, signal }) => ({ id, title, description, signal })),
		evidence: mapping.evidence.map(({ id, kind, ref, detail }) => ({ id, kind, ref, detail })),
		frameworks: mapping.frameworks.map(({ framework, controls }) => ({
			id: framework.id,
			name: framework.name,
			version: framework.version,
			reference: framework.reference,
			scope: framework.scope,
			controls: controls.map(({ id, group, title, capabilities, evidence, coverage, note }) => ({
				id, group, title, capabilities, evidence, coverage, note,
			})),
		})),
	};
	return [
		"// Generated from governance/frameworks/*.yaml; do not edit.",
		"// Regenerate: node scripts/sync-governance-frameworks.mjs --write",
		"",
		"type GovernanceCoverage = \"full\" | \"partial\" | \"customer-responsibility\";",
		"",
		"export interface GovernanceCapability {",
		"\treadonly id: string;",
		"\treadonly title: string;",
		"\treadonly description: string;",
		"\treadonly signal: string;",
		"}",
		"",
		"export interface GovernanceEvidenceSource {",
		"\treadonly id: string;",
		"\treadonly kind: string;",
		"\treadonly ref: string;",
		"\treadonly detail: string;",
		"}",
		"",
		"export interface GovernanceControl {",
		"\treadonly id: string;",
		"\treadonly group: string;",
		"\treadonly title: string;",
		"\treadonly capabilities: readonly string[];",
		"\treadonly evidence: readonly string[];",
		"\treadonly coverage: GovernanceCoverage;",
		"\treadonly note: string;",
		"}",
		"",
		"export interface GovernanceFramework {",
		"\treadonly id: string;",
		"\treadonly name: string;",
		"\treadonly version: string;",
		"\treadonly reference: string;",
		"\treadonly scope: string;",
		"\treadonly controls: readonly GovernanceControl[];",
		"}",
		"",
		"export const GOVERNANCE_MAPPING: {",
		"\treadonly source: string;",
		"\treadonly source_sha256: string;",
		"\treadonly capabilities: readonly GovernanceCapability[];",
		"\treadonly evidence: readonly GovernanceEvidenceSource[];",
		"\treadonly frameworks: readonly GovernanceFramework[];",
		`} = ${JSON.stringify(embedded, null, "\t")};`,
		"",
	].join("\n");
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
	const mapping = loadGovernanceFrameworks();
	const problems = validateGovernanceFrameworks(mapping);
	if (problems.length > 0) {
		console.error("Governance framework mapping is invalid:");
		for (const problem of problems) console.error(`- ${problem}`);
		process.exitCode = 1;
	} else {
		const outputs = [
			[GENERATED, governanceFrameworksSource(mapping)],
			[GENERATED_EDGE, complianceControlMappingSource(mapping)],
		];
		if (process.argv.includes("--write")) {
			for (const [relative, expected] of outputs) {
				writeFileSync(join(ROOT, relative), expected);
				console.log(`Wrote ${relative}.`);
			}
		} else {
			const drifted = outputs.filter(([relative, expected]) => {
				const target = join(ROOT, relative);
				return (existsSync(target) ? readFileSync(target, "utf8").replaceAll("\r\n", "\n") : "") !== expected;
			});
			if (drifted.length > 0) {
				console.error(
					`Governance framework drift (${drifted.map(([relative]) => relative).join(", ")}): run node scripts/sync-governance-frameworks.mjs --write`,
				);
				process.exitCode = 1;
			} else {
				console.log("Governance framework embeds match governance/frameworks.");
			}
		}
	}
}
