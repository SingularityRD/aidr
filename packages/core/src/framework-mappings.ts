/**
 * Security framework mapping for detection rules.
 *
 * `threats/mappings/frameworks.yaml` maps every shipped rule id to OWASP Top 10
 * for LLM Applications 2025 (LLM01-LLM10), OWASP Top 10 for Agentic
 * Applications 2026 (ASI01-ASI10) and MITRE ATLAS techniques. The threat loader
 * attaches the resolved mapping to each rule, so a verdict and its audit entry
 * can name the framework items the matched rule belongs to.
 *
 * The mapping is enrichment, never detection input: a missing or invalid file
 * leaves `frameworks` off the verdict, is logged, and changes no decision.
 */

import { join } from "node:path";
import { getFileContent } from "./file-utils.js";
import {
	FRAMEWORK_IDS,
	FRAMEWORKS,
	type FrameworkId,
	frameworkItemLabel,
	frameworkItemTitle,
	frameworkOfItem,
	MITRE_ATLAS_TACTICS,
	MITRE_ATLAS_TECHNIQUES,
	OWASP_AGENTIC_2026,
	OWASP_LLM_2025,
} from "./framework-catalog.js";
import type { FrameworkRefs, FrameworkRefsJson, Logger, Threat } from "./types.js";
import { nullLogger } from "./types.js";
import { parseShippedYaml } from "./yaml-parse-cache.js";

/** Path of the mapping file relative to a threats directory. */
export const FRAMEWORK_MAPPINGS_RELATIVE_PATH = join("mappings", "frameworks.yaml");

export type CoverageStatus = "covered" | "partial" | "not_covered" | "not_applicable";

const COVERAGE_STATUSES: readonly CoverageStatus[] = [
	"covered",
	"partial",
	"not_covered",
	"not_applicable",
];

export interface FrameworkAssessment {
	status: CoverageStatus;
	rationale: string;
}

export interface FrameworkMappings {
	schemaVersion: 1;
	assessments: Record<FrameworkId, Record<string, FrameworkAssessment>>;
	fileDefaults: Record<string, string[]>;
	categoryDefaults: Record<string, string[]>;
	rules: Record<string, string[]>;
}

/** The rule fields the mapping is resolved from. */
export interface FrameworkRuleRef {
	id: string;
	category: string;
	sourceFile?: string;
}

export interface FrameworkMappingsParseResult {
	mappings: FrameworkMappings | null;
	errors: string[];
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function parseIdList(value: unknown, where: string, errors: string[]): string[] {
	if (!Array.isArray(value)) {
		errors.push(`${where}: expected a list of framework IDs`);
		return [];
	}
	const ids: string[] = [];
	for (const entry of value) {
		if (typeof entry !== "string" || frameworkOfItem(entry) === null) {
			errors.push(`${where}: ${JSON.stringify(entry)} is not an official framework ID`);
			continue;
		}
		if (ids.includes(entry)) {
			errors.push(`${where}: duplicate ID ${entry}`);
			continue;
		}
		ids.push(entry);
	}
	return ids;
}

function parseIdListMap(value: unknown, where: string, errors: string[]): Record<string, string[]> {
	const out: Record<string, string[]> = {};
	if (value === undefined) return out;
	if (!isRecord(value)) {
		errors.push(`${where}: expected a mapping`);
		return out;
	}
	for (const [key, list] of Object.entries(value)) {
		out[key] = parseIdList(list, `${where}.${key}`, errors);
	}
	return out;
}

function parseAssessment(
	framework: FrameworkId,
	id: string,
	raw: unknown,
	errors: string[],
): FrameworkAssessment | null {
	const where = `assessments.${framework}.${id}`;
	if (frameworkOfItem(id) !== framework) {
		errors.push(`${where}: not an official ${FRAMEWORKS[framework].name} ID`);
		return null;
	}
	if (!isRecord(raw)) {
		errors.push(`${where}: expected {status, rationale}`);
		return null;
	}
	const { status, rationale } = raw;
	if (typeof status !== "string" || !COVERAGE_STATUSES.includes(status as CoverageStatus)) {
		errors.push(`${where}.status: must be one of ${COVERAGE_STATUSES.join(", ")}`);
		return null;
	}
	if (typeof rationale !== "string" || rationale.trim().length < 20) {
		errors.push(`${where}.rationale: a rationale of at least 20 characters is required`);
		return null;
	}
	return { status: status as CoverageStatus, rationale: rationale.trim() };
}

function parseAssessments(
	value: unknown,
	errors: string[],
): Record<FrameworkId, Record<string, FrameworkAssessment>> {
	const out: Record<FrameworkId, Record<string, FrameworkAssessment>> = {
		owasp_llm: {},
		owasp_agentic: {},
		mitre_atlas: {},
	};
	if (!isRecord(value)) {
		errors.push("assessments: expected a mapping");
		return out;
	}
	for (const [framework, items] of Object.entries(value)) {
		if (!FRAMEWORK_IDS.includes(framework as FrameworkId) || !isRecord(items)) {
			errors.push(`assessments.${framework}: expected a mapping for a known framework`);
			continue;
		}
		for (const [id, raw] of Object.entries(items)) {
			const assessment = parseAssessment(framework as FrameworkId, id, raw, errors);
			if (assessment) out[framework as FrameworkId][id] = assessment;
		}
	}
	for (const item of [...OWASP_LLM_2025, ...OWASP_AGENTIC_2026]) {
		const framework = frameworkOfItem(item.id) as FrameworkId;
		if (!out[framework][item.id]) {
			errors.push(`assessments.${framework}.${item.id}: every OWASP item needs an assessment`);
		}
	}
	return out;
}

/**
 * Validate and normalise a parsed mapping document. Every problem is reported;
 * `mappings` is null when any error was found so a half-valid file is never
 * used to label verdicts.
 */
export function parseFrameworkMappings(raw: unknown): FrameworkMappingsParseResult {
	const errors: string[] = [];
	if (!isRecord(raw)) return { mappings: null, errors: ["mapping file must be a YAML mapping"] };
	if (raw.schema_version !== 1) errors.push("schema_version: must be 1");
	const assessments = parseAssessments(raw.assessments, errors);
	const defaults = raw.defaults === undefined ? {} : raw.defaults;
	if (!isRecord(defaults)) errors.push("defaults: expected a mapping");
	const defaultsRecord = isRecord(defaults) ? defaults : {};
	const fileDefaults = parseIdListMap(defaultsRecord.files, "defaults.files", errors);
	const categoryDefaults = parseIdListMap(defaultsRecord.categories, "defaults.categories", errors);
	if (!isRecord(raw.rules)) errors.push("rules: expected a mapping of rule id to framework IDs");
	const rules = parseIdListMap(raw.rules ?? {}, "rules", errors);
	if (errors.length > 0) return { mappings: null, errors };
	return {
		mappings: { schemaVersion: 1, assessments, fileDefaults, categoryDefaults, rules },
		errors,
	};
}

/** Parse mapping YAML text. */
export function parseFrameworkMappingsYaml(text: string): FrameworkMappingsParseResult {
	let raw: unknown;
	try {
		raw = parseShippedYaml(text);
	} catch (error) {
		return { mappings: null, errors: [`invalid YAML: ${String(error)}`] };
	}
	return parseFrameworkMappings(raw);
}

/**
 * Load `<threatDir>/mappings/frameworks.yaml`. Returns null (and logs) when it is
 * absent or invalid; it never throws, because a mapping problem must not stop
 * rules from loading.
 */
export async function loadFrameworkMappings(
	threatDir: string,
	logger: Logger = nullLogger,
): Promise<FrameworkMappings | null> {
	const path = join(threatDir, FRAMEWORK_MAPPINGS_RELATIVE_PATH);
	let text: string;
	try {
		text = await getFileContent(path);
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
			logger.warn("Framework mapping file is unreadable; verdicts carry no framework IDs", {
				path,
				error: String(error),
			});
		}
		return null;
	}
	const { mappings, errors } = parseFrameworkMappingsYaml(text);
	if (!mappings) {
		logger.warn("Framework mapping file is invalid; verdicts carry no framework IDs", {
			path,
			errors: errors.slice(0, 20),
		});
	}
	return mappings;
}

function compareIds(a: string, b: string): number {
	return a < b ? -1 : a > b ? 1 : 0;
}

/**
 * Effective mapping of one rule: file default ∪ category default ∪ rule entry.
 * Returns null when the rule maps to nothing.
 */
export function resolveRuleFrameworks(
	mappings: FrameworkMappings,
	rule: FrameworkRuleRef,
): FrameworkRefs | null {
	const ids = new Set<string>([
		...(rule.sourceFile ? (mappings.fileDefaults[rule.sourceFile] ?? []) : []),
		...(Object.hasOwn(mappings.categoryDefaults, rule.category)
			? (mappings.categoryDefaults[rule.category] ?? [])
			: []),
		...(Object.hasOwn(mappings.rules, rule.id) ? (mappings.rules[rule.id] ?? []) : []),
	]);
	if (ids.size === 0) return null;
	const refs: FrameworkRefs = { owaspLlm: [], owaspAgentic: [], mitreAtlas: [] };
	for (const id of [...ids].sort(compareIds)) {
		const framework = frameworkOfItem(id);
		if (framework === "owasp_llm") refs.owaspLlm.push(id);
		else if (framework === "owasp_agentic") refs.owaspAgentic.push(id);
		else if (framework === "mitre_atlas") refs.mitreAtlas.push(id);
	}
	return refs;
}

export function frameworkRefsToJson(refs: FrameworkRefs): FrameworkRefsJson {
	return {
		owasp_llm: [...refs.owaspLlm],
		owasp_agentic: [...refs.owaspAgentic],
		mitre_atlas: [...refs.mitreAtlas],
	};
}

/**
 * Read a serialized `frameworks` object back (e.g. from an audit entry). Only
 * official IDs in the right bucket survive, so a tampered log cannot inject
 * arbitrary text into SIEM output through this field.
 */
export function frameworkRefsFromJson(value: unknown): FrameworkRefs | null {
	if (!isRecord(value)) return null;
	const pick = (key: keyof FrameworkRefsJson, framework: FrameworkId): string[] => {
		const list = value[key];
		if (!Array.isArray(list)) return [];
		const ids = list.filter(
			(id): id is string => typeof id === "string" && frameworkOfItem(id) === framework,
		);
		return [...new Set(ids)].sort(compareIds).slice(0, 32);
	};
	const refs: FrameworkRefs = {
		owaspLlm: pick("owasp_llm", "owasp_llm"),
		owaspAgentic: pick("owasp_agentic", "owasp_agentic"),
		mitreAtlas: pick("mitre_atlas", "mitre_atlas"),
	};
	return refs.owaspLlm.length + refs.owaspAgentic.length + refs.mitreAtlas.length > 0 ? refs : null;
}

/** All IDs of a mapping in one flat list, with OWASP edition labels (`LLM01:2025`). */
export function frameworkRefLabels(refs: FrameworkRefs): string[] {
	return [...refs.owaspLlm, ...refs.owaspAgentic, ...refs.mitreAtlas].map(frameworkItemLabel);
}

// ---------------------------------------------------------------------------
// Consistency checks (tests and the coverage generator)
// ---------------------------------------------------------------------------

/** A loaded rule as seen by the consistency check and the coverage matrix. */
export interface CoverageRule extends FrameworkRuleRef {
	title: string;
	sourceFile: string;
}

/**
 * Check a mapping against the rules it describes. Returns human-readable
 * problems; an empty list means every rule is mapped, every default points at
 * a real file or category, and every assessment agrees with the rule counts.
 */
export function validateFrameworkMappingsAgainstRules(
	mappings: FrameworkMappings,
	rules: readonly CoverageRule[],
): string[] {
	return [...ruleEntryProblems(mappings, rules), ...assessmentProblems(mappings, rules)];
}

/** Every rule has an entry with an OWASP item; every entry/default points at something real. */
function ruleEntryProblems(mappings: FrameworkMappings, rules: readonly CoverageRule[]): string[] {
	const problems: string[] = [];
	for (const rule of rules) {
		if (!Object.hasOwn(mappings.rules, rule.id)) {
			problems.push(
				`rule ${rule.id} (${rule.sourceFile}) has no entry in threats/mappings/frameworks.yaml`,
			);
			continue;
		}
		const refs = resolveRuleFrameworks(mappings, rule);
		if (!refs || refs.owaspLlm.length + refs.owaspAgentic.length === 0) {
			problems.push(`rule ${rule.id} maps to no OWASP LLM or Agentic item`);
		}
	}
	const unknown = (keys: string[], known: Set<string>, what: string) =>
		keys.filter((key) => !known.has(key)).map((key) => `${what} ${key}`);
	problems.push(
		...unknown(
			Object.keys(mappings.rules),
			new Set(rules.map((rule) => rule.id)),
			"mapping for unknown or inactive rule",
		),
		...unknown(
			Object.keys(mappings.fileDefaults),
			new Set(rules.map((rule) => rule.sourceFile)),
			"file default for unknown rule file",
		),
		...unknown(
			Object.keys(mappings.categoryDefaults),
			new Set(rules.map((rule) => rule.category)),
			"category default for unknown category",
		),
	);
	return problems;
}

/** Assessments agree with the rule counts; every mapped ATLAS technique is assessed. */
function assessmentProblems(mappings: FrameworkMappings, rules: readonly CoverageRule[]): string[] {
	const problems: string[] = [];
	const counts = countRulesPerItem(mappings, rules);
	for (const framework of FRAMEWORK_IDS) {
		for (const [id, assessment] of Object.entries(mappings.assessments[framework])) {
			const count = counts.get(id)?.length ?? 0;
			const claimsCoverage = assessment.status === "covered" || assessment.status === "partial";
			if (claimsCoverage !== count > 0) {
				problems.push(`${id} is assessed "${assessment.status}" but ${count} rule(s) map to it`);
			}
		}
	}
	for (const id of counts.keys()) {
		if (frameworkOfItem(id) === "mitre_atlas" && !mappings.assessments.mitre_atlas[id]) {
			problems.push(`ATLAS technique ${id} is mapped but has no assessment`);
		}
	}
	return problems;
}

function countRulesPerItem(
	mappings: FrameworkMappings,
	rules: readonly CoverageRule[],
): Map<string, string[]> {
	const byItem = new Map<string, string[]>();
	for (const rule of rules) {
		const refs = resolveRuleFrameworks(mappings, rule);
		if (!refs) continue;
		for (const id of [...refs.owaspLlm, ...refs.owaspAgentic, ...refs.mitreAtlas]) {
			const list = byItem.get(id) ?? [];
			list.push(rule.id);
			byItem.set(id, list);
		}
	}
	for (const list of byItem.values()) list.sort(compareIds);
	return byItem;
}

// ---------------------------------------------------------------------------
// Coverage matrix
// ---------------------------------------------------------------------------

const EXAMPLE_RULE_COUNT = 3;

export interface CoverageItem {
	id: string;
	label: string;
	title: string;
	status: CoverageStatus;
	rationale: string;
	ruleCount: number;
	exampleRules: string[];
	/** ATLAS only: tactics the technique achieves. */
	tactics?: string[];
}

export interface CoverageTacticSummary {
	id: string;
	name: string;
	techniquesMapped: number;
	techniquesTotal: number;
}

export interface FrameworkCoverage {
	id: FrameworkId;
	name: string;
	version: string;
	url: string;
	/** Items in the official list (ATLAS: techniques and sub-techniques). */
	itemsTotal: number;
	statusCounts: Record<CoverageStatus, number>;
	/** OWASP: all ten items. ATLAS: only techniques at least one rule maps to. */
	items: CoverageItem[];
	/** ATLAS only. */
	tactics?: CoverageTacticSummary[];
}

export interface CoverageMatrix {
	ruleCount: number;
	ruleFiles: number;
	frameworks: FrameworkCoverage[];
}

function emptyStatusCounts(): Record<CoverageStatus, number> {
	return { covered: 0, partial: 0, not_covered: 0, not_applicable: 0 };
}

/** Build the coverage matrix for a rule set and its mapping. */
export function buildCoverageMatrix(
	mappings: FrameworkMappings,
	rules: readonly CoverageRule[],
): CoverageMatrix {
	const byItem = countRulesPerItem(mappings, rules);
	const item = (framework: FrameworkId, id: string): CoverageItem => {
		const ruleIds = byItem.get(id) ?? [];
		const assessment = mappings.assessments[framework][id];
		const built: CoverageItem = {
			id,
			label: frameworkItemLabel(id),
			title: frameworkItemTitle(id) ?? id,
			status: assessment?.status ?? (ruleIds.length > 0 ? "partial" : "not_covered"),
			rationale: assessment?.rationale ?? "No assessment recorded.",
			ruleCount: ruleIds.length,
			exampleRules: ruleIds.slice(0, EXAMPLE_RULE_COUNT),
		};
		if (framework === "mitre_atlas") {
			built.tactics = [...(MITRE_ATLAS_TECHNIQUES[id]?.tactics ?? [])];
		}
		return built;
	};

	const owasp = (framework: "owasp_llm" | "owasp_agentic"): FrameworkCoverage => {
		const list = framework === "owasp_llm" ? OWASP_LLM_2025 : OWASP_AGENTIC_2026;
		const items = list.map((entry) => item(framework, entry.id));
		const statusCounts = emptyStatusCounts();
		for (const entry of items) statusCounts[entry.status] += 1;
		return { ...FRAMEWORKS[framework], itemsTotal: list.length, statusCounts, items };
	};

	const atlasIds = [...byItem.keys()]
		.filter((id) => frameworkOfItem(id) === "mitre_atlas")
		.sort(compareIds);
	const atlasItems = atlasIds.map((id) => item("mitre_atlas", id));
	const atlasStatus = emptyStatusCounts();
	for (const entry of atlasItems) atlasStatus[entry.status] += 1;
	const allTechniques = Object.keys(MITRE_ATLAS_TECHNIQUES);
	atlasStatus.not_covered = allTechniques.length - atlasItems.length;
	const mappedSet = new Set(atlasIds);
	const tactics: CoverageTacticSummary[] = Object.entries(MITRE_ATLAS_TACTICS).map(
		([tacticId, name]) => {
			const inTactic = allTechniques.filter((id) =>
				MITRE_ATLAS_TECHNIQUES[id]?.tactics.includes(tacticId),
			);
			return {
				id: tacticId,
				name,
				techniquesMapped: inTactic.filter((id) => mappedSet.has(id)).length,
				techniquesTotal: inTactic.length,
			};
		},
	);

	return {
		ruleCount: rules.length,
		ruleFiles: new Set(rules.map((rule) => rule.sourceFile)).size,
		frameworks: [
			owasp("owasp_llm"),
			owasp("owasp_agentic"),
			{
				...FRAMEWORKS.mitre_atlas,
				itemsTotal: allTechniques.length,
				statusCounts: atlasStatus,
				items: atlasItems,
				tactics,
			},
		],
	};
}

/** snake_case JSON form of the matrix (CLI `--format json`, dashboard artifact). */
export function coverageMatrixToJson(matrix: CoverageMatrix): Record<string, unknown> {
	return {
		rule_count: matrix.ruleCount,
		rule_files: matrix.ruleFiles,
		frameworks: matrix.frameworks.map((framework) => ({
			id: framework.id,
			name: framework.name,
			version: framework.version,
			url: framework.url,
			items_total: framework.itemsTotal,
			status_counts: { ...framework.statusCounts },
			items: framework.items.map((entry) => ({
				id: entry.id,
				label: entry.label,
				title: entry.title,
				status: entry.status,
				rationale: entry.rationale,
				rule_count: entry.ruleCount,
				example_rules: [...entry.exampleRules],
				...(entry.tactics ? { tactics: [...entry.tactics] } : {}),
			})),
			...(framework.tactics
				? {
						tactics: framework.tactics.map((tactic) => ({
							id: tactic.id,
							name: tactic.name,
							techniques_mapped: tactic.techniquesMapped,
							techniques_total: tactic.techniquesTotal,
						})),
					}
				: {}),
		})),
	};
}

const STATUS_LABEL: Record<CoverageStatus, string> = {
	covered: "covered",
	partial: "partial",
	not_covered: "not covered",
	not_applicable: "not applicable",
};

function summaryLine(framework: FrameworkCoverage): string {
	const s = framework.statusCounts;
	if (framework.id === "mitre_atlas") {
		const mapped = framework.items.length;
		const tacticsHit = (framework.tactics ?? []).filter((t) => t.techniquesMapped > 0).length;
		return `${mapped} of ${framework.itemsTotal} techniques/sub-techniques mapped (${s.covered} covered, ${s.partial} partial); ${tacticsHit} of ${(framework.tactics ?? []).length} tactics touched`;
	}
	return `${s.covered} covered, ${s.partial} partial, ${s.not_covered} not covered, ${s.not_applicable} not applicable (of ${framework.itemsTotal})`;
}

function pad(text: string, width: number): string {
	return text.length >= width ? text : text + " ".repeat(width - text.length);
}

function truncate(text: string, width: number): string {
	return text.length <= width ? text : `${text.slice(0, width - 1)}…`;
}

/** Plain-text table for a terminal. */
export function renderCoverageTable(matrix: CoverageMatrix): string {
	const lines: string[] = [];
	lines.push(`Detection rule coverage: ${matrix.ruleCount} rules in ${matrix.ruleFiles} files`);
	for (const framework of matrix.frameworks) {
		lines.push("");
		lines.push(`${framework.name} ${framework.version}`);
		lines.push(`  ${summaryLine(framework)}`);
		lines.push(
			`  ${pad("ID", 15)}${pad("Title", 40)}${pad("Status", 16)}${pad("Rules", 7)}Examples`,
		);
		for (const entry of framework.items) {
			lines.push(
				`  ${pad(entry.label, 15)}${pad(truncate(entry.title, 38), 40)}${pad(STATUS_LABEL[entry.status], 16)}${pad(String(entry.ruleCount), 7)}${entry.exampleRules.join(", ") || "-"}`,
			);
		}
	}
	lines.push("");
	lines.push(
		"Rationale per item: aidr coverage --format markdown (or --format json). A mapping means a rule detects an instance of the risk at the agent's tool boundary; it does not claim every variant is prevented.",
	);
	return `${lines.join("\n")}\n`;
}

function mdEscape(text: string): string {
	return text.replace(/\|/g, "\\|").replace(/\s+/g, " ").trim();
}

/** Markdown matrix (docs/framework-coverage.md body and `--format markdown`). */
export function renderCoverageMarkdown(matrix: CoverageMatrix): string {
	const lines: string[] = [];
	lines.push(
		`Rules evaluated: **${matrix.ruleCount}** active rules in **${matrix.ruleFiles}** rule files.`,
	);
	lines.push("");
	lines.push(
		"Status meanings: **covered** - the rules address the item's attack surface at the agent's tool-call boundary; **partial** - some behaviours of the item are detected and the rationale names what is not; **not covered** - in scope for an agent guard but no rule addresses it; **not applicable** - the risk sits somewhere AIDR's rules cannot observe.",
	);
	for (const framework of matrix.frameworks) {
		lines.push("");
		lines.push(`## ${framework.name} ${framework.version}`);
		lines.push("");
		lines.push(`Source: ${framework.url}`);
		lines.push("");
		lines.push(`Summary: ${summaryLine(framework)}.`);
		lines.push("");
		lines.push("| ID | Title | Status | Rules | Example rules | Rationale |");
		lines.push("| --- | --- | --- | ---: | --- | --- |");
		for (const entry of framework.items) {
			lines.push(
				`| ${entry.label} | ${mdEscape(entry.title)} | ${STATUS_LABEL[entry.status]} | ${entry.ruleCount} | ${entry.exampleRules.join(", ") || "-"} | ${mdEscape(entry.rationale)} |`,
			);
		}
		if (framework.tactics) {
			lines.push("");
			lines.push(
				"ATLAS techniques that no rule maps to are not covered by the rule set. Many are model-centric (training-data poisoning, model evasion or theft, adversarial data crafting) and sit outside an agent tool-call guard. Per tactic:",
			);
			lines.push("");
			lines.push("| Tactic | Name | Techniques mapped |");
			lines.push("| --- | --- | ---: |");
			for (const tactic of framework.tactics) {
				lines.push(
					`| ${tactic.id} | ${mdEscape(tactic.name)} | ${tactic.techniquesMapped} of ${tactic.techniquesTotal} |`,
				);
			}
		}
	}
	return `${lines.join("\n")}\n`;
}

/**
 * Artifact bundled into the dashboard: the matrix plus the per-rule mapping so
 * an event that carries `matched_threat_id` can show its framework IDs without
 * trusting any framework field a client uploads.
 */
export function buildDashboardCoverageArtifact(
	mappings: FrameworkMappings,
	rules: readonly CoverageRule[],
): Record<string, unknown> {
	const ruleMap: Record<string, FrameworkRefsJson> = {};
	for (const rule of [...rules].sort((a, b) => compareIds(a.id, b.id))) {
		const refs = resolveRuleFrameworks(mappings, rule);
		if (refs) ruleMap[rule.id] = frameworkRefsToJson(refs);
	}
	const titles: Record<string, string> = {};
	for (const refs of Object.values(ruleMap)) {
		for (const id of [...refs.owasp_llm, ...refs.owasp_agentic, ...refs.mitre_atlas]) {
			titles[id] = frameworkItemTitle(id) ?? id;
		}
	}
	const sortedTitles = Object.fromEntries(
		Object.entries(titles).sort(([a], [b]) => compareIds(a, b)),
	);
	return {
		schema_version: 1,
		matrix: coverageMatrixToJson(buildCoverageMatrix(mappings, rules)),
		rules: ruleMap,
		titles: sortedTitles,
	};
}

/** Loaded threats as coverage rules (a rule loaded without a source file is skipped). */
export function toCoverageRules(threats: readonly Threat[]): CoverageRule[] {
	return threats
		.filter((threat): threat is Threat & { sourceFile: string } => Boolean(threat.sourceFile))
		.map((threat) => ({
			id: threat.id,
			category: threat.category,
			sourceFile: threat.sourceFile,
			title: threat.title,
		}));
}

/** Full `docs/framework-coverage.md`, generated by `pnpm coverage:frameworks -- --write`. */
export function renderCoverageDocument(matrix: CoverageMatrix): string {
	const header = [
		"# Security framework coverage",
		"",
		"<!-- Generated by `pnpm coverage:frameworks -- --write` from threats/*.yaml and threats/mappings/frameworks.yaml. Do not edit by hand: `pnpm coverage:frameworks` and the core test suite fail when this file is stale. -->",
		"",
		"This matrix maps every shipped Singularity AIDR detection rule to the OWASP Top 10 for LLM Applications 2025, the OWASP Top 10 for Agentic Applications 2026 and MITRE ATLAS (content release 2026.09). The mapping is data (`threats/mappings/frameworks.yaml`), keyed by rule id; a test fails when a rule has no mapping or uses an identifier that is not in the official lists.",
		"",
		"A mapping means the rule detects an instance of that risk or technique where AIDR sees it: an agent's tool call (command, file path, URL, tool input) or a skill/plugin file. It is not a claim that every variant of the risk is prevented. The rules are patterns, and each item's rationale states what is and is not detected. Other AIDR components (DLP/privacy engine, MCP gateway, package reputation, behavioural analyzer) are named where they matter but are not counted here.",
		"",
		"At runtime the matched rule's IDs travel with the verdict: `Verdict.frameworks` in TypeScript and `frameworks: {owasp_llm, owasp_agentic, mitre_atlas}` in local audit-log entries, SIEM incident exports (JSON, CEF, LEEF) and `aidr audit export`. Remote telemetry sends only `matched_threat_id`; the dashboard resolves the IDs from the mapping bundled at build time. `aidr coverage` prints this matrix from the rules installed with the CLI.",
		"",
		"",
	];
	return `${header.join("\n")}${renderCoverageMarkdown(matrix)}`;
}
