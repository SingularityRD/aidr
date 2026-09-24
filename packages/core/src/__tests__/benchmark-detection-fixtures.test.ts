import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { DecisionEngine } from "../engine.js";
import { HeuristicsEngine } from "../heuristics.js";
import { loadThreats } from "../threat-loader.js";

const fixturePath = fileURLToPath(
	new URL("../../../../scripts/benchmarks/detection-fixtures-v1.json", import.meta.url),
);
const threatsPath = fileURLToPath(new URL("../../../../threats", import.meta.url));
const fixtures = JSON.parse(readFileSync(fixturePath, "utf8")) as {
	schema_version: number;
	corpus_id: string;
	version: string;
	provenance: string;
	test_boundary: string;
	measurement_status: string;
	scope: {
		required_attack_families: string[];
		required_connectors: string[];
		required_surfaces: string[];
	};
	cases: Array<{
		case_id: string;
		partition: string;
		oracle: "malicious" | "benign";
		family: string;
		connector: string;
		surface: string;
		content: string;
		content_sha256: string;
		expected_decision: "allow" | "ask" | "deny";
		expected_threat_id: string | null;
	}>;
};

describe("committed synthetic detection fixtures", () => {
	it("covers each declared family and connector/surface slice with benign and malicious cases", () => {
		expect(fixtures.schema_version).toBe(1);
		expect(fixtures.version).toBe("1.0.0");
		expect(fixtures.provenance).toBe("synthetic_open");
		expect(fixtures.measurement_status).toBe("not_measured");
		expect(fixtures.test_boundary).toMatch(/core heuristic and decision engine only/i);
		expect(fixtures.cases.length).toBe(8);
		expect(new Set(fixtures.cases.map((entry) => entry.case_id)).size).toBe(fixtures.cases.length);
		expect(fixtures.cases.every((entry) => entry.partition === "development")).toBe(true);
		expect(fixtures.cases.every((entry) => entry.oracle === "malicious"
			? entry.expected_decision !== "allow" && entry.expected_threat_id !== null
			: entry.expected_decision === "allow" && entry.expected_threat_id === null,
		)).toBe(true);
		expect(fixtures.cases.every((entry) =>
			createHash("sha256").update(entry.content.replace(/\r\n?/g, "\n").trim()).digest("hex") === entry.content_sha256,
		)).toBe(true);

		for (const family of fixtures.scope.required_attack_families) {
			const cases = fixtures.cases.filter((entry) => entry.family === family);
			expect(cases.some((entry) => entry.oracle === "malicious"), `${family} malicious`).toBe(true);
			expect(cases.some((entry) => entry.oracle === "benign"), `${family} benign twin`).toBe(true);
		}
		for (const [dimension, required] of [
			["connector", fixtures.scope.required_connectors],
			["surface", fixtures.scope.required_surfaces],
		] as const) {
			for (const id of required) {
				const cases = fixtures.cases.filter((entry) => entry[dimension] === id);
				expect(cases.some((entry) => entry.oracle === "malicious"), `${dimension} ${id} malicious`).toBe(true);
				expect(cases.some((entry) => entry.oracle === "benign"), `${dimension} ${id} benign`).toBe(true);
			}
		}
	});

	it("feeds every committed case through the shipped heuristic and decision engines", async () => {
		const threats = await loadThreats(threatsPath);
		const heuristics = new HeuristicsEngine(threats);
		const decisions = new DecisionEngine();

		for (const fixture of fixtures.cases) {
			const matches = heuristics.match([{ type: "content", value: fixture.content }]);
			const verdict = await decisions.decide({ heuristicMatches: matches, urlCheckResults: [] });

			expect(verdict.decision, fixture.case_id).toBe(fixture.expected_decision);
			if (fixture.expected_threat_id === null) {
				expect(matches, fixture.case_id).toHaveLength(0);
			} else {
				expect(
					matches.some((match) => match.threat.id === fixture.expected_threat_id),
					`${fixture.case_id} should match ${fixture.expected_threat_id}`,
				).toBe(true);
			}
		}
	});
});
