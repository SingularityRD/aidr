import { cp, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { toCsv } from "../commands/audit.js";
import { runCoverage } from "../commands/coverage.js";

/**
 * `aidr coverage` prints the OWASP LLM 2025 / OWASP Agentic 2026 / MITRE ATLAS
 * matrix from the rule files and mapping that ship with the CLI.
 */

const repoThreats = fileURLToPath(new URL("../../../../threats", import.meta.url));

describe("aidr coverage", () => {
	let out: string[];
	let err: string[];
	let scratch: string | null;
	const deps = (threatsDir = repoThreats) => ({
		threatsDir,
		out: (text: string) => out.push(text),
		err: (text: string) => err.push(text),
	});

	beforeEach(() => {
		out = [];
		err = [];
		scratch = null;
		process.exitCode = undefined;
	});
	afterEach(async () => {
		process.exitCode = undefined;
		if (scratch) await rm(scratch, { recursive: true, force: true });
	});

	it("prints the table by default with every OWASP item and the ATLAS summary", async () => {
		await runCoverage({}, deps());
		expect(process.exitCode).toBeUndefined();
		expect(err).toEqual([]);
		const text = out.join("");
		expect(text).toMatch(/Detection rule coverage: \d+ rules in \d+ files/);
		for (let i = 1; i <= 10; i++) {
			const n = String(i).padStart(2, "0");
			expect(text).toContain(`LLM${n}:2025`);
			expect(text).toContain(`ASI${n}:2026`);
		}
		expect(text).toContain("MITRE ATLAS 2026.09");
		expect(text).toContain("not applicable");
	});

	it("emits parseable snake_case JSON", async () => {
		await runCoverage({ format: "json" }, deps());
		const json = JSON.parse(out.join("")) as {
			rule_count: number;
			frameworks: Array<{ id: string; items: Array<{ rule_count: number; status: string }> }>;
		};
		expect(json.rule_count).toBeGreaterThan(300);
		expect(json.frameworks.map((framework) => framework.id)).toEqual([
			"owasp_llm",
			"owasp_agentic",
			"mitre_atlas",
		]);
		for (const item of json.frameworks[0]?.items ?? []) {
			expect(["covered", "partial", "not_covered", "not_applicable"]).toContain(item.status);
		}
	});

	it("emits a markdown matrix", async () => {
		await runCoverage({ format: "markdown" }, deps());
		const text = out.join("");
		expect(text).toContain("| ID | Title | Status | Rules | Example rules | Rationale |");
		expect(text).toContain("## OWASP Top 10 for Agentic Applications 2026");
	});

	it("rejects an unknown format", async () => {
		await runCoverage({ format: "xml" }, deps());
		expect(process.exitCode).toBe(1);
		expect(out).toEqual([]);
		expect(err.join("")).toContain('Unknown format "xml"');
	});

	it("fails when the rule directory has no mapping instead of printing an empty matrix", async () => {
		scratch = await mkdtemp(join(tmpdir(), "aidr-coverage-"));
		await writeFile(join(scratch, "rules.yaml"), "[]\n");
		await runCoverage({}, deps(scratch));
		expect(process.exitCode).toBe(1);
		expect(out).toEqual([]);
		expect(err.join("")).toContain("No rule set with a framework mapping");
	});

	it("prints the matrix but exits non-zero when an installed rule is unmapped", async () => {
		scratch = await mkdtemp(join(tmpdir(), "aidr-coverage-"));
		await cp(repoThreats, scratch, { recursive: true });
		await writeFile(
			join(scratch, "zz-extra.yaml"),
			`- id: "EXTRA-001"
  category: "tool"
  severity: "high"
  confidence: 0.9
  action: "block"
  pattern: "definitely-not-a-real-command"
  match_on: command
  title: "Unmapped test rule"
`,
		);
		await runCoverage({}, deps(scratch));
		expect(out.join("")).toContain("OWASP Top 10 for LLM Applications 2025");
		expect(process.exitCode).toBe(1);
		expect(err.join("")).toContain("rule EXTRA-001 (zz-extra.yaml) has no entry");
	});
});

describe("aidr audit export frameworks column", () => {
	it("flattens validated framework IDs with their edition labels", () => {
		const csv = toCsv([
			{
				timestamp: "2026-09-25T10:00:00.000Z",
				type: "runtime_verdict",
				verdict: "deny",
				matched_threat_id: "CLT-CMD-003",
				frameworks: {
					owasp_llm: ["LLM05"],
					owasp_agentic: ["ASI05", "bogus"],
					mitre_atlas: ["AML.T0072"],
				},
			},
		]);
		const [header, row] = csv.trim().split("\n");
		expect(header?.endsWith(",frameworks")).toBe(true);
		expect(row?.endsWith(",LLM05:2025; ASI05:2026; AML.T0072")).toBe(true);
	});
});
