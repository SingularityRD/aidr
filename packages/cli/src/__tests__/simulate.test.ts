import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	buildReport,
	type CaseResult,
	connectorRepoRoot,
	DEFAULT_MIN_SCORE,
	formatHtml,
	formatReport,
	formatTable,
	runSimulation,
	type SimOutcome,
	simulateRuntime,
} from "../commands/simulate.js";
import {
	loadSimulationCorpus,
	SIM_CATEGORIES,
	type SimCase,
	type SimInput,
} from "../commands/simulate-corpus.js";

/**
 * `aidr simulate` is a DEFENSIVE self-test. These tests pin its contract:
 *   - the corpus is well-formed and defanged (no live credentials, only reserved
 *     network endpoints),
 *   - the evaluator mode never executes a process or opens a socket,
 *   - the scoring math is correct,
 *   - the built claude-code connector is actually driven, and
 *   - the shipped rules still detect the whole corpus (regression floor).
 */

const RESERVED_HOST =
	/(\.invalid|\.example|(^|[/@.])example\.com|192\.0\.2\.\d|198\.51\.100\.\d|203\.0\.113\.\d|169\.254\.169\.254|metadata\.google\.internal|pastebin\.com|paste\.ee|discord|github\.com)/;

function textOf(input: SimInput): string {
	if (input.channel === "tool") return JSON.stringify(input.toolInput);
	return input.text;
}

function urlsIn(input: SimInput): string[] {
	const text = textOf(input);
	return [...text.matchAll(/https?:\/\/[^\s"'`)]+/g)].map((m) => m[0]);
}

describe("simulate corpus schema", () => {
	const corpus = loadSimulationCorpus();

	it("is non-empty and every id is unique", () => {
		expect(corpus.length).toBeGreaterThanOrEqual(90);
		expect(new Set(corpus.map((c) => c.id)).size).toBe(corpus.length);
	});

	it("every case is well-formed", () => {
		for (const c of corpus) {
			expect(SIM_CATEGORIES).toContain(c.category);
			expect(["ask", "deny"]).toContain(c.expect);
			expect(c.description.length).toBeGreaterThan(0);
			assertInput(c.input);
			if (c.benign) assertInput(c.benign);
		}
	});

	it("covers every declared category with at least one case", () => {
		for (const category of SIM_CATEGORIES) {
			expect(
				corpus.some((c) => c.category === category),
				category,
			).toBe(true);
		}
	});

	it("only references reserved / non-routable network endpoints", () => {
		for (const c of corpus) {
			for (const input of [c.input, c.benign].filter(Boolean) as SimInput[]) {
				for (const url of urlsIn(input)) {
					expect(RESERVED_HOST.test(url), `${c.id} -> ${url}`).toBe(true);
				}
			}
		}
	});

	it("carries no literal live credential (fake markers only)", () => {
		// The privacy fixtures assemble fake credentials at load time; every one of
		// them must carry an obvious fake marker so it can never be mistaken for a
		// real secret by a scanner or a reader.
		for (const c of corpus.filter((entry) => entry.category === "privacy")) {
			const text = textOf(c.input);
			const looksLikeToken = /(ghp_|AKIA|sk-ant-)/.test(text);
			if (looksLikeToken) {
				expect(/SIMULATED|FAKE|EXAMPLE/i.test(text), `${c.id} carries a fake marker`).toBe(true);
			}
		}
	});
});

function assertInput(input: SimInput): void {
	if (input.channel === "tool") {
		expect(typeof input.toolName).toBe("string");
		expect(input.toolName.length).toBeGreaterThan(0);
		expect(typeof input.toolInput).toBe("object");
	} else {
		expect(["prompt", "output"]).toContain(input.channel);
		expect(typeof input.text).toBe("string");
		expect(input.text.length).toBeGreaterThan(0);
	}
}

describe("simulate scoring math", () => {
	function caseResult(
		id: string,
		expect_: "ask" | "deny",
		malicious: SimOutcome,
		benign?: SimOutcome,
	): CaseResult {
		return {
			id,
			category: "destructive",
			description: id,
			expect: expect_,
			malicious,
			benign,
		};
	}
	const decide = (decision: "allow" | "ask" | "deny"): SimOutcome => ({
		kind: "decision",
		decision,
	});
	const abort = (reason: string): SimOutcome => ({ kind: "abort", reason });

	it("counts a detection only when the outcome meets the minimum", () => {
		const report = buildReport({
			results: [
				caseResult("a", "deny", decide("deny")), // detected
				caseResult("b", "deny", decide("ask")), // miss (below minimum)
				caseResult("c", "ask", decide("ask")), // detected
				caseResult("d", "ask", decide("allow")), // miss (allow)
			],
			suites: ["destructive"],
			connector: null,
			minScore: 0,
			sensitivity: "balanced",
			mode: "evaluator",
		});
		expect(report.totals.counted).toBe(4);
		expect(report.totals.detected).toBe(2);
		expect(report.score).toBe(50);
		expect(report.misses.map((m) => m.id).sort()).toEqual(["b", "d"]);
	});

	it("excludes aborted cases from the score entirely", () => {
		const report = buildReport({
			results: [
				caseResult("a", "deny", decide("deny")),
				caseResult("b", "deny", abort("reputation leg unavailable")),
			],
			suites: ["destructive"],
			connector: null,
			minScore: 0,
			sensitivity: "balanced",
			mode: "evaluator",
		});
		expect(report.totals.counted).toBe(1);
		expect(report.totals.detected).toBe(1);
		expect(report.totals.aborted).toBe(1);
		expect(report.score).toBe(100);
		expect(report.aborted.map((a) => a.id)).toEqual(["b"]);
	});

	it("measures the benign false-positive rate independently", () => {
		const report = buildReport({
			results: [
				caseResult("a", "deny", decide("deny"), decide("allow")), // benign ok
				caseResult("b", "deny", decide("deny"), decide("ask")), // benign FP
			],
			suites: ["destructive"],
			connector: null,
			minScore: 0,
			sensitivity: "balanced",
			mode: "evaluator",
		});
		expect(report.totals.benignCounted).toBe(2);
		expect(report.totals.benignFalsePositives).toBe(1);
		expect(report.falsePositiveRate).toBe(50);
		expect(report.falsePositives.map((f) => f.id)).toEqual(["b"]);
	});

	it("passes or fails against the minimum score", () => {
		const results = [
			caseResult("a", "deny", decide("deny")),
			caseResult("b", "deny", decide("ask")),
		];
		const base = {
			results,
			suites: ["destructive" as const],
			connector: null,
			sensitivity: "balanced",
			mode: "evaluator" as const,
		};
		expect(buildReport({ ...base, minScore: 50 }).passed).toBe(true);
		expect(buildReport({ ...base, minScore: 60 }).passed).toBe(false);
		// MSC-12: the default threshold fails a half-blind engine.
		expect(buildReport({ ...base, minScore: DEFAULT_MIN_SCORE }).passed).toBe(false);
		expect(formatTable(buildReport({ ...base, minScore: DEFAULT_MIN_SCORE }))).toContain(
			`FAIL — score 50% < minimum ${DEFAULT_MIN_SCORE}%`,
		);
	});

	it("never passes a run in which nothing could be scored, whatever the threshold", () => {
		const report = buildReport({
			results: [caseResult("a", "deny", abort("reputation leg unavailable"))],
			suites: ["destructive"],
			connector: null,
			minScore: 0,
			sensitivity: "balanced",
			mode: "evaluator",
		});
		expect(report.totals.counted).toBe(0);
		expect(report.passed).toBe(false);
		expect(formatTable(report)).toContain("FAIL — no fixture could be scored");
	});
});

describe("simulate formatting", () => {
	const report = buildReport({
		results: [
			{
				id: "x",
				category: "destructive",
				description: "sample",
				expect: "deny",
				malicious: { kind: "decision", decision: "deny" },
			},
		],
		suites: ["destructive"],
		connector: null,
		minScore: 0,
		sensitivity: "balanced",
		mode: "evaluator",
	});

	it("renders a table", () => {
		const table = formatTable(report);
		expect(table).toContain("Attack Simulation Self-Test");
		expect(table).toContain("Overall detection score: 100%");
		vi.stubEnv("AIDR_LOCALE", "tr");
		try {
			const turkish = formatTable(report);
			expect(turkish).toContain("Genel tespit puanı: %100");
			expect(turkish).toContain("Kategori");
			expect(turkish).toContain("BAŞARILI");
			expect(formatHtml(report)).toContain('<html lang="tr">');
		} finally {
			vi.unstubAllEnvs();
		}
	});

	it("renders self-contained HTML without vendor names", () => {
		const html = formatHtml(report);
		expect(html.startsWith("<!doctype html>")).toBe(true);
		expect(html).toContain("<style>");
		// No external stylesheet/script references (self-contained).
		expect(html).not.toMatch(/<link[^>]+stylesheet/i);
		expect(html).not.toMatch(/<script[^>]+src=/i);
		// No third-party vendor names in the customer-facing report.
		for (const banned of ["AI Infra Guard", "AIG", "Tencent"]) {
			expect(html.includes(banned)).toBe(false);
		}
	});

	it("emits parseable JSON", () => {
		const parsed = JSON.parse(formatReport(report, "json"));
		expect(parsed.score).toBe(100);
		expect(parsed.mode).toBe("evaluator");
	});
});

describe("simulate evaluator mode isolation", () => {
	let home: string;
	let prevHome: string | undefined;
	let prevProfile: string | undefined;

	beforeEach(async () => {
		home = await mkdtemp(join(tmpdir(), "aidr-sim-test-"));
		prevHome = process.env.HOME;
		prevProfile = process.env.USERPROFILE;
		process.env.HOME = home;
		process.env.USERPROFILE = home;
	});
	afterEach(async () => {
		if (prevHome === undefined) delete process.env.HOME;
		else process.env.HOME = prevHome;
		if (prevProfile === undefined) delete process.env.USERPROFILE;
		else process.env.USERPROFILE = prevProfile;
		await rm(home, { recursive: true, force: true });
	});

	it("never spawns a process or opens a socket in evaluator mode", async () => {
		const spawnSpy = vi.spyOn(simulateRuntime, "spawn");
		const fetchSpy = vi.spyOn(globalThis, "fetch");
		try {
			const report = await runSimulation({ suite: "destructive,exfiltration,self-defense" });
			expect(spawnSpy).not.toHaveBeenCalled();
			expect(fetchSpy).not.toHaveBeenCalled();
			expect(report.mode).toBe("evaluator");
			// MSC-12: without --min-score the gate is the default threshold, not 0.
			expect(report.minScore).toBe(DEFAULT_MIN_SCORE);
			expect(report.passed).toBe(report.score >= DEFAULT_MIN_SCORE);
			expect(report.totals.counted).toBeGreaterThan(0);
		} finally {
			spawnSpy.mockRestore();
			fetchSpy.mockRestore();
		}
	}, 120_000);

	it("meets the regression floor across the whole corpus at balanced sensitivity", async () => {
		const report = await runSimulation({ sensitivity: "balanced" });
		// The shipped rules must still detect the whole defanged corpus. A drop
		// here means a rule regressed or the corpus drifted from the rules.
		expect(report.totals.aborted).toBe(0);
		expect(report.score).toBeGreaterThanOrEqual(99);
		expect(report.falsePositiveRate).toBe(0);
		expect(report.misses).toEqual([]);
	}, 120_000);
});

describe("simulate connector mode (claude-code)", () => {
	let home: string;
	let prevHome: string | undefined;
	let prevProfile: string | undefined;

	beforeEach(async () => {
		home = await mkdtemp(join(tmpdir(), "aidr-sim-conn-"));
		prevHome = process.env.HOME;
		prevProfile = process.env.USERPROFILE;
		process.env.HOME = home;
		process.env.USERPROFILE = home;
	});
	afterEach(async () => {
		if (prevHome === undefined) delete process.env.HOME;
		else process.env.HOME = prevHome;
		if (prevProfile === undefined) delete process.env.USERPROFILE;
		else process.env.USERPROFILE = prevProfile;
		await rm(home, { recursive: true, force: true });
	});

	it("drives the built claude-code entry point and detects tool-call fixtures", async () => {
		const spawnSpy = vi.spyOn(simulateRuntime, "spawn");
		try {
			const report = await runSimulation({ connector: "claude-code", suite: "destructive" });
			expect(spawnSpy).toHaveBeenCalled();
			expect(report.mode).toBe("connector");
			expect(report.connector).toBe("claude-code");
			expect(report.totals.counted).toBeGreaterThan(0);
			expect(report.score).toBeGreaterThanOrEqual(99);
		} finally {
			spawnSpy.mockRestore();
		}
	}, 120_000);

	it("spawns only the checkout's own connector build, never one from the working directory", async () => {
		const spawnSpy = vi.spyOn(simulateRuntime, "spawn");
		try {
			await runSimulation({ connector: "claude-code", suite: "destructive" });
			const repoRoot = connectorRepoRoot(resolve(__dirname, "..", ".."));
			expect(repoRoot).not.toBeNull();
			const scripts = spawnSpy.mock.calls.map((call) => (call[1] as string[])[0]);
			expect(scripts.length).toBeGreaterThan(0);
			for (const script of scripts) {
				expect(script).toBe(
					join(repoRoot as string, "packages", "claude-code", "dist", "pre-tool-use.cjs"),
				);
			}
		} finally {
			spawnSpy.mockRestore();
		}
	}, 120_000);

	it("refuses connector mode outside a source checkout instead of falling back to cwd", () => {
		expect(connectorRepoRoot("/usr/lib/node_modules/@singularityrd/aidr-cli")).toBeNull();
		expect(connectorRepoRoot("/work/evil/packages/aidr-cli")).toBeNull();
		expect(connectorRepoRoot("/src/aidr/packages/cli")).toBe("/src/aidr");
	});

	it("rejects a connector it cannot drive from stdin", async () => {
		await expect(runSimulation({ connector: "openclaw", suite: "destructive" })).rejects.toThrow(
			/cannot be driven from stdin/,
		);
	});
});

// Ensures the exported corpus type is exercised so a signature drift is caught.
const _typeGuard: (c: SimCase) => string = (c) => c.id;
void _typeGuard;
