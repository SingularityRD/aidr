/**
 * `aidr simulate` — a defensive self-test for Singularity AIDR.
 *
 * It feeds a corpus of DEFANGED detection fixtures (see `simulate-corpus.ts`) to
 * the product's own LOCAL evaluator and reports what the product detects, the way
 * an EICAR test file proves an anti-virus is live. It never executes a command,
 * reads a target file, or opens a network socket: each fixture is passed to the
 * detector as data and the returned verdict is scored.
 *
 * Two evaluation modes:
 *   - evaluator (default): calls the shared core in-process — `evaluateToolCall`
 *     + `extractFromToolCall` for tool calls, `scanPrompt` for prompts and
 *     `scanModelOutput` for model/tool output — inside a temporary sandbox HOME
 *     with a local-only, network-disabled config derived from the user's own.
 *   - connector (`--connector`): spawns a BUILT connector entry point (the same
 *     `dist` binary that ships) and drives its stdin/stdout, so the report
 *     reflects the real connector, not just the library. Tool-call fixtures run
 *     through the connector; prompt/output fixtures fall back to the in-process
 *     scanners because those are separate connector surfaces.
 */

import { spawn as nodeSpawn } from "node:child_process";
import { existsSync } from "node:fs";
import { cp, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
	type Artifact,
	type Config,
	evaluateToolCall,
	extractFromToolCall,
	loadConfig,
	resolvePath,
	scanModelOutput,
	scanPrompt,
	type Verdict,
} from "@singularityrd/aidr-core";
import { resolveBundledDataDirs } from "../utils/test-protection.js";
import {
	loadSimulationCorpus,
	SIM_CATEGORIES,
	type SimCase,
	type SimCategory,
	type SimInput,
} from "./simulate-corpus.js";

type Decision = "allow" | "ask" | "deny";
const DECISION_RANK: Record<Decision, number> = { allow: 0, ask: 1, deny: 2 };

/**
 * Process spawning is routed through this object so a test can observe it: the
 * evaluator path must never spawn, and connector mode must. Overriding a plain
 * object property is possible where spying on an ESM named import is not.
 */
export const simulateRuntime = { spawn: nodeSpawn };

/** Non-detection outcome that must NOT be scored (see CLAUDE.md failure policy). */
export interface SimAbort {
	kind: "abort";
	reason: string;
}
export interface SimDecision {
	kind: "decision";
	decision: Decision;
}
export type SimOutcome = SimDecision | SimAbort;

export type SimConnector = "claude-code" | "codex" | "cursor" | "vscode" | "openclaw" | "opencode";

export interface SimulateOptions {
	suite?: string;
	sensitivity?: string;
	format?: string;
	output?: string;
	minScore?: string;
	connector?: string;
}

export interface CaseResult {
	id: string;
	category: SimCategory;
	description: string;
	expect: Decision;
	/** Malicious-input outcome. */
	malicious: SimOutcome;
	/** Benign-twin outcome, when the case declares one. */
	benign?: SimOutcome;
}

interface CategoryScore {
	category: SimCategory;
	counted: number;
	detected: number;
	aborted: number;
	benignCounted: number;
	benignFalsePositives: number;
}

export interface SimulationReport {
	generatedAt: string;
	mode: "evaluator" | "connector";
	connector: SimConnector | null;
	sensitivity: string;
	suites: SimCategory[];
	categories: CategoryScore[];
	misses: Array<{
		id: string;
		category: SimCategory;
		description: string;
		expected: Decision;
		actual: Decision;
	}>;
	falsePositives: Array<{
		id: string;
		category: SimCategory;
		description: string;
		actual: Decision;
	}>;
	aborted: Array<{ id: string; category: SimCategory; reason: string }>;
	totals: {
		counted: number;
		detected: number;
		aborted: number;
		benignCounted: number;
		benignFalsePositives: number;
	};
	/** Overall detection score: percentage of counted malicious cases meeting their minimum. */
	score: number;
	/** Benign false-positive rate as a percentage of counted benign twins. */
	falsePositiveRate: number;
	minScore: number;
	passed: boolean;
}

/* ------------------------------------------------------------------ *
 * Sandbox: an isolated HOME with a local-only, network-disabled config
 * derived from the user's effective configuration.
 * ------------------------------------------------------------------ */

interface Sandbox {
	home: string;
	configPath: string;
	threatsDir: string;
	allowlistsDir: string;
	cleanup: () => Promise<void>;
	restoreEnv: () => void;
}

/**
 * Build the sandbox. Reads the user's real config FIRST (before HOME is
 * repointed), copies their custom threat rules, then forces a local,
 * network-free configuration into a throwaway HOME so the run touches nothing.
 */
async function createSandbox(sensitivityOverride?: string): Promise<Sandbox> {
	// Read the user's effective config from the real HOME before repointing it.
	let userConfig: Config;
	try {
		userConfig = await loadConfig();
	} catch {
		userConfig = await loadConfig(join(tmpdir(), "aidr-simulate-missing-config.json"));
	}
	const realUserThreats = resolvePath("~/.singularity-aidr/threats");

	const home = await mkdtemp(join(tmpdir(), "aidr-simulate-"));
	const aidrDir = join(home, ".singularity-aidr");
	await mkdir(aidrDir, { recursive: true });

	// Carry over only the detection-shaping fields; force local and switch off
	// every network / persistence leg so the self-test is hermetic and offline.
	const sandboxConfig = {
		mode: "local",
		sensitivity: sensitivityOverride ?? userConfig.sensitivity,
		heuristics_enabled: userConfig.heuristics_enabled,
		disabled_threats: userConfig.disabled_threats,
		policy: userConfig.policy,
		prompt_protection: userConfig.prompt_protection,
		control_plane: { enabled: false },
		url_check: { enabled: false },
		file_check: { enabled: false },
		package_check: { enabled: false },
		version_check: { enabled: false },
		amsi_check: { enabled: false },
		intel: { enabled: false },
		intel_packs: { enabled: false },
		incident: { enabled: false },
		cache: { enabled: false },
		logging: { enabled: false },
	};
	const configPath = join(aidrDir, "config.json");
	await writeFile(configPath, JSON.stringify(sandboxConfig, null, 2), { mode: 0o600 });

	// Copy the user's custom rules so the self-test measures the rules that
	// actually run on this machine, not only the shipped set.
	if (existsSync(realUserThreats)) {
		try {
			await cp(realUserThreats, join(aidrDir, "threats"), { recursive: true });
		} catch {
			// A custom-rules copy failure must not silently change the result set;
			// the run continues with the bundled rules only.
		}
	}

	const { threatsDir, allowlistsDir } = resolveBundledDataDirs();

	const prevHome = process.env.HOME;
	const prevUserProfile = process.env.USERPROFILE;
	process.env.HOME = home;
	process.env.USERPROFILE = home;

	return {
		home,
		configPath,
		threatsDir,
		allowlistsDir,
		restoreEnv: () => {
			if (prevHome === undefined) delete process.env.HOME;
			else process.env.HOME = prevHome;
			if (prevUserProfile === undefined) delete process.env.USERPROFILE;
			else process.env.USERPROFILE = prevUserProfile;
		},
		cleanup: async () => {
			await rm(home, { recursive: true, force: true });
		},
	};
}

/* ------------------------------------------------------------------ *
 * In-process (evaluator) detection for each channel.
 * ------------------------------------------------------------------ */

/**
 * Verdicts that mean the call was not actually inspected, so they must NOT be
 * scored as a detection or a clean result (CLAUDE.md: an unavailable leg is
 * never reported as clean). Offline, the reputation legs (URL/file/package) are
 * inert, so an `ask` that carries no matched threat and only says "not verified
 * clean" is an uninspected leg, not a detection — it is excluded from the score.
 */
function abortReasonForVerdict(verdict: Verdict): string | null {
	if (verdict.category === "managed_disabled" || verdict.source === "managed_disabled") {
		return "managed features disabled (run in local/dev mode)";
	}
	if (verdict.category === "config_invalid") return "configuration invalid";
	if (verdict.reasons.some((reason) => /could not (?:inspect|finish inspecting)/i.test(reason))) {
		return "input could not be inspected";
	}
	// Only when nothing actually matched: a real heuristic/policy hit keeps its
	// matchedThreatId even when a reputation leg is also unavailable.
	if (verdict.matchedThreatId === null) {
		if (/_unavailable$/.test(verdict.category)) {
			return "a detection leg was unavailable (offline self-test)";
		}
		if (verdict.reasons.some((reason) => /not verified clean|requires review/i.test(reason))) {
			return "reputation leg unavailable (offline self-test)";
		}
	}
	return null;
}

async function evaluateInput(input: SimInput, sandbox: Sandbox): Promise<SimOutcome> {
	if (input.channel === "tool") {
		const artifacts: Artifact[] = extractFromToolCall(input.toolName, input.toolInput);
		const verdict = await evaluateToolCall(
			{
				sessionId: "aidr-simulate",
				toolName: input.toolName,
				toolInput: input.toolInput,
				artifacts,
			},
			{
				threatsDir: sandbox.threatsDir,
				allowlistsDir: sandbox.allowlistsDir,
				configPath: sandbox.configPath,
				agentRuntime: "claude-code",
			},
		);
		const abort = abortReasonForVerdict(verdict);
		if (abort) return { kind: "abort", reason: abort };
		return { kind: "decision", decision: verdict.decision };
	}
	if (input.channel === "prompt") {
		const result = scanPrompt(input.text);
		const decision: Decision =
			result.decision === "block" ? "deny" : result.decision === "warn" ? "ask" : "allow";
		return { kind: "decision", decision };
	}
	// channel === "output"
	const findings = scanModelOutput(input.text);
	if (findings.some((finding) => finding.type === "inspection_incomplete")) {
		return { kind: "abort", reason: "output could not be fully inspected" };
	}
	const decision: Decision = findings.some((finding) => finding.severity === "critical")
		? "deny"
		: findings.length > 0
			? "ask"
			: "allow";
	return { kind: "decision", decision };
}

/* ------------------------------------------------------------------ *
 * Connector (spawned built entry point) detection for tool-call fixtures.
 * ------------------------------------------------------------------ */

interface ConnectorEntry {
	/** Path to the built entry, relative to the repository root. */
	dist: string;
	/** Extra argv the entry needs (the extension hook takes a mode). */
	args: string[];
	/** Map the entry's stdout/exit to a decision. */
	parse: (stdout: string, code: number | null) => Decision;
}

function repoRootFrom(sandbox: Sandbox): string {
	// The bundled data dir is <cli>/resources/threats; the repo root is four up
	// from packages/cli/resources when running from source. Fall back to cwd.
	const marker = sandbox.threatsDir;
	const idx = marker.indexOf(`${join("packages", "cli")}`);
	if (idx > 0) return marker.slice(0, idx).replace(/[\\/]+$/, "");
	return process.cwd();
}

function parseHookDecision(stdout: string): Decision {
	const trimmed = stdout.trim();
	if (!trimmed) return "allow";
	let parsed: Record<string, unknown>;
	try {
		parsed = JSON.parse(trimmed.split("\n").filter(Boolean).at(-1) ?? "{}");
	} catch {
		return "allow";
	}
	const hso = parsed.hookSpecificOutput as Record<string, unknown> | undefined;
	const raw =
		(hso?.permissionDecision as string | undefined) ??
		(parsed.permission as string | undefined) ??
		(parsed.decision as string | undefined);
	if (raw === "deny" || raw === "block") return "deny";
	if (raw === "ask") return "ask";
	return "allow";
}

function connectorEntries(root: string): Record<SimConnector, ConnectorEntry> {
	const p = (...parts: string[]) => join(root, ...parts);
	return {
		"claude-code": {
			dist: p("packages", "claude-code", "dist", "pre-tool-use.cjs"),
			args: [],
			parse: parseHookDecision,
		},
		codex: {
			dist: p("packages", "codex", "dist", "pre-tool-use.cjs"),
			args: [],
			// Codex's secondary block channel is exit 2 with a stderr reason.
			parse: (stdout, code) => (code === 2 ? "deny" : parseHookDecision(stdout)),
		},
		cursor: {
			dist: p("packages", "extension", "dist", "aidr-hook.cjs"),
			args: ["cursor"],
			parse: parseHookDecision,
		},
		vscode: {
			dist: p("packages", "extension", "dist", "aidr-hook.cjs"),
			args: ["vscode"],
			parse: parseHookDecision,
		},
		openclaw: {
			dist: p("packages", "openclaw", "dist", "index.cjs"),
			args: [],
			parse: parseHookDecision,
		},
		opencode: {
			dist: p("packages", "opencode", "dist", "index.js"),
			args: [],
			parse: parseHookDecision,
		},
	};
}

/** Connectors whose stdin hook this command can drive directly. */
const SPAWNABLE_CONNECTORS: readonly SimConnector[] = ["claude-code", "codex", "cursor", "vscode"];

function connectorPayload(connector: SimConnector, input: Extract<SimInput, { channel: "tool" }>) {
	const base: Record<string, unknown> = { session_id: "aidr-simulate" };
	if (connector === "codex" || connector === "vscode") base.hook_event_name = "PreToolUse";
	if (connector === "cursor") {
		// Cursor's native surfaces carry the artifact directly.
		if (input.toolName === "Bash" && typeof input.toolInput.command === "string") {
			return {
				conversation_id: "aidr-simulate",
				hook_event_name: "beforeShellExecution",
				command: input.toolInput.command,
				cwd: "/srv",
			};
		}
		if (input.toolName === "Read" && typeof input.toolInput.file_path === "string") {
			return {
				conversation_id: "aidr-simulate",
				hook_event_name: "beforeReadFile",
				file_path: input.toolInput.file_path,
				content: "",
			};
		}
		return {
			conversation_id: "aidr-simulate",
			hook_event_name: "preToolUse",
			tool_name: input.toolName,
			tool_input: input.toolInput,
		};
	}
	return { ...base, tool_name: input.toolName, tool_input: input.toolInput };
}

function runProcess(
	command: string,
	args: string[],
	stdin: string,
	home: string,
): Promise<{ stdout: string; code: number | null }> {
	return new Promise((resolvePromise) => {
		const child = simulateRuntime.spawn(command, args, {
			env: { ...process.env, HOME: home, USERPROFILE: home },
			timeout: 30_000,
		});
		let stdout = "";
		child.stdout.on("data", (chunk) => {
			stdout += String(chunk);
		});
		child.on("error", () => resolvePromise({ stdout: "", code: 1 }));
		child.on("close", (code) => resolvePromise({ stdout, code }));
		child.stdin.end(stdin);
	});
}

async function evaluateThroughConnector(
	input: SimInput,
	connector: SimConnector,
	entry: ConnectorEntry,
	sandbox: Sandbox,
): Promise<SimOutcome> {
	if (input.channel !== "tool") {
		// Prompt / output are separate connector surfaces; measure them with the
		// same in-process scanners the connectors themselves call.
		return evaluateInput(input, sandbox);
	}
	if (!existsSync(entry.dist)) {
		return { kind: "abort", reason: `connector entry not built: ${entry.dist}` };
	}
	const payload = connectorPayload(connector, input);
	const { stdout, code } = await runProcess(
		process.execPath,
		[entry.dist, ...entry.args],
		JSON.stringify(payload),
		sandbox.home,
	);
	return { kind: "decision", decision: entry.parse(stdout, code) };
}

/* ------------------------------------------------------------------ *
 * Runner + scoring.
 * ------------------------------------------------------------------ */

function parseSuites(suite: string | undefined): SimCategory[] {
	if (!suite) return [...SIM_CATEGORIES];
	const requested = suite
		.split(",")
		.map((s) => s.trim().toLowerCase())
		.filter(Boolean);
	const valid = new Set<string>(SIM_CATEGORIES);
	const unknown = requested.filter((r) => !valid.has(r));
	if (unknown.length > 0) {
		throw new Error(
			`Unknown suite(s): ${unknown.join(", ")}. Valid suites: ${SIM_CATEGORIES.join(", ")}`,
		);
	}
	return SIM_CATEGORIES.filter((c) => requested.includes(c));
}

function normalizeConnector(value: string | undefined): SimConnector | null {
	if (!value) return null;
	const normalized = value.trim().toLowerCase();
	const valid: readonly SimConnector[] = [
		"claude-code",
		"codex",
		"cursor",
		"vscode",
		"openclaw",
		"opencode",
	];
	if (!valid.includes(normalized as SimConnector)) {
		throw new Error(`Unknown connector: ${value}. Valid connectors: ${valid.join(", ")}`);
	}
	return normalized as SimConnector;
}

export async function runSimulation(options: SimulateOptions): Promise<SimulationReport> {
	const suites = parseSuites(options.suite);
	const connector = normalizeConnector(options.connector);
	const minScore = clampScore(options.minScore);
	const sensitivityOverride = normalizeSensitivity(options.sensitivity);

	const corpus = loadSimulationCorpus().filter((c) => suites.includes(c.category));
	const sandbox = await createSandbox(sensitivityOverride);

	const results: CaseResult[] = [];
	try {
		const evaluate = connector
			? await connectorEvaluator(connector, sandbox)
			: (input: SimInput) => evaluateInput(input, sandbox);

		for (const testCase of corpus) {
			results.push(await runCase(testCase, evaluate));
		}
	} finally {
		sandbox.restoreEnv();
		await sandbox.cleanup();
	}

	return buildReport({
		results,
		suites,
		connector,
		minScore,
		sensitivity: sensitivityOverride ?? "(from config)",
		mode: connector ? "connector" : "evaluator",
	});
}

async function connectorEvaluator(
	connector: SimConnector,
	sandbox: Sandbox,
): Promise<(input: SimInput) => Promise<SimOutcome>> {
	if (!SPAWNABLE_CONNECTORS.includes(connector)) {
		throw new Error(
			`Connector "${connector}" cannot be driven from stdin; supported connector modes: ${SPAWNABLE_CONNECTORS.join(", ")}`,
		);
	}
	const root = repoRootFrom(sandbox);
	const entry = connectorEntries(root)[connector];
	return (input: SimInput) => evaluateThroughConnector(input, connector, entry, sandbox);
}

async function runCase(
	testCase: SimCase,
	evaluate: (input: SimInput) => Promise<SimOutcome>,
): Promise<CaseResult> {
	const malicious = await evaluate(testCase.input);
	const benign = testCase.benign ? await evaluate(testCase.benign) : undefined;
	return {
		id: testCase.id,
		category: testCase.category,
		description: testCase.description,
		expect: testCase.expect,
		malicious,
		benign,
	};
}

interface ReportAccumulator {
	misses: SimulationReport["misses"];
	falsePositives: SimulationReport["falsePositives"];
	aborted: SimulationReport["aborted"];
}

/** Fold one result's malicious outcome into its category score and the run lists. */
function scoreMalicious(result: CaseResult, score: CategoryScore, acc: ReportAccumulator): void {
	if (result.malicious.kind === "abort") {
		score.aborted += 1;
		acc.aborted.push({ id: result.id, category: result.category, reason: result.malicious.reason });
		return;
	}
	score.counted += 1;
	if (DECISION_RANK[result.malicious.decision] >= DECISION_RANK[result.expect]) {
		score.detected += 1;
		return;
	}
	acc.misses.push({
		id: result.id,
		category: result.category,
		description: result.description,
		expected: result.expect,
		actual: result.malicious.decision,
	});
}

/** Fold one result's benign twin (when present) into its category score. */
function scoreBenign(result: CaseResult, score: CategoryScore, acc: ReportAccumulator): void {
	if (!result.benign) return;
	if (result.benign.kind === "abort") {
		acc.aborted.push({
			id: `${result.id}(benign)`,
			category: result.category,
			reason: result.benign.reason,
		});
		return;
	}
	score.benignCounted += 1;
	if (result.benign.decision !== "allow") {
		score.benignFalsePositives += 1;
		acc.falsePositives.push({
			id: result.id,
			category: result.category,
			description: result.description,
			actual: result.benign.decision,
		});
	}
}

export function buildReport(input: {
	results: CaseResult[];
	suites: SimCategory[];
	connector: SimConnector | null;
	minScore: number;
	sensitivity: string;
	mode: "evaluator" | "connector";
}): SimulationReport {
	const { results, suites, connector, minScore, sensitivity, mode } = input;
	const byCategory = new Map<SimCategory, CategoryScore>();
	for (const category of suites) {
		byCategory.set(category, {
			category,
			counted: 0,
			detected: 0,
			aborted: 0,
			benignCounted: 0,
			benignFalsePositives: 0,
		});
	}

	const acc: ReportAccumulator = { misses: [], falsePositives: [], aborted: [] };
	for (const result of results) {
		const score = byCategory.get(result.category);
		if (!score) continue;
		scoreMalicious(result, score, acc);
		scoreBenign(result, score, acc);
	}
	const { misses, falsePositives, aborted } = acc;

	const categories = suites.map(
		(c) =>
			byCategory.get(c) ?? {
				category: c,
				counted: 0,
				detected: 0,
				aborted: 0,
				benignCounted: 0,
				benignFalsePositives: 0,
			},
	);
	const totals = categories.reduce(
		(acc, c) => ({
			counted: acc.counted + c.counted,
			detected: acc.detected + c.detected,
			aborted: acc.aborted + c.aborted,
			benignCounted: acc.benignCounted + c.benignCounted,
			benignFalsePositives: acc.benignFalsePositives + c.benignFalsePositives,
		}),
		{ counted: 0, detected: 0, aborted: 0, benignCounted: 0, benignFalsePositives: 0 },
	);

	const scoreValue = totals.counted === 0 ? 0 : round1((totals.detected / totals.counted) * 100);
	const fpRate =
		totals.benignCounted === 0
			? 0
			: round1((totals.benignFalsePositives / totals.benignCounted) * 100);

	return {
		generatedAt: new Date().toISOString(),
		mode,
		connector,
		sensitivity,
		suites,
		categories,
		misses,
		falsePositives,
		aborted,
		totals,
		score: scoreValue,
		falsePositiveRate: fpRate,
		minScore,
		passed: scoreValue >= minScore,
	};
}

function clampScore(value: string | undefined): number {
	if (value === undefined) return 0;
	const parsed = Number(value);
	if (!Number.isFinite(parsed)) {
		throw new Error(`--min-score must be a number between 0 and 100 (got: ${value})`);
	}
	return Math.min(100, Math.max(0, parsed));
}

function normalizeSensitivity(value: string | undefined): string | undefined {
	if (value === undefined) return undefined;
	const normalized = value.trim().toLowerCase();
	if (!["paranoid", "balanced", "relaxed"].includes(normalized)) {
		throw new Error(`--sensitivity must be one of paranoid, balanced, relaxed (got: ${value})`);
	}
	return normalized;
}

function round1(value: number): number {
	return Math.round(value * 10) / 10;
}

/* ------------------------------------------------------------------ *
 * Output formatting.
 * ------------------------------------------------------------------ */

const CATEGORY_LABELS: Record<SimCategory, string> = {
	injection: "Prompt injection",
	exfiltration: "Data exfiltration",
	destructive: "Destructive commands",
	encoding: "Obfuscation / encoding",
	"supply-chain": "Supply chain",
	mcp: "MCP tool poisoning",
	"self-defense": "Self-defense",
	privacy: "Personal data / secrets",
};

function pct(numerator: number, denominator: number): string {
	if (denominator === 0) return "n/a";
	return `${round1((numerator / denominator) * 100)}%`;
}

export function formatTable(report: SimulationReport): string {
	const lines: string[] = [];
	lines.push("Singularity AIDR — Attack Simulation Self-Test");
	lines.push(
		`Mode: ${report.mode}${report.connector ? ` (${report.connector})` : ""}   Sensitivity: ${report.sensitivity}`,
	);
	lines.push("");
	const header = `${"Category".padEnd(24)}${"Detected".padStart(12)}${"Rate".padStart(9)}${"Benign FP".padStart(12)}`;
	lines.push(header);
	lines.push("-".repeat(header.length));
	for (const c of report.categories) {
		lines.push(
			`${CATEGORY_LABELS[c.category].padEnd(24)}${`${c.detected}/${c.counted}`.padStart(12)}${pct(c.detected, c.counted).padStart(9)}${`${c.benignFalsePositives}/${c.benignCounted}`.padStart(12)}`,
		);
	}
	lines.push("-".repeat(header.length));
	lines.push(
		`${"TOTAL".padEnd(24)}${`${report.totals.detected}/${report.totals.counted}`.padStart(12)}${`${report.score}%`.padStart(9)}${`${report.totals.benignFalsePositives}/${report.totals.benignCounted}`.padStart(12)}`,
	);
	lines.push("");
	lines.push(`Overall detection score: ${report.score}%`);
	lines.push(`Benign false-positive rate: ${report.falsePositiveRate}%`);
	if (report.totals.aborted > 0) {
		lines.push(`Not counted (uninspected / disabled): ${report.totals.aborted}`);
	}
	if (report.misses.length > 0) {
		lines.push("");
		lines.push("Misses (malicious fixtures the product did not flag to the expected level):");
		for (const miss of report.misses) {
			lines.push(
				`  - [${miss.category}] ${miss.id}: expected >= ${miss.expected}, got ${miss.actual} — ${miss.description}`,
			);
		}
	}
	if (report.falsePositives.length > 0) {
		lines.push("");
		lines.push("Benign twins that were incorrectly flagged:");
		for (const fp of report.falsePositives) {
			lines.push(`  - [${fp.category}] ${fp.id}: flagged as ${fp.actual} — ${fp.description}`);
		}
	}
	if (report.aborted.length > 0) {
		lines.push("");
		lines.push("Uninspected / not scored:");
		for (const a of report.aborted) {
			lines.push(`  - [${a.category}] ${a.id}: ${a.reason}`);
		}
	}
	lines.push("");
	lines.push(
		report.passed
			? `PASS — score ${report.score}% >= minimum ${report.minScore}%`
			: `FAIL — score ${report.score}% < minimum ${report.minScore}%`,
	);
	return lines.join("\n");
}

function escapeHtml(value: string): string {
	return value
		.replace(/&/g, "&amp;")
		.replace(/</g, "&lt;")
		.replace(/>/g, "&gt;")
		.replace(/"/g, "&quot;");
}

export function formatHtml(report: SimulationReport): string {
	const rows = report.categories
		.map(
			(c) => `      <tr>
        <td>${escapeHtml(CATEGORY_LABELS[c.category])}</td>
        <td class="num">${c.detected}/${c.counted}</td>
        <td class="num">${pct(c.detected, c.counted)}</td>
        <td class="num">${c.benignFalsePositives}/${c.benignCounted}</td>
      </tr>`,
		)
		.join("\n");

	const missRows =
		report.misses.length === 0
			? '<p class="ok">No misses: every counted fixture was flagged to at least its expected level.</p>'
			: `<table><thead><tr><th>Case</th><th>Category</th><th>Expected</th><th>Actual</th><th>Description</th></tr></thead><tbody>${report.misses
					.map(
						(m) =>
							`<tr><td>${escapeHtml(m.id)}</td><td>${escapeHtml(m.category)}</td><td>${m.expected}</td><td class="miss">${m.actual}</td><td>${escapeHtml(m.description)}</td></tr>`,
					)
					.join("")}</tbody></table>`;

	const fpRows =
		report.falsePositives.length === 0
			? '<p class="ok">No false positives: every benign twin was allowed.</p>'
			: `<table><thead><tr><th>Case</th><th>Category</th><th>Flagged as</th><th>Description</th></tr></thead><tbody>${report.falsePositives
					.map(
						(f) =>
							`<tr><td>${escapeHtml(f.id)}</td><td>${escapeHtml(f.category)}</td><td class="miss">${f.actual}</td><td>${escapeHtml(f.description)}</td></tr>`,
					)
					.join("")}</tbody></table>`;

	const verdictClass = report.passed ? "pass" : "fail";
	const verdictText = report.passed ? "PASS" : "FAIL";

	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>AIDR Attack Simulation Report</title>
<style>
  :root { color-scheme: light dark; --bg:#f6f7f9; --card:#ffffff; --fg:#1c2330; --muted:#5b6472; --line:#e2e6ec; --accent:#1f6feb; --pass:#127436; --fail:#b42318; --pass-bg:#e7f5ec; --fail-bg:#fdecea; }
  @media (prefers-color-scheme: dark) { :root { --bg:#0f1117; --card:#171b23; --fg:#e6e9ef; --muted:#9aa3b2; --line:#262c38; --accent:#4c8dff; --pass:#4ac47c; --fail:#ff7a6b; --pass-bg:#12281c; --fail-bg:#2a1512; } }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--fg); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif; padding:24px 16px; }
  .wrap { max-width:960px; margin:0 auto; }
  h1 { font-size:22px; margin:0 0 4px; }
  .sub { color:var(--muted); margin:0 0 20px; font-size:13px; }
  .cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr)); gap:12px; margin-bottom:20px; }
  .card { background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px 16px; }
  .card .label { color:var(--muted); font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
  .card .value { font-size:26px; font-weight:600; margin-top:4px; }
  .verdict { display:inline-block; padding:4px 12px; border-radius:999px; font-weight:600; font-size:13px; }
  .verdict.pass { background:var(--pass-bg); color:var(--pass); }
  .verdict.fail { background:var(--fail-bg); color:var(--fail); }
  table { width:100%; border-collapse:collapse; background:var(--card); border:1px solid var(--line); border-radius:10px; overflow:hidden; margin-bottom:20px; }
  th,td { text-align:left; padding:10px 14px; border-bottom:1px solid var(--line); font-size:14px; }
  th { color:var(--muted); font-weight:600; font-size:12px; text-transform:uppercase; letter-spacing:.03em; }
  tr:last-child td { border-bottom:none; }
  td.num { text-align:right; font-variant-numeric:tabular-nums; }
  td.miss { color:var(--fail); font-weight:600; }
  h2 { font-size:16px; margin:24px 0 10px; }
  .ok { color:var(--pass); }
  footer { color:var(--muted); font-size:12px; margin-top:28px; }
</style>
</head>
<body>
  <div class="wrap">
    <h1>AI Agent Security — Attack Simulation Report</h1>
    <p class="sub">Defensive self-test of the local detection engine. Generated ${escapeHtml(report.generatedAt)} · mode: ${escapeHtml(report.mode)}${report.connector ? ` (${escapeHtml(report.connector)})` : ""} · sensitivity: ${escapeHtml(report.sensitivity)}</p>
    <div class="cards">
      <div class="card"><div class="label">Detection score</div><div class="value">${report.score}%</div></div>
      <div class="card"><div class="label">Detected</div><div class="value">${report.totals.detected}/${report.totals.counted}</div></div>
      <div class="card"><div class="label">Benign false positives</div><div class="value">${report.falsePositiveRate}%</div></div>
      <div class="card"><div class="label">Result</div><div class="value"><span class="verdict ${verdictClass}">${verdictText}</span></div></div>
    </div>
    <table>
      <thead><tr><th>Category</th><th class="num">Detected</th><th class="num">Rate</th><th class="num">Benign FP</th></tr></thead>
      <tbody>
${rows}
      </tbody>
    </table>
    <h2>Misses</h2>
    ${missRows}
    <h2>False positives</h2>
    ${fpRows}
    <footer>This report reflects locally shipped detection rules evaluated against defanged test fixtures. No commands were executed and no network requests were made during the self-test.</footer>
  </div>
</body>
</html>
`;
}

export function formatReport(report: SimulationReport, format: string): string {
	if (format === "json") return JSON.stringify(report, null, 2);
	if (format === "html") return formatHtml(report);
	return formatTable(report);
}

/* ------------------------------------------------------------------ *
 * Command entry.
 * ------------------------------------------------------------------ */

export default async function simulateCommand(options: SimulateOptions): Promise<void> {
	const format = (options.format ?? "table").trim().toLowerCase();
	if (!["table", "json", "html"].includes(format)) {
		process.stderr.write(`Unknown --format: ${options.format}. Use table, json or html.\n`);
		process.exitCode = 1;
		return;
	}

	let report: SimulationReport;
	try {
		report = await runSimulation(options);
	} catch (error) {
		process.stderr.write(
			`aidr simulate failed: ${error instanceof Error ? error.message : String(error)}\n`,
		);
		process.exitCode = 1;
		return;
	}

	const rendered = formatReport(report, format);
	if (options.output) {
		await writeFile(options.output, rendered, { mode: 0o600 });
		process.stdout.write(`Wrote ${format} report to ${options.output}\n`);
	} else {
		process.stdout.write(`${rendered}\n`);
	}

	if (!report.passed) process.exitCode = 1;
}
