/**
 * Runaway guardrails: loops, repeated failing calls, rate spikes and optional
 * session budgets turn an allow into an ask (never a deny); state problems are
 * a skipped, logged, non-clean signal.
 */
import { readdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	applyRunawayOutcome,
	checkRunaway,
	evaluateRunawayCall,
	RUNAWAY_SIGNAL_IDS,
	type RunawayState,
	recordToolOutcome,
	runawayStateDir,
	toolCallFingerprints,
	writtenPaths,
} from "../agent-safety/runaway-guard.js";
import { allowVerdict, evaluateToolCall } from "../evaluator.js";
import { normalizeToolEvaluationRequest } from "../tool-normalization.js";
import { type Config, ConfigSchema, type RunawayConfig, RunawayConfigSchema } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const THREATS_DIR = join(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = join(__dirname, "..", "..", "..", "..", "allowlists");

function settings(overrides: Partial<RunawayConfig> = {}): RunawayConfig {
	return RunawayConfigSchema.parse(overrides);
}

function config(runaway: Partial<RunawayConfig> = {}, extra: Record<string, unknown> = {}): Config {
	return ConfigSchema.parse({ agent_safety: { runaway }, ...extra });
}

/** Feed calls through the pure evaluator; returns the signals of the last one. */
function run(
	calls: Array<{ exact: string; similar?: string; files?: string[]; at: number }>,
	s: RunawayConfig,
	initial?: RunawayState,
) {
	let state = initial;
	let signals: ReturnType<typeof evaluateRunawayCall>["signals"] = [];
	for (const call of calls) {
		const result = evaluateRunawayCall(
			state,
			{ exact: call.exact, similar: call.similar ?? call.exact, writtenFiles: call.files ?? [] },
			call.at,
			s,
		);
		state = result.next;
		signals = result.signals;
	}
	return { state: state as RunawayState, signals };
}

const ids = (signals: Array<{ id: string }>) => signals.map((signal) => signal.id);

describe("evaluateRunawayCall (pure)", () => {
	it("pauses the call after max_consecutive_identical_calls identical calls in a row", () => {
		const s = settings({ max_consecutive_identical_calls: 3 });
		const calls = Array.from({ length: 3 }, (_, i) => ({ exact: "aaa", at: 1000 + i }));
		expect(run(calls, s).signals).toEqual([]);
		const fourth = run([...calls, { exact: "aaa", at: 1010 }], s);
		expect(ids(fourth.signals)).toContain(RUNAWAY_SIGNAL_IDS.consecutiveIdentical);
		expect(fourth.signals[0]?.reason).toMatch(/repeated 4 times in a row \(limit 3\)/);
	});

	it("an intervening different call breaks the streak (edit-and-rerun is not a loop)", () => {
		const s = settings({ max_consecutive_identical_calls: 2, max_identical_calls: 0 });
		const calls = [];
		for (let i = 0; i < 10; i++) {
			calls.push({ exact: "test", at: 1000 + i * 2 }, { exact: `edit${i}`, at: 1001 + i * 2 });
		}
		expect(run(calls, s).signals).toEqual([]);
	});

	it("flags the same call too often within the window, and forgets it after the window", () => {
		const s = settings({
			max_identical_calls: 3,
			max_consecutive_identical_calls: 0,
			window_seconds: 60,
		});
		const calls = [];
		for (let i = 0; i < 4; i++)
			calls.push({ exact: "read", at: i * 1000 }, { exact: `x${i}`, at: i * 1000 + 1 });
		expect(ids(run(calls, s).signals)).toEqual([]); // last call is x3
		const again = run([...calls, { exact: "read", at: 5000 }], s);
		expect(ids(again.signals)).toContain(RUNAWAY_SIGNAL_IDS.identicalInWindow);
		const later = run([...calls, { exact: "read", at: 5000 + 120_000 }], s);
		expect(later.signals).toEqual([]);
	});

	it("flags near-identical calls (numbers and ids ignored)", () => {
		const a = toolCallFingerprints("Bash", { command: "sleep 5 && curl localhost:3000/health" });
		const b = toolCallFingerprints("Bash", { command: "sleep 30 && curl localhost:3000/health" });
		const c = toolCallFingerprints("Bash", { command: "npm test" });
		expect(a.exact).not.toBe(b.exact);
		expect(a.similar).toBe(b.similar);
		expect(a.similar).not.toBe(c.similar);
		const s = settings({ max_similar_calls: 3, max_consecutive_identical_calls: 0 });
		const calls = Array.from({ length: 4 }, (_, i) => ({
			exact: `e${i}`,
			similar: "shape",
			at: i,
		}));
		expect(ids(run(calls, s).signals)).toEqual([RUNAWAY_SIGNAL_IDS.similarInWindow]);
	});

	it("flags a tool-call rate spike", () => {
		const s = settings({ max_calls_per_minute: 5 });
		const calls = Array.from({ length: 6 }, (_, i) => ({ exact: `c${i}`, at: 1000 + i * 100 }));
		const result = run(calls, s);
		expect(ids(result.signals)).toEqual([RUNAWAY_SIGNAL_IDS.rateSpike]);
		expect(result.signals[0]?.reason).toMatch(/6 tool calls in the last 60 seconds \(limit 5\)/);
		const spread = Array.from({ length: 6 }, (_, i) => ({ exact: `c${i}`, at: i * 20_000 }));
		expect(run(spread, s).signals).toEqual([]);
	});

	it("flags repeated failures of the same call until a file changes", () => {
		const s = settings({ max_repeated_failures: 2 });
		const base = run([{ exact: "build", at: 1000 }], s).state;
		const failed: RunawayState = {
			...base,
			failures: [
				[1001, "build"],
				[1002, "build"],
			],
		};
		expect(ids(run([{ exact: "build", at: 1003 }], s, failed).signals)).toContain(
			RUNAWAY_SIGNAL_IDS.repeatedFailures,
		);
		const afterEdit = run([{ exact: "edit", files: ["f1"], at: 1003 }], s, failed).state;
		expect(afterEdit.failures).toEqual([]);
		expect(run([{ exact: "build", at: 1004 }], s, afterEdit).signals).toEqual([]);
	});

	it("enforces optional budgets (off by default)", () => {
		const unlimited = settings();
		expect(unlimited.max_tool_calls).toBe(0);
		expect(unlimited.max_session_minutes).toBe(0);
		expect(unlimited.max_files_written).toBe(0);
		const many = Array.from({ length: 50 }, (_, i) => ({
			exact: `c${i}`,
			files: [`f${i}`],
			at: i * 5000,
		}));
		expect(run(many, settings({ max_calls_per_minute: 0 })).signals).toEqual([]);

		expect(ids(run(many.slice(0, 11), settings({ max_tool_calls: 10 })).signals)).toContain(
			RUNAWAY_SIGNAL_IDS.toolCallBudget,
		);
		expect(ids(run(many.slice(0, 4), settings({ max_files_written: 3 })).signals)).toContain(
			RUNAWAY_SIGNAL_IDS.filesWrittenBudget,
		);
		const long = [
			{ exact: "a", at: 0 },
			{ exact: "b", at: 31 * 60_000 },
		];
		expect(ids(run(long, settings({ max_session_minutes: 30 })).signals)).toContain(
			RUNAWAY_SIGNAL_IDS.sessionTimeBudget,
		);
	});

	it("keeps its state bounded however long the session runs", () => {
		const s = settings({ max_calls_per_minute: 0, max_similar_calls: 0, max_identical_calls: 0 });
		const calls = Array.from({ length: 3000 }, (_, i) => ({
			exact: `c${i}`,
			files: [`f${i}`],
			at: i,
		}));
		const { state } = run(calls, s);
		expect(state.recent.length).toBeLessThanOrEqual(1024);
		expect(state.files.length).toBeLessThanOrEqual(2048);
		expect(state.calls).toBe(3000);
	});

	it("honours disabled_threats for individual signals", () => {
		const s = settings({ max_calls_per_minute: 1 });
		const result = evaluateRunawayCall(
			run([{ exact: "a", at: 0 }], s).state,
			{ exact: "b", similar: "b", writtenFiles: [] },
			1,
			s,
			new Set([RUNAWAY_SIGNAL_IDS.rateSpike]),
		);
		expect(result.signals).toEqual([]);
	});
});

describe("writtenPaths", () => {
	it("covers Write/Edit/MultiEdit/Delete and every patch section, nothing else", () => {
		const norm = (toolName: string, toolInput: Record<string, unknown>) =>
			normalizeToolEvaluationRequest({ sessionId: "s", toolName, toolInput, artifacts: [] });
		expect(writtenPaths(norm("Write", { file_path: "a.ts", content: "x" }))).toEqual(["a.ts"]);
		expect(writtenPaths(norm("MultiEdit", { file_path: "b.ts", edits: [] }))).toEqual(["b.ts"]);
		expect(
			writtenPaths(
				norm("apply_patch", {
					input:
						"*** Begin Patch\n*** Add File: x.ts\n+a\n*** Update File: y.ts\n@@\n-a\n+b\n*** End Patch",
				}),
			),
		).toEqual(["x.ts", "y.ts"]);
		expect(writtenPaths(norm("Bash", { command: "ls" }))).toEqual([]);
		expect(writtenPaths(norm("Read", { file_path: "a.ts" }))).toEqual([]);
	});
});

describe("applyRunawayOutcome", () => {
	it("turns allow into ask, keeps deny, and marks an unavailable guard as not clean", () => {
		const signals = [{ id: RUNAWAY_SIGNAL_IDS.rateSpike, reason: "too fast" }];
		const asked = applyRunawayOutcome(allowVerdict(), { status: "checked", signals });
		expect(asked).toMatchObject({
			decision: "ask",
			category: "agent_runaway",
			matchedThreatId: "CLT-AGENT-RUN-005",
		});
		expect(asked.reasons.join(" ")).toMatch(
			/^Runaway guard paused this session for human review: too fast$/,
		);
		const deny = { ...allowVerdict("heuristic"), decision: "deny" as const, category: "tool" };
		expect(applyRunawayOutcome(deny, { status: "checked", signals })).toBe(deny);
		const unavailable = applyRunawayOutcome(allowVerdict(), {
			status: "unavailable",
			reason: "state broken",
		});
		expect(unavailable).toMatchObject({
			decision: "allow",
			category: "runaway_guard_unavailable",
			severity: "warning",
		});
		expect(applyRunawayOutcome(allowVerdict(), { status: "disabled" })).toEqual(allowVerdict());
	});
});

describe("checkRunaway / recordToolOutcome with on-disk state", () => {
	let dir: string;
	let configPath: string;

	beforeAll(async () => {
		dir = await makeTmpDir();
		configPath = join(dir, "config.json");
		await writeFile(
			configPath,
			JSON.stringify({ agent_safety: { runaway: { max_repeated_failures: 2 } } }),
		);
	});

	afterAll(async () => {
		await removeTmpDir(dir);
	});

	it("keeps state next to the active config, keyed by a digest (no raw command text)", async () => {
		const c = config({ max_consecutive_identical_calls: 2 });
		const call = {
			sessionId: "sess-1",
			toolName: "Bash",
			toolInput: { command: "cat secret-plan.txt" },
		};
		for (let i = 0; i < 2; i++) {
			expect(await checkRunaway(call, c, { configPath })).toEqual({
				status: "checked",
				signals: [],
			});
		}
		const third = await checkRunaway(call, c, { configPath });
		expect(third.status === "checked" && ids(third.signals)).toEqual([
			RUNAWAY_SIGNAL_IDS.consecutiveIdentical,
		]);
		const stateDir = runawayStateDir(configPath);
		expect(stateDir).toBe(join(dir, "agent-safety"));
		for (const file of await readdir(stateDir)) {
			const text = await readFile(join(stateDir, file), "latin1");
			expect(text).not.toContain("secret-plan");
			expect(text).not.toContain("sess-1");
		}
	});

	it("records failures and pauses the next identical retry", async () => {
		const call = { sessionId: "sess-fail", toolName: "Bash", toolInput: { command: "make build" } };
		const c = config({ max_repeated_failures: 2 });
		for (let i = 0; i < 2; i++) {
			expect((await checkRunaway(call, c, { configPath })).status).toBe("checked");
			expect(await recordToolOutcome({ ...call, failed: true }, { configPath })).toBe("recorded");
		}
		const retry = await checkRunaway(call, c, { configPath });
		expect(retry.status === "checked" && ids(retry.signals)).toContain(
			RUNAWAY_SIGNAL_IDS.repeatedFailures,
		);
		expect(await recordToolOutcome({ ...call, failed: false }, { configPath })).toBe("skipped");
	});

	it("reports tampered state as unavailable (not clean) and recovers", async () => {
		const call = { sessionId: "sess-tamper", toolName: "Read", toolInput: { file_path: "a.ts" } };
		const c = config();
		await checkRunaway(call, c, { configPath });
		const stateDir = runawayStateDir(configPath);
		for (const file of await readdir(stateDir)) {
			if (!file.startsWith("runaway-") || !file.endsWith(".json")) continue;
			const document = JSON.parse(await readFile(join(stateDir, file), "utf8"));
			document.payload = document.payload.replace(/"calls":\d+/, '"calls":0');
			await writeFile(join(stateDir, file), JSON.stringify(document));
		}
		const tampered = await checkRunaway(call, c, { configPath });
		expect(tampered.status).toBe("unavailable");
		expect(tampered.status === "unavailable" && tampered.reason).toMatch(
			/integrity check.*not a clean result/,
		);
		expect((await checkRunaway(call, c, { configPath })).status).toBe("checked");
	});

	it("reports an unusable state directory as unavailable, never throws", async () => {
		const { mkdir } = await import("node:fs/promises");
		await mkdir(join(dir, "blocked"), { recursive: true });
		const blockedConfig = join(dir, "blocked", "config.json");
		await writeFile(blockedConfig, "{}");
		// The state directory's name is taken by a regular file.
		await writeFile(join(dir, "blocked", "agent-safety"), "not a directory");
		const outcome = await checkRunaway(
			{ sessionId: "s", toolName: "Bash", toolInput: { command: "ls" } },
			config(),
			{ configPath: blockedConfig },
		);
		expect(outcome.status).toBe("unavailable");
		expect(
			await recordToolOutcome(
				{ sessionId: "s", toolName: "Bash", toolInput: {}, failed: true },
				{ configPath: blockedConfig },
			),
		).toBe("unavailable");
	});

	it("is inert when disabled", async () => {
		expect(
			await checkRunaway(
				{ sessionId: "s", toolName: "Bash", toolInput: {} },
				config({ enabled: false }),
				{ configPath },
			),
		).toEqual({ status: "disabled" });
	});
});

describe("evaluateToolCall integration", () => {
	let dir: string;
	let previousHome: string | undefined;

	beforeAll(async () => {
		dir = await makeTmpDir();
		previousHome = process.env.HOME;
		process.env.HOME = dir;
	});

	afterAll(async () => {
		if (previousHome === undefined) delete process.env.HOME;
		else process.env.HOME = previousHome;
		await removeTmpDir(dir);
	});

	async function writeConfig(name: string, runaway: Record<string, unknown>): Promise<string> {
		const path = join(dir, name, "config.json");
		const { mkdir } = await import("node:fs/promises");
		await mkdir(join(dir, name), { recursive: true });
		await writeFile(
			path,
			JSON.stringify({
				agent_safety: { runaway },
				url_check: { enabled: false },
				package_check: { enabled: false },
				cache: { enabled: false },
				logging: { enabled: false },
			}),
		);
		return path;
	}

	it("pauses a loop of an otherwise clean call with an ask, across all connectors' pipeline", async () => {
		const configPath = await writeConfig("loop", { max_consecutive_identical_calls: 3 });
		const call = {
			sessionId: "loop-session",
			toolName: "Bash",
			toolInput: { command: "npm test" },
			artifacts: [{ type: "command" as const, value: "npm test" }],
		};
		const context = { threatsDir: THREATS_DIR, allowlistsDir: ALLOWLISTS_DIR, configPath };
		for (let i = 0; i < 3; i++) {
			expect((await evaluateToolCall(call, context)).decision).toBe("allow");
		}
		const paused = await evaluateToolCall(call, context);
		expect(paused).toMatchObject({
			decision: "ask",
			category: "agent_runaway",
			source: "runaway_guard",
		});
		// A different session is unaffected.
		expect((await evaluateToolCall({ ...call, sessionId: "other" }, context)).decision).toBe(
			"allow",
		);
	});

	it("still counts calls that take the no-artifact fast path", async () => {
		const configPath = await writeConfig("fast", { max_consecutive_identical_calls: 1 });
		const call = { sessionId: "fast", toolName: "TodoWrite", toolInput: {}, artifacts: [] };
		const context = { threatsDir: THREATS_DIR, allowlistsDir: ALLOWLISTS_DIR, configPath };
		expect((await evaluateToolCall(call, context)).decision).toBe("allow");
		expect((await evaluateToolCall(call, context)).decision).toBe("ask");
	});

	it("applies the diff-aware edit rules end to end", async () => {
		const configPath = await writeConfig("edits", {});
		const verdict = await evaluateToolCall(
			{
				sessionId: "edits",
				toolName: "Edit",
				toolInput: {
					file_path: "src/auth.test.ts",
					old_string: "it('logs in', () => {",
					new_string: "it.skip('logs in', () => {",
				},
				artifacts: [],
			},
			{ threatsDir: THREATS_DIR, allowlistsDir: ALLOWLISTS_DIR, configPath },
		);
		expect(verdict).toMatchObject({
			decision: "ask",
			matchedThreatId: "CLT-AGENT-RH-101",
			category: "reward_hacking",
		});
		expect(verdict.artifacts).toContain("src/auth.test.ts");
	});
});
