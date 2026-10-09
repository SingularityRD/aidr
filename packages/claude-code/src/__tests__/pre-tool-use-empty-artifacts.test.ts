import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runInNewContext } from "node:vm";
import {
	createHookResponder,
	type HookResponderOptions,
	isWellFormedToolCall,
	malformedShellCommandReason,
} from "@singularityrd/aidr-core";
import { transformSync } from "esbuild";
import { describe, expect, it, vi } from "vitest";
import { MAX_PRE_TOOL_INPUT_BYTES, resolvePreToolUseDeadlineMs } from "../hook-input.js";

const hookSource = readFileSync(resolve(__dirname, "../pre-tool-use.ts"), "utf8");
const hookCode = transformSync(hookSource, {
	format: "cjs",
	loader: "ts",
	target: "es2020",
}).code;

function verdict(decision: "allow" | "ask" | "deny") {
	return {
		decision,
		category: decision === "allow" ? "none" : "dlp",
		severity: decision === "deny" ? "critical" : "warning",
		confidence: 1,
		source: "runtime_detectors",
		artifacts: [],
		matchedThreatId: null,
		reasons: decision === "allow" ? [] : ["Raw input inspection"],
	};
}

async function runHook(
	input: string,
	decision: "allow" | "ask" | "deny",
	options: {
		readError?: Error;
		evaluateError?: Error;
		provisionedContext?: Record<string, unknown>;
		provisionError?: Error;
		oversized?: boolean;
		hangEvaluation?: boolean;
		env?: Record<string, string>;
		verdictOverride?: Record<string, unknown>;
	} = {},
) {
	const output: string[] = [];
	const exit = vi.fn();
	const extract = vi.fn().mockReturnValue([]);
	const evaluate = options.hangEvaluation
		? vi.fn().mockReturnValue(new Promise(() => {}))
		: options.evaluateError
			? vi.fn().mockRejectedValue(options.evaluateError)
			: vi.fn().mockResolvedValue(options.verdictOverride ?? verdict(decision));
	const readBoundedJson = vi.fn((_fd: number, maxBytes: number) => {
		if (options.readError) throw options.readError;
		if (options.oversized) return { status: "oversized" };
		expect(maxBytes).toBe(MAX_PRE_TOOL_INPUT_BYTES);
		try {
			return { status: "parsed", value: JSON.parse(input) };
		} catch {
			return { status: "invalid" };
		}
	});
	const addPendingApproval = vi.fn();
	const core = {
		allowVerdict: () => verdict("allow"),
		// The hook reads the native-host acceptance contract at module load. This
		// sandbox runs an ordinary session, so the contract is absent and the hook
		// must behave exactly as before: createHostObservation returns null and
		// recordHostObservation is a no-op. Returning a real observation here would
		// hide a regression in that inertness.
		createHostObservation: () => null,
		recordHostObservation: vi.fn(),
		evaluateToolCall: evaluate,
		extractFromToolCall: extract,
		// Local mode, default host_dialog: the ask step leaves the verdict unchanged.
		resolveHostAsk: vi.fn(async (_request: unknown, evaluated: unknown) => ({
			verdict: evaluated,
			dashboardOnly: false,
			mode: "host_dialog",
		})),
		formatDashboardApprovalNotice: () => null,
		// Pre-operation snapshots are off by default; the hook must not depend on them.
		snapshotBeforeAllowedToolCall: vi.fn(async () => ({ records: [], snapshot: null })),
		// Real implementations, wired to the sandbox's stdout and exit so the
		// single-answer/exit-after-flush behaviour is exercised as shipped.
		createHookResponder: (responderOptions: HookResponderOptions) =>
			createHookResponder({
				...responderOptions,
				io: {
					writeStdout: (text, done) => {
						output.push(text);
						done();
					},
					exit,
				},
			}),
		isWellFormedToolCall,
		malformedShellCommandReason,
		initSentry: vi.fn(),
		verifyArtifactIntegrityAndLog: vi.fn().mockResolvedValue({ status: "skipped" }),
	};
	const pino = Object.assign(() => ({}), { destination: () => ({}) });
	const modules: Record<string, unknown> = {
		"./hook-input.js": {
			MAX_PRE_TOOL_INPUT_BYTES,
			readStdinJson: async (maxBytes: number) => readBoundedJson(0, maxBytes),
			resolvePreToolUseDeadlineMs,
		},
		"@singularityrd/aidr-core": core,
		pino,
		"./approval-tracker.js": { addPendingApproval },
		"./assets.js": { resolveAssetDir: (name: string) => `/test/${name}` },
		"./detector-provisioning.js": {
			loadProvisionedDetectorContext: options.provisionError
				? async () => {
						throw options.provisionError;
					}
				: async () => options.provisionedContext ?? {},
		},
		"./format.js": { formatBlockReason: () => "Inspected tool input" },
	};
	const module = { exports: {} };
	runInNewContext(hookCode, {
		module,
		exports: module.exports,
		require: (name: string) => {
			if (!Object.hasOwn(modules, name)) throw new Error(`Unexpected hook import: ${name}`);
			return modules[name];
		},
		process: {
			env: options.env ?? {},
			exit,
			stdout: {
				write: (chunk: string, onWritten?: () => void) => {
					output.push(chunk);
					onWritten?.();
					return true;
				},
			},
		},
		setTimeout,
		clearTimeout,
		__dirname: "/test",
	});
	await vi.waitFor(() => expect(output.length).toBeGreaterThan(0));
	return {
		response: JSON.parse(output.join("").trim()) as Record<string, unknown>,
		output,
		exit,
		extract,
		evaluate,
		addPendingApproval,
	};
}

describe("PreToolUse empty-artifact inspection", () => {
	it("passes provisioned detector context through to the evaluator", async () => {
		const runtimeDetectors = { tenantId: "tenant-a", dlp: { enabled: true } };
		const reputationFeed = { feedId: "enterprise-feed" };
		const { evaluate } = await runHook(
			JSON.stringify({ tool_name: "OpaqueNativeTool", tool_input: { payload: "secret" } }),
			"deny",
			{ provisionedContext: { runtimeDetectors, reputationFeed } },
		);
		expect(evaluate).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({ runtimeDetectors, reputationFeed }),
		);
	});

	it("blocks when provisioned detector trust cannot be verified", async () => {
		const { response, evaluate } = await runHook(
			JSON.stringify({ tool_name: "OpaqueNativeTool", tool_input: {} }),
			"allow",
			{ provisionError: new Error("untrusted policy") },
		);
		expect(response).toMatchObject({
			hookSpecificOutput: { permissionDecision: "deny" },
		});
		expect(evaluate).not.toHaveBeenCalled();
		expect(JSON.stringify(response)).not.toContain("untrusted policy");
	});

	it("passes raw non-MCP tool input to the evaluator and maps deny", async () => {
		const toolInput = { payload: { secret: "sensitive test payload" } };
		const input = JSON.stringify({
			session_id: "session-a",
			tool_name: "OpaqueNativeTool",
			tool_input: toolInput,
		});

		const { response, extract, evaluate } = await runHook(input, "deny");

		expect(extract).toHaveBeenCalledWith("OpaqueNativeTool", toolInput);
		expect(evaluate).toHaveBeenCalledWith(
			{ sessionId: "session-a", toolName: "OpaqueNativeTool", toolInput, artifacts: [] },
			expect.objectContaining({ agentRuntime: "claude-code" }),
		);
		expect(response.hookSpecificOutput).toMatchObject({
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
		});
	}, 15_000);

	it("maps an empty-artifact ask without recording an allowlist approval", async () => {
		const input = JSON.stringify({
			session_id: "session-b",
			tool_use_id: "tool-b",
			tool_name: "Bash",
			tool_input: { command: "" },
		});

		const { response, evaluate, addPendingApproval } = await runHook(input, "ask");

		expect(evaluate).toHaveBeenCalledWith(
			expect.objectContaining({ toolName: "Bash", artifacts: [] }),
			expect.any(Object),
		);
		expect(response.hookSpecificOutput).toMatchObject({
			hookEventName: "PreToolUse",
			permissionDecision: "ask",
			permissionDecisionReason: "Inspected tool input",
		});
		expect(addPendingApproval).not.toHaveBeenCalled();
	});

	it("declares input-rewrite support and maps a redacted allow to updatedInput only", async () => {
		const transformedInput = { command: "echo [REDACTED]" };
		const { response, evaluate } = await runHook(
			JSON.stringify({ tool_name: "Bash", tool_input: { command: "echo secret-value" } }),
			"allow",
			{
				verdictOverride: {
					...verdict("allow"),
					category: "dlp_redacted",
					source: "dlp",
					reasons: ["DLP redaction applied: 1 value(s)"],
					transformedInput,
				},
			},
		);
		expect(evaluate).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({ supportsInputRewrite: true }),
		);
		expect(response.hookSpecificOutput).toEqual({
			hookEventName: "PreToolUse",
			updatedInput: transformedInput,
			additionalContext: expect.any(String),
		});
		// A permissionDecision would auto-approve and bypass the user's permission flow.
		expect(response.hookSpecificOutput).not.toHaveProperty("permissionDecision");
		expect(response.systemMessage).toContain("DLP redaction applied");
		expect(JSON.stringify(response)).not.toContain("secret-value");
	});

	it("keeps the empty-artifact allow response empty after evaluation", async () => {
		const input = JSON.stringify({ tool_name: "Bash", tool_input: { command: "" } });
		const { response, evaluate } = await runHook(input, "allow");

		expect(response).toEqual({});
		expect(evaluate).toHaveBeenCalledOnce();
	});
});

describe("PreToolUse input and runtime failures", () => {
	it("denies oversized input before extraction or evaluation", async () => {
		const { response, extract, evaluate } = await runHook(
			JSON.stringify({ tool_name: "Write", tool_input: { content: "a" } }),
			"allow",
			{ oversized: true },
		);
		expect(response.hookSpecificOutput).toMatchObject({ permissionDecision: "deny" });
		expect(extract).not.toHaveBeenCalled();
		expect(evaluate).not.toHaveBeenCalled();
	});

	it.each([
		"",
		"{ malformed secret-marker",
		"null",
		"42",
		"{}",
		'{"tool_name":"Bash","tool_input":"invalid"}',
	])("denies malformed stdin without echoing it: %s", async (input) => {
		const { response, evaluate } = await runHook(input, "allow");
		expect(response.hookSpecificOutput).toMatchObject({
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
		});
		expect(JSON.stringify(response)).not.toContain("secret-marker");
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("denies stdin read failure without exposing the exception", async () => {
		const { response, evaluate } = await runHook("", "allow", {
			readError: new Error("secret-read-failure"),
		});
		expect(response.hookSpecificOutput).toMatchObject({ permissionDecision: "deny" });
		expect(JSON.stringify(response)).not.toContain("secret-read-failure");
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("denies evaluator failure without exposing tool input or exception details", async () => {
		const input = JSON.stringify({
			tool_name: "OpaqueNativeTool",
			tool_input: { payload: "secret-tool-input" },
		});
		const { response, evaluate } = await runHook(input, "allow", {
			evaluateError: new Error("secret-evaluator-failure"),
		});
		expect(evaluate).toHaveBeenCalledOnce();
		expect(response.hookSpecificOutput).toMatchObject({ permissionDecision: "deny" });
		expect(JSON.stringify(response)).not.toMatch(/secret-tool-input|secret-evaluator-failure/);
	});
});

describe("PreToolUse bounded input and internal deadline", () => {
	it("reads stdin through the bounded reader and denies oversized input", async () => {
		const { response, evaluate } = await runHook("{}", "allow", { oversized: true });
		expect(response.hookSpecificOutput).toMatchObject({
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
			permissionDecisionReason: "Singularity AIDR input too large to inspect",
		});
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("denies a hung evaluation at the configured deadline and exits", async () => {
		const input = JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } });
		const started = Date.now();
		const { response, output, exit, evaluate } = await runHook(input, "allow", {
			hangEvaluation: true,
			env: { AIDR_PRE_TOOL_USE_DEADLINE_MS: "150" },
		});
		expect(Date.now() - started).toBeGreaterThanOrEqual(140);
		expect(evaluate).toHaveBeenCalledOnce();
		expect(response.hookSpecificOutput).toMatchObject({
			permissionDecision: "deny",
			permissionDecisionReason: "Singularity AIDR inspection timed out",
		});
		expect(output).toHaveLength(1);
		expect(exit).toHaveBeenCalledWith(0);
	});

	it("exits after a timely verdict and never fires the deadline", async () => {
		// Pending sockets from the evaluation must not keep the hook alive past
		// the host timeout: the hook exits once its answer is flushed.
		const input = JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } });
		const { output, exit } = await runHook(input, "allow", {
			env: { AIDR_PRE_TOOL_USE_DEADLINE_MS: "100" },
		});
		await new Promise((resolve) => setTimeout(resolve, 200));
		expect(output).toEqual(["{}\n"]);
		expect(exit).toHaveBeenCalledOnce();
		expect(exit).toHaveBeenCalledWith(0);
	});

	it("exits after a deny verdict too", async () => {
		const input = JSON.stringify({ tool_name: "Bash", tool_input: { command: "ls" } });
		const { response, exit } = await runHook(input, "deny");
		expect(response.hookSpecificOutput).toMatchObject({ permissionDecision: "deny" });
		expect(exit).toHaveBeenCalledWith(0);
	});
});

describe("PreToolUse input shape and malformed commands", () => {
	it.each([
		['{"tool_name":"Bash"}', "missing tool_input"],
		['{"tool_name":"Bash","tool_input":null}', "null tool_input"],
		['{"tool_name":"Bash","tool_input":[]}', "array tool_input"],
		['{"tool_name":"","tool_input":{}}', "empty tool name"],
	])("denies %s (%s) without evaluating", async (input) => {
		const { response, evaluate, exit } = await runHook(input, "allow");
		expect(response.hookSpecificOutput).toMatchObject({ permissionDecision: "deny" });
		expect(evaluate).not.toHaveBeenCalled();
		expect(exit).toHaveBeenCalledWith(0);
	});

	it.each([
		["NUL", "rm -rf /tmp/x\u0000 && echo ok"],
		["unpaired surrogate", "echo \ud800"],
	])("denies a Bash command containing %s instead of asking", async (_label, command) => {
		// The evaluator would have returned `ask`; the malformed text must deny first.
		const { response, evaluate } = await runHook(
			JSON.stringify({ tool_name: "Bash", tool_input: { command } }),
			"ask",
		);
		expect(response.hookSpecificOutput).toMatchObject({
			permissionDecision: "deny",
			permissionDecisionReason: "Singularity AIDR malformed command",
		});
		expect(evaluate).not.toHaveBeenCalled();
	});

	it("evaluates a Bash command containing a validly encoded U+FFFD", async () => {
		const { response, evaluate } = await runHook(
			JSON.stringify({ tool_name: "Bash", tool_input: { command: "echo �" } }),
			"allow",
		);
		expect(evaluate).toHaveBeenCalledTimes(1);
		expect(JSON.stringify(response)).not.toContain("malformed");
	});

	it("denies a non-string Bash command", async () => {
		const { response, evaluate } = await runHook(
			JSON.stringify({ tool_name: "Bash", tool_input: { command: 42 } }),
			"allow",
		);
		expect(response.hookSpecificOutput).toMatchObject({ permissionDecision: "deny" });
		expect(evaluate).not.toHaveBeenCalled();
	});
});

describe("resolvePreToolUseDeadlineMs", () => {
	it("defaults to 10 s, below the 15 s hooks.json timeout", () => {
		const hooks = JSON.parse(
			readFileSync(resolve(__dirname, "../../../../hooks/hooks.json"), "utf8"),
		) as { hooks: { PreToolUse: { hooks: { timeout: number }[] }[] } };
		const hostTimeoutMs = (hooks.hooks.PreToolUse[0]?.hooks[0]?.timeout ?? 0) * 1000;
		expect(resolvePreToolUseDeadlineMs({})).toBe(10_000);
		expect(resolvePreToolUseDeadlineMs({})).toBeLessThan(hostTimeoutMs);
	});

	it.each([
		["2500", 2500],
		["100", 100],
		["14000", 14_000],
		["15000", 10_000],
		["99", 10_000],
		["-5", 10_000],
		["1.5", 10_000],
		["abc", 10_000],
		["", 10_000],
	])("resolves %j to %d ms", (value, expected) => {
		expect(resolvePreToolUseDeadlineMs({ AIDR_PRE_TOOL_USE_DEADLINE_MS: value })).toBe(expected);
	});
});
