import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { runInNewContext } from "node:vm";
import { transformSync } from "esbuild";
import { describe, expect, it, vi } from "vitest";

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
		verdictOverride?: Record<string, unknown>;
	} = {},
) {
	const output: string[] = [];
	const extract = vi.fn().mockReturnValue([]);
	const evaluate = options.evaluateError
		? vi.fn().mockRejectedValue(options.evaluateError)
		: vi.fn().mockResolvedValue(options.verdictOverride ?? verdict(decision));
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
		initSentry: vi.fn(),
		verifyArtifactIntegrityAndLog: vi.fn().mockResolvedValue({ status: "skipped" }),
	};
	const pino = Object.assign(() => ({}), { destination: () => ({}) });
	const modules: Record<string, unknown> = {
		"node:fs": {
			readFileSync: (fd: number) => {
				if (options.readError) throw options.readError;
				return fd === 0 ? input : "";
			},
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
		process: { stdout: { write: (chunk: string) => output.push(chunk) } },
		__dirname: "/test",
	});
	await vi.waitFor(() => expect(output.length).toBeGreaterThan(0));
	return {
		response: JSON.parse(output.join("").trim()) as Record<string, unknown>,
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
