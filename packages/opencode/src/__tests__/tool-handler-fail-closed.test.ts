import { guardToolCall, loadKnownMcpServers } from "@singularityrd/aidr-core";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AidrVerdictBlockError } from "../error.js";
import { createToolHandlers } from "../tool-handler.js";

vi.mock("@singularityrd/aidr-core", async (importOriginal) => ({
	// Real shape checks, MCP naming and deadline helpers; the guard is what fails.
	...(await importOriginal<Record<string, unknown>>()),
	createHostObservation: vi.fn(() => null),
	guardToolCall: vi.fn().mockRejectedValue(new Error("policy unavailable")),
	formatAskMessage: vi.fn(),
	formatDenyMessage: vi.fn(() => "denied by policy"),
	// Provisioning is not what this test is about; an unprovisioned install
	// returns an empty context so the guard call itself is the failing step.
	loadProvisionedDetectorContext: vi.fn().mockResolvedValue({}),
	loadKnownMcpServers: vi.fn().mockResolvedValue({ declarations: [], names: [] }),
	recordHostObservation: vi.fn(),
}));

function testLogger() {
	return { debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn() };
}

function handlers(logger = testLogger()) {
	return createToolHandlers(logger, {} as never, "/threats", "/allowlists")["tool.execute.before"];
}

const allowVerdict = {
	verdict: {
		decision: "allow",
		category: "none",
		confidence: 1,
		severity: "info",
		source: "test",
		artifacts: [],
		matchedThreatId: null,
		reasons: [],
	},
};

describe("OpenCode tool handler failure policy", () => {
	afterEach(() => {
		vi.unstubAllEnvs();
	});

	it("denies the tool call when policy evaluation fails", async () => {
		const logger = testLogger();
		await expect(
			handlers(logger)(
				{ tool: "bash", sessionID: "session-1", callID: "call-1" },
				{ args: { command: "git status" } },
			),
		).rejects.toBeInstanceOf(AidrVerdictBlockError);
		expect(logger.error).toHaveBeenCalledWith(
			"Singularity AIDR opencode hook failed closed",
			expect.objectContaining({ tool: "bash" }),
		);
	});

	it("denies the tool call when evaluation outlives the deadline", async () => {
		vi.stubEnv("AIDR_TOOL_CALL_DEADLINE_MS", "100");
		vi.mocked(guardToolCall).mockImplementationOnce(() => new Promise(() => {}));
		const started = Date.now();
		const result = handlers()(
			{ tool: "bash", sessionID: "session-1", callID: "call-1" },
			{ args: { command: "git status" } },
		);
		await expect(result).rejects.toThrow(/in time/);
		expect(Date.now() - started).toBeGreaterThanOrEqual(90);
	});

	it.each([
		["null input", null, { args: {} }],
		["missing tool name", { sessionID: "s", callID: "c" }, { args: {} }],
		["undefined args", { tool: "bash", sessionID: "s", callID: "c" }, {}],
		["string args", { tool: "bash", sessionID: "s", callID: "c" }, { args: "rm -rf /" }],
		["array args", { tool: "bash", sessionID: "s", callID: "c" }, { args: ["rm"] }],
		["null output", { tool: "bash", sessionID: "s", callID: "c" }, null],
	])("denies a malformed tool call (%s) without evaluating it", async (_label, input, output) => {
		vi.mocked(guardToolCall).mockClear();
		await expect(handlers()(input as never, output as never)).rejects.toBeInstanceOf(
			AidrVerdictBlockError,
		);
		expect(guardToolCall).not.toHaveBeenCalled();
	});

	it.each(["rm -rf /tmp/x\u0000", "echo \ud800"])(
		"denies a bash command with malformed text %j",
		async (command) => {
			vi.mocked(guardToolCall).mockClear();
			await expect(
				handlers()({ tool: "bash", sessionID: "s", callID: "c" }, { args: { command } }),
			).rejects.toThrow(/malformed/);
			expect(guardToolCall).not.toHaveBeenCalled();
		},
	);

	it("evaluates a bash command containing a valid U+FFFD instead of denying it", async () => {
		vi.mocked(guardToolCall).mockClear();
		vi.mocked(guardToolCall).mockResolvedValueOnce(allowVerdict as never);
		await handlers()(
			{ tool: "bash", sessionID: "s", callID: "c" },
			{ args: { command: "echo �" } },
		);
		expect(guardToolCall).toHaveBeenCalledTimes(1);
	});

	it("evaluates a known server's MCP tool under the canonical mcp__ name", async () => {
		vi.mocked(loadKnownMcpServers).mockResolvedValueOnce({
			declarations: [],
			names: ["my_github"],
		});
		vi.mocked(guardToolCall).mockResolvedValueOnce(allowVerdict as never);
		const args = { title: "x" };
		await handlers()({ tool: "my_github_create_issue", sessionID: "s", callID: "c" }, { args });
		expect(guardToolCall).toHaveBeenLastCalledWith(
			expect.objectContaining({ toolName: "mcp__my_github__create_issue", toolInput: args }),
			expect.anything(),
			expect.anything(),
		);
	});

	it("keeps a built-in tool name when no server matches", async () => {
		vi.mocked(guardToolCall).mockResolvedValueOnce(allowVerdict as never);
		await handlers()({ tool: "plan_exit", sessionID: "s", callID: "c" }, { args: {} });
		expect(guardToolCall).toHaveBeenLastCalledWith(
			expect.objectContaining({ toolName: "plan_exit" }),
			expect.anything(),
			expect.anything(),
		);
	});
});
