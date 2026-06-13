import { ApprovalStore, nullLogger } from "@singularityrd/aidr-core";
import { describe, expect, it, vi } from "vitest";
import { createToolHandlers } from "../tool-handler.js";

vi.mock("@singularityrd/aidr-core", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return {
		...actual,
		guardToolCall: vi.fn().mockResolvedValue({
			verdict: {
				decision: "allow",
				category: "none",
				confidence: 1.0,
				severity: "info",
				source: "none",
				artifacts: [],
				matchedThreatId: null,
				reasons: [],
			},
		}),
	};
});

describe("createToolHandlers", () => {
	it("empty-artifact MCP tool calls still reach guard policy", async () => {
		const approvalStore = new ApprovalStore();
		const handlers = createToolHandlers(nullLogger, approvalStore, "/threats", "/allowlists");
		const { guardToolCall } = await import("@singularityrd/aidr-core");

		await handlers["tool.execute.before"](
			{ tool: "mcp__unknownServer__query", sessionID: "s1", callID: "c1" },
			{ args: {} },
		);

		expect(guardToolCall).toHaveBeenCalledWith(
			expect.objectContaining({
				sessionId: "s1",
				toolName: "mcp__unknownServer__query",
				toolInput: {},
				artifacts: [],
			}),
			expect.objectContaining({ agentRuntime: "opencode" }),
			approvalStore,
		);
	});
});
