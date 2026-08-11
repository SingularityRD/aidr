import { describe, expect, it, vi } from "vitest";
import { AidrVerdictBlockError } from "../error.js";
import { createToolHandlers } from "../tool-handler.js";

vi.mock("@singularityrd/aidr-core", () => ({
	guardToolCall: vi.fn().mockRejectedValue(new Error("policy unavailable")),
	formatAskMessage: vi.fn(),
	formatDenyMessage: vi.fn(),
}));

describe("OpenCode tool handler failure policy", () => {
	it("denies the tool call when policy evaluation fails", async () => {
		const logger = {
			debug: vi.fn(),
			info: vi.fn(),
			warn: vi.fn(),
			error: vi.fn(),
		};
		const handlers = createToolHandlers(logger, {} as never, "/threats", "/allowlists");

		await expect(
			handlers["tool.execute.before"](
				{ tool: "bash", sessionID: "session-1", callID: "call-1" },
				{ args: { command: "git status" } },
			),
		).rejects.toBeInstanceOf(AidrVerdictBlockError);
		expect(logger.error).toHaveBeenCalledWith(
			"Singularity AIDR opencode hook failed closed",
			expect.objectContaining({ tool: "bash" }),
		);
	});
});
