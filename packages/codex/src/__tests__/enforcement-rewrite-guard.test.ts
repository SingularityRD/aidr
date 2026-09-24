import { describe, expect, it, vi } from "vitest";

vi.mock("@singularityrd/aidr-core", async (importOriginal) => {
	const actual = (await importOriginal()) as Record<string, unknown>;
	return {
		...actual,
		loadProvisionedDetectorContext: vi.fn().mockResolvedValue({}),
		guardToolCall: vi.fn().mockResolvedValue({
			verdict: {
				decision: "allow",
				category: "dlp_redacted",
				confidence: 1,
				severity: "warning",
				source: "dlp",
				artifacts: [],
				matchedThreatId: "rule-1",
				reasons: ["DLP redaction applied"],
				transformedInput: { command: "echo [REDACTED]" },
			},
			responseActions: [],
		}),
	};
});

const { enforceCodexPreToolUse } = await import("../enforcement.js");

describe("Codex redacted-input guard", () => {
	it("denies rather than running the original input when a redacted input is returned", async () => {
		const { guardToolCall } = await import("@singularityrd/aidr-core");
		const outcome = await enforceCodexPreToolUse(
			{ session_id: "s", tool_name: "Bash", tool_input: { command: "echo secret-value" } },
			{ threatsDir: "/threats", allowlistsDir: "/allowlists" },
		);
		expect(guardToolCall).toHaveBeenCalledWith(
			expect.anything(),
			expect.not.objectContaining({ supportsInputRewrite: true }),
			expect.anything(),
		);
		expect(outcome).toMatchObject({ decision: "deny", reasonCode: "dlp" });
		expect(outcome.wire).toMatchObject({
			hookSpecificOutput: { hookEventName: "PreToolUse", permissionDecision: "deny" },
		});
		expect(JSON.stringify(outcome.wire)).not.toContain("updatedInput");
	});
});
