import { ApprovalStore } from "@singularityrd/aidr-core";
import { describe, expect, it } from "vitest";
import { createAidrApproveTool } from "../gate-tool.js";

describe("aidr_approve gate tool", () => {
	it("approve stores approval and returns success", async () => {
		const approvalStore = new ApprovalStore();
		// Must have a pending entry first
		approvalStore.setPending("test-id", {
			artifacts: [{ type: "command", value: "chmod 777 ./x" }],
			createdAt: Date.now(),
		});

		const tool = createAidrApproveTool(approvalStore);
		const result = await tool.execute("call-1", {
			actionId: "test-id",
			approved: true,
		});

		expect(result.content[0]?.text).toContain("Approved action test-id");
		expect(approvalStore.isApproved("test-id")).toBe(true);
	});

	it("approve with no pending entry returns not-found message", async () => {
		const approvalStore = new ApprovalStore();
		const tool = createAidrApproveTool(approvalStore);
		const result = await tool.execute("call-1", {
			actionId: "nonexistent",
			approved: true,
		});

		expect(result.content[0]?.text).toContain("No pending Singularity AIDR approval");
	});

	it("reject returns rejection message", async () => {
		const approvalStore = new ApprovalStore();
		const tool = createAidrApproveTool(approvalStore);
		const result = await tool.execute("call-1", {
			actionId: "test-id",
			approved: false,
		});

		expect(result.content[0]?.text).toBe("Rejected by user.");
	});

	it("tool schema matches expected shape", () => {
		const approvalStore = new ApprovalStore();
		const tool = createAidrApproveTool(approvalStore);
		expect(tool.name).toBe("aidr_approve");
		expect(tool.description).toBeTruthy();

		const params = tool.parameters as Record<string, unknown>;
		expect(params.type).toBe("object");

		const properties = params.properties as Record<string, Record<string, unknown>>;
		expect(properties.actionId).toBeTruthy();
		expect(properties.approved).toBeTruthy();

		const required = params.required as string[];
		expect(required).toContain("actionId");
		expect(required).toContain("approved");
	});
});
