import { describe, expect, it } from "vitest";
import { getCodexConnectorCoverageEvidence, inspectionCoverageForEvent } from "../coverage.js";

describe("Codex event inspection coverage", () => {
	it("marks PreToolUse input as inline blocking without claiming output visibility", () => {
		const coverage = inspectionCoverageForEvent("PreToolUse");

		expect(coverage).toMatchObject({
			eventVisibility: { toolInput: true, toolOutput: false },
			enforcement: {
				toolCall: "inline_blocking",
				outputBeforeModelConsumption: "unavailable",
			},
			outputInspection: "unavailable",
		});
	});

	it("marks PostToolUse output as observation only", () => {
		const coverage = inspectionCoverageForEvent("PostToolUse");

		expect(coverage).toMatchObject({
			eventVisibility: { toolInput: true, toolOutput: true },
			enforcement: {
				toolCall: "none",
				outputBeforeModelConsumption: "unavailable",
			},
			outputInspection: "post_execution_observation",
		});
	});

	it("marks UserPromptSubmit as inline prompt blocking with no tool visibility", () => {
		expect(inspectionCoverageForEvent("UserPromptSubmit")).toMatchObject({
			eventVisibility: { toolInput: false, toolOutput: false, userPrompt: true },
			enforcement: { toolCall: "none", prompt: "inline_blocking" },
			outputInspection: "unavailable",
		});
	});
});

describe("Codex connector coverage evidence", () => {
	it("reports the shipped PreToolUse + UserPromptSubmit + PostToolUse boundary without an inline output claim", () => {
		const evidence = getCodexConnectorCoverageEvidence();

		expect(evidence.configuredEvents).toEqual(["PreToolUse", "UserPromptSubmit", "PostToolUse"]);
		expect(evidence.eventCoverage).toEqual({
			preToolUse: true,
			postToolUse: true,
			userPromptSubmit: true,
		});
		expect(evidence.capabilities).toEqual({
			toolInputInspection: "inline_blocking",
			toolOutputInspection: "post_execution_observation",
			promptInspection: "inline_blocking",
			canBlockOutputBeforeModelConsumption: false,
		});
		expect(evidence.claims).toEqual({
			inlineToolCallBlocking: true,
			inlinePromptBlocking: true,
			inlineOutputBlocking: false,
		});
		expect(evidence.hostFailureBoundary).toMatchObject({
			mode: "fail_open",
			connectorCanOverride: false,
		});
		expect(evidence.health).toMatchObject({
			status: "degraded",
			runtimeRegistrationVerified: false,
		});
		expect(evidence.health.reasonCodes).toContain("tool_output_is_observation_only");
		expect(evidence.health.reasonCodes).toContain("pre_model_output_blocking_unavailable");
	});

	it("reports a registration without PostToolUse as lacking output inspection", () => {
		const evidence = getCodexConnectorCoverageEvidence(["PreToolUse", "UserPromptSubmit"]);

		expect(evidence.capabilities.toolOutputInspection).toBe("unavailable");
		expect(evidence.health.reasonCodes).toContain("tool_output_inspection_unavailable");
	});

	it("does not promote PostToolUse observation to pre-consumption enforcement", () => {
		const evidence = getCodexConnectorCoverageEvidence(["PreToolUse", "PostToolUse"]);

		expect(evidence.capabilities.toolOutputInspection).toBe("post_execution_observation");
		expect(evidence.capabilities.canBlockOutputBeforeModelConsumption).toBe(false);
		expect(evidence.claims.inlineOutputBlocking).toBe(false);
		expect(evidence.health.reasonCodes).toContain("tool_output_is_observation_only");
	});

	it("reports a PreToolUse-only registration as lacking prompt inspection", () => {
		const evidence = getCodexConnectorCoverageEvidence(["PreToolUse"]);

		expect(evidence.capabilities.promptInspection).toBe("unavailable");
		expect(evidence.claims.inlinePromptBlocking).toBe(false);
		expect(evidence.health.reasonCodes).toContain("prompt_inspection_unavailable");
	});

	it("reports an event set without PreToolUse as not enforcing", () => {
		const evidence = getCodexConnectorCoverageEvidence(["PostToolUse"]);

		expect(evidence.health.status).toBe("unhealthy");
		expect(evidence.claims.inlineToolCallBlocking).toBe(false);
		expect(evidence.health.reasonCodes[0]).toBe("pre_tool_use_enforcement_unavailable");
	});
});
