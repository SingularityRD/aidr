#!/usr/bin/env node
/**
 * Singularity AIDR PostToolUse hook entry point.
 * Detects user approvals of ask verdicts and records them for MCP allowlist flow.
 * Always exits 0 and returns valid JSON.
 */

import {
	type Logger,
	recordToolOutputFlow,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import pino from "pino";
import { consumePendingApproval } from "./approval-tracker.js";
import { approvedActionContext } from "./format.js";
import { MAX_POST_TOOL_INPUT_BYTES, readBoundedJson } from "./hook-input.js";
import {
	postToolInspectionUnavailable,
	scanToolResponse,
	type ToolResponseScan,
	toolResponseInspectionResult,
} from "./output-inspection.js";
import {
	appendPostToolContext,
	quarantineFailedToolInspection,
	quarantineInspectedToolOutput,
} from "./tool-output-quarantine.js";

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

function reportUnavailableCoverage(reason: string): void {
	process.stdout.write(`${JSON.stringify(postToolInspectionUnavailable(reason))}\n`);
}

async function main(): Promise<void> {
	await verifyArtifactIntegrityAndLog({
		artifactDir: __dirname,
		artifactId: "claude-code/dist",
		logger,
	});

	let input: ReturnType<typeof readBoundedJson>;
	try {
		input = readBoundedJson();
	} catch {
		reportUnavailableCoverage("Could not read PostToolUse input.");
		return;
	}
	if (input.status === "oversized") {
		const reason = `Singularity AIDR PostToolUse input exceeded the ${MAX_POST_TOOL_INPUT_BYTES}-byte processing limit; the tool already completed, its result shape could not be inspected, and no replacement was attempted. Inspection coverage is unavailable and the original output may remain available to the host; treat it as untrusted.`;
		process.stdout.write(
			`${JSON.stringify({
				decision: "block",
				reason,
				hookSpecificOutput: { hookEventName: "PostToolUse", additionalContext: reason },
			})}\n`,
		);
		return;
	}
	if (input.status === "invalid") {
		reportUnavailableCoverage("Could not parse PostToolUse input.");
		return;
	}
	const parsed: unknown = input.value;
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		reportUnavailableCoverage("Received malformed PostToolUse input.");
		return;
	}
	const hookInput = parsed as Record<string, unknown>;
	if (!("tool_response" in hookInput)) {
		reportUnavailableCoverage("Received PostToolUse input without a tool response.");
		return;
	}
	if (hookInput.tool_use_id !== undefined && typeof hookInput.tool_use_id !== "string") {
		reportUnavailableCoverage("Received malformed PostToolUse identity.");
		return;
	}
	if (hookInput.session_id !== undefined && typeof hookInput.session_id !== "string") {
		reportUnavailableCoverage("Received malformed PostToolUse session.");
		return;
	}

	const toolUseId = (hookInput.tool_use_id ?? "") as string;
	const sessionId = (hookInput.session_id ?? "unknown") as string;
	let inspection: Record<string, unknown> | null;
	let scan: ToolResponseScan | null = null;
	try {
		scan = scanToolResponse(hookInput.tool_response);
		inspection = quarantineInspectedToolOutput(
			toolResponseInspectionResult(scan),
			hookInput.tool_response,
		);
	} catch {
		inspection = quarantineFailedToolInspection(hookInput.tool_response);
	}
	if (scan && scan.findings.length > 0) {
		// The output is already in Claude's context: record what it carried
		// (secrets, injection payloads) so the session's next calls are judged
		// with it. Never changes this hook's response and never throws.
		const toolInput = hookInput.tool_input;
		await recordToolOutputFlow(
			{
				sessionId,
				toolName: typeof hookInput.tool_name === "string" ? hookInput.tool_name : "unknown",
				toolInput:
					toolInput && typeof toolInput === "object" && !Array.isArray(toolInput)
						? (toolInput as Record<string, unknown>)
						: undefined,
				findings: scan.findings,
			},
			{ agentRuntime: "claude-code", logger },
		);
	}
	let response: Record<string, unknown> = inspection ?? {};
	if (toolUseId) {
		try {
			const entry = await consumePendingApproval(sessionId, toolUseId, logger);
			if (entry) {
				response = appendPostToolContext(response, approvedActionContext(entry));
			}
			// No pending approval is the common path; retain the inspection result.
		} catch {
			// Approval bookkeeping must not discard an output quarantine.
		}
	}
	process.stdout.write(`${JSON.stringify(response)}\n`);
}

main().catch(() => {
	reportUnavailableCoverage("Failed while processing PostToolUse input.");
});
