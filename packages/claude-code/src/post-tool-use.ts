#!/usr/bin/env node
/**
 * Singularity AIDR PostToolUse hook entry point.
 * Detects user approvals of ask verdicts and records them for MCP allowlist flow.
 * Always exits 0 and returns valid JSON.
 */

import { readFileSync } from "node:fs";
import type { Logger } from "@singularityrd/aidr-core";
import pino from "pino";
import { consumePendingApproval, type PendingApproval } from "./approval-tracker.js";
import { artifactTypeLabel } from "./format.js";
import { inspectToolResponse } from "./output-inspection.js";
import {
	appendPostToolContext,
	quarantineFailedToolInspection,
	quarantineInspectedToolOutput,
} from "./tool-output-quarantine.js";

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

async function maybeVerifyIntegrity(): Promise<boolean> {
	try {
		// biome-ignore lint/suspicious/noExplicitAny: Transitional wiring
		const core = (await import("@singularityrd/aidr-core")) as any;
		const fn = core?.verifyArtifactIntegrityAndLog as
			| ((args: { artifactDir: string; artifactId: string; logger?: unknown }) => Promise<unknown>)
			| undefined;
		if (typeof fn === "function") {
			await fn({ artifactDir: __dirname, artifactId: "claude-code/dist", logger });
		}
		return true;
	} catch {
		return false;
	}
}

function approvedActionContext(entry: PendingApproval): string {
	const artifactList = entry.artifacts
		.map((artifact) => `${artifactTypeLabel(artifact.type)} '${artifact.value}'`)
		.join(", ");
	const typeSet = [...new Set(entry.artifacts.map((artifact) => artifactTypeLabel(artifact.type)))];
	const typeStr = typeSet.join("/");
	const noun =
		typeStr === "URL"
			? "these URLs"
			: typeStr === "command"
				? "these commands"
				: `these ${typeStr}s`;
	return `Singularity AIDR: The user approved a flagged action (threat ${entry.threatId}: ${entry.threatTitle}, artifacts: ${artifactList}). To permanently allow ${noun} in the future, an operator can use the CLI allowlist controls.`;
}

function deny(reason: string): void {
	process.stdout.write(`${JSON.stringify({ decision: "deny", reason })}\n`);
}

async function main(): Promise<void> {
	if (!(await maybeVerifyIntegrity())) {
		deny("Singularity AIDR integrity verification failed; execution was denied.");
		return;
	}

	let rawInput: string;
	try {
		rawInput = readFileSync(0, "utf-8");
	} catch {
		deny("Singularity AIDR could not read PostToolUse input; execution was denied.");
		return;
	}

	let parsed: unknown;
	try {
		parsed = JSON.parse(rawInput);
	} catch {
		deny("Singularity AIDR could not parse PostToolUse input; execution was denied.");
		return;
	}
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		deny("Singularity AIDR received malformed PostToolUse input; execution was denied.");
		return;
	}
	const hookInput = parsed as Record<string, unknown>;
	if (!("tool_response" in hookInput)) {
		deny("Singularity AIDR received malformed PostToolUse input without a tool response; execution was denied.");
		return;
	}
	if (hookInput.tool_use_id !== undefined && typeof hookInput.tool_use_id !== "string") {
		deny("Singularity AIDR received malformed PostToolUse identity; execution was denied.");
		return;
	}
	if (hookInput.session_id !== undefined && typeof hookInput.session_id !== "string") {
		deny("Singularity AIDR received malformed PostToolUse session; execution was denied.");
		return;
	}

	const toolUseId = (hookInput.tool_use_id ?? "") as string;
	const sessionId = (hookInput.session_id ?? "unknown") as string;
	let inspection: Record<string, unknown> | null;
	try {
		inspection = quarantineInspectedToolOutput(
			inspectToolResponse(hookInput.tool_response),
			hookInput.tool_response,
		);
	} catch {
		inspection = quarantineFailedToolInspection(hookInput.tool_response);
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
	deny("Singularity AIDR failed while processing PostToolUse input; execution was denied.");
});
