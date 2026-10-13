#!/usr/bin/env node
/**
 * Singularity AIDR PostToolUse hook entry point.
 * Inspects the tool result before Claude sees it and replaces risky or
 * uninspectable output with a quarantine notice (`updatedToolOutput`); also
 * records approvals of ask verdicts. Always exits 0 and returns valid JSON.
 */

import {
	exitAfterStdoutFlush,
	type Logger,
	quarantineAgentWrittenFiles,
	recordToolOutcome,
	recordToolOutputCanaries,
	recordToolOutputFlow,
	resolveHookDeadlineMs,
	scanProvisionedOutput,
	toolResultReportsFailure,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import pino from "pino";
import { consumePendingApproval } from "./approval-tracker.js";
import { resolveAssetDir } from "./assets.js";
import { approvedActionContext } from "./format.js";
import {
	type PostToolInputProgress,
	readPostToolStdin,
	resolvePostToolInputLimit,
	toolNameFromInputPrefix,
} from "./hook-input.js";
import {
	postToolInspectionUnavailable,
	scanCachedProvisionedToolResponse,
	type ToolResponseScan,
	toolResponseInspectionResult,
} from "./output-inspection.js";
import {
	appendPostToolContext,
	quarantineFailedToolInspection,
	quarantineInspectedToolOutput,
} from "./tool-output-quarantine.js";

const logger: Logger = pino({ level: "warn" }, pino.destination(2));

/**
 * What is known about the current result, for answers given before (or
 * instead of) a completed inspection: the deadline, malformed input and
 * internal errors must still withhold the output, never only annotate it.
 */
const current: {
	/** Leading input bytes, so an incomplete read still names its tool. */
	input: PostToolInputProgress;
	toolName?: string;
	toolResponse?: unknown;
	/** The final answer once inspection finished; `undefined` until then. */
	inspected?: Record<string, unknown>;
} = { input: { prefix: "" } };

/** Answer for a run that did not complete: its settled verdict, else a fail-closed one. */
function reportIncompleteRun(reason: string): void {
	if (current.inspected) {
		process.stdout.write(`${JSON.stringify(current.inspected)}\n`);
	} else {
		reportUnavailableCoverage(reason);
	}
}

function reportUnavailableCoverage(reason: string): void {
	const answer = quarantineInspectedToolOutput(
		postToolInspectionUnavailable(reason),
		current.toolResponse,
		current.toolName ?? toolNameFromInputPrefix(current.input.prefix),
	);
	process.stdout.write(`${JSON.stringify(answer)}\n`);
}

async function main(): Promise<void> {
	await verifyArtifactIntegrityAndLog({
		artifactDir: __dirname,
		artifactId: "claude-code/dist",
		logger,
	});

	const maxInputBytes = resolvePostToolInputLimit(process.env);
	let input: Awaited<ReturnType<typeof readPostToolStdin>>;
	try {
		input = await readPostToolStdin(maxInputBytes, process.stdin, current.input);
	} catch {
		reportUnavailableCoverage("Could not read PostToolUse input.");
		return;
	}
	if (input.status === "oversized") {
		reportUnavailableCoverage(
			`PostToolUse input exceeded the ${maxInputBytes}-byte processing limit.`,
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
	const toolName = typeof hookInput.tool_name === "string" ? hookInput.tool_name : undefined;
	current.toolName = toolName;
	current.toolResponse = hookInput.tool_response;
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
	let approvalContext: string | null = null;
	if (toolUseId) {
		try {
			const entry = await consumePendingApproval(sessionId, toolUseId, logger);
			if (entry) approvalContext = approvedActionContext(entry);
		} catch {
			// Approval bookkeeping must not discard an output quarantine.
		}
	}
	let inspection: Record<string, unknown> | null;
	let scan: ToolResponseScan | null = null;
	try {
		// Warm signed output-policy trust, then inspect and replace the current
		// payload in the same turn after all async work.
		await scanProvisionedOutput([], "claude-code");
		// An empty response still passes the signed scanner, so unavailable
		// policy trust is never skipped as "nothing to inspect".
		scan = scanCachedProvisionedToolResponse(hookInput.tool_response);
		inspection = quarantineInspectedToolOutput(
			toolResponseInspectionResult(scan),
			hookInput.tool_response,
			toolName,
		);
	} catch {
		inspection = quarantineFailedToolInspection(hookInput.tool_response, toolName);
	}
	// The verdict for the output is now settled: a later deadline answers with
	// it rather than with a blanket "unavailable".
	current.inspected = inspection ?? {};
	// The output scanner already blocks canary content; this adds the audit entry
	// and, in managed mode, the incident. Never changes the response.
	await recordToolOutputCanaries({
		sessionId,
		toolName: toolName ?? "unknown",
		toolOutput: hookInput.tool_response,
		agentRuntime: "claude-code",
		logger,
	});
	if (scan && scan.findings.length > 0) {
		// The output is already in Claude's context: record what it carried
		// (secrets, injection payloads) so the session's next calls are judged
		// with it. Never changes this hook's response and never throws.
		const toolInput = hookInput.tool_input;
		await recordToolOutputFlow(
			{
				sessionId,
				toolName: toolName ?? "unknown",
				toolInput:
					toolInput && typeof toolInput === "object" && !Array.isArray(toolInput)
						? (toolInput as Record<string, unknown>)
						: undefined,
				findings: scan.findings,
			},
			{ agentRuntime: "claude-code", logger },
		);
	}
	if (toolResultReportsFailure(hookInput.tool_response)) {
		// Runaway guard: the same call failing again and again with no file change
		// in between is a stuck loop; its next retry is paused for review.
		// Never changes this hook's response and never throws.
		const toolInput = hookInput.tool_input;
		await recordToolOutcome(
			{
				sessionId,
				toolName: toolName ?? "unknown",
				toolInput:
					toolInput && typeof toolInput === "object" && !Array.isArray(toolInput)
						? (toolInput as Record<string, unknown>)
						: {},
				failed: true,
			},
			{ agentRuntime: "claude-code", logger },
		);
	}
	// File quarantine (opt-in, `response.quarantine.enabled`): a file this call
	// wrote or downloaded that the content scan classifies as malicious is moved
	// into the quarantine vault, and Claude is told it is gone. Never throws.
	const toolInputForQuarantine = hookInput.tool_input;
	const fileQuarantine = await quarantineAgentWrittenFiles({
		sessionId,
		toolName: toolName ?? "unknown",
		toolInput:
			toolInputForQuarantine &&
			typeof toolInputForQuarantine === "object" &&
			!Array.isArray(toolInputForQuarantine)
				? (toolInputForQuarantine as Record<string, unknown>)
				: {},
		workingDirectory: typeof hookInput.cwd === "string" ? hookInput.cwd : undefined,
		agentRuntime: "claude-code",
		threatsDir: resolveAssetDir("threats"),
		logger,
	});
	let response: Record<string, unknown> = inspection ?? {};
	if (approvalContext) response = appendPostToolContext(response, approvalContext);
	if (fileQuarantine.agentNotice) {
		response = appendPostToolContext(response, fileQuarantine.agentNotice);
	}
	// The watchdog already answered; never append a second response.
	if (answered) return;
	process.stdout.write(`${JSON.stringify(response)}\n`);
}

/**
 * Watchdog below the host's 5 s PostToolUse timeout: an inspection that has
 * not answered by then withholds the output (never a clean result) instead of
 * being killed silently; one that already finished answers with its verdict.
 * `AIDR_POST_TOOL_USE_DEADLINE_MS` overrides it.
 */
let answered = false;
const watchdog = setTimeout(
	() => {
		if (answered) return;
		answered = true;
		reportIncompleteRun("PostToolUse inspection did not finish in time.");
		exitAfterStdoutFlush(0);
	},
	resolveHookDeadlineMs(
		{ envVar: "AIDR_POST_TOOL_USE_DEADLINE_MS", hostTimeoutMs: 5_000, defaultMs: 4_000 },
		process.env,
	),
);

main()
	.catch(() => {
		if (!answered) reportIncompleteRun("Failed while processing PostToolUse input.");
	})
	.finally(() => {
		if (answered) return;
		answered = true;
		clearTimeout(watchdog);
		// Exit once the answer is flushed; pending handles must not outlive it.
		exitAfterStdoutFlush(0);
	});
