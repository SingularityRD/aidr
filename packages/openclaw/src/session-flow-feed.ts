import {
	type Logger,
	recordToolOutcome,
	recordToolOutputCanaries,
	recordToolOutputFlow,
} from "@singularityrd/aidr-core";
import type { OutputInspection } from "./output-inspection.js";
import type {
	AfterToolCallEvent,
	OutputHookContext,
	ToolResultMiddlewareContext,
	ToolResultMiddlewareEvent,
} from "./output-protection.js";

/**
 * Feed a completed tool's inspection findings into the session's toxic-flow
 * record (docs/toxic-flow.md). The session key matches `before_tool_call`
 * (`ctx.sessionKey`), so the next call in the same OpenClaw session is judged
 * with the secrets or injection payloads this output carried.
 *
 * Observation only: the tool already ran, and output protection decides what
 * happens to the output itself. Never throws.
 */
export async function feedToolOutputFlow(
	event: AfterToolCallEvent,
	context: OutputHookContext | undefined,
	inspection: OutputInspection,
	logger: Logger,
): Promise<void> {
	if (inspection.findings.length === 0) return;
	try {
		await recordToolOutputFlow(
			{
				sessionId: context?.sessionKey ?? "unknown",
				toolName: typeof event?.toolName === "string" ? event.toolName : "unknown",
				toolInput:
					event?.params && typeof event.params === "object" && !Array.isArray(event.params)
						? event.params
						: undefined,
				findings: inspection.findings,
			},
			{ agentRuntime: "openclaw", logger },
		);
	} catch {
		// recordToolOutputFlow never throws; a hostile event shape must not either.
	}
}

/**
 * Record a canary credential value in a completed tool's output (docs/canary-tokens.md):
 * audit entry and, in managed mode, an incident. Output protection already
 * quarantines such output (finding `OUT-CANARY-001`). Observation only; never throws.
 */
export async function feedToolOutputCanaries(
	event: AfterToolCallEvent,
	context: OutputHookContext | undefined,
	logger: Logger,
): Promise<void> {
	if (event?.result === undefined) return;
	try {
		await recordToolOutputCanaries({
			sessionId: context?.sessionKey ?? "unknown",
			toolName: typeof event.toolName === "string" ? event.toolName : "unknown",
			toolOutput: event.result,
			agentRuntime: "openclaw",
			logger,
		});
	} catch {
		// recordToolOutputCanaries never throws; a hostile event shape must not either.
	}
}

/**
 * Feed the flow and canary records from a tool result that the pre-model
 * middleware quarantined. `after_tool_call` then only sees AIDR's notice, so the
 * original output is recorded here, once. Never throws.
 */
export async function feedQuarantinedOutput(
	event: ToolResultMiddlewareEvent,
	context: ToolResultMiddlewareContext | undefined,
	inspection: OutputInspection | undefined,
	logger: Logger,
): Promise<void> {
	try {
		const observed: AfterToolCallEvent = {
			toolName: typeof event?.toolName === "string" ? event.toolName : "unknown",
			params:
				event?.args && typeof event.args === "object" && !Array.isArray(event.args)
					? event.args
					: {},
			toolCallId: typeof event?.toolCallId === "string" ? event.toolCallId : undefined,
			runId: context?.runId,
			result: event?.result?.content,
		};
		const hookContext: OutputHookContext = {
			sessionKey: context?.sessionKey,
			sessionId: context?.sessionId,
			runId: context?.runId,
		};
		if (inspection) await feedToolOutputFlow(observed, hookContext, inspection, logger);
		await feedToolOutputCanaries(observed, hookContext, logger);
	} catch {
		// Recording is best effort; the quarantine itself has already been decided.
	}
}

/**
 * Report a failed tool call to the runaway guard (docs/agent-safety.md), so a
 * command that keeps failing unchanged is paused for review on its next retry.
 * OpenClaw reports failures as `event.error`. Observation only; never throws.
 */
export async function feedToolOutcome(
	event: AfterToolCallEvent,
	context: OutputHookContext | undefined,
	logger: Logger,
): Promise<void> {
	if (typeof event?.error !== "string" || event.error.trim() === "") return;
	try {
		await recordToolOutcome(
			{
				sessionId: context?.sessionKey ?? "unknown",
				toolName: typeof event.toolName === "string" ? event.toolName : "unknown",
				toolInput:
					event.params && typeof event.params === "object" && !Array.isArray(event.params)
						? event.params
						: {},
				failed: true,
			},
			{ agentRuntime: "openclaw", logger },
		);
	} catch {
		// recordToolOutcome never throws; a hostile event shape must not either.
	}
}
