import { type Logger, recordToolOutcome, recordToolOutputFlow } from "@singularityrd/aidr-core";
import type { OutputInspection } from "./output-inspection.js";
import type { AfterToolCallEvent, OutputHookContext } from "./output-protection.js";

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
