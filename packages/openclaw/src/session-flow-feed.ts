import { type Logger, recordToolOutputFlow } from "@singularityrd/aidr-core";
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
