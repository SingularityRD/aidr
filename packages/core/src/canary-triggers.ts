/**
 * Canary triggers seen outside the pre-execution tool check, shared by every
 * connector: a user prompt that carries a decoy value, and tool output that
 * contains one. Both are recorded through {@link recordCanaryTrigger} (audit
 * entry, and in managed mode an incident through the control-plane ingest
 * path). Records name canary ids only; the token value, the prompt and the
 * tool output never enter them.
 *
 * Canary detection is a detection-internal signal: a registry that cannot be
 * read is logged and skipped, and the caller's other layers still decide.
 */

import {
	type CanaryHit,
	findCanaryTokens,
	inspectValueForCanaryTokens,
	loadCanaryIndex,
} from "./canary/detect.js";
import { recordCanaryTrigger } from "./evaluator.js";
import type { AgentRuntime, Config, Logger } from "./types.js";
import { nullLogger } from "./types.js";

/** Shown to the user for a blocked prompt; names no value and no path. */
export const CANARY_PROMPT_BLOCK_MESSAGE =
	"🛡️ Singularity AIDR blocked this prompt before it reached the model: it contains a canary credential planted by Singularity AIDR. Decoy credentials are never needed for real work; if this text came from a file, page or tool output, treat that source as untrusted.";

/** `triggered` hits were recorded; `unavailable` means the check was skipped (logged). */
export type CanaryCheckStatus = "absent" | "clear" | "triggered" | "unavailable";

/**
 * Check a user prompt for canary token values. A hit is recorded as a
 * `user_prompt` canary trigger (audit entry, managed incident); the caller
 * blocks the prompt with {@link CANARY_PROMPT_BLOCK_MESSAGE}. Never throws.
 */
export async function checkPromptForCanaries(params: {
	sessionId: string;
	/** Host event name, recorded as the audit entry's tool name. */
	hookEvent: string;
	prompt: string;
	agentRuntime: AgentRuntime;
	config?: Config;
	logger?: Logger;
}): Promise<CanaryCheckStatus> {
	const logger = params.logger ?? nullLogger;
	let hits: CanaryHit[];
	try {
		const index = loadCanaryIndex();
		if (index.status === "absent") return "absent";
		if (index.status === "unavailable") {
			logger.warn("Canary check of the prompt unavailable; signal skipped", {
				reason: index.reason,
			});
			return "unavailable";
		}
		hits = findCanaryTokens(params.prompt, index);
	} catch {
		logger.warn("Canary check of the prompt unavailable; signal skipped");
		return "unavailable";
	}
	if (hits.length === 0) return "clear";
	await recordCanaryTrigger({
		sessionId: params.sessionId,
		toolName: params.hookEvent,
		hits,
		stage: "user_prompt",
		config: params.config,
		logger,
		agentRuntime: params.agentRuntime,
	});
	return "triggered";
}

/**
 * Check a completed tool's output for canary token values and record a hit as
 * a `tool_output` canary trigger. The connector's output inspection already
 * quarantines such output (finding `OUT-CANARY-001`); this adds the audit entry
 * and the managed incident. Observation only; never throws.
 */
export async function recordToolOutputCanaries(params: {
	sessionId: string;
	toolName: string;
	/** The tool result as the host reports it (any JSON-like value). */
	toolOutput: unknown;
	agentRuntime: AgentRuntime;
	configPath?: string;
	logger?: Logger;
}): Promise<CanaryCheckStatus> {
	const logger = params.logger ?? nullLogger;
	try {
		const inspection = inspectValueForCanaryTokens(params.toolOutput);
		if (inspection.status === "unavailable") {
			logger.warn("Canary check of tool output unavailable; signal skipped", {
				reason: inspection.reason,
			});
			return "unavailable";
		}
		if (inspection.status !== "triggered") return inspection.status;
		await recordCanaryTrigger({
			sessionId: params.sessionId,
			toolName: params.toolName,
			hits: inspection.hits,
			stage: "tool_output",
			configPath: params.configPath,
			logger,
			agentRuntime: params.agentRuntime,
		});
		return "triggered";
	} catch {
		// Recording is best effort; the output inspection's block stands.
		return "unavailable";
	}
}
