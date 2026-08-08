import { normalizeCodexHookInput } from "./normalize.js";
import { CentralPolicyClient, type CentralPolicyClientOptions } from "./policy.js";
import {
	type CodexHookInput,
	type CodexHookResult,
	CodexNormalizationError,
	type CodexRuntimeIdentity,
	type PolicyHandoff,
} from "./types.js";
export interface CodexInstrumentationOptions {
	identity: CodexRuntimeIdentity;
	policy: PolicyHandoff | CentralPolicyClientOptions;
}
function deny(reasonCode: string, event: CodexHookResult["event"] = null): CodexHookResult {
	return { decision: "deny", reasonCode, decisionId: `fail-closed-${reasonCode}`, event };
}
export function createCodexInstrumentation(options: CodexInstrumentationOptions) {
	const policy =
		"decide" in options.policy ? options.policy : new CentralPolicyClient(options.policy);
	return {
		async preToolUse(input: CodexHookInput): Promise<CodexHookResult> {
			let event: CodexHookResult["event"] = null;
			try {
				event = normalizeCodexHookInput({ ...input, phase: "pre_tool_use" }, options.identity);
				const decision = await policy.decide(event);
				return { ...decision, event };
			} catch (error) {
				return deny(
					error instanceof CodexNormalizationError
						? "codex_input_malformed"
						: "central_policy_unavailable",
					event,
				);
			}
		},
		async postToolUse(input: CodexHookInput): Promise<CodexHookResult> {
			try {
				const event = normalizeCodexHookInput(
					{ ...input, phase: "post_tool_use" },
					options.identity,
				);
				const published = await policy.publish(event);
				return published.accepted
					? {
							decision: "allow",
							reasonCode: "observation_published",
							decisionId: `observation-${event.eventId}`,
							event,
						}
					: deny(published.reasonCode, event);
			} catch (error) {
				return deny(
					error instanceof CodexNormalizationError
						? "codex_input_malformed"
						: "central_event_unavailable",
				);
			}
		},
	};
}
