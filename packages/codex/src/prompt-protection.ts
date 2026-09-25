/**
 * Codex `UserPromptSubmit` prompt protection.
 *
 * Codex 0.141.0 runs `UserPromptSubmit` command hooks before the prompt starts a
 * turn (`codex-rs/hooks/src/events/user_prompt_submit.rs@rust-v0.141.0`). The
 * handler's output contract is Claude-Code-shaped:
 *   - block: `{"decision":"block","reason":…}` (non-empty reason) stops the turn;
 *     `exit 2` with non-empty stderr blocks too. A block without a reason fails.
 *   - warn:  `systemMessage` (shown to the user as a warning) plus
 *     `hookSpecificOutput.additionalContext` (given to the model).
 *   - allow: empty stdout.
 * Every other failure (crash, timeout, malformed output, an untrusted hook) lets
 * the prompt through: Codex fails open, so this connector always answers with
 * one of the shapes above and never with an empty reason.
 *
 * The inspection itself is the shared core runner (`inspectUserPrompt`): secrets
 * block and personal data warns by default (`prompt_protection`), a provisioned
 * tenant DLP policy applies, and an uninspectable or late prompt is blocked when
 * secrets are in `block` mode.
 */

import {
	inspectUserPrompt,
	type Logger,
	type PromptInspectionOutcome,
	resolvePromptInspectionDeadlineMs,
} from "@singularityrd/aidr-core";

export const CODEX_USER_PROMPT_SUBMIT = "UserPromptSubmit" as const;

/**
 * Codex kills the hook at its configured `timeout` and then sends the prompt, so
 * the hook answers itself first. The documented registration uses `timeout = 10`;
 * `AIDR_PROMPT_INSPECTION_DEADLINE_MS` may override the deadline within [100, 9000].
 */
const DEFAULT_CODEX_PROMPT_DEADLINE_MS = 7_000;
const MAX_CODEX_PROMPT_DEADLINE_MS = 9_000;

/** UserPromptSubmit output (`user-prompt-submit.command.output.schema.json`). */
export interface CodexPromptWireOutput {
	decision?: "block";
	reason?: string;
	systemMessage?: string;
	hookSpecificOutput?: {
		hookEventName: typeof CODEX_USER_PROMPT_SUBMIT;
		additionalContext: string;
	};
}

export interface CodexPromptProtectionResult {
	outcome: PromptInspectionOutcome;
	/** `null` for an allow: Codex's no-op is empty stdout. */
	wire: CodexPromptWireOutput | null;
}

export function toCodexPromptWire(outcome: PromptInspectionOutcome): CodexPromptWireOutput | null {
	if (outcome.decision === "allow") return null;
	if (outcome.decision === "block") return { decision: "block", reason: outcome.userMessage };
	return {
		systemMessage: outcome.userMessage,
		hookSpecificOutput: {
			hookEventName: CODEX_USER_PROMPT_SUBMIT,
			additionalContext: outcome.modelContext,
		},
	};
}

export async function enforceCodexUserPromptSubmit(
	input: Record<string, unknown>,
	options: { startedAt: number; logger?: Logger; env?: Record<string, string | undefined> },
): Promise<CodexPromptProtectionResult> {
	const deadlineMs = resolvePromptInspectionDeadlineMs(
		options.env ?? process.env,
		DEFAULT_CODEX_PROMPT_DEADLINE_MS,
		MAX_CODEX_PROMPT_DEADLINE_MS,
	);
	const outcome = await inspectUserPrompt({
		runtime: "codex",
		hookEvent: CODEX_USER_PROMPT_SUBMIT,
		sessionId: typeof input.session_id === "string" ? input.session_id : "codex",
		prompt: input.prompt,
		deadlineAt: options.startedAt + deadlineMs,
		...(options.logger ? { logger: options.logger } : {}),
	});
	return { outcome, wire: toCodexPromptWire(outcome) };
}
