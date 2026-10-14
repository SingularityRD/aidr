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
	checkDashboardDecisions,
	detectUnprotectedAiTools,
	formatDashboardDecisionNotices,
	inspectUserPrompt,
	isInvalidConfig,
	type Logger,
	loadConfig,
	type PromptInspectionOutcome,
	resolvePath,
	resolvePromptInspectionDeadlineMs,
	takeFirstRunPrivacyNotice,
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

/**
 * What the developer must be told on the next prompt, for the user only
 * (`systemMessage`, never the model's context): the first-run privacy notice
 * (Codex has no session-start hook, so the first prompt carries it) and
 * dashboard approval decisions that landed since. Bounded; never throws.
 */
export async function codexPromptNotices(options: {
	logger?: Logger;
	aidrDir?: string;
	unprotectedTools?: string[];
}): Promise<string | null> {
	try {
		const config = await loadConfig(undefined, options.logger);
		if (!config || isInvalidConfig(config)) return null;
		const tools =
			options.unprotectedTools ??
			detectUnprotectedAiTools({ home: resolvePath("~"), env: process.env }).map(
				(tool) => tool.label,
			);
		const notice = await takeFirstRunPrivacyNotice(config, "codex", {
			aidrDir: options.aidrDir,
			unprotectedTools: tools,
		});
		const decisions = formatDashboardDecisionNotices(
			await checkDashboardDecisions(config, {
				logger: options.logger,
				totalBudgetMs: 1_500,
				requestTimeoutMs: 1_500,
			}),
		);
		const lines = [decisions, notice].filter((line): line is string => Boolean(line));
		return lines.length > 0 ? lines.join("\n") : null;
	} catch {
		return null;
	}
}

/** Add a user-only notice to an allow or warn answer; a block is left as it is. */
export function withUserNotice(
	wire: CodexPromptWireOutput | null,
	notice: string | null,
): CodexPromptWireOutput | null {
	if (!notice || wire?.decision === "block") return wire;
	if (!wire) return { systemMessage: notice };
	return {
		...wire,
		systemMessage: wire.systemMessage ? `${wire.systemMessage}\n${notice}` : notice,
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
