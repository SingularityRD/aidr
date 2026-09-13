/**
 * Shared fail-closed enforcement of AIDR check results.
 *
 * ── Semantic (applies to EVERY SDK adapter and middleware) ──────────────────
 *
 * A wrapped function/tool/agent-message may execute ONLY when the AIDR check
 * returns `decision: "allow"`. Everything else is treated as "do not execute":
 *
 *   deny        → never executed, and never approvable.
 *   ask         → executed only if the caller configured an `onAsk` approval
 *                 callback AND that callback explicitly returns true.
 *                 Without an `onAsk` callback the action is blocked.
 *   indeterminate (the security check itself failed after all retries, or the
 *                 result object is internally inconsistent, e.g.
 *                 `allowed: true` with `decision: "ask"`) → blocked, and NOT
 *                 approvable by default. A failed check carries no security
 *                 signal at all, so it must not be converted into an approval
 *                 by a y/n prompt. Callers that accept that risk can opt in
 *                 with `allowApprovalOfIndeterminateResults: true`, which
 *                 routes the result to `onAsk` like a normal `ask`.
 *
 * The SDK never synthesizes an approval and never invents an `allow` verdict.
 * `onAsk` is always caller-supplied: it is the caller's job to route it to a
 * real human (CLI prompt, host UI, ticket queue, ...). If no such out-of-band
 * channel exists, the action stays blocked.
 */

import type { CheckResult } from "./config.js";

/**
 * Caller-supplied human-approval callback.
 *
 * Return `true` only for explicit human approval. Returning `false`, throwing,
 * or returning any other value keeps the action blocked.
 */
export type ApprovalCallback = (result: CheckResult) => Promise<boolean> | boolean;

/**
 * Enforcement options shared by all SDK adapters and middleware.
 */
export interface EnforcementOptions {
	/** Human-approval callback used for `ask` verdicts. Omit to always block. */
	onAsk?: ApprovalCallback;
	/**
	 * Allow an indeterminate result (failed check / inconsistent result) to be
	 * routed to `onAsk`. Defaults to `false`: a broken security check can never
	 * be turned into an approval, not even by a human prompt.
	 */
	allowApprovalOfIndeterminateResults?: boolean;
}

/** Why an action was not executed. */
export type EnforcementBlock = "deny" | "ask-denied" | "ask-unavailable" | "indeterminate";

/** Result of enforcing a check result. */
export type EnforcementOutcome =
	| { execute: true }
	| { execute: false; block: EnforcementBlock; message: string };

/** Metadata key the client sets on the fail-closed fallback result. */
export const INDETERMINATE_METADATA_KEY = "indeterminate";

export const DENY_MESSAGE_PREFIX = "Security check denied";
export const ASK_REQUIRES_APPROVAL_MESSAGE =
	'Singularity AIDR: this action requires explicit human approval (verdict "ask") and no approval callback is configured; it was NOT executed.';
export const ASK_DENIED_MESSAGE =
	'Singularity AIDR: human approval for this action (verdict "ask") was not granted; it was NOT executed.';
export const INDETERMINATE_MESSAGE =
	"Singularity AIDR: the security check could not be completed, so this action is indeterminate and was NOT executed.";
export const INCONSISTENT_MESSAGE =
	"Singularity AIDR: the security check returned an inconsistent result and was NOT executed.";

function withReason(message: string, result: CheckResult): string {
	const reason = result.reason?.trim();
	return reason ? `${message} Reason: ${reason}` : message;
}

/**
 * True when the result marks the check itself as failed/unresolved
 * (the client sets this after exhausting retries).
 */
export function isIndeterminate(result: CheckResult): boolean {
	return result.metadata?.[INDETERMINATE_METADATA_KEY] === true;
}

/**
 * True when `allowed` and `decision` disagree. Such a result cannot be trusted
 * to authorize execution regardless of which field a caller happens to read.
 */
export function isInconsistent(result: CheckResult): boolean {
	return result.allowed !== (result.decision === "allow");
}

/**
 * Decide whether an action may execute for a given check result.
 *
 * Never returns `execute: true` for anything other than an explicit `allow`
 * (or an explicit human approval of a non-indeterminate `ask`).
 */
export async function enforceCheckResult(
	result: CheckResult,
	options: EnforcementOptions = {},
): Promise<EnforcementOutcome> {
	if (isInconsistent(result)) {
		return {
			execute: false,
			block: "indeterminate",
			message: withReason(
				`${INCONSISTENT_MESSAGE} (allowed=${String(result.allowed)}, decision="${result.decision}")`,
				result,
			),
		};
	}

	if (result.decision === "allow") {
		return { execute: true };
	}

	if (result.decision === "deny") {
		return {
			execute: false,
			block: "deny",
			message: `${DENY_MESSAGE_PREFIX}: ${result.reason || "Unknown threat"}`,
		};
	}

	// decision === "ask"
	const indeterminate = isIndeterminate(result);
	if (indeterminate && options.allowApprovalOfIndeterminateResults !== true) {
		return {
			execute: false,
			block: "indeterminate",
			message: withReason(INDETERMINATE_MESSAGE, result),
		};
	}

	if (!options.onAsk) {
		return {
			execute: false,
			block: indeterminate ? "indeterminate" : "ask-unavailable",
			message: withReason(
				indeterminate ? INDETERMINATE_MESSAGE : ASK_REQUIRES_APPROVAL_MESSAGE,
				result,
			),
		};
	}

	const approved = await options.onAsk(result);
	if (approved !== true) {
		return {
			execute: false,
			block: indeterminate ? "indeterminate" : "ask-denied",
			message: withReason(ASK_DENIED_MESSAGE, result),
		};
	}

	return { execute: true };
}
