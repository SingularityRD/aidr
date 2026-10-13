/**
 * Host-format fail-closed answers shared by the hook runner (`aidr-hook.ts`)
 * and the stable hook launcher (`hook-launcher.ts`). Kept free of core and
 * `vscode` imports so the launcher bundle stays a few kilobytes.
 */

export type ExtensionHookHost = "cursor" | "vscode";

export function internalCursorResponse(
	decision: "allow" | "deny",
	reason: string,
): Record<string, unknown> {
	return {
		decision,
		permission: decision,
		reason,
		user_message: reason,
		agent_message:
			decision === "allow" ? undefined : "Singularity AIDR internal error policy applied.",
	};
}

export function internalVsCodeResponse(reason: string): Record<string, unknown> {
	return {
		hookSpecificOutput: {
			hookEventName: "PreToolUse",
			permissionDecision: "deny",
			permissionDecisionReason: reason,
		},
	};
}

/**
 * Block for a run whose event is unknown or unanswered: it denies a tool call
 * and, through the prompt-event stop fields (`continue: false`), also stops a
 * prompt submission.
 */
export function unansweredBlock(
	host: ExtensionHookHost | string | undefined,
	reason: string,
): Record<string, unknown> {
	return host === "vscode"
		? { ...internalVsCodeResponse(reason), continue: false, stopReason: reason }
		: { ...internalCursorResponse("deny", reason), continue: false };
}
