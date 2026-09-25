/**
 * Did a Claude Code tool call fail? Conservative on purpose: only the explicit
 * failure markers of the built-in tool results count — a Bash `exit_code` other
 * than 0, or `is_error: true`. Anything else (including an unknown shape) is not
 * a recorded failure, so the runaway guard's repeated-failure signal can only
 * under-count, never invent a loop.
 */
export function toolResponseFailed(toolResponse: unknown): boolean {
	if (!toolResponse || typeof toolResponse !== "object" || Array.isArray(toolResponse)) {
		return false;
	}
	const response = toolResponse as Record<string, unknown>;
	if (response.is_error === true) return true;
	const exitCode = response.exit_code ?? response.exitCode;
	return typeof exitCode === "number" && Number.isFinite(exitCode) && exitCode !== 0;
}
