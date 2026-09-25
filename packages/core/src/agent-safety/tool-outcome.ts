/**
 * Did a host report a completed tool call as failed? Feeds the runaway guard's
 * repeated-failure signal (`recordToolOutcome`).
 *
 * Conservative on purpose: only explicit failure markers count, namely
 * `is_error: true` / `isError: true`, or a numeric `exit_code` / `exitCode`
 * other than 0. Hosts that report the result as a JSON-encoded string (Cursor's
 * `tool_output`) are decoded first, within a size bound. Anything else, including
 * an unknown shape, is not a failure, so the signal can only under-count, never
 * invent a loop.
 */

/** Largest JSON-encoded result that is decoded to look for a failure marker. */
const MAX_DECODED_RESULT_CHARS = 1024 * 1024;

function markersFail(result: Record<string, unknown>): boolean {
	if (result.is_error === true || result.isError === true) return true;
	const exitCode = result.exit_code ?? result.exitCode;
	return typeof exitCode === "number" && Number.isFinite(exitCode) && exitCode !== 0;
}

export function toolResultReportsFailure(result: unknown): boolean {
	let value = result;
	if (typeof value === "string") {
		const text = value.trim();
		if (!text.startsWith("{") || text.length > MAX_DECODED_RESULT_CHARS) return false;
		try {
			value = JSON.parse(text);
		} catch {
			return false;
		}
	}
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	try {
		return markersFail(value as Record<string, unknown>);
	} catch {
		// A hostile getter is not a reported failure.
		return false;
	}
}
