/**
 * Read the human-readable message out of a failure.
 *
 * PostgREST failures (`{ message, code, details, hint }`) and Supabase Edge
 * Function failures are plain objects, not `Error` instances, so the common
 * `err instanceof Error ? err.message : "…"` pattern discards the only
 * actionable text and shows a generic fallback instead. Callers must still
 * pass a fallback: an error whose text cannot be recovered must never be
 * reported as a success.
 */
export function readErrorMessage(cause: unknown, fallback: string): string {
	if (cause instanceof Error && cause.message) return cause.message;
	if (cause && typeof cause === "object" && "message" in cause) {
		const message = (cause as { message?: unknown }).message;
		if (typeof message === "string" && message.trim().length > 0) return message;
	}
	return fallback;
}
