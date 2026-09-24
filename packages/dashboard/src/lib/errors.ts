const PUBLIC_ERROR_CODE = /^[a-z][a-z0-9_]*(?::[a-z0-9_.-]+)*$/;
const PUBLIC_ERROR_WITH_STATUS = /^[a-z][a-z0-9_]*(?::[a-z0-9_.-]+)*(?: \([1-5]\d{2}\))$/;
const SENSITIVE_ERROR_DETAIL =
	/(?:https?:\/\/|\bBearer\s+|\b(?:code|state|secret|token|password|credential)\s*[:=]|permission denied for|schema cache|\bSQLSTATE\b|\bPGRST\d+)/i;

function isBackendError(cause: Error): boolean {
	return ["code", "context", "details", "hint", "status"].some((key) => key in cause);
}

/**
 * Return only an intentionally machine-readable public error code.
 *
 * Database, authentication and Edge Function error messages routinely contain
 * table names, policy details or request data. Those details belong in
 * redacted telemetry, not in the browser UI. Known snake-case response codes
 * remain actionable; everything else uses the caller's safe fallback.
 */
export function readErrorMessage(cause: unknown, fallback: string): string {
	let message: unknown;
	if (cause instanceof Error) {
		message = cause.message;
		const trimmed = cause.message.trim();
		if (
			!isBackendError(cause) &&
			trimmed.length > 0 &&
			trimmed.length <= 240 &&
			!/[\u0000-\u001f\u007f]/.test(trimmed) &&
			!SENSITIVE_ERROR_DETAIL.test(trimmed)
		) {
			return trimmed;
		}
	}
	if (cause && typeof cause === "object" && "message" in cause) {
		message = (cause as { message?: unknown }).message;
	}
	if (
		typeof message === "string" &&
		message.trim().length <= 160 &&
		(PUBLIC_ERROR_CODE.test(message.trim()) || PUBLIC_ERROR_WITH_STATUS.test(message.trim()))
	)
		return message.trim();
	return fallback;
}
