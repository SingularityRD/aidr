/**
 * Privacy boundary for diagnostics and telemetry.
 *
 * Detection needs the original tool input, but observability sinks do not.
 * Keep this module deliberately dependency-free so it can be used by the
 * local JSONL audit logger and Sentry integration alike.
 */

export const REDACTED_TELEMETRY_VALUE = "[Redacted]";

const SENSITIVE_KEY_RE =
	/(?:api[_-]?key|access[_-]?token|auth(?:orization)?|bearer|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|signature|sig|token|client[_-]?secret|invite|grant|state|dsn|prompt|tool[_-]?input(?![_-]?summary)|tool[_-]?output|completion|response[_-]?body|request[_-]?body|content)/i;

// Secrets commonly appear in free-form commands, exception messages and URL
// query strings rather than under an object key.  Keep these expressions
// conservative: they target known credential forms and do not redact ordinary
// URLs such as https://example.test/path.
const BEARER_RE = /(\bBearer\s+)[^\s,;"']+/gi;
// The optional prefix covers env-style names (ANTHROPIC_API_KEY, PGPASSWORD,
// GITHUB_TOKEN) where the leading word characters defeat a plain \b anchor.
const KEY_VALUE_RE =
	/(\b[A-Za-z0-9_-]*?(?:api[_-]?key|x-api-key|access[_-]?token|auth(?:orization|[_-]?token)?|client[_-]?secret|cookie|password|passwd|private[_-]?key|refresh[_-]?token|id[_-]?token|invite(?:[_-]?token)?|grant(?:[_-]?id)?|state|secret|session[_-]?token|signature|sig|token)\b\s*[:=]\s*)(["']?)([^\s,;&"']+)\2/gi;
// Database clients accept the password glued to the flag (mysql -pSECRET).
const DB_CLIENT_PASSWORD_RE =
	/(\b(?:mysql|mysqldump|mysqladmin|mariadb)\b[^\n|;&]*?\s-p)(["']?)([^\s"']+)\2/gi;
const URL_CREDENTIAL_RE = /(https?:\/\/)([^\s/@:]+):([^\s/@]+)@/gi;
const URL_SECRET_QUERY_RE =
	/([?&](?:api[_-]?key|x-api-key|access[_-]?token|auth(?:orization|[_-]?token)?|code|client[_-]?secret|password|passwd|refresh[_-]?token|id[_-]?token|invite(?:[_-]?token)?|grant(?:[_-]?id)?|state|secret|session[_-]?token|signature|sig|token)\s*=)[^&#\s]*/gi;
const JWT_RE = /\beyJ[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\.[a-zA-Z0-9_-]{8,}\b/g;
const KNOWN_SECRET_RE =
	/\b(?:sk-(?:ant-|proj-|svcacct-|admin-)?[a-zA-Z0-9_-]{16,}|hf_[a-zA-Z0-9]{30,}|glpat-[a-zA-Z0-9_-]{20,}|AIza[0-9A-Za-z_-]{35}|xai-[a-zA-Z0-9]{20,}|sk_live_[a-zA-Z0-9_-]{12,}|ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}|xox[baprs]-[a-zA-Z0-9-]{12,}|npm_[a-zA-Z0-9]{12,}|pypi-[a-zA-Z0-9_-]{12,}|AKIA[0-9A-Z]{16})\b/g;

/** Redact credential material embedded in an arbitrary string. */
export function redactTelemetryString(value: string, maxLength = 2000): string {
	let safe = value
		.replace(BEARER_RE, `$1${REDACTED_TELEMETRY_VALUE}`)
		.replace(KEY_VALUE_RE, `$1${REDACTED_TELEMETRY_VALUE}`)
		.replace(DB_CLIENT_PASSWORD_RE, `$1${REDACTED_TELEMETRY_VALUE}`)
		.replace(URL_CREDENTIAL_RE, `$1$2:${REDACTED_TELEMETRY_VALUE}@`)
		.replace(URL_SECRET_QUERY_RE, `$1${REDACTED_TELEMETRY_VALUE}`)
		.replace(KNOWN_SECRET_RE, REDACTED_TELEMETRY_VALUE)
		.replace(JWT_RE, REDACTED_TELEMETRY_VALUE);

	if (safe.length > maxLength) {
		safe = `${safe.slice(0, maxLength)}…`;
	}
	return safe;
}

/**
 * Recursively redact an object before it crosses an observability boundary.
 * The return value is a detached copy, so callers never mutate detection
 * inputs while preparing telemetry.
 */
function redactTelemetryNode(
	input: unknown,
	depth: number,
	maxDepth: number,
	active: WeakSet<object>,
): unknown {
	if (typeof input === "string") return redactTelemetryString(input);
	if (input === null || typeof input !== "object") return input;
	if (depth > maxDepth) return REDACTED_TELEMETRY_VALUE;

	const objectInput = input as object;
	if (active.has(objectInput)) return REDACTED_TELEMETRY_VALUE;
	active.add(objectInput);
	try {
		if (Array.isArray(input)) {
			return input.map((item) => redactTelemetryNode(item, depth + 1, maxDepth, active));
		}

		const output: Record<string, unknown> = {};
		for (const [key, item] of Object.entries(input as Record<string, unknown>)) {
			output[key] = SENSITIVE_KEY_RE.test(key)
				? REDACTED_TELEMETRY_VALUE
				: redactTelemetryNode(item, depth + 1, maxDepth, active);
		}
		return output;
	} finally {
		active.delete(objectInput);
	}
}

export function redactTelemetryData<T>(value: T, maxDepth = 8): T {
	return redactTelemetryNode(value, 0, maxDepth, new WeakSet<object>()) as T;
}

/** @deprecated Retained for public API compatibility. */
export function redactTelemetryAttributes(
	attributes: Record<string, string | number | boolean>,
): Record<string, string | number | boolean> {
	const safe: Record<string, string | number | boolean> = {};
	for (const [key, value] of Object.entries(attributes)) {
		safe[key] = SENSITIVE_KEY_RE.test(key)
			? REDACTED_TELEMETRY_VALUE
			: typeof value === "string"
				? redactTelemetryString(value, 500)
				: value;
	}
	return safe;
}

/** @deprecated Retained for public API compatibility. */
export function sanitizeTelemetryEndpoint(value: string | undefined): string | undefined {
	if (!value?.trim()) return undefined;
	try {
		const parsed = new URL(value.trim());
		if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return undefined;
		parsed.username = "";
		parsed.password = "";
		parsed.search = "";
		parsed.hash = "";
		return parsed.toString();
	} catch {
		return undefined;
	}
}
