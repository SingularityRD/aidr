import * as Sentry from "@sentry/browser";

const REDACTED = "[Redacted]";
const SENSITIVE_KEY_RE =
	/(?:api[_-]?key|access[_-]?token|auth(?:orization)?|bearer|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|signature|sig|token|client[_-]?secret|invite|grant|state|dsn|prompt|tool[_-]?input|tool[_-]?output|completion|response[_-]?body|request[_-]?body|content)/i;
const BEARER_RE = /(\bBearer\s+)[^\s,;"']+/gi;
const KEY_VALUE_RE =
	/(\b(?:api[_-]?key|x-api-key|access[_-]?token|auth(?:orization|[_-]?token)?|client[_-]?secret|cookie|password|passwd|private[_-]?key|refresh[_-]?token|id[_-]?token|secret|session[_-]?token|signature|sig|token)\b\s*[:=]\s*)(["']?)([^\s,;&"']+)\2/gi;
const URL_CREDENTIAL_RE = /(https?:\/\/)([^\s/@:]+):([^\s/@]+)@/gi;
const URL_SECRET_QUERY_RE =
	/([?&#](?:api[_-]?key|x-api-key|access[_-]?token|auth(?:orization|[_-]?token)?|code|client[_-]?secret|password|passwd|refresh[_-]?token|id[_-]?token|invite(?:[_-]?token)?|grant(?:[_-]?id)?|state|secret|session[_-]?token|signature|sig|token(?:[_-]?hash)?)\s*=)[^&#\s]*/gi;
const KNOWN_SECRET_RE =
	/\b(?:sk-[a-zA-Z0-9]{16,}|sk_live_[a-zA-Z0-9_-]{12,}|ghp_[a-zA-Z0-9]{20,}|github_pat_[a-zA-Z0-9_]{20,}|xox[baprs]-[a-zA-Z0-9-]{12,}|npm_[a-zA-Z0-9]{12,}|pypi-[a-zA-Z0-9_-]{12,}|AKIA[0-9A-Z]{16})\b/g;
const ABSOLUTE_URL_DETAILS_RE = /(https?:\/\/[^\s?#"']+)[?#][^\s"']*/gi;
const RELATIVE_URL_DETAILS_RE = /((?:\/|\.\/)[^\s?#"'()]*)[?#][^\s"'()]*/g;

export function redactSentryString(value: string, maxLength = 2000): string {
	const safe = value
		.replace(ABSOLUTE_URL_DETAILS_RE, "$1")
		.replace(RELATIVE_URL_DETAILS_RE, "$1")
		.replace(BEARER_RE, `$1${REDACTED}`)
		.replace(KEY_VALUE_RE, `$1${REDACTED}`)
		.replace(URL_CREDENTIAL_RE, `$1$2:${REDACTED}@`)
		.replace(URL_SECRET_QUERY_RE, `$1${REDACTED}`)
		.replace(KNOWN_SECRET_RE, REDACTED);
	return safe.length > maxLength ? `${safe.slice(0, maxLength)}…` : safe;
}

export function redactSentryUrl(value: string): string {
	const redacted = redactSentryString(value);
	try {
		const parsed = new URL(redacted);
		parsed.search = "";
		parsed.hash = "";
		return parsed.toString();
	} catch {
		return redacted.split(/[?#]/, 1)[0] ?? "";
	}
}

function redactData(value: unknown, depth = 0): unknown {
	if (typeof value === "string") return redactSentryString(value);
	if (!value || typeof value !== "object") return value;
	if (depth > 8) return REDACTED;
	if (Array.isArray(value)) return value.map((item) => redactData(item, depth + 1));
	const output: Record<string, unknown> = {};
	for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
		output[key] = SENSITIVE_KEY_RE.test(key) ? REDACTED : redactData(item, depth + 1);
	}
	return output;
}

export function redactSentryEvent<T extends Record<string, unknown>>(event: T): T {
	const safe = redactData(event) as T;
	const mutable = safe as Record<string, unknown>;
	if (typeof mutable.message === "string") mutable.message = redactSentryString(mutable.message);
	if (typeof mutable.transaction === "string") {
		mutable.transaction = redactSentryString(mutable.transaction, 200);
	}
	// sendDefaultPii=false does not remove identity manually attached by an SDK integration.
	delete mutable.user;
	const request = mutable.request;
	if (request && typeof request === "object" && !Array.isArray(request)) {
		const requestRecord = request as Record<string, unknown>;
		const publicRequest: Record<string, string> = {};
		if (
			typeof requestRecord.method === "string" &&
			/^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/.test(requestRecord.method)
		) {
			publicRequest.method = requestRecord.method;
		}
		if (typeof requestRecord.url === "string") {
			publicRequest.url = redactSentryUrl(requestRecord.url);
		}
		mutable.request = publicRequest;
	} else {
		delete mutable.request;
	}
	return safe;
}

function parseSampleRate(value: unknown, fallback: number): number {
	const parsed = Number.parseFloat(String(value ?? ""));
	return Number.isFinite(parsed) ? Math.max(0, Math.min(1, parsed)) : fallback;
}

export function initSentry(): void {
	const runtime = typeof window !== "undefined" ? window.__AIDR_CONFIG__ : undefined;
	const runtimeDsn = runtime?.sentryDsn;
	const dsn = String(
		runtimeDsn === undefined ? (import.meta.env.VITE_SENTRY_DSN ?? "") : (runtimeDsn ?? ""),
	).trim();
	if (!dsn) return;
	Sentry.init({
		dsn,
		environment:
			runtime?.sentryEnvironment ?? (import.meta.env.VITE_SENTRY_ENVIRONMENT || "development"),
		// Browser PII (cookies, IP, user-agent enrichment) is never required for
		// the demo dashboard. Keep traces opt-in and bounded by environment.
		sendDefaultPii: false,
		tracesSampleRate: parseSampleRate(
			runtime?.sentryTracesSampleRate ?? import.meta.env.VITE_SENTRY_TRACES_SAMPLE_RATE,
			0,
		),
		integrations: [Sentry.browserTracingIntegration()],
		beforeSend(event) {
			return redactSentryEvent(
				event as unknown as Record<string, unknown>,
			) as unknown as typeof event;
		},
		beforeSendTransaction(event) {
			return redactSentryEvent(
				event as unknown as Record<string, unknown>,
			) as unknown as typeof event;
		},
		beforeBreadcrumb(breadcrumb) {
			return redactData(breadcrumb) as typeof breadcrumb;
		},
	});
}
