export const MAX_INGEST_EVENTS = 200;
export const MAX_INGEST_EVENT_BYTES = 256 * 1024;
export const MAX_INGEST_BATCH_BYTES = 4 * 1024 * 1024;

const EVENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SENSITIVE_IDENTIFIER_PATTERN = /(?:^|[._:-])(?:api[_-]?key|access[_-]?token|authorization|bearer|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|client[_-]?secret|refresh[_-]?token|signature)(?:[._:-]|$)|^(?:sk[_-]|ghp_|github_pat_|xox[baprs]-|npm_|pypi-|AKIA)/i;
const PHONE_LIKE_IDENTIFIER_PATTERN = /^(?:\d[.:-]?){8,15}$/;
const EVENT_TYPES = new Set([
	"runtime_verdict",
	"incident",
	"plugin_scan",
	"plugin_scan_finding",
	"runtime_policy_cache",
]);
const DECISIONS = new Set(["allow", "ask", "deny"]);
const SEVERITIES = new Set(["info", "warning", "high", "critical"]);
const STATUSES = new Set(["open", "acknowledged", "contained", "resolved", "suppressed"]);
const RECOMMENDED_ACTIONS = new Set([
	"review",
	"investigate",
	"isolate",
	"revoke",
	"rotate_credentials",
	"notify",
]);
const REDACTED = "[Redacted]";

function safeIdentifier(value: unknown): string | undefined {
	return typeof value === "string" &&
		IDENTIFIER_PATTERN.test(value) &&
		!SENSITIVE_IDENTIFIER_PATTERN.test(value) &&
		!PHONE_LIKE_IDENTIFIER_PATTERN.test(value)
			? value
			: undefined;
}

function safeEnum(value: unknown, allowed: Set<string>): string | undefined {
	return typeof value === "string" && allowed.has(value) ? value : undefined;
}

function safeTimestamp(value: unknown): string | undefined {
	if (typeof value !== "string" || value.length > 40) return undefined;
	const timestamp = Date.parse(value);
	return Number.isFinite(timestamp) ? new Date(timestamp).toISOString() : undefined;
}

function safeBoundedCount(value: unknown): number | undefined {
	return typeof value === "number" && Number.isInteger(value) && value >= 0 && value <= 1_000_000
		? value
		: undefined;
}

function safeDigestOrMarker(value: unknown): string {
	// Raw commands, prompts, paths and domains are never stored, even when a
	// caller bypasses the runtime's privacy mode. Existing client-side digests
	// retain their correlation value without exposing the original text.
	return typeof value === "string" && HASH_PATTERN.test(value) ? value : REDACTED;
}

/**
 * Storage projection for an authenticated but untrusted telemetry client.
 * Keep this intentionally narrow: a generic recursive scrub cannot know
 * whether an unknown field contains an API key, prompt, personal data or a
 * nested copy of those values. Unknown fields are omitted, and the only
 * nested object we accept is the bounded runtime-policy-cache summary.
 */
function projectEvent(event: Record<string, unknown> & { event_id: string }) {
	const projected: Record<string, unknown> & { event_id: string } = {
		event_id: event.event_id,
		type: safeEnum(event.type, EVENT_TYPES) ?? "runtime_verdict",
	};
	const timestamp = safeTimestamp(event.timestamp);
	if (timestamp) projected.timestamp = timestamp;

	for (const key of ["session_id", "incident_id", "tool_name", "source", "matched_threat_id", "plugin_key"] as const) {
		const safe = safeIdentifier(event[key]);
		if (safe) projected[key] = safe;
	}
	for (const key of ["verdict", "decision"] as const) {
		const safe = safeEnum(event[key], DECISIONS);
		if (safe) projected[key] = safe;
	}
	const severity = safeEnum(event.severity, SEVERITIES);
	if (severity) projected.severity = severity;
	const status = safeEnum(event.status, STATUSES);
	if (status) projected.status = status;
	const findingsCount = safeBoundedCount(event.findings_count);
	if (findingsCount !== undefined) projected.findings_count = findingsCount;
	if (typeof event.user_override === "boolean") projected.user_override = event.user_override;

	if (event.tool_input_summary !== undefined) {
		projected.tool_input_summary = safeDigestOrMarker(event.tool_input_summary);
	}
	if (Array.isArray(event.artifacts)) {
		projected.artifacts = event.artifacts.slice(0, 32).map(safeDigestOrMarker);
	}
	if (Array.isArray(event.reasons)) projected.reasons = [];
	if (Array.isArray(event.recommended_actions)) {
		projected.recommended_actions = event.recommended_actions
			.slice(0, 16)
			.filter((action): action is string => typeof action === "string" && RECOMMENDED_ACTIONS.has(action));
	}

	if (event.runtime_policy_cache && typeof event.runtime_policy_cache === "object" && !Array.isArray(event.runtime_policy_cache)) {
		const cache = event.runtime_policy_cache as Record<string, unknown>;
		const summary: Record<string, unknown> = {};
		const source = safeIdentifier(cache.source);
		const version = safeIdentifier(cache.policy_version);
		if (source) summary.source = source;
		if (version) summary.policy_version = version;
		if (typeof cache.usable === "boolean") summary.usable = cache.usable;
		projected.runtime_policy_cache = summary;
	}
	return projected;
}

export type NormalizedIngestEvents =
	| { ok: true; events: Array<Record<string, unknown> & { event_id: string }> }
	| {
			ok: false;
			status: 400 | 413;
			error:
				| "events_batch_too_large"
				| "events_limit_exceeded"
				| "invalid_event"
				| "missing_event_id";
			detail?: string;
	  };

/**
 * Validate the delivery contract before registration or database writes.
 * Rejecting oversized input is intentional: silently slicing a batch makes the
 * caller believe records after the limit were accepted and loses telemetry.
 */
export function normalizeIngestEvents(value: unknown): NormalizedIngestEvents {
	if (value === undefined) return { ok: true, events: [] };
	if (!Array.isArray(value)) return { ok: false, status: 400, error: "invalid_event" };
	if (value.length > MAX_INGEST_EVENTS) {
		return { ok: false, status: 413, error: "events_limit_exceeded" };
	}

	const events: Array<Record<string, unknown> & { event_id: string }> = [];
	let batchBytes = 0;
	const seen = new Set<string>();
	for (let index = 0; index < value.length; index += 1) {
		const candidate = value[index];
		if (!candidate || typeof candidate !== "object" || Array.isArray(candidate)) {
			return { ok: false, status: 400, error: "invalid_event", detail: `events[${index}]` };
		}
		const event = candidate as Record<string, unknown>;
		if (typeof event.event_id !== "string" || !EVENT_ID_PATTERN.test(event.event_id)) {
			return {
				ok: false,
				status: 400,
				error: "missing_event_id",
				detail: `events[${index}].event_id`,
			};
		}
		if (SENSITIVE_IDENTIFIER_PATTERN.test(event.event_id) || PHONE_LIKE_IDENTIFIER_PATTERN.test(event.event_id)) {
			return { ok: false, status: 400, error: "invalid_event", detail: `events[${index}].event_id` };
		}
		if (event.type !== undefined && safeEnum(event.type, EVENT_TYPES) === undefined) {
			return { ok: false, status: 400, error: "invalid_event", detail: `events[${index}].type` };
		}
		if (seen.has(event.event_id)) {
			return {
				ok: false,
				status: 400,
				error: "invalid_event",
				detail: `duplicate event_id in request: ${event.event_id}`,
			};
		}
		seen.add(event.event_id);

		let encoded: string;
		try {
			encoded = JSON.stringify(event);
		} catch {
			return { ok: false, status: 400, error: "invalid_event", detail: `events[${index}]` };
		}
		const bytes = new TextEncoder().encode(encoded).byteLength;
		if (bytes > MAX_INGEST_EVENT_BYTES) {
			return {
				ok: false,
				status: 413,
				error: "events_batch_too_large",
				detail: `events[${index}]`,
			};
		}
		batchBytes += bytes;
		if (batchBytes > MAX_INGEST_BATCH_BYTES) {
			return { ok: false, status: 413, error: "events_batch_too_large" };
		}
		events.push(projectEvent(event as Record<string, unknown> & { event_id: string }));
	}
	return { ok: true, events };
}
