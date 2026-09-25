import { POSTURE_EVENT_TYPES, projectPostureFields } from "./posture.ts";

export const MAX_INGEST_EVENTS = 200;
const MAX_INGEST_EVENT_BYTES = 256 * 1024;
const MAX_INGEST_BATCH_BYTES = 4 * 1024 * 1024;

const EVENT_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const IDENTIFIER_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HASH_PATTERN = /^sha256:[a-f0-9]{64}$/;
const SENSITIVE_IDENTIFIER_PATTERN = /(?:^|[._:-])(?:api[_-]?key|access[_-]?token|authorization|bearer|cookie|credential|password|passwd|private[_-]?key|secret|session[_-]?token|client[_-]?secret|refresh[_-]?token|signature)(?:[._:-]|$)|^(?:sk[_-]|ghp_|github_pat_|xox[baprs]-|npm_|pypi-|AKIA)/i;
// Compact JWTs have base64url-encoded JSON objects in their first two segments.
// Matching the high-signal `eyJ...eyJ...` shape avoids treating ordinary dotted
// versions and event identifiers as credentials.
const JWT_LIKE_IDENTIFIER_PATTERN = /^eyJ[A-Za-z0-9_-]{5,}\.eyJ[A-Za-z0-9_-]{5,}\.(?:[A-Za-z0-9_-]{8,})?$/;
const PHONE_LIKE_IDENTIFIER_PATTERN = /^(?:\d[.:-]?){8,15}$/;
const EVENT_TYPES = new Set([
	"runtime_verdict",
	"incident",
	"plugin_scan",
	"plugin_scan_finding",
	"runtime_policy_cache",
	"privacy_scan",
	"shadow_ai_usage",
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
// AI security posture findings (aidr scan/discover --upload); fields in ./posture.ts.
for (const type of POSTURE_EVENT_TYPES) EVENT_TYPES.add(type);

/**
 * Browser Guard privacy telemetry (docs/contracts/privacy-telemetry.md).
 * Keys mirror packages/privacy/src/types.ts ENTITY_TYPES; the edge runtime
 * cannot import that package, so the contract suite pins the two lists.
 */
export const PRIVACY_ENTITY_TYPES = [
	"PERSON", "EMAIL", "PHONE", "TC_KIMLIK", "IBAN", "CREDIT_CARD", "ADDRESS",
	"US_SSN", "DATE_OF_BIRTH", "PASSPORT", "NATIONAL_ID", "TAX_ID", "BANK_ACCOUNT",
	"IP_ADDRESS", "MAC_ADDRESS", "SECRET", "PRIVATE_KEY", "INTERNAL", "CLASSIFIED",
	"LOCATION", "USERNAME", "HEALTH_ID", "LICENSE_PLATE",
] as const;
export const PRIVACY_SITES = [
	"chatgpt", "gemini", "claude", "copilot", "perplexity", "deepseek", "mistral", "grok", "custom",
	"other",
] as const;
const PRIVACY_CHANNELS = ["prompt", "paste", "file"] as const;
/** Generic decision for each guard action: a masked send left redacted, so it was allowed. */
export const PRIVACY_ACTION_DECISIONS = {
	masked: "allow",
	warned: "ask",
	blocked: "deny",
	allowed: "allow",
} as const;
export const MAX_PRIVACY_ENTITY_KEYS = 32;
const MAX_PRIVACY_ENTITY_COUNT = 100_000;
const PRIVACY_ENTITY_TYPE_SET = new Set<string>(PRIVACY_ENTITY_TYPES);
const PRIVACY_SITE_SET = new Set<string>(PRIVACY_SITES);
const PRIVACY_CHANNEL_SET = new Set<string>(PRIVACY_CHANNELS);

/**
 * Browser Guard Shadow AI usage (docs/contracts/privacy-telemetry.md): aggregated
 * visit/block counts per catalogued AI service. Keys and categories mirror the catalog in
 * packages/browser-guard/src/sites/catalog.ts (pinned by the contract suite); a
 * well-formed id this server does not know yet is filed under "other".
 */
export const SHADOW_AI_SERVICE_CATEGORIES: Readonly<Record<string, string>> = {
	chatgpt: "chat", gemini: "chat", claude: "chat", copilot: "chat", perplexity: "search",
	deepseek: "chat", mistral: "chat", grok: "chat", poe: "chat", "character-ai": "chat",
	huggingface: "chat", "meta-ai": "chat", pi: "chat", "duck-ai": "chat", kimi: "chat",
	qwen: "chat", doubao: "chat", ernie: "chat", chatglm: "chat", yuanbao: "chat",
	cohere: "chat", groq: "chat", openrouter: "chat", together: "chat", lmarena: "chat",
	monica: "chat", replika: "chat", chatpdf: "chat", notebooklm: "chat", you: "search",
	consensus: "search", elicit: "search", phind: "coding", "ai-studio": "coding",
	"openai-platform": "coding", "anthropic-console": "coding", "azure-ai-foundry": "coding",
	cursor: "coding", v0: "coding", bolt: "coding", lovable: "coding", replit: "coding",
	windsurf: "coding", tabnine: "coding", blackbox: "coding", devin: "agent", manus: "agent",
	genspark: "agent", jasper: "writing", writesonic: "writing", "copy-ai": "writing",
	quillbot: "writing", deepl: "writing", grammarly: "writing", wordtune: "writing",
	rytr: "writing", gamma: "writing", tome: "writing", "beautiful-ai": "writing",
	midjourney: "image", leonardo: "image", ideogram: "image", runway: "image",
	elevenlabs: "image", suno: "image", pika: "image", krea: "image", firefly: "image",
	heygen: "image", synthesia: "image", otter: "meeting", fireflies: "meeting",
	tldv: "meeting", fathom: "meeting", "read-ai": "meeting",
};
export const SHADOW_AI_ACTION_DECISIONS = { visited: "allow", blocked: "deny" } as const;
export const MAX_SHADOW_AI_COUNT = 100_000;
const SHADOW_AI_SERVICE_ID_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;

function shadowAiAction(value: unknown): keyof typeof SHADOW_AI_ACTION_DECISIONS | undefined {
	return typeof value === "string" && Object.hasOwn(SHADOW_AI_ACTION_DECISIONS, value)
		? (value as keyof typeof SHADOW_AI_ACTION_DECISIONS)
		: undefined;
}

function isShadowAiCount(value: unknown): value is number {
	return typeof value === "number" && Number.isInteger(value) && value >= 1 &&
		value <= MAX_SHADOW_AI_COUNT;
}

/** Reject a Shadow AI event whose required fields cannot be projected faithfully. */
function shadowAiEventProblem(event: Record<string, unknown>): string | undefined {
	if (!shadowAiAction(event.action)) return "action";
	if (typeof event.service_id !== "string" || !SHADOW_AI_SERVICE_ID_PATTERN.test(event.service_id)) {
		return "service_id";
	}
	if (!isShadowAiCount(event.count)) return "count";
	if (event.sanctioned !== undefined && typeof event.sanctioned !== "boolean") return "sanctioned";
	return undefined;
}

/**
 * Counts-only projection of a Shadow AI usage event: a catalog id (or "other"), its
 * category, visited|blocked, a bounded count and the sanctioned flag. URLs, hosts, paths
 * and titles are dropped even when a client sends them.
 */
function projectShadowAiEvent(event: Record<string, unknown> & { event_id: string }) {
	const action = shadowAiAction(event.action) ?? "visited";
	const serviceId = typeof event.service_id === "string" &&
			Object.hasOwn(SHADOW_AI_SERVICE_CATEGORIES, event.service_id)
		? event.service_id
		: "other";
	const projected: Record<string, unknown> & { event_id: string } = {
		event_id: event.event_id,
		type: "shadow_ai_usage",
	};
	const timestamp = safeTimestamp(event.timestamp);
	if (timestamp) projected.timestamp = timestamp;
	projected.service_id = serviceId;
	projected.category = SHADOW_AI_SERVICE_CATEGORIES[serviceId] ?? "other";
	projected.action = action;
	projected.decision = SHADOW_AI_ACTION_DECISIONS[action];
	projected.count = isShadowAiCount(event.count) ? event.count : 1;
	projected.sanctioned = event.sanctioned === true;
	const policyId = safeIdentifier(event.policy_id);
	if (policyId) projected.policy_id = policyId;
	return projected;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function privacyAction(value: unknown): keyof typeof PRIVACY_ACTION_DECISIONS | undefined {
	return typeof value === "string" && Object.hasOwn(PRIVACY_ACTION_DECISIONS, value)
		? (value as keyof typeof PRIVACY_ACTION_DECISIONS)
		: undefined;
}

/**
 * Resolve the event type from `type` or its contract alias `event_type`.
 * Returns null when the two disagree or name an unknown type.
 */
function resolveEventType(event: Record<string, unknown>): string | null {
	const declared = [event.type, event.event_type].filter((value) => value !== undefined);
	if (declared.length === 0) return "runtime_verdict";
	const type = safeEnum(declared[0], EVENT_TYPES);
	if (!type || declared.some((value) => value !== type)) return null;
	return type;
}

/** Reject a privacy event whose required fields cannot be projected faithfully. */
function privacyEventProblem(event: Record<string, unknown>): string | undefined {
	if (!privacyAction(event.action)) return "action";
	if (safeEnum(event.channel, PRIVACY_CHANNEL_SET) === undefined) return "channel";
	if (event.entity_counts !== undefined) {
		if (!isPlainObject(event.entity_counts)) return "entity_counts";
		if (Object.keys(event.entity_counts).length > MAX_PRIVACY_ENTITY_KEYS) return "entity_counts";
	}
	return undefined;
}

/**
 * Counts-only projection of a Browser Guard scan. Nothing but enums, bounded
 * integers and an optional policy identifier survives: raw prompt text, masked
 * text, matched values and page URLs are dropped even when a client sends them.
 */
function projectPrivacyEvent(event: Record<string, unknown> & { event_id: string }) {
	const action = privacyAction(event.action) ?? "allowed";
	const projected: Record<string, unknown> & { event_id: string } = {
		event_id: event.event_id,
		type: "privacy_scan",
	};
	const timestamp = safeTimestamp(event.timestamp);
	if (timestamp) projected.timestamp = timestamp;
	// A site this server does not know yet is still a real send: keep it as "other".
	projected.site = safeEnum(event.site, PRIVACY_SITE_SET) ?? "other";
	projected.action = action;
	projected.channel = safeEnum(event.channel, PRIVACY_CHANNEL_SET);
	projected.decision = PRIVACY_ACTION_DECISIONS[action];
	const counts: Record<string, number> = {};
	if (isPlainObject(event.entity_counts)) {
		for (const [key, value] of Object.entries(event.entity_counts)) {
			if (!PRIVACY_ENTITY_TYPE_SET.has(key)) continue;
			if (typeof value !== "number" || !Number.isInteger(value)) continue;
			if (value < 1 || value > MAX_PRIVACY_ENTITY_COUNT) continue;
			counts[key] = value;
		}
	}
	projected.entity_counts = counts;
	const findingsCount = safeBoundedCount(event.findings_count);
	if (findingsCount !== undefined) projected.findings_count = findingsCount;
	const policyId = safeIdentifier(event.policy_id);
	if (policyId) projected.policy_id = policyId;
	return projected;
}

function isSensitiveIdentifier(value: string): boolean {
	return SENSITIVE_IDENTIFIER_PATTERN.test(value) ||
		JWT_LIKE_IDENTIFIER_PATTERN.test(value) ||
		PHONE_LIKE_IDENTIFIER_PATTERN.test(value);
}

function safeIdentifier(value: unknown): string | undefined {
	return typeof value === "string" &&
		IDENTIFIER_PATTERN.test(value) &&
		!isSensitiveIdentifier(value)
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
function projectEvent(event: Record<string, unknown> & { event_id: string }, type: string) {
	if (type === "privacy_scan") return projectPrivacyEvent(event);
	if (type === "shadow_ai_usage") return projectShadowAiEvent(event);
	const projected: Record<string, unknown> & { event_id: string } = {
		event_id: event.event_id,
		type,
	};
	const timestamp = safeTimestamp(event.timestamp);
	if (timestamp) projected.timestamp = timestamp;
	Object.assign(projected, projectPostureFields(event));

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
		if (isSensitiveIdentifier(event.event_id)) {
			return { ok: false, status: 400, error: "invalid_event", detail: `events[${index}].event_id` };
		}
		const type = resolveEventType(event);
		if (type === null) {
			return { ok: false, status: 400, error: "invalid_event", detail: `events[${index}].type` };
		}
		const privacyProblem = type === "privacy_scan"
			? privacyEventProblem(event)
			: type === "shadow_ai_usage"
				? shadowAiEventProblem(event)
				: undefined;
		if (privacyProblem) {
			return {
				ok: false,
				status: 400,
				error: "invalid_event",
				detail: `events[${index}].${privacyProblem}`,
			};
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
		events.push(projectEvent(event as Record<string, unknown> & { event_id: string }, type));
	}
	return { ok: true, events };
}
