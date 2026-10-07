// Time-limited detection exceptions for managed tenants (catalog item 80).
//
// Two consumers:
// - the `detection-exceptions` Edge Function (dashboard: owner/admin + AAL2),
//   which parses requests here before calling its service-role RPCs; and
// - the `policy` Edge Function, which validates the per-principal feed here and
//   binds its digest into the Ed25519-signed runtime-policy envelope.
//
// The wire shape mirrors `DetectionExceptionWireSchema` in
// packages/core/src/detection-exceptions.ts; Edge Functions cannot import the
// workspace packages, so the rules (rule id format, protected self-defense
// rules, 30-day window) are repeated here and pinned by contract tests.

export const DETECTION_EXCEPTIONS_MAX_BODY_BYTES = 8_192;
export const DETECTION_EXCEPTION_MAX_DAYS = 30;
export const DETECTION_EXCEPTION_MIN_MINUTES = 5;
export const DETECTION_EXCEPTION_MAX_ENTRIES = 500;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/;
const DIGEST = /^[a-f0-9]{64}$/;
const ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/;
const CONTROL = /[\u0000-\u001f\u007f]/;
const PROTECTED_PREFIXES = ["CLT-SELF-", "CLT-CANARY-"];
const DAY_MS = 86_400_000;

export type DetectionExceptionSubjectKind = "user" | "agent" | "repo";

/** One exception as signed into the runtime policy (snake_case, strict). */
export interface DetectionExceptionWire {
	id: string;
	rule_id: string;
	artifact_sha256: string | null;
	subject_kind: DetectionExceptionSubjectKind;
	subject_value: string;
	created_at: string;
	expires_at: string;
	created_by: string;
	reason: string;
}

/** Self-defense and canary rules: never excepted. */
export function isProtectedRuleId(ruleId: string): boolean {
	const upper = ruleId.toUpperCase();
	return PROTECTED_PREFIXES.some((prefix) => upper.startsWith(prefix));
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function boundedText(value: unknown, max: number): string | null {
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	return trimmed.length >= 1 && trimmed.length <= max && !CONTROL.test(trimmed) ? trimmed : null;
}

/** Canonical ISO-8601 UTC form of a Postgres timestamp, or null. */
function isoInstant(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const ms = Date.parse(value);
	return Number.isFinite(ms) ? new Date(ms).toISOString() : null;
}

function subjectValueValid(kind: DetectionExceptionSubjectKind, value: string): boolean {
	return kind === "repo" ? value.length <= 512 : UUID.test(value);
}

/** One wire record, or null when anything is off (the whole feed is then refused). */
function wireRecord(raw: unknown): DetectionExceptionWire | null {
	if (!isRecord(raw)) return null;
	const kind = raw.subject_kind;
	if (kind !== "user" && kind !== "agent" && kind !== "repo") return null;
	const id = typeof raw.id === "string" && UUID.test(raw.id) ? raw.id.toLowerCase() : null;
	const ruleId = typeof raw.rule_id === "string" && RULE_ID.test(raw.rule_id) ? raw.rule_id : null;
	const digest =
		raw.artifact_sha256 === null
			? null
			: typeof raw.artifact_sha256 === "string" && DIGEST.test(raw.artifact_sha256)
				? raw.artifact_sha256
				: undefined;
	const subject = boundedText(raw.subject_value, 512);
	const created = isoInstant(raw.created_at);
	const expires = isoInstant(raw.expires_at);
	const createdBy = boundedText(raw.created_by, 200);
	const reason = boundedText(raw.reason, 500);
	if (!id || !ruleId || digest === undefined || !subject || !created || !expires || !createdBy || !reason) {
		return null;
	}
	if (isProtectedRuleId(ruleId) || !subjectValueValid(kind, subject)) return null;
	const window = Date.parse(expires) - Date.parse(created);
	if (!(window > 0 && window <= DETECTION_EXCEPTION_MAX_DAYS * DAY_MS)) return null;
	if (!ISO.test(created) || !ISO.test(expires)) return null;
	return {
		id,
		rule_id: ruleId,
		artifact_sha256: digest,
		subject_kind: kind,
		subject_value: subject,
		created_at: created,
		expires_at: expires,
		created_by: createdBy,
		reason,
	};
}

/**
 * Validate the `detection_exceptions_for_principal` RPC result. Returns null
 * when it is malformed; the policy endpoint then refuses to serve (a policy
 * whose exception set or sequence it cannot state must not be signed).
 */
export function validateDetectionExceptionFeed(
	data: unknown,
): { exceptions: DetectionExceptionWire[]; changedAt: string | null } | null {
	if (!isRecord(data) || !Array.isArray(data.exceptions)) return null;
	if (data.exceptions.length > DETECTION_EXCEPTION_MAX_ENTRIES) return null;
	const exceptions: DetectionExceptionWire[] = [];
	for (const item of data.exceptions) {
		const record = wireRecord(item);
		if (!record) return null;
		exceptions.push(record);
	}
	exceptions.sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
	const changedAt = data.changed_at === null || data.changed_at === undefined ? null : isoInstant(data.changed_at);
	if (data.changed_at !== null && data.changed_at !== undefined && changedAt === null) return null;
	return { exceptions, changedAt };
}

// ── Management requests (dashboard) ─────────────────────────────────────

export type DetectionExceptionCommand =
	| { action: "list" }
	| {
			action: "create";
			fields: {
				rule_id: string;
				artifact_sha256: string | null;
				subject_kind: DetectionExceptionSubjectKind;
				subject_value: string;
				expires_at: string;
				reason: string;
			};
	  }
	| { action: "revoke"; exceptionId: string; reason: string };

export type ParsedDetectionExceptionRequest =
	| { ok: true; tenantId: string; command: DetectionExceptionCommand }
	| { ok: false; error: string };

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

/**
 * Parse a dashboard request. `now` bounds the requested expiry (5 minutes to 30
 * days ahead); the RPC re-checks every field against its own clock.
 */
export function parseDetectionExceptionRequest(body: unknown, now: number): ParsedDetectionExceptionRequest {
	if (!isRecord(body)) return { ok: false, error: "invalid_request" };
	const tenantId = typeof body.tenant_id === "string" && UUID.test(body.tenant_id) ? body.tenant_id.toLowerCase() : null;
	if (!tenantId) return { ok: false, error: "invalid_tenant_id" };
	switch (body.action) {
		case "list":
			return exactKeys(body, ["action", "tenant_id"])
				? { ok: true, tenantId, command: { action: "list" } }
				: { ok: false, error: "invalid_request" };
		case "revoke": {
			if (!exactKeys(body, ["action", "tenant_id", "exception_id", "reason"])) return { ok: false, error: "invalid_request" };
			const id = typeof body.exception_id === "string" && UUID.test(body.exception_id) ? body.exception_id.toLowerCase() : null;
			const reason = boundedText(body.reason, 500);
			if (!id) return { ok: false, error: "invalid_exception_id" };
			if (!reason) return { ok: false, error: "invalid_reason" };
			return { ok: true, tenantId, command: { action: "revoke", exceptionId: id, reason } };
		}
		case "create": {
			if (
				!exactKeys(
					body,
					["action", "tenant_id", "rule_id", "subject_kind", "subject_value", "expires_at", "reason"],
					["artifact_sha256"],
				)
			) {
				return { ok: false, error: "invalid_request" };
			}
			const ruleId = typeof body.rule_id === "string" ? body.rule_id.trim() : "";
			if (!RULE_ID.test(ruleId)) return { ok: false, error: "invalid_rule_id" };
			if (isProtectedRuleId(ruleId)) return { ok: false, error: "protected_rule" };
			const kind = body.subject_kind;
			if (kind !== "user" && kind !== "agent" && kind !== "repo") return { ok: false, error: "invalid_subject" };
			const subject = boundedText(body.subject_value, 512);
			if (!subject || !subjectValueValid(kind, subject)) return { ok: false, error: "invalid_subject" };
			const digest = body.artifact_sha256 ?? null;
			if (digest !== null && !(typeof digest === "string" && DIGEST.test(digest))) {
				return { ok: false, error: "invalid_artifact_sha256" };
			}
			const expires = isoInstant(body.expires_at);
			const expiresMs = expires ? Date.parse(expires) : Number.NaN;
			if (
				!expires ||
				expiresMs < now + DETECTION_EXCEPTION_MIN_MINUTES * 60_000 ||
				expiresMs > now + DETECTION_EXCEPTION_MAX_DAYS * DAY_MS
			) {
				return { ok: false, error: "invalid_expires_at" };
			}
			const reason = boundedText(body.reason, 500);
			if (!reason) return { ok: false, error: "invalid_reason" };
			return {
				ok: true,
				tenantId,
				command: {
					action: "create",
					fields: {
						rule_id: ruleId,
						artifact_sha256: digest as string | null,
						subject_kind: kind,
						subject_value: kind === "repo" ? subject : subject.toLowerCase(),
						expires_at: expires,
						reason,
					},
				},
			};
		}
		default:
			return { ok: false, error: "invalid_action" };
	}
}

const KNOWN_RPC_ERRORS = new Set([
	"detection_exception_forbidden",
	"invalid_detection_exception",
	"detection_exception_protected_rule",
	"detection_exception_subject_unknown",
	"detection_exception_quota",
	"detection_exception_not_found",
	"detection_exception_not_active",
]);

/** The stable error code in an RPC error message, or null. */
export function detectionExceptionErrorCode(message: unknown): string | null {
	if (typeof message !== "string") return null;
	const token = /^([a-z][a-z0-9_]{0,63})/.exec(message)?.[1] ?? null;
	return token && KNOWN_RPC_ERRORS.has(token) ? token : null;
}

export function detectionExceptionRpcStatus(code: string | undefined): number {
	switch (code) {
		case "42501":
			return 403;
		case "P0002":
			return 404;
		case "55000":
			return 409;
		case "22023":
		case "22P02":
		case "23514":
			return 400;
		case "54000":
			return 429;
		default:
			return 503;
	}
}
