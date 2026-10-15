// Incident triage requests for the `incidents` Edge Function (E1).
//
// The SQL (20261014000100_incident_triage.sql) re-checks every field under a
// tenant lock; this parser refuses malformed input early with a stable error
// code and never forwards keys the RPC does not know.

export const INCIDENT_TRIAGE_MAX_BODY_BYTES = 4_096;
const INCIDENT_TRIAGE_STATUSES = ["open", "acknowledged", "resolved", "false_positive"] as const;
type IncidentTriageStatus = (typeof INCIDENT_TRIAGE_STATUSES)[number];
const INCIDENT_SNOOZE_MAX_DAYS = 30;
const INCIDENT_SNOOZE_MIN_MINUTES = 5;
const INCIDENT_NOTE_MAX = 1_000;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
/** Control characters other than newline and tab. */
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f]/;
const DAY_MS = 86_400_000;

type IncidentTriageCommand =
	| { action: "list" }
	| { action: "history"; eventId: number }
	| {
			action: "update";
			eventId: number;
			expectedVersion: number;
			fields: {
				status: IncidentTriageStatus;
				owner_user_id: string | null;
				resolution_note: string | null;
				snoozed_until: string | null;
			};
	  };

export type ParsedIncidentTriageRequest =
	| { ok: true; tenantId: string; command: IncidentTriageCommand }
	| { ok: false; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

/** A positive bigint event id that fits a JS safe integer. */
function eventId(value: unknown): number | null {
	const numeric = typeof value === "string" && /^[1-9]\d{0,15}$/.test(value) ? Number(value) : value;
	return typeof numeric === "number" && Number.isSafeInteger(numeric) && numeric > 0 ? numeric : null;
}

function note(value: unknown): string | null | undefined {
	if (value === null || value === undefined) return null;
	if (typeof value !== "string") return undefined;
	const trimmed = value.trim();
	if (trimmed === "") return null;
	return trimmed.length <= INCIDENT_NOTE_MAX && !CONTROL.test(trimmed) ? trimmed : undefined;
}

function isStatus(value: unknown): value is IncidentTriageStatus {
	return typeof value === "string" && (INCIDENT_TRIAGE_STATUSES as readonly string[]).includes(value);
}

/**
 * Parse a dashboard request. `now` bounds the snooze (5 minutes to 30 days
 * ahead); the RPC re-checks it against the database clock.
 */
export function parseIncidentTriageRequest(body: unknown, now: number): ParsedIncidentTriageRequest {
	if (!isRecord(body)) return { ok: false, error: "invalid_request" };
	const tenantId = typeof body.tenant_id === "string" && UUID.test(body.tenant_id) ? body.tenant_id.toLowerCase() : null;
	if (!tenantId) return { ok: false, error: "invalid_tenant_id" };
	switch (body.action) {
		case "list":
			return exactKeys(body, ["action", "tenant_id"])
				? { ok: true, tenantId, command: { action: "list" } }
				: { ok: false, error: "invalid_request" };
		case "history": {
			if (!exactKeys(body, ["action", "tenant_id", "event_id"])) return { ok: false, error: "invalid_request" };
			const id = eventId(body.event_id);
			return id ? { ok: true, tenantId, command: { action: "history", eventId: id } } : { ok: false, error: "invalid_event_id" };
		}
		case "update": {
			if (
				!exactKeys(
					body,
					["action", "tenant_id", "event_id", "expected_version", "status"],
					["owner_user_id", "resolution_note", "snoozed_until"],
				)
			) {
				return { ok: false, error: "invalid_request" };
			}
			const id = eventId(body.event_id);
			if (!id) return { ok: false, error: "invalid_event_id" };
			const version = body.expected_version;
			if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 0 || version > 1_000_000) {
				return { ok: false, error: "invalid_expected_version" };
			}
			if (!isStatus(body.status)) return { ok: false, error: "invalid_status" };
			const owner = body.owner_user_id ?? null;
			if (owner !== null && !(typeof owner === "string" && UUID.test(owner))) return { ok: false, error: "invalid_owner" };
			const resolution = note(body.resolution_note);
			if (resolution === undefined) return { ok: false, error: "invalid_resolution_note" };
			if ((body.status === "resolved" || body.status === "false_positive") && resolution === null) {
				return { ok: false, error: "incident_resolution_note_required" };
			}
			let snooze: string | null = null;
			if (body.snoozed_until !== null && body.snoozed_until !== undefined) {
				if (body.status !== "open" && body.status !== "acknowledged") return { ok: false, error: "incident_snooze_closed" };
				const ms = typeof body.snoozed_until === "string" && body.snoozed_until.length <= 40
					? Date.parse(body.snoozed_until)
					: Number.NaN;
				if (
					!Number.isFinite(ms) ||
					ms < now + INCIDENT_SNOOZE_MIN_MINUTES * 60_000 ||
					ms > now + INCIDENT_SNOOZE_MAX_DAYS * DAY_MS
				) {
					return { ok: false, error: "invalid_snoozed_until" };
				}
				snooze = new Date(ms).toISOString();
			}
			return {
				ok: true,
				tenantId,
				command: {
					action: "update",
					eventId: id,
					expectedVersion: version,
					fields: {
						status: body.status,
						owner_user_id: owner === null ? null : owner.toLowerCase(),
						resolution_note: resolution,
						snoozed_until: snooze,
					},
				},
			};
		}
		default:
			return { ok: false, error: "invalid_action" };
	}
}

const KNOWN_RPC_ERRORS = new Set([
	"invalid_incident_triage",
	"incident_triage_forbidden",
	"incident_not_found",
	"incident_triage_conflict",
	"incident_owner_not_member",
	"incident_resolution_note_required",
	"incident_snooze_closed",
	"incident_triage_unchanged",
]);

/** The stable error code at the start of an RPC error message, or null. */
export function incidentTriageErrorCode(message: unknown): string | null {
	if (typeof message !== "string") return null;
	const token = /^([a-z][a-z0-9_]{0,63})/.exec(message)?.[1] ?? null;
	return token && KNOWN_RPC_ERRORS.has(token) ? token : null;
}

export function incidentTriageRpcStatus(code: string | undefined): number {
	switch (code) {
		case "42501":
			return 403;
		case "P0002":
			return 404;
		case "40001":
			return 409;
		case "22023":
		case "22P02":
		case "23514":
			return 400;
		default:
			return 503;
	}
}
