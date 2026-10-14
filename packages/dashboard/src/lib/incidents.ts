import type { DashboardMessageKey } from "../i18n/en";
import { englishT, type Translate } from "../i18n/I18nProvider";
import { supabase } from "./supabase";

/**
 * Incident triage (status, owner, resolution note, snooze, history) through the
 * `incidents` Edge Function. Every member can read; owners and admins with AAL2
 * can change triage. Triage never changes enforcement: a false positive is
 * turned into a detection exception only through the separate, pre-filled
 * detection-exception form, which the server checks on its own.
 */

export const TRIAGE_STATUSES = ["open", "acknowledged", "resolved", "false_positive"] as const;
export type TriageStatus = (typeof TRIAGE_STATUSES)[number];
export const INCIDENT_SNOOZE_MAX_DAYS = 30;
export const INCIDENT_NOTE_MAX = 1000;

export const TRIAGE_STATUS_LABEL: Readonly<Record<TriageStatus, DashboardMessageKey>> = {
	open: "inc.status.open",
	acknowledged: "inc.status.acknowledged",
	resolved: "inc.status.resolved",
	false_positive: "inc.status.false_positive",
};

export interface TriageRow {
	eventId: number;
	status: TriageStatus;
	ownerUserId: string | null;
	resolutionNote: string | null;
	snoozedUntil: string | null;
	version: number;
	updatedBy: string;
	updatedAt: string;
}

export interface TriageHistoryRow {
	id: number;
	actorUserId: string;
	fromStatus: TriageStatus | null;
	toStatus: TriageStatus;
	fromOwnerUserId: string | null;
	toOwnerUserId: string | null;
	note: string | null;
	snoozedUntil: string | null;
	selfClosure: boolean;
	createdAt: string;
}

export interface TriageList {
	canTriage: boolean;
	rows: Map<number, TriageRow>;
}

export type TriageResult<T> = { ok: true; value: T } | { ok: false; error: string };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isStatus(value: unknown): value is TriageStatus {
	return typeof value === "string" && (TRIAGE_STATUSES as readonly string[]).includes(value);
}

const text = (value: unknown): string | null => (typeof value === "string" ? value : null);

function parseTriage(raw: unknown): TriageRow | null {
	if (!isRecord(raw) || !isStatus(raw.status)) return null;
	const eventId = Number(raw.event_id);
	if (!Number.isSafeInteger(eventId) || eventId <= 0 || !Number.isSafeInteger(raw.version))
		return null;
	return {
		eventId,
		status: raw.status,
		ownerUserId: text(raw.owner_user_id),
		resolutionNote: text(raw.resolution_note),
		snoozedUntil: text(raw.snoozed_until),
		version: raw.version as number,
		updatedBy: text(raw.updated_by) ?? "",
		updatedAt: text(raw.updated_at) ?? "",
	};
}

function parseHistory(raw: unknown): TriageHistoryRow | null {
	if (!isRecord(raw) || !isStatus(raw.to_status) || typeof raw.created_at !== "string") return null;
	return {
		id: Number(raw.id),
		actorUserId: text(raw.actor_user_id) ?? "",
		fromStatus: isStatus(raw.from_status) ? raw.from_status : null,
		toStatus: raw.to_status,
		fromOwnerUserId: text(raw.from_owner_user_id),
		toOwnerUserId: text(raw.to_owner_user_id),
		note: text(raw.note),
		snoozedUntil: text(raw.snoozed_until),
		selfClosure: raw.self_closure === true,
		createdAt: raw.created_at,
	};
}

async function errorCode(error: unknown): Promise<string | null> {
	const context = (error as { context?: unknown } | null | undefined)?.context;
	if (!(context instanceof Response)) return null;
	try {
		const body: unknown = await context.clone().json();
		return isRecord(body) &&
			typeof body.error === "string" &&
			/^[a-z][a-z0-9_]{0,63}$/.test(body.error)
			? body.error
			: null;
	} catch {
		return null;
	}
}

async function invoke(
	tenantId: string,
	action: "list" | "history" | "update",
	payload: Record<string, unknown> = {},
): Promise<TriageResult<Record<string, unknown>>> {
	try {
		const { data, error } = await supabase.functions.invoke("incidents", {
			method: "POST",
			body: { action, tenant_id: tenantId, ...payload },
		});
		if (error) return { ok: false, error: (await errorCode(error)) ?? "incidents_unavailable" };
		if (!isRecord(data) || data.ok !== true) return { ok: false, error: "incidents_unavailable" };
		return { ok: true, value: data };
	} catch {
		return { ok: false, error: "incidents_unavailable" };
	}
}

export async function listTriage(tenantId: string): Promise<TriageResult<TriageList>> {
	const result = await invoke(tenantId, "list");
	if (!result.ok) return result;
	if (!Array.isArray(result.value.triage)) return { ok: false, error: "incidents_unavailable" };
	const rows = new Map<number, TriageRow>();
	for (const raw of result.value.triage) {
		const row = parseTriage(raw);
		if (row) rows.set(row.eventId, row);
	}
	return { ok: true, value: { canTriage: result.value.can_triage === true, rows } };
}

export async function triageHistory(
	tenantId: string,
	eventId: number,
): Promise<TriageResult<TriageHistoryRow[]>> {
	const result = await invoke(tenantId, "history", { event_id: eventId });
	if (!result.ok) return result;
	if (!Array.isArray(result.value.history)) return { ok: false, error: "incidents_unavailable" };
	return {
		ok: true,
		value: result.value.history
			.map(parseHistory)
			.filter((row): row is TriageHistoryRow => row !== null),
	};
}

export interface TriageDraft {
	status: TriageStatus;
	ownerUserId: string;
	note: string;
	/** "" for no snooze, else a yyyy-mm-dd day (snoozed until 00:00 UTC that day). */
	snoozeUntil: string;
}

/** Client-side checks that mirror the server; the server re-checks everything. */
export function triageDraftProblem(
	draft: TriageDraft,
	nowMs: number,
	t: Translate = englishT,
): string | null {
	const closing = draft.status === "resolved" || draft.status === "false_positive";
	if (closing && draft.note.trim() === "") return t("inc.problem.note");
	if (draft.note.trim().length > INCIDENT_NOTE_MAX)
		return t("inc.problem.noteLong", { max: INCIDENT_NOTE_MAX });
	if (draft.snoozeUntil) {
		if (closing) return t("inc.problem.snoozeClosed");
		const ms = Date.parse(`${draft.snoozeUntil}T00:00:00.000Z`);
		if (!Number.isFinite(ms) || ms <= nowMs + 5 * 60_000) return t("inc.problem.snoozeFuture");
		if (ms > nowMs + INCIDENT_SNOOZE_MAX_DAYS * 86_400_000) {
			return t("inc.problem.snoozeMax", { days: INCIDENT_SNOOZE_MAX_DAYS });
		}
	}
	return null;
}

export async function updateTriage(
	tenantId: string,
	eventId: number,
	expectedVersion: number,
	draft: TriageDraft,
): Promise<TriageResult<TriageRow>> {
	const result = await invoke(tenantId, "update", {
		event_id: eventId,
		expected_version: expectedVersion,
		status: draft.status,
		owner_user_id: draft.ownerUserId || null,
		resolution_note: draft.note.trim() || null,
		snoozed_until: draft.snoozeUntil ? `${draft.snoozeUntil}T00:00:00.000Z` : null,
	});
	if (!result.ok) return result;
	const row = parseTriage(result.value.triage);
	return row ? { ok: true, value: row } : { ok: false, error: "incidents_unavailable" };
}

/** Effective status: an incident nobody has triaged yet is open. */
export function effectiveStatus(row: TriageRow | undefined): TriageStatus {
	return row?.status ?? "open";
}

export function isSnoozed(row: TriageRow | undefined, nowMs: number): boolean {
	return (
		!!row?.snoozedUntil &&
		(row.status === "open" || row.status === "acknowledged") &&
		Date.parse(row.snoozedUntil) > nowMs
	);
}

const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * Link to the detection-exception form, pre-filled from a false-positive
 * incident: the matched rule scoped to the incident's agent, with the
 * resolution note as the reason. The administrator still reviews, narrows (for
 * example to one artifact digest from `aidr exception`) and submits it. Null
 * when the event names no rule, or names a self-defense/canary rule, which can
 * never be excepted.
 */
export function exceptionPrefillPath(input: {
	ruleId: unknown;
	agentId: string;
	note: string | null;
}): string | null {
	const rule = typeof input.ruleId === "string" ? input.ruleId.trim() : "";
	if (!RULE_ID.test(rule)) return null;
	const upper = rule.toUpperCase();
	if (
		upper.startsWith("CLT-SELF-") ||
		upper.startsWith("CLT-CANARY-") ||
		/^(?:AIDR|OUT)-CANARY-/.test(upper)
	) {
		return null;
	}
	const params = new URLSearchParams({ rule });
	if (UUID.test(input.agentId)) {
		params.set("subject_kind", "agent");
		params.set("subject", input.agentId.toLowerCase());
	}
	const reason = (input.note ?? "").trim().slice(0, 500);
	if (reason) params.set("reason", reason);
	return `/governance/detection-exceptions?${params.toString()}`;
}

const ERROR_MESSAGES: Readonly<Record<string, DashboardMessageKey>> = {
	mfa_required: "inc.err.mfa",
	incident_role_insufficient: "inc.err.role",
	incident_triage_forbidden: "inc.err.role",
	incident_triage_conflict: "inc.err.conflict",
	incident_not_found: "inc.err.notFound",
	incident_owner_not_member: "inc.err.owner",
	incident_resolution_note_required: "inc.problem.note",
	incident_snooze_closed: "inc.problem.snoozeClosed",
	invalid_snoozed_until: "inc.problem.snoozeFuture",
	incident_triage_unchanged: "inc.err.unchanged",
	rate_limited: "inc.err.rateLimited",
};

export function triageErrorMessage(code: string, t: Translate = englishT): string {
	const key = ERROR_MESSAGES[code];
	return key ? t(key) : t("inc.err.unavailable");
}
