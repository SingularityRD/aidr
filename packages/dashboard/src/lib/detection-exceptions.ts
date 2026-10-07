import { supabase } from "./supabase";

/**
 * Time-limited detection exceptions (docs/configuration.md, "Detection
 * exceptions"): lift one detection rule for one member, agent or repository
 * until an end date at most 30 days ahead.
 *
 * Every call goes through the `detection-exceptions` Edge Function, which
 * requires an owner or admin with AAL2 and whose RPCs re-check and write the
 * audit trail. Connectors receive active exceptions only inside the signed
 * runtime policy. Self-defense rules can never be excepted.
 */

export const DETECTION_EXCEPTION_MAX_DAYS = 30;
export const SUBJECT_KINDS = ["user", "agent", "repo"] as const;
export type SubjectKind = (typeof SUBJECT_KINDS)[number];

export const SUBJECT_LABEL: Readonly<Record<SubjectKind, string>> = {
	user: "Member",
	agent: "Agent",
	repo: "Repository",
};

export interface DetectionExceptionRow {
	id: string;
	ruleId: string;
	artifactSha256: string | null;
	subjectKind: SubjectKind;
	subject: string;
	reason: string;
	createdBy: string;
	createdAt: string;
	expiresAt: string;
	revokedAt: string | null;
	revokeReason: string | null;
}

export type ExceptionState = "active" | "expired" | "revoked";

export type ExceptionsResult<T> = { ok: true; value: T } | { ok: false; error: string };

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RULE_ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,99}$/;
const DIGEST = /^[a-f0-9]{64}$/;

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Self-defense and canary rules: never excepted (the server refuses them too). */
export function isProtectedRule(ruleId: string): boolean {
	const upper = ruleId.trim().toUpperCase();
	return upper.startsWith("CLT-SELF-") || upper.startsWith("CLT-CANARY-");
}

export function exceptionState(row: DetectionExceptionRow, nowMs: number): ExceptionState {
	if (row.revokedAt) return "revoked";
	return Date.parse(row.expiresAt) > nowMs ? "active" : "expired";
}

function parseRow(raw: unknown): DetectionExceptionRow | null {
	if (!isRecord(raw)) return null;
	const kind = raw.subject_kind;
	if (kind !== "user" && kind !== "agent" && kind !== "repo") return null;
	const subject =
		kind === "user"
			? raw.subject_user_id
			: kind === "agent"
				? raw.subject_agent_id
				: raw.subject_repo;
	if (
		typeof raw.id !== "string" ||
		typeof raw.rule_id !== "string" ||
		typeof subject !== "string" ||
		typeof raw.reason !== "string" ||
		typeof raw.created_at !== "string" ||
		typeof raw.expires_at !== "string"
	) {
		return null;
	}
	return {
		id: raw.id,
		ruleId: raw.rule_id,
		artifactSha256: typeof raw.artifact_sha256 === "string" ? raw.artifact_sha256 : null,
		subjectKind: kind,
		subject,
		reason: raw.reason,
		createdBy: typeof raw.created_by === "string" ? raw.created_by : "",
		createdAt: raw.created_at,
		expiresAt: raw.expires_at,
		revokedAt: typeof raw.revoked_at === "string" ? raw.revoked_at : null,
		revokeReason: typeof raw.revoke_reason === "string" ? raw.revoke_reason : null,
	};
}

/** The service's machine-readable error code, if the failed response carried one. */
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
	action: "list" | "create" | "revoke",
	payload: Record<string, unknown> = {},
): Promise<ExceptionsResult<Record<string, unknown>>> {
	try {
		const { data, error } = await supabase.functions.invoke("detection-exceptions", {
			method: "POST",
			body: { action, tenant_id: tenantId, ...payload },
		});
		if (error)
			return { ok: false, error: (await errorCode(error)) ?? "detection_exceptions_unavailable" };
		if (!isRecord(data) || data.ok !== true)
			return { ok: false, error: "detection_exceptions_unavailable" };
		return { ok: true, value: data };
	} catch {
		return { ok: false, error: "detection_exceptions_unavailable" };
	}
}

export async function listDetectionExceptions(
	tenantId: string,
): Promise<ExceptionsResult<DetectionExceptionRow[]>> {
	const result = await invoke(tenantId, "list");
	if (!result.ok) return result;
	const rows = Array.isArray(result.value.exceptions) ? result.value.exceptions : null;
	if (!rows) return { ok: false, error: "detection_exceptions_unavailable" };
	return {
		ok: true,
		value: rows.map(parseRow).filter((row): row is DetectionExceptionRow => row !== null),
	};
}

export interface ExceptionDraft {
	ruleId: string;
	subjectKind: SubjectKind;
	subject: string;
	/** YYYY-MM-DD end date (UTC end of day is NOT assumed: the date's 00:00 UTC). */
	endDate: string;
	reason: string;
	artifactSha256: string;
}

/** A user-facing problem with the draft, or null when it can be sent. */
export function draftProblem(draft: ExceptionDraft, nowMs: number): string | null {
	const ruleId = draft.ruleId.trim();
	if (!RULE_ID.test(ruleId)) return "Enter a rule id such as CLT-CMD-011.";
	if (isProtectedRule(ruleId)) return "Self-defense rules cannot be excepted.";
	const subject = draft.subject.trim();
	if (draft.subjectKind === "repo") {
		if (!subject || subject.length > 512)
			return "Enter the repository (origin remote such as github.com/acme/app).";
	} else if (!UUID.test(subject)) {
		return draft.subjectKind === "user" ? "Choose a workspace member." : "Enter the agent id.";
	}
	const end = Date.parse(`${draft.endDate}T00:00:00.000Z`);
	if (!Number.isFinite(end) || end <= nowMs + 5 * 60_000)
		return "The end date must be in the future.";
	if (end > nowMs + DETECTION_EXCEPTION_MAX_DAYS * 86_400_000) {
		return `An exception can last at most ${DETECTION_EXCEPTION_MAX_DAYS} days.`;
	}
	if (!draft.reason.trim() || draft.reason.trim().length > 500)
		return "A reason (up to 500 characters) is required.";
	const digest = draft.artifactSha256.trim().toLowerCase();
	if (digest && !DIGEST.test(digest))
		return "The artifact digest must be a 64-character SHA-256 hex value.";
	return null;
}

export async function createDetectionException(
	tenantId: string,
	draft: ExceptionDraft,
): Promise<ExceptionsResult<Record<string, unknown>>> {
	const digest = draft.artifactSha256.trim().toLowerCase();
	return invoke(tenantId, "create", {
		rule_id: draft.ruleId.trim(),
		subject_kind: draft.subjectKind,
		subject_value: draft.subject.trim(),
		expires_at: new Date(`${draft.endDate}T00:00:00.000Z`).toISOString(),
		// Single line: the service refuses control characters, newlines included.
		reason: draft.reason.replace(/\s+/g, " ").trim(),
		...(digest ? { artifact_sha256: digest } : {}),
	});
}

export async function revokeDetectionException(
	tenantId: string,
	exceptionId: string,
	reason: string,
): Promise<ExceptionsResult<Record<string, unknown>>> {
	return invoke(tenantId, "revoke", {
		exception_id: exceptionId,
		reason: reason.replace(/\s+/g, " ").trim(),
	});
}

export function exceptionErrorMessage(code: string): string {
	switch (code) {
		case "mfa_required":
			return "Multi-factor verification (AAL2) is required. Verify with your authenticator, then try again.";
		case "sso_required":
			return "This workspace requires single sign-on. Sign in with your identity provider, then try again.";
		case "detection_exception_role_insufficient":
		case "detection_exception_forbidden":
			return "Only workspace owners and admins can manage detection exceptions.";
		case "workspace_forbidden":
			return "You are not an active member of this workspace.";
		case "protected_rule":
		case "detection_exception_protected_rule":
			return "Self-defense rules cannot be excepted.";
		case "detection_exception_subject_unknown":
			return "That member or agent does not belong to this workspace.";
		case "detection_exception_quota":
			return "At most 500 detection exceptions can be active at once.";
		case "detection_exception_not_active":
			return "This exception is no longer active.";
		case "detection_exception_not_found":
			return "This exception no longer exists.";
		case "invalid_expires_at":
			return `The end date must be between 5 minutes and ${DETECTION_EXCEPTION_MAX_DAYS} days from now.`;
		case "rate_limited":
			return "Too many requests. Wait a minute and try again.";
		case "invalid_access_token":
		case "session_revoked":
			return "Your session is no longer valid. Sign in again.";
		default:
			return "The detection exception service did not confirm the request. Nothing changed.";
	}
}
