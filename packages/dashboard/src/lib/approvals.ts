import { supabase } from "./supabase";

/**
 * Managed-mode dashboard approvals (docs/contracts/dashboard-approvals.md).
 *
 * Reads go straight to `approval_requests` under RLS: members see their
 * tenant's requests without the token columns, which are never granted to the
 * browser. Decisions and key rotation go through the `approval-requests` Edge
 * Function, which re-checks role, identity barrier and AAL2 on the server.
 */

export type ApprovalStatus = "pending" | "approved" | "denied" | "expired";
export type ApprovalDecision = "approve" | "deny";

export interface ApprovalRequest {
	id: string;
	iid: string;
	agentId: string | null;
	agentRuntime: string | null;
	actionId: string;
	artifactDigest: string;
	tool: string;
	threatIds: string[];
	summary: string;
	/** Stored status with a lapsed pending request shown as expired. */
	status: ApprovalStatus;
	decidedBy: string | null;
	decidedAt: string | null;
	reason: string | null;
	keyId: string | null;
	expiresAt: string;
	createdAt: string;
}

export type ApprovalResult<T> = { ok: true; value: T } | { ok: false; error: string };

export const APPROVAL_COLUMNS =
	"id,iid,agent_id,agent_runtime,action_id,artifact_digest,tool,threat_ids,summary,status,decided_by,decided_at,reason,key_id,expires_at,created_at";
/** The server refuses new requests once a tenant has 500 live pending ones. */
const APPROVAL_PENDING_LIMIT = 500;
const APPROVAL_HISTORY_LIMIT = 200;
export const APPROVAL_REASON_MAX = 500;

const STATUSES: readonly ApprovalStatus[] = ["pending", "approved", "denied", "expired"];

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function nullableString(value: unknown): string | null | undefined {
	if (value === null) return null;
	return typeof value === "string" ? value : undefined;
}

/** Validate one row; a malformed row is dropped rather than rendered. */
export function parseApprovalRow(value: unknown, nowMs: number): ApprovalRequest | null {
	if (!isRecord(value)) return null;
	const {
		id,
		iid,
		action_id,
		artifact_digest,
		tool,
		summary,
		status,
		expires_at,
		created_at,
		threat_ids,
	} = value;
	if (
		typeof id !== "string" ||
		typeof iid !== "string" ||
		typeof action_id !== "string" ||
		typeof artifact_digest !== "string" ||
		typeof tool !== "string" ||
		typeof summary !== "string" ||
		typeof expires_at !== "string" ||
		typeof created_at !== "string" ||
		!STATUSES.includes(status as ApprovalStatus) ||
		!Array.isArray(threat_ids) ||
		!threat_ids.every((item) => typeof item === "string")
	)
		return null;
	const nullable: Record<string, string | null> = {};
	for (const key of ["agent_id", "agent_runtime", "decided_by", "decided_at", "reason", "key_id"]) {
		const item = nullableString(value[key] ?? null);
		if (item === undefined) return null;
		nullable[key] = item;
	}
	const text = (key: string): string | null => nullable[key] ?? null;
	const expiresMs = Date.parse(expires_at);
	if (!Number.isFinite(expiresMs)) return null;
	return {
		id,
		iid,
		agentId: text("agent_id"),
		agentRuntime: text("agent_runtime"),
		actionId: action_id,
		artifactDigest: artifact_digest,
		tool,
		threatIds: threat_ids as string[],
		summary,
		status: status === "pending" && expiresMs <= nowMs ? "expired" : (status as ApprovalStatus),
		decidedBy: text("decided_by"),
		decidedAt: text("decided_at"),
		reason: text("reason"),
		keyId: text("key_id"),
		expiresAt: expires_at,
		createdAt: created_at,
	};
}

function parseRows(data: unknown, nowMs: number): ApprovalRequest[] | null {
	if (!Array.isArray(data)) return null;
	const rows = data.map((row) => parseApprovalRow(row, nowMs));
	return rows.some((row) => row === null) ? null : (rows as ApprovalRequest[]);
}

export interface ApprovalQueue {
	/** Every live (pending, unexpired) request, soonest deadline first. */
	pending: ApprovalRequest[];
	/** Server-side count of live requests matching the pending read. */
	pendingTotal: number;
	/** The newest decided, expired or lapsed requests. */
	history: ApprovalRequest[];
	/** True when older history exists beyond {@link APPROVAL_HISTORY_LIMIT}. */
	historyTruncated: boolean;
}

/**
 * Read the queue as two queries. The pending read uses the same filter as the
 * navigation badge and the server's quota (status = pending, expires_at > now),
 * so the list can never be a subset of a mixed "newest N" window.
 */
export async function loadApprovals(
	tenantId: string,
	nowMs: number = Date.now(),
): Promise<ApprovalResult<ApprovalQueue>> {
	const nowIso = new Date(nowMs).toISOString();
	try {
		const [pendingRead, historyRead] = await Promise.all([
			supabase
				.from("approval_requests")
				.select(APPROVAL_COLUMNS, { count: "exact" })
				.eq("tenant_id", tenantId)
				.eq("status", "pending")
				.gt("expires_at", nowIso)
				.order("expires_at", { ascending: true })
				.limit(APPROVAL_PENDING_LIMIT),
			supabase
				.from("approval_requests")
				.select(APPROVAL_COLUMNS, { count: "exact" })
				.eq("tenant_id", tenantId)
				.or(`status.neq.pending,expires_at.lte.${nowIso}`)
				.order("created_at", { ascending: false })
				.limit(APPROVAL_HISTORY_LIMIT),
		]);
		if (pendingRead.error || historyRead.error)
			return { ok: false, error: "approvals_unavailable" };
		const pending = parseRows(pendingRead.data, nowMs);
		const history = parseRows(historyRead.data, nowMs);
		if (!pending || !history) return { ok: false, error: "approvals_unavailable" };
		const pendingTotal =
			typeof pendingRead.count === "number" && Number.isSafeInteger(pendingRead.count)
				? Math.max(pendingRead.count, pending.length)
				: pending.length;
		const historyTruncated =
			typeof historyRead.count === "number"
				? historyRead.count > history.length
				: history.length >= APPROVAL_HISTORY_LIMIT;
		return { ok: true, value: { pending, pendingTotal, history, historyTruncated } };
	} catch {
		return { ok: false, error: "approvals_unavailable" };
	}
}

/** Pending, unexpired requests for the navigation badge; null when unknown. */
export async function countPendingApprovals(
	tenantId: string,
	nowMs: number = Date.now(),
): Promise<number | null> {
	try {
		const { count, error } = await supabase
			.from("approval_requests")
			.select("id", { count: "exact", head: true })
			.eq("tenant_id", tenantId)
			.eq("status", "pending")
			.gt("expires_at", new Date(nowMs).toISOString());
		if (error || typeof count !== "number" || !Number.isSafeInteger(count) || count < 0)
			return null;
		return count;
	} catch {
		return null;
	}
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

export interface ApprovalDecisionResult {
	status: "approved" | "denied";
	decidedAt: string;
	keyId: string;
	tokenExpiresAt: string;
}

export async function decideApproval(
	tenantId: string,
	requestId: string,
	decision: ApprovalDecision,
	reason: string,
): Promise<ApprovalResult<ApprovalDecisionResult>> {
	try {
		const { data, error } = await supabase.functions.invoke("approval-requests", {
			method: "POST",
			body: { action: "decide", tenant_id: tenantId, request_id: requestId, decision, reason },
		});
		if (error) return { ok: false, error: (await errorCode(error)) ?? "approval_decision_failed" };
		if (
			!isRecord(data) ||
			data.ok !== true ||
			data.request_id !== requestId ||
			(data.status !== "approved" && data.status !== "denied") ||
			typeof data.decided_at !== "string" ||
			typeof data.key_id !== "string" ||
			typeof data.token_expires_at !== "string"
		)
			return { ok: false, error: "approval_decision_failed" };
		return {
			ok: true,
			value: {
				status: data.status,
				decidedAt: data.decided_at,
				keyId: data.key_id,
				tokenExpiresAt: data.token_expires_at,
			},
		};
	} catch {
		return { ok: false, error: "approval_decision_failed" };
	}
}

export async function rotateApprovalSigningKey(
	tenantId: string,
): Promise<ApprovalResult<{ keyId: string; retiredKeyId: string | null }>> {
	try {
		const { data, error } = await supabase.functions.invoke("approval-requests", {
			method: "POST",
			body: { action: "rotate_key", tenant_id: tenantId },
		});
		if (error)
			return { ok: false, error: (await errorCode(error)) ?? "approval_key_rotation_failed" };
		if (!isRecord(data) || data.ok !== true || typeof data.key_id !== "string")
			return { ok: false, error: "approval_key_rotation_failed" };
		return {
			ok: true,
			value: {
				keyId: data.key_id,
				retiredKeyId: typeof data.retired_key_id === "string" ? data.retired_key_id : null,
			},
		};
	} catch {
		return { ok: false, error: "approval_key_rotation_failed" };
	}
}

/**
 * Separation of duties for approvals (CP-9). `configured` is the tenant's
 * explicit choice (null = plan default: Business/Enterprise require a different
 * approver); `effective` is what decide_approval_request enforces.
 */
export type ApprovalSeparation = { configured: boolean | null; effective: boolean };

export async function loadApprovalSeparation(
	tenantId: string,
): Promise<ApprovalResult<ApprovalSeparation>> {
	try {
		const { data, error } = await supabase.rpc("get_approval_settings", { p_tenant_id: tenantId });
		if (
			error ||
			!isRecord(data) ||
			typeof data.effective !== "boolean" ||
			(data.require_distinct_approver !== null &&
				typeof data.require_distinct_approver !== "boolean")
		)
			return { ok: false, error: "approvals_unavailable" };
		return {
			ok: true,
			value: {
				configured: data.require_distinct_approver as boolean | null,
				effective: data.effective,
			},
		};
	} catch {
		return { ok: false, error: "approvals_unavailable" };
	}
}

export async function updateApprovalSeparation(
	tenantId: string,
	requireDistinctApprover: boolean | null,
): Promise<ApprovalResult<ApprovalSeparation>> {
	try {
		const { data, error } = await supabase.functions.invoke("ai-governance", {
			method: "POST",
			body: {
				action: "update_approval_settings",
				tenant_id: tenantId,
				require_distinct_approver: requireDistinctApprover,
			},
		});
		if (error) return { ok: false, error: (await errorCode(error)) ?? "approval_settings_failed" };
		if (!isRecord(data) || data.ok !== true || typeof data.effective !== "boolean")
			return { ok: false, error: "approval_settings_failed" };
		return { ok: true, value: { configured: requireDistinctApprover, effective: data.effective } };
	} catch {
		return { ok: false, error: "approval_settings_failed" };
	}
}

/** "4:05" style countdown; "expired" once the deadline passes. */
export function formatCountdown(expiresAt: string, nowMs: number): string {
	const remaining = Date.parse(expiresAt) - nowMs;
	if (!Number.isFinite(remaining) || remaining <= 0) return "expired";
	const totalSeconds = Math.floor(remaining / 1000);
	const minutes = Math.floor(totalSeconds / 60);
	const seconds = totalSeconds % 60;
	return `${minutes}:${String(seconds).padStart(2, "0")}`;
}
