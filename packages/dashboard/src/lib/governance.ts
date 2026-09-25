import { supabase } from "./supabase";

/**
 * AI governance (docs/ai-governance.md): asset register, intake requests,
 * exceptions, periodic review and four-eyes policy change control.
 *
 * Reads go straight to the governance tables under RLS (members read their
 * tenant's rows; the policy-change payload column is never granted to the
 * browser). Every change goes through the `ai-governance` Edge Function, which
 * re-checks role, identity barrier and AAL2, and whose RPCs re-check again
 * under row locks and write the audit trail.
 */

export const ASSET_TYPES = ["coding_agent", "mcp_server", "ai_site", "model_service"] as const;
export const ASSET_STATUSES = ["proposed", "approved", "restricted", "banned", "retired"] as const;
export const RISK_TIERS = ["unassessed", "minimal", "limited", "high", "prohibited"] as const;
export const DATA_CATEGORIES = [
	"personal_data",
	"special_category",
	"source_code",
	"secrets",
	"customer_data",
] as const;
/** Browser Guard site ids that the managed `blockedSites` policy accepts. */
export const BROWSER_GUARD_SITES = [
	"chatgpt",
	"gemini",
	"claude",
	"copilot",
	"perplexity",
	"deepseek",
	"mistral",
	"grok",
] as const;

export type AssetType = (typeof ASSET_TYPES)[number];
export type AssetStatus = (typeof ASSET_STATUSES)[number];
export type RiskTier = (typeof RISK_TIERS)[number];
export type DataCategory = (typeof DATA_CATEGORIES)[number];

export const ASSET_TYPE_LABEL: Record<AssetType, string> = {
	coding_agent: "Coding agent / connector",
	mcp_server: "MCP server",
	ai_site: "AI chat site / SaaS",
	model_service: "Model / AI service",
};
export const STATUS_LABEL: Record<AssetStatus, string> = {
	proposed: "Proposed",
	approved: "Approved",
	restricted: "Restricted",
	banned: "Banned",
	retired: "Retired",
};
export const STATUS_BADGE: Record<AssetStatus, string> = {
	proposed: "badge badge-neutral",
	approved: "badge badge-success",
	restricted: "badge badge-warning",
	banned: "badge badge-error",
	retired: "badge badge-neutral",
};
export const RISK_LABEL: Record<RiskTier, string> = {
	unassessed: "Not assessed",
	minimal: "Minimal",
	limited: "Limited",
	high: "High",
	prohibited: "Prohibited",
};
export const CATEGORY_LABEL: Record<DataCategory, string> = {
	personal_data: "Personal data",
	special_category: "Special category data",
	source_code: "Source code",
	secrets: "Secrets / credentials",
	customer_data: "Customer data",
};
export const SOURCE_LABEL: Record<string, string> = {
	manual: "Manual",
	intake: "Intake request",
	fleet: "Enrolled agents",
	posture: "MCP inventory",
	browser_telemetry: "Browser Guard",
	discovery: "Discovery",
};

export interface AiAsset {
	id: string;
	assetType: AssetType;
	identifier: string;
	name: string;
	vendor: string | null;
	ownerUserId: string | null;
	businessPurpose: string | null;
	dataCategories: DataCategory[];
	riskTier: RiskTier;
	riskScore: number | null;
	status: AssetStatus;
	reviewDueAt: string | null;
	lastReviewedAt: string | null;
	lastReviewedBy: string | null;
	source: string;
	firstObservedAt: string | null;
	lastObservedAt: string | null;
	version: number;
	updatedAt: string;
}

export interface AssetEvidence {
	id: string;
	assetId: string;
	kind: "posture_finding" | "incident" | "approval_request";
	ref: string;
	label: string;
	observedAt: string | null;
	linkedAt: string;
}

export type RequestStatus = "pending" | "approved" | "rejected" | "cancelled" | "expired";

export interface IntakeRequest {
	id: string;
	assetId: string | null;
	assetType: AssetType;
	identifier: string;
	name: string;
	vendor: string | null;
	businessPurpose: string;
	dataCategories: DataCategory[];
	requestedStatus: "approved" | "restricted";
	/** Stored status with a lapsed pending request shown as expired. */
	status: RequestStatus;
	requestedBy: string;
	createdAt: string;
	expiresAt: string;
	decidedBy: string | null;
	decidedAt: string | null;
	decisionReason: string | null;
}

export type ExceptionStatus = "pending" | "approved" | "rejected" | "cancelled" | "revoked" | "expired";

export interface GovernanceException {
	id: string;
	assetId: string;
	scopeKind: "tenant" | "members" | "agents";
	scopeUserIds: string[];
	scopeAgentIds: string[];
	justification: string;
	/** Stored status with an approved exception past its end shown as expired. */
	status: ExceptionStatus;
	requestedBy: string;
	createdAt: string;
	expiresAt: string;
	startsAt: string | null;
	decidedBy: string | null;
	decisionReason: string | null;
	revokedBy: string | null;
	revokeReason: string | null;
}

export type ChangeKind =
	| "runtime_publish"
	| "runtime_publish_document"
	| "runtime_restore"
	| "runtime_stage"
	| "runtime_rollout"
	| "dlp_publish"
	| "disable_four_eyes";

export type ChangeStatus =
	| "pending"
	| "approved"
	| "rejected"
	| "cancelled"
	| "superseded"
	| "failed"
	| "expired";

export interface PolicyChangeRequest {
	id: string;
	changeKind: ChangeKind;
	baseVersion: number;
	targetVersion: number | null;
	payloadSha256: string;
	summary: Record<string, number>;
	status: ChangeStatus;
	requestedBy: string;
	createdAt: string;
	expiresAt: string;
	decidedBy: string | null;
	decidedAt: string | null;
	decisionReason: string | null;
	appliedVersion: number | null;
	outcomeCode: string | null;
}

export interface GovernanceSettings {
	policyFourEyes: boolean;
	defaultReviewDays: number;
}

export interface GovernanceData {
	assets: AiAsset[];
	evidence: AssetEvidence[];
	intake: IntakeRequest[];
	exceptions: GovernanceException[];
	changes: PolicyChangeRequest[];
	reviewers: string[];
	settings: GovernanceSettings;
}

export type GovernanceResult<T> = { ok: true; value: T } | { ok: false; error: string };

export const ASSET_COLUMNS =
	"id,asset_type,identifier,name,vendor,owner_user_id,business_purpose,data_categories,risk_tier,risk_score,status,review_due_at,last_reviewed_at,last_reviewed_by,source,first_observed_at,last_observed_at,version,updated_at";
export const EVIDENCE_COLUMNS = "id,asset_id,evidence_kind,evidence_ref,label,observed_at,linked_at";
export const INTAKE_COLUMNS =
	"id,asset_id,asset_type,identifier,name,vendor,business_purpose,data_categories,requested_status,status,requested_by,created_at,expires_at,decided_by,decided_at,decision_reason";
export const EXCEPTION_COLUMNS =
	"id,asset_id,scope_kind,scope_user_ids,scope_agent_ids,justification,status,requested_by,created_at,expires_at,starts_at,decided_by,decision_reason,revoked_by,revoke_reason";
/** Never includes `payload` (not granted to the browser; DLP payloads are sensitive). */
export const CHANGE_COLUMNS =
	"id,change_kind,base_version,target_version,payload_sha256,summary,status,requested_by,created_at,expires_at,decided_by,decided_at,decision_reason,applied_version,outcome_code";
export const REASON_MAX = 500;
export const TEXT_MAX = 1000;
const LIMITS = { assets: 2000, evidence: 2000, intake: 300, exceptions: 300, changes: 100, reviewers: 100 };

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function str(value: unknown): string | undefined {
	return typeof value === "string" ? value : undefined;
}

function nullableStr(value: unknown): string | null | undefined {
	if (value === null || value === undefined) return null;
	return typeof value === "string" ? value : undefined;
}

function oneOf<T extends string>(values: readonly T[], value: unknown): T | undefined {
	return typeof value === "string" && (values as readonly string[]).includes(value) ? (value as T) : undefined;
}

function strings(value: unknown): string[] | undefined {
	return Array.isArray(value) && value.every((item) => typeof item === "string") ? (value as string[]) : undefined;
}

function categories(value: unknown): DataCategory[] | undefined {
	const list = strings(value);
	return list?.every((item) => (DATA_CATEGORIES as readonly string[]).includes(item))
		? (list as DataCategory[])
		: undefined;
}

export function parseAsset(value: unknown): AiAsset | null {
	if (!isRecord(value)) return null;
	const assetType = oneOf(ASSET_TYPES, value.asset_type);
	const status = oneOf(ASSET_STATUSES, value.status);
	const riskTier = oneOf(RISK_TIERS, value.risk_tier);
	const dataCategories = categories(value.data_categories);
	const id = str(value.id);
	const identifier = str(value.identifier);
	const name = str(value.name);
	const source = str(value.source);
	const updatedAt = str(value.updated_at);
	const nullable = [
		"vendor", "owner_user_id", "business_purpose", "review_due_at", "last_reviewed_at",
		"last_reviewed_by", "first_observed_at", "last_observed_at",
	].map((key) => nullableStr(value[key]));
	const riskScore = value.risk_score === null || value.risk_score === undefined
		? null
		: Number.isSafeInteger(value.risk_score) ? (value.risk_score as number) : undefined;
	if (!id || !assetType || !status || !riskTier || !dataCategories || !identifier || !name || !source ||
		!updatedAt || !Number.isSafeInteger(value.version) || riskScore === undefined ||
		nullable.some((item) => item === undefined)) return null;
	const [vendor, ownerUserId, businessPurpose, reviewDueAt, lastReviewedAt, lastReviewedBy, firstObservedAt, lastObservedAt] =
		nullable as (string | null)[];
	return {
		id, assetType, identifier, name, vendor, ownerUserId, businessPurpose, dataCategories, riskTier, riskScore,
		status, reviewDueAt, lastReviewedAt, lastReviewedBy, source, firstObservedAt, lastObservedAt,
		version: value.version as number, updatedAt,
	};
}

export function parseEvidence(value: unknown): AssetEvidence | null {
	if (!isRecord(value)) return null;
	const kind = oneOf(["posture_finding", "incident", "approval_request"] as const, value.evidence_kind);
	const observedAt = nullableStr(value.observed_at);
	const id = str(value.id);
	const assetId = str(value.asset_id);
	const ref = str(value.evidence_ref);
	const label = str(value.label);
	const linkedAt = str(value.linked_at);
	if (!kind || observedAt === undefined || !id || !assetId || !ref || !label || !linkedAt) return null;
	return { id, assetId, kind, ref, label, observedAt, linkedAt };
}

export function parseIntake(value: unknown, nowMs: number): IntakeRequest | null {
	if (!isRecord(value)) return null;
	const assetType = oneOf(ASSET_TYPES, value.asset_type);
	const status = oneOf(["pending", "approved", "rejected", "cancelled", "expired"] as const, value.status);
	const requestedStatus = oneOf(["approved", "restricted"] as const, value.requested_status);
	const dataCategories = categories(value.data_categories);
	const nullable = ["asset_id", "vendor", "decided_by", "decided_at", "decision_reason"].map((key) => nullableStr(value[key]));
	const required = ["id", "identifier", "name", "business_purpose", "requested_by", "created_at", "expires_at"].map((key) => str(value[key]));
	if (!assetType || !status || !requestedStatus || !dataCategories || nullable.some((item) => item === undefined) ||
		required.some((item) => item === undefined)) return null;
	const [id, identifier, name, businessPurpose, requestedBy, createdAt, expiresAt] = required as string[];
	const [assetId, vendor, decidedBy, decidedAt, decisionReason] = nullable as (string | null)[];
	const lapsed = status === "pending" && !(Date.parse(expiresAt) > nowMs);
	return {
		id, assetId, assetType, identifier, name, vendor, businessPurpose, dataCategories, requestedStatus,
		status: lapsed ? "expired" : status, requestedBy, createdAt, expiresAt, decidedBy, decidedAt, decisionReason,
	};
}

export function parseException(value: unknown, nowMs: number): GovernanceException | null {
	if (!isRecord(value)) return null;
	const scopeKind = oneOf(["tenant", "members", "agents"] as const, value.scope_kind);
	const status = oneOf(["pending", "approved", "rejected", "cancelled", "revoked", "expired"] as const, value.status);
	const scopeUserIds = strings(value.scope_user_ids);
	const scopeAgentIds = strings(value.scope_agent_ids);
	const nullable = ["starts_at", "decided_by", "decision_reason", "revoked_by", "revoke_reason"].map((key) => nullableStr(value[key]));
	const required = ["id", "asset_id", "justification", "requested_by", "created_at", "expires_at"].map((key) => str(value[key]));
	if (!scopeKind || !status || !scopeUserIds || !scopeAgentIds || nullable.some((item) => item === undefined) ||
		required.some((item) => item === undefined)) return null;
	const [id, assetId, justification, requestedBy, createdAt, expiresAt] = required as string[];
	const [startsAt, decidedBy, decisionReason, revokedBy, revokeReason] = nullable as (string | null)[];
	const lapsed = (status === "approved" || status === "pending") && !(Date.parse(expiresAt) > nowMs);
	return {
		id, assetId, scopeKind, scopeUserIds, scopeAgentIds, justification, status: lapsed ? "expired" : status,
		requestedBy, createdAt, expiresAt, startsAt, decidedBy, decisionReason, revokedBy, revokeReason,
	};
}

const CHANGE_KINDS: readonly ChangeKind[] = [
	"runtime_publish", "runtime_publish_document", "runtime_restore", "runtime_stage", "runtime_rollout",
	"dlp_publish", "disable_four_eyes",
];

export function parseChange(value: unknown, nowMs: number): PolicyChangeRequest | null {
	if (!isRecord(value)) return null;
	const changeKind = oneOf(CHANGE_KINDS, value.change_kind);
	const status = oneOf(["pending", "approved", "rejected", "cancelled", "superseded", "failed", "expired"] as const, value.status);
	const nullable = ["decided_by", "decided_at", "decision_reason", "outcome_code"].map((key) => nullableStr(value[key]));
	const required = ["id", "payload_sha256", "requested_by", "created_at", "expires_at"].map((key) => str(value[key]));
	const summary = isRecord(value.summary) && Object.values(value.summary).every((item) => Number.isSafeInteger(item))
		? (value.summary as Record<string, number>)
		: undefined;
	const targetVersion = value.target_version === null || value.target_version === undefined ? null
		: Number.isSafeInteger(value.target_version) ? (value.target_version as number) : undefined;
	const appliedVersion = value.applied_version === null || value.applied_version === undefined ? null
		: Number.isSafeInteger(value.applied_version) ? (value.applied_version as number) : undefined;
	if (!changeKind || !status || !summary || targetVersion === undefined || appliedVersion === undefined ||
		!Number.isSafeInteger(value.base_version) || nullable.some((item) => item === undefined) ||
		required.some((item) => item === undefined)) return null;
	const [id, payloadSha256, requestedBy, createdAt, expiresAt] = required as string[];
	const [decidedBy, decidedAt, decisionReason, outcomeCode] = nullable as (string | null)[];
	const lapsed = status === "pending" && !(Date.parse(expiresAt) > nowMs);
	return {
		id, changeKind, baseVersion: value.base_version as number, targetVersion, payloadSha256, summary,
		status: lapsed ? "expired" : status, requestedBy, createdAt, expiresAt, decidedBy, decidedAt, decisionReason,
		appliedVersion, outcomeCode,
	};
}

function parseAll<T>(rows: unknown, parse: (row: unknown) => T | null): T[] | null {
	if (!Array.isArray(rows)) return null;
	const parsed = rows.map(parse);
	return parsed.some((row) => row === null) ? null : (parsed as T[]);
}

/** Everything the governance pages show, read under RLS. One malformed row fails the load. */
export async function loadGovernance(tenantId: string, nowMs: number = Date.now()): Promise<GovernanceResult<GovernanceData>> {
	try {
		const [assets, evidence, intake, exceptions, changes, reviewers, settings] = await Promise.all([
			supabase.from("ai_assets").select(ASSET_COLUMNS).eq("tenant_id", tenantId).order("name", { ascending: true }).limit(LIMITS.assets),
			supabase.from("ai_asset_evidence").select(EVIDENCE_COLUMNS).eq("tenant_id", tenantId).order("linked_at", { ascending: false }).limit(LIMITS.evidence),
			supabase.from("ai_intake_requests").select(INTAKE_COLUMNS).eq("tenant_id", tenantId).order("created_at", { ascending: false }).limit(LIMITS.intake),
			supabase.from("ai_governance_exceptions").select(EXCEPTION_COLUMNS).eq("tenant_id", tenantId).order("created_at", { ascending: false }).limit(LIMITS.exceptions),
			supabase.from("policy_change_requests").select(CHANGE_COLUMNS).eq("tenant_id", tenantId).order("created_at", { ascending: false }).limit(LIMITS.changes),
			supabase.from("ai_governance_reviewers").select("user_id").eq("tenant_id", tenantId).limit(LIMITS.reviewers),
			supabase.from("tenant_ai_governance_settings").select("policy_four_eyes,default_review_days").eq("tenant_id", tenantId).maybeSingle(),
		]);
		if ([assets, evidence, intake, exceptions, changes, reviewers, settings].some((result) => result.error)) {
			return { ok: false, error: "governance_unavailable" };
		}
		const value = {
			assets: parseAll(assets.data, parseAsset),
			evidence: parseAll(evidence.data, parseEvidence),
			intake: parseAll(intake.data, (row) => parseIntake(row, nowMs)),
			exceptions: parseAll(exceptions.data, (row) => parseException(row, nowMs)),
			changes: parseAll(changes.data, (row) => parseChange(row, nowMs)),
			reviewers: parseAll(reviewers.data, (row) => (isRecord(row) && typeof row.user_id === "string" ? row.user_id : null)),
		};
		if (Object.values(value).some((item) => item === null)) return { ok: false, error: "governance_unavailable" };
		const raw = settings.data as { policy_four_eyes?: unknown; default_review_days?: unknown } | null;
		if (raw && (typeof raw.policy_four_eyes !== "boolean" || !Number.isSafeInteger(raw.default_review_days))) {
			return { ok: false, error: "governance_unavailable" };
		}
		return {
			ok: true,
			value: {
				...(value as Omit<GovernanceData, "settings">),
				settings: raw
					? { policyFourEyes: raw.policy_four_eyes as boolean, defaultReviewDays: raw.default_review_days as number }
					: { policyFourEyes: false, defaultReviewDays: 180 },
			},
		};
	} catch {
		return { ok: false, error: "governance_unavailable" };
	}
}

/** The service's machine-readable error code, if the failed response carried one. */
async function errorCode(error: unknown): Promise<string | null> {
	const context = (error as { context?: unknown } | null | undefined)?.context;
	if (!(context instanceof Response)) return null;
	try {
		const body: unknown = await context.clone().json();
		return isRecord(body) && typeof body.error === "string" && /^[a-z][a-z0-9_]{0,63}$/.test(body.error)
			? body.error
			: null;
	} catch {
		return null;
	}
}

/** One `ai-governance` call; `payload` carries the action's fields. */
export async function governanceAction(
	tenantId: string,
	action: string,
	payload: Record<string, unknown> = {},
): Promise<GovernanceResult<Record<string, unknown>>> {
	try {
		const { data, error } = await supabase.functions.invoke("ai-governance", {
			method: "POST",
			body: { action, tenant_id: tenantId, ...payload },
		});
		if (error) return { ok: false, error: (await errorCode(error)) ?? "governance_unavailable" };
		if (!isRecord(data) || data.ok !== true) return { ok: false, error: "governance_unavailable" };
		return { ok: true, value: data };
	} catch {
		return { ok: false, error: "governance_unavailable" };
	}
}

export function governanceErrorMessage(code: string): string {
	switch (code) {
		case "mfa_required":
			return "Multi-factor verification (AAL2) is required for this action. Verify with your authenticator, then try again.";
		case "sso_required":
			return "This workspace requires single sign-on. Sign in with your identity provider, then try again.";
		case "four_eyes_self_approval":
			return "You filed this request, so someone else must decide it (four-eyes).";
		case "governance_four_eyes_required":
			return "Four-eyes change control is on: relaxing a ban or restriction needs an intake request decided by another person.";
		case "governance_reviewer_scope":
			return "Designated reviewers cannot lift a ban or restriction; an owner or administrator must decide this request.";
		case "governance_role_insufficient":
		case "ai_governance_forbidden":
		case "governance_forbidden":
		case "policy_forbidden":
			return "Your role cannot perform this action in this workspace.";
		case "workspace_forbidden":
			return "You are not an active member of this workspace.";
		case "ai_asset_exists":
			return "This AI system is already in the register.";
		case "ai_asset_version_conflict":
			return "Someone else changed this entry. Reload and try again.";
		case "ai_asset_owner_not_member":
			return "The owner must be an active member of this workspace.";
		case "ai_asset_prohibited":
			return "A prohibited-tier system cannot be approved or waived; it must stay banned or retired.";
		case "ai_asset_already_approved":
			return "This AI system is already approved.";
		case "ai_intake_request_pending":
			return "A request for this AI system is already pending.";
		case "ai_governance_exception_not_restricted":
			return "Exceptions apply only to banned or restricted systems.";
		case "four_eyes_requires_two_approvers":
			return "Four-eyes needs at least two active owners or administrators in this workspace.";
		case "ai_governance_enforcement_quota":
			return "At most 500 MCP servers can be banned or restricted.";
		case "request_final":
			return "This request was already decided.";
		case "request_expired":
			return "This request expired before it was decided.";
		case "exception_not_active":
			return "This exception is no longer active.";
		case "policy_change_superseded":
			return "The policy changed after this request was filed, so nothing was applied. The author must file a new change.";
		case "policy_change_failed":
			return "The change could not be applied (for example the author is no longer an administrator). Nothing was published.";
		case "rate_limited":
			return "Too many requests. Wait a minute and try again.";
		case "invalid_fields":
		case "invalid_request":
		case "invalid_reason":
		case "invalid_ai_governance_field":
			return "Check the form: a field is missing, too long or not allowed.";
		case "session_revoked":
		case "invalid_access_token":
			return "Your session is no longer valid. Sign in again.";
		default:
			return "The governance service did not confirm the request. Nothing changed.";
	}
}

export function stepUpPath(tenantId: string): string {
	return `/auth/dlp-step-up?tenant=${encodeURIComponent(tenantId)}&return=governance`;
}

/** YYYY-MM-DD in UTC. */
export function isoDay(ms: number): string {
	return new Date(ms).toISOString().slice(0, 10);
}

export function isReviewOverdue(asset: AiAsset, nowMs: number): boolean {
	return asset.status !== "retired" && asset.reviewDueAt !== null && asset.reviewDueAt < isoDay(nowMs);
}

export type Enforcement = "connector_deny" | "connector_ask" | "browser_block" | "none";

/** What a register status actually changes at enforcement points today. */
export function enforcementOf(asset: Pick<AiAsset, "assetType" | "identifier" | "status">): Enforcement {
	if (asset.assetType === "mcp_server" && asset.status === "banned") return "connector_deny";
	if (asset.assetType === "mcp_server" && asset.status === "restricted") return "connector_ask";
	if (asset.assetType === "ai_site" && asset.status === "banned" &&
		(BROWSER_GUARD_SITES as readonly string[]).includes(asset.identifier)) return "browser_block";
	return "none";
}

export const ENFORCEMENT_LABEL: Record<Enforcement, string> = {
	connector_deny: "Blocked by connectors",
	connector_ask: "Connectors ask for approval",
	browser_block: "Browser Guard blockedSites (deploy via browser management)",
	none: "Register only",
};

/**
 * A publication filed for four-eyes approval (HTTP 202 from policy-management).
 * Returns operator copy, or null when the response is not a pending change.
 */
export function pendingPolicyChangeNotice(data: unknown): string | null {
	if (!isRecord(data) || data.pending_approval !== true || typeof data.change_request_id !== "string") return null;
	return "Four-eyes change control is on: nothing was published. The change is waiting for a second owner or administrator under AI governance → Change control.";
}
