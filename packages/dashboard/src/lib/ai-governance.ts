import type { DashboardMessageKey } from "../i18n/en";
import { englishT, type Translate } from "../i18n/I18nProvider";
import { readAllPages } from "./paged-read";
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
const BROWSER_GUARD_SITES = [
	"chatgpt",
	"gemini",
	"claude",
	"copilot",
	"perplexity",
	"deepseek",
	"mistral",
	"grok",
] as const;

/**
 * Browser Guard Shadow AI catalog id: a banned `ai_site` with such an identifier is
 * delivered to enrolled browsers in the signed `browser-guard-policy` document.
 */
const SHADOW_AI_SERVICE_ID = /^[a-z0-9][a-z0-9-]{0,31}$/;

export type AssetType = (typeof ASSET_TYPES)[number];
export type AssetStatus = (typeof ASSET_STATUSES)[number];
export type RiskTier = (typeof RISK_TIERS)[number];
export type DataCategory = (typeof DATA_CATEGORIES)[number];

/** Catalog keys: render with `t(ASSET_TYPE_LABEL[type])`. */
export const ASSET_TYPE_LABEL: Record<AssetType, DashboardMessageKey> = {
	coding_agent: "gov.type.codingAgent",
	mcp_server: "gov.type.mcpServer",
	ai_site: "gov.type.aiSite",
	model_service: "gov.type.modelService",
};
export const STATUS_LABEL: Record<AssetStatus, DashboardMessageKey> = {
	proposed: "gov.status.proposed",
	approved: "gov.status.approved",
	restricted: "gov.status.restricted",
	banned: "gov.status.banned",
	retired: "gov.status.retired",
};
export const STATUS_BADGE: Record<AssetStatus, string> = {
	proposed: "badge badge-neutral",
	approved: "badge badge-success",
	restricted: "badge badge-warning",
	banned: "badge badge-error",
	retired: "badge badge-neutral",
};
export const RISK_LABEL: Record<RiskTier, DashboardMessageKey> = {
	unassessed: "gov.risk.unassessed",
	minimal: "gov.risk.minimal",
	limited: "gov.risk.limited",
	high: "gov.risk.high",
	prohibited: "gov.risk.prohibited",
};
export const CATEGORY_LABEL: Record<DataCategory, DashboardMessageKey> = {
	personal_data: "gov.cat.personal",
	special_category: "gov.cat.special",
	source_code: "gov.cat.sourceCode",
	secrets: "gov.cat.secrets",
	customer_data: "gov.cat.customer",
};
const SOURCE_LABEL: Record<string, DashboardMessageKey> = {
	manual: "gov.source.manual",
	intake: "gov.source.intake",
	fleet: "gov.source.fleet",
	posture: "gov.source.posture",
	browser_telemetry: "nav.browserGuard",
	discovery: "gov.source.discovery",
};

/** Where a register entry came from; an unknown source is shown as stored. */
export function sourceLabel(source: string, t: Translate = englishT): string {
	const key = Object.hasOwn(SOURCE_LABEL, source) ? SOURCE_LABEL[source] : undefined;
	return key ? t(key) : source;
}

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

type RequestStatus = "pending" | "approved" | "rejected" | "cancelled" | "expired";

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

type ExceptionStatus = "pending" | "approved" | "rejected" | "cancelled" | "revoked" | "expired";

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
	| "agent_profiles_stage"
	| "disable_four_eyes";

type ChangeStatus =
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

interface GovernanceSettings {
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
	/**
	 * Lists that were read only in part. The API caps a response at 1000 rows,
	 * so the register and its evidence are paged up to an explicit bound; a
	 * page must say when rows beyond that bound exist.
	 */
	truncated: { assets: boolean; evidence: boolean };
}

export type GovernanceResult<T> = { ok: true; value: T } | { ok: false; error: string };

const ASSET_COLUMNS =
	"id,asset_type,identifier,name,vendor,owner_user_id,business_purpose,data_categories,risk_tier,risk_score,status,review_due_at,last_reviewed_at,last_reviewed_by,source,first_observed_at,last_observed_at,version,updated_at";
const EVIDENCE_COLUMNS = "id,asset_id,evidence_kind,evidence_ref,label,observed_at,linked_at";
const INTAKE_COLUMNS =
	"id,asset_id,asset_type,identifier,name,vendor,business_purpose,data_categories,requested_status,status,requested_by,created_at,expires_at,decided_by,decided_at,decision_reason";
const EXCEPTION_COLUMNS =
	"id,asset_id,scope_kind,scope_user_ids,scope_agent_ids,justification,status,requested_by,created_at,expires_at,starts_at,decided_by,decision_reason,revoked_by,revoke_reason";
/** Never includes `payload` (not granted to the browser; DLP payloads are sensitive). */
export const CHANGE_COLUMNS =
	"id,change_kind,base_version,target_version,payload_sha256,summary,status,requested_by,created_at,expires_at,decided_by,decided_at,decision_reason,applied_version,outcome_code";
export const REASON_MAX = 500;
export const TEXT_MAX = 1000;
const LIMITS = {
	/** The register quota (`ai_governance_register_quota`): every asset is read. */
	assets: 5000,
	/** Evidence is bounded per asset server-side, not per tenant; read the newest 5000. */
	evidence: 5000,
	intake: 300,
	exceptions: 300,
	changes: 100,
	reviewers: 100,
};

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Thrown by the field readers below; a parser turns it into `null`. */
class MalformedRow extends Error {}

/** Typed field readers over one untrusted row. */
function reader(row: Record<string, unknown>) {
	const fail = (): never => {
		throw new MalformedRow();
	};
	return {
		str: (key: string): string => (typeof row[key] === "string" ? (row[key] as string) : fail()),
		opt: (key: string): string | null =>
			row[key] === null || row[key] === undefined
				? null
				: typeof row[key] === "string"
					? (row[key] as string)
					: fail(),
		int: (key: string): number => (Number.isSafeInteger(row[key]) ? (row[key] as number) : fail()),
		optInt: (key: string): number | null =>
			row[key] === null || row[key] === undefined
				? null
				: Number.isSafeInteger(row[key])
					? (row[key] as number)
					: fail(),
		one: <T extends string>(key: string, values: readonly T[]): T =>
			typeof row[key] === "string" && (values as readonly string[]).includes(row[key] as string)
				? (row[key] as T)
				: fail(),
		strings: (key: string): string[] => {
			const value = row[key];
			return Array.isArray(value) && value.every((item) => typeof item === "string")
				? (value as string[])
				: fail();
		},
		categories: (key: string): DataCategory[] => {
			const value = row[key];
			return Array.isArray(value) &&
				value.every((item) => (DATA_CATEGORIES as readonly unknown[]).includes(item))
				? (value as DataCategory[])
				: fail();
		},
	};
}

function tryParse<T>(value: unknown, build: (read: ReturnType<typeof reader>) => T): T | null {
	if (!isRecord(value)) return null;
	try {
		return build(reader(value));
	} catch (error) {
		if (error instanceof MalformedRow) return null;
		throw error;
	}
}

export function parseAsset(value: unknown): AiAsset | null {
	return tryParse(value, (r) => ({
		id: r.str("id"),
		assetType: r.one("asset_type", ASSET_TYPES),
		identifier: r.str("identifier"),
		name: r.str("name"),
		vendor: r.opt("vendor"),
		ownerUserId: r.opt("owner_user_id"),
		businessPurpose: r.opt("business_purpose"),
		dataCategories: r.categories("data_categories"),
		riskTier: r.one("risk_tier", RISK_TIERS),
		riskScore: r.optInt("risk_score"),
		status: r.one("status", ASSET_STATUSES),
		reviewDueAt: r.opt("review_due_at"),
		lastReviewedAt: r.opt("last_reviewed_at"),
		lastReviewedBy: r.opt("last_reviewed_by"),
		source: r.str("source"),
		firstObservedAt: r.opt("first_observed_at"),
		lastObservedAt: r.opt("last_observed_at"),
		version: r.int("version"),
		updatedAt: r.str("updated_at"),
	}));
}

function parseEvidence(value: unknown): AssetEvidence | null {
	return tryParse(value, (r) => ({
		id: r.str("id"),
		assetId: r.str("asset_id"),
		kind: r.one("evidence_kind", ["posture_finding", "incident", "approval_request"] as const),
		ref: r.str("evidence_ref"),
		label: r.str("label"),
		observedAt: r.opt("observed_at"),
		linkedAt: r.str("linked_at"),
	}));
}

const lapsedAt = (expiresAt: string, nowMs: number) => !(Date.parse(expiresAt) > nowMs);

function parseIntake(value: unknown, nowMs: number): IntakeRequest | null {
	return tryParse(value, (r) => {
		const status = r.one("status", [
			"pending",
			"approved",
			"rejected",
			"cancelled",
			"expired",
		] as const);
		const expiresAt = r.str("expires_at");
		return {
			id: r.str("id"),
			assetId: r.opt("asset_id"),
			assetType: r.one("asset_type", ASSET_TYPES),
			identifier: r.str("identifier"),
			name: r.str("name"),
			vendor: r.opt("vendor"),
			businessPurpose: r.str("business_purpose"),
			dataCategories: r.categories("data_categories"),
			requestedStatus: r.one("requested_status", ["approved", "restricted"] as const),
			status: status === "pending" && lapsedAt(expiresAt, nowMs) ? "expired" : status,
			requestedBy: r.str("requested_by"),
			createdAt: r.str("created_at"),
			expiresAt,
			decidedBy: r.opt("decided_by"),
			decidedAt: r.opt("decided_at"),
			decisionReason: r.opt("decision_reason"),
		};
	});
}

export function parseException(value: unknown, nowMs: number): GovernanceException | null {
	return tryParse(value, (r) => {
		const status = r.one("status", [
			"pending",
			"approved",
			"rejected",
			"cancelled",
			"revoked",
			"expired",
		] as const);
		const expiresAt = r.str("expires_at");
		return {
			id: r.str("id"),
			assetId: r.str("asset_id"),
			scopeKind: r.one("scope_kind", ["tenant", "members", "agents"] as const),
			scopeUserIds: r.strings("scope_user_ids"),
			scopeAgentIds: r.strings("scope_agent_ids"),
			justification: r.str("justification"),
			status:
				(status === "pending" || status === "approved") && lapsedAt(expiresAt, nowMs)
					? "expired"
					: status,
			requestedBy: r.str("requested_by"),
			createdAt: r.str("created_at"),
			expiresAt,
			startsAt: r.opt("starts_at"),
			decidedBy: r.opt("decided_by"),
			decisionReason: r.opt("decision_reason"),
			revokedBy: r.opt("revoked_by"),
			revokeReason: r.opt("revoke_reason"),
		};
	});
}

const CHANGE_KINDS: readonly ChangeKind[] = [
	"runtime_publish",
	"runtime_publish_document",
	"runtime_restore",
	"runtime_stage",
	"runtime_rollout",
	"dlp_publish",
	"agent_profiles_stage",
	"disable_four_eyes",
];

export function parseChange(value: unknown, nowMs: number): PolicyChangeRequest | null {
	return tryParse(value, (r) => {
		const status = r.one("status", [
			"pending",
			"approved",
			"rejected",
			"cancelled",
			"superseded",
			"failed",
			"expired",
		] as const);
		const expiresAt = r.str("expires_at");
		const summary = (value as Record<string, unknown>).summary;
		if (!isRecord(summary) || !Object.values(summary).every((item) => Number.isSafeInteger(item)))
			throw new MalformedRow();
		return {
			id: r.str("id"),
			changeKind: r.one("change_kind", CHANGE_KINDS),
			baseVersion: r.int("base_version"),
			targetVersion: r.optInt("target_version"),
			payloadSha256: r.str("payload_sha256"),
			summary: summary as Record<string, number>,
			status: status === "pending" && lapsedAt(expiresAt, nowMs) ? "expired" : status,
			requestedBy: r.str("requested_by"),
			createdAt: r.str("created_at"),
			expiresAt,
			decidedBy: r.opt("decided_by"),
			decidedAt: r.opt("decided_at"),
			decisionReason: r.opt("decision_reason"),
			appliedVersion: r.optInt("applied_version"),
			outcomeCode: r.opt("outcome_code"),
		};
	});
}

function parseAll<T>(rows: unknown, parse: (row: unknown) => T | null): T[] | null {
	if (!Array.isArray(rows)) return null;
	const parsed = rows.map(parse);
	return parsed.some((row) => row === null) ? null : (parsed as T[]);
}

/** Everything the governance pages show, read under RLS. One malformed row fails the load. */
export async function loadGovernance(
	tenantId: string,
	nowMs: number = Date.now(),
): Promise<GovernanceResult<GovernanceData>> {
	try {
		const [assetPages, evidencePages, intake, exceptions, changes, reviewers, settings] =
			await Promise.all([
				readAllPages(
					(from, to) =>
						supabase
							.from("ai_assets")
							.select(ASSET_COLUMNS, { count: "exact" })
							.eq("tenant_id", tenantId)
							.order("name", { ascending: true })
							.order("id", { ascending: true })
							.range(from, to),
					LIMITS.assets,
				),
				readAllPages(
					(from, to) =>
						supabase
							.from("ai_asset_evidence")
							.select(EVIDENCE_COLUMNS, { count: "exact" })
							.eq("tenant_id", tenantId)
							.order("linked_at", { ascending: false })
							.order("id", { ascending: true })
							.range(from, to),
					LIMITS.evidence,
				),
				supabase
					.from("ai_intake_requests")
					.select(INTAKE_COLUMNS)
					.eq("tenant_id", tenantId)
					.order("created_at", { ascending: false })
					.limit(LIMITS.intake),
				supabase
					.from("ai_governance_exceptions")
					.select(EXCEPTION_COLUMNS)
					.eq("tenant_id", tenantId)
					.order("created_at", { ascending: false })
					.limit(LIMITS.exceptions),
				supabase
					.from("policy_change_requests")
					.select(CHANGE_COLUMNS)
					.eq("tenant_id", tenantId)
					.order("created_at", { ascending: false })
					.limit(LIMITS.changes),
				supabase
					.from("ai_governance_reviewers")
					.select("user_id")
					.eq("tenant_id", tenantId)
					.limit(LIMITS.reviewers),
				supabase
					.from("tenant_ai_governance_settings")
					.select("policy_four_eyes,default_review_days")
					.eq("tenant_id", tenantId)
					.maybeSingle(),
			]);
		if (
			!assetPages.ok ||
			!evidencePages.ok ||
			[intake, exceptions, changes, reviewers, settings].some((result) => result.error)
		) {
			return { ok: false, error: "governance_unavailable" };
		}
		const value = {
			assets: parseAll(assetPages.rows, parseAsset),
			evidence: parseAll(evidencePages.rows, parseEvidence),
			intake: parseAll(intake.data, (row) => parseIntake(row, nowMs)),
			exceptions: parseAll(exceptions.data, (row) => parseException(row, nowMs)),
			changes: parseAll(changes.data, (row) => parseChange(row, nowMs)),
			reviewers: parseAll(reviewers.data, (row) =>
				isRecord(row) && typeof row.user_id === "string" ? row.user_id : null,
			),
		};
		if (Object.values(value).some((item) => item === null))
			return { ok: false, error: "governance_unavailable" };
		const raw = settings.data as {
			policy_four_eyes?: unknown;
			default_review_days?: unknown;
		} | null;
		if (
			raw &&
			(typeof raw.policy_four_eyes !== "boolean" || !Number.isSafeInteger(raw.default_review_days))
		) {
			return { ok: false, error: "governance_unavailable" };
		}
		return {
			ok: true,
			value: {
				...(value as Omit<GovernanceData, "settings" | "truncated">),
				truncated: { assets: assetPages.truncated, evidence: evidencePages.truncated },
				settings: raw
					? {
							policyFourEyes: raw.policy_four_eyes as boolean,
							defaultReviewDays: raw.default_review_days as number,
						}
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
		return isRecord(body) &&
			typeof body.error === "string" &&
			/^[a-z][a-z0-9_]{0,63}$/.test(body.error)
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

export function governanceErrorMessage(code: string, t: Translate = englishT): string {
	switch (code) {
		case "mfa_required":
			return t("gov.err.mfa");
		case "sso_required":
			return t("gov.err.sso");
		case "four_eyes_self_approval":
			return t("gov.err.selfApproval");
		case "governance_four_eyes_required":
			return t("gov.err.fourEyes");
		case "browser_guard_four_eyes_required":
			return t("gov.err.bgFourEyes");
		case "governance_reviewer_scope":
			return t("gov.err.reviewerScope");
		case "governance_role_insufficient":
		case "ai_governance_forbidden":
		case "governance_forbidden":
		case "policy_forbidden":
			return t("gov.err.role");
		case "workspace_forbidden":
			return t("gov.err.notMember");
		case "ai_asset_exists":
			return t("gov.err.assetExists");
		case "ai_asset_version_conflict":
			return t("gov.err.versionConflict");
		case "ai_asset_owner_not_member":
			return t("gov.err.ownerNotMember");
		case "ai_asset_prohibited":
			return t("gov.err.prohibited");
		case "ai_asset_already_approved":
			return t("gov.err.alreadyApproved");
		case "ai_intake_request_pending":
			return t("gov.err.intakePending");
		case "ai_governance_exception_not_restricted":
			return t("gov.err.notRestricted");
		case "four_eyes_requires_two_approvers":
			return t("gov.err.twoApprovers");
		case "ai_governance_enforcement_quota":
			return t("gov.err.quota");
		case "request_final":
			return t("gov.err.final");
		case "request_expired":
			return t("gov.err.expired");
		case "exception_not_active":
			return t("gov.err.exceptionInactive");
		case "policy_change_superseded":
			return t("gov.err.superseded");
		case "policy_change_failed":
			return t("gov.err.changeFailed");
		case "rate_limited":
			return t("gov.err.rateLimited");
		case "invalid_fields":
		case "invalid_request":
		case "invalid_reason":
		case "invalid_ai_governance_field":
			return t("gov.err.invalid");
		case "session_revoked":
		case "invalid_access_token":
			return t("common.sessionInvalid");
		default:
			return t("gov.err.generic");
	}
}

export function stepUpPath(tenantId: string): string {
	return `/auth/dlp-step-up?tenant=${encodeURIComponent(tenantId)}&return=governance`;
}

/** YYYY-MM-DD in UTC. */
function isoDay(ms: number): string {
	return new Date(ms).toISOString().slice(0, 10);
}

export function isReviewOverdue(asset: AiAsset, nowMs: number): boolean {
	return (
		asset.status !== "retired" && asset.reviewDueAt !== null && asset.reviewDueAt < isoDay(nowMs)
	);
}

export type Enforcement = "connector_deny" | "connector_ask" | "browser_block" | "none";

/** What a register status actually changes at enforcement points today. */
export function enforcementOf(
	asset: Pick<AiAsset, "assetType" | "identifier" | "status">,
): Enforcement {
	if (asset.assetType === "mcp_server" && asset.status === "banned") return "connector_deny";
	if (asset.assetType === "mcp_server" && asset.status === "restricted") return "connector_ask";
	if (
		asset.assetType === "ai_site" &&
		asset.status === "banned" &&
		((BROWSER_GUARD_SITES as readonly string[]).includes(asset.identifier) ||
			SHADOW_AI_SERVICE_ID.test(asset.identifier))
	)
		return "browser_block";
	return "none";
}

export const ENFORCEMENT_LABEL: Record<Enforcement, DashboardMessageKey> = {
	connector_deny: "gov.effect.deny",
	connector_ask: "gov.effect.ask",
	browser_block: "gov.effect.browser",
	none: "gov.effect.none",
};

/**
 * A publication filed for four-eyes approval (HTTP 202 from policy-management).
 * Returns operator copy, or null when the response is not a pending change.
 */
export function pendingPolicyChangeNotice(data: unknown, t: Translate = englishT): string | null {
	if (
		!isRecord(data) ||
		data.pending_approval !== true ||
		typeof data.change_request_id !== "string"
	)
		return null;
	return t("governance.pendingChange");
}
