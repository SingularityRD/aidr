// Request parsing and authorization rules for the `ai-governance` Edge
// Function (docs/ai-governance.md). Every mutation is also re-validated and
// re-authorized by its service-role RPC under row locks; this module only
// refuses malformed input early and decides which role and assurance level an
// action needs before any privileged read.

export const AI_GOVERNANCE_MAX_BODY_BYTES = 16_384;

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const DATE = /^\d{4}-\d{2}-\d{2}$/;
const CONTROL_EXCEPT_NEWLINE_TAB = /[\u0000-\u0008\u000b-\u001f\u007f]/;

export type GovernanceRole = "owner" | "admin" | "member" | "viewer";

export type GovernanceAction =
	| "enforcement_preview"
	| "policy_change_detail"
	| "upsert_asset"
	| "import_candidates"
	| "link_evidence"
	| "review_asset"
	| "set_reviewer"
	| "submit_intake"
	| "decide_intake"
	| "request_exception"
	| "decide_exception"
	| "revoke_exception"
	| "cancel_request"
	| "update_settings"
	| "update_browser_guard_settings"
	| "decide_policy_change";

interface ActionRule {
	/** Roles admitted by the Edge Function; the RPC narrows further. */
	roles: readonly GovernanceRole[];
	/** Step-up (AAL2) required even when the tenant's MFA policy is optional. */
	aal2: boolean;
	/** Rate-limit bucket. */
	bucket: "read" | "write" | "import";
}

const OWNER_ADMIN: readonly GovernanceRole[] = ["owner", "admin"];
const CONTRIBUTORS: readonly GovernanceRole[] = ["owner", "admin", "member"];

/**
 * Who may call what. Members reach `decide_intake` and `review_asset` only as
 * designated reviewers (checked by the RPC); requesting and cancelling your own
 * request needs no step-up; every decision and register change does.
 */
export const GOVERNANCE_ACTIONS: Readonly<Record<GovernanceAction, ActionRule>> = Object.freeze({
	enforcement_preview: { roles: ["owner", "admin", "member", "viewer"], aal2: false, bucket: "read" },
	policy_change_detail: { roles: OWNER_ADMIN, aal2: true, bucket: "read" },
	upsert_asset: { roles: OWNER_ADMIN, aal2: true, bucket: "write" },
	import_candidates: { roles: OWNER_ADMIN, aal2: true, bucket: "import" },
	link_evidence: { roles: OWNER_ADMIN, aal2: true, bucket: "write" },
	review_asset: { roles: CONTRIBUTORS, aal2: true, bucket: "write" },
	set_reviewer: { roles: OWNER_ADMIN, aal2: true, bucket: "write" },
	submit_intake: { roles: CONTRIBUTORS, aal2: false, bucket: "write" },
	decide_intake: { roles: CONTRIBUTORS, aal2: true, bucket: "write" },
	request_exception: { roles: CONTRIBUTORS, aal2: false, bucket: "write" },
	decide_exception: { roles: OWNER_ADMIN, aal2: true, bucket: "write" },
	revoke_exception: { roles: OWNER_ADMIN, aal2: true, bucket: "write" },
	cancel_request: { roles: CONTRIBUTORS, aal2: false, bucket: "write" },
	update_settings: { roles: OWNER_ADMIN, aal2: true, bucket: "write" },
	update_browser_guard_settings: { roles: OWNER_ADMIN, aal2: true, bucket: "write" },
	decide_policy_change: { roles: OWNER_ADMIN, aal2: true, bucket: "write" },
});

export const GOVERNANCE_RATE_LIMITS = Object.freeze({
	read: { perSubject: 120, perTenant: 2_000 },
	write: { perSubject: 60, perTenant: 600 },
	import: { perSubject: 5, perTenant: 20 },
});

export type GovernanceCommand =
	| { action: "enforcement_preview" }
	| { action: "policy_change_detail"; requestId: string }
	| { action: "upsert_asset"; assetId: string | null; expectedVersion: number | null; fields: Record<string, unknown> }
	| { action: "import_candidates" }
	| { action: "link_evidence"; assetId: string; kind: string; ref: string; link: boolean }
	| { action: "review_asset"; assetId: string; nextReviewDue: string | null }
	| { action: "set_reviewer"; userId: string; designated: boolean }
	| { action: "submit_intake"; fields: Record<string, unknown> }
	| { action: "decide_intake"; requestId: string; decision: "approve" | "reject"; reason: string }
	| { action: "request_exception"; fields: Record<string, unknown> }
	| { action: "decide_exception"; exceptionId: string; decision: "approve" | "reject"; reason: string }
	| { action: "revoke_exception"; exceptionId: string; reason: string }
	| { action: "cancel_request"; kind: "intake" | "exception" | "policy_change"; requestId: string }
	| { action: "update_settings"; policyFourEyes: boolean | null; defaultReviewDays: number | null }
	| { action: "update_browser_guard_settings"; requireNativeNer: boolean }
	| { action: "decide_policy_change"; requestId: string; decision: "approve" | "reject"; reason: string };

export type ParsedGovernanceRequest =
	| { ok: true; tenantId: string; command: GovernanceCommand }
	| { ok: false; error: string };

export function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function exactKeys(value: Record<string, unknown>, required: readonly string[], optional: readonly string[] = []): boolean {
	const allowed = new Set([...required, ...optional]);
	return required.every((key) => Object.hasOwn(value, key)) && Object.keys(value).every((key) => allowed.has(key));
}

function uuid(value: unknown): string | null {
	return typeof value === "string" && UUID.test(value) ? value.toLowerCase() : null;
}

/** 1..max characters after trimming; newlines and tabs allowed, other controls refused. */
function boundedText(value: unknown, max: number): string | null {
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	if (trimmed.length < 1 || trimmed.length > max || CONTROL_EXCEPT_NEWLINE_TAB.test(trimmed)) return null;
	return trimmed;
}

const ASSET_FIELDS = new Set([
	"asset_type", "identifier", "name", "vendor", "owner_user_id", "business_purpose",
	"data_categories", "risk_tier", "risk_score", "status", "review_due_at",
]);
const INTAKE_FIELDS = new Set([
	"asset_id", "asset_type", "identifier", "name", "vendor", "business_purpose", "data_categories", "requested_status",
]);
const EXCEPTION_FIELDS = new Set([
	"asset_id", "scope_kind", "scope_user_ids", "scope_agent_ids", "justification", "expires_at",
]);

const ASSET_TYPES = ["coding_agent", "mcp_server", "ai_site", "model_service"] as const;
const ASSET_STATUSES = ["proposed", "approved", "restricted", "banned", "retired"] as const;
const RISK_TIERS = ["unassessed", "minimal", "limited", "high", "prohibited"] as const;
const DATA_CATEGORIES = ["personal_data", "special_category", "source_code", "secrets", "customer_data"] as const;
const IDENTIFIER = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$/;

/**
 * Shape-check a field object: only known keys, JSON types the RPC accepts,
 * and bounded text. Values are passed through; the RPC is authoritative.
 */
function fieldObject(value: unknown, allowed: ReadonlySet<string>): Record<string, unknown> | null {
	if (!isRecord(value) || Object.keys(value).length === 0 || Object.keys(value).length > allowed.size) return null;
	const out: Record<string, unknown> = {};
	for (const [key, item] of Object.entries(value)) {
		if (!allowed.has(key)) return null;
		switch (key) {
			case "asset_type":
				if (!(ASSET_TYPES as readonly unknown[]).includes(item)) return null;
				break;
			case "status":
				if (!(ASSET_STATUSES as readonly unknown[]).includes(item)) return null;
				break;
			case "requested_status":
				if (item !== "approved" && item !== "restricted") return null;
				break;
			case "risk_tier":
				if (!(RISK_TIERS as readonly unknown[]).includes(item)) return null;
				break;
			case "scope_kind":
				if (item !== "tenant" && item !== "members" && item !== "agents") return null;
				break;
			case "identifier":
				if (typeof item !== "string" || !IDENTIFIER.test(item)) return null;
				break;
			case "name":
			case "vendor":
				if (item !== null && boundedText(item, 120) === null) return null;
				break;
			case "business_purpose":
			case "justification":
				if (item !== null && boundedText(item, 1000) === null) return null;
				break;
			case "owner_user_id":
			case "asset_id":
				if (item !== null && uuid(item) === null) return null;
				break;
			case "risk_score":
				if (item !== null && (!Number.isSafeInteger(item) || (item as number) < 0 || (item as number) > 100)) return null;
				break;
			case "review_due_at":
				if (item !== null && (typeof item !== "string" || !DATE.test(item))) return null;
				break;
			case "expires_at":
				if (typeof item !== "string" || !Number.isFinite(Date.parse(item))) return null;
				break;
			case "data_categories":
				if (!Array.isArray(item) || item.length > DATA_CATEGORIES.length ||
					!item.every((c) => (DATA_CATEGORIES as readonly unknown[]).includes(c)) ||
					new Set(item).size !== item.length) return null;
				break;
			case "scope_user_ids":
			case "scope_agent_ids":
				if (!Array.isArray(item) || item.length > (key === "scope_user_ids" ? 100 : 200) ||
					!item.every((id) => uuid(id) !== null)) return null;
				break;
			default:
				return null;
		}
		out[key] = typeof item === "string" && key !== "identifier" ? item.trim() : item;
	}
	return out;
}

function decision(value: Record<string, unknown>): { decision: "approve" | "reject"; reason: string } | null {
	if (value.decision !== "approve" && value.decision !== "reject") return null;
	const reason = boundedText(value.reason, 500);
	return reason ? { decision: value.decision, reason } : null;
}

export function parseGovernanceRequest(value: unknown): ParsedGovernanceRequest {
	if (!isRecord(value) || typeof value.action !== "string") return { ok: false, error: "invalid_request" };
	const tenantId = uuid(value.tenant_id);
	if (!tenantId) return { ok: false, error: "invalid_tenant" };
	const action = value.action as GovernanceAction;
	if (!Object.hasOwn(GOVERNANCE_ACTIONS, action)) return { ok: false, error: "invalid_action" };
	const base = ["action", "tenant_id"];
	const done = (command: GovernanceCommand): ParsedGovernanceRequest => ({ ok: true, tenantId, command });
	const invalid: ParsedGovernanceRequest = { ok: false, error: "invalid_request" };

	switch (action) {
		case "enforcement_preview":
		case "import_candidates":
			return exactKeys(value, base) ? done({ action }) : invalid;
		case "policy_change_detail": {
			const requestId = uuid(value.request_id);
			return exactKeys(value, [...base, "request_id"]) && requestId ? done({ action, requestId }) : invalid;
		}
		case "upsert_asset": {
			if (!exactKeys(value, [...base, "fields"], ["asset_id", "expected_version"])) return invalid;
			const assetId = value.asset_id === undefined || value.asset_id === null ? null : uuid(value.asset_id);
			const expectedVersion = value.expected_version === undefined || value.expected_version === null
				? null
				: Number.isSafeInteger(value.expected_version) && (value.expected_version as number) >= 1
					? (value.expected_version as number)
					: undefined;
			if (assetId === null && value.asset_id !== undefined && value.asset_id !== null) return invalid;
			if (expectedVersion === undefined || (assetId === null) !== (expectedVersion === null)) return invalid;
			const fields = fieldObject(value.fields, ASSET_FIELDS);
			if (!fields) return { ok: false, error: "invalid_fields" };
			if (assetId === null && (!fields.asset_type || !fields.identifier || !fields.name)) {
				return { ok: false, error: "invalid_fields" };
			}
			return done({ action, assetId, expectedVersion, fields });
		}
		case "link_evidence": {
			if (!exactKeys(value, [...base, "asset_id", "kind", "ref", "link"])) return invalid;
			const assetId = uuid(value.asset_id);
			const kind = value.kind;
			const ref = typeof value.ref === "string" ? value.ref.toLowerCase() : null;
			const validRef = kind === "approval_request"
				? ref !== null && UUID.test(ref)
				: (kind === "posture_finding" || kind === "incident") && ref !== null && /^[1-9]\d{0,18}$/.test(ref);
			if (!assetId || !validRef || typeof value.link !== "boolean") return invalid;
			return done({ action, assetId, kind: kind as string, ref: ref as string, link: value.link });
		}
		case "review_asset": {
			if (!exactKeys(value, [...base, "asset_id"], ["next_review_due"])) return invalid;
			const assetId = uuid(value.asset_id);
			const next = value.next_review_due === undefined || value.next_review_due === null
				? null
				: typeof value.next_review_due === "string" && DATE.test(value.next_review_due)
					? value.next_review_due
					: undefined;
			return assetId && next !== undefined ? done({ action, assetId, nextReviewDue: next }) : invalid;
		}
		case "set_reviewer": {
			const userId = uuid(value.user_id);
			return exactKeys(value, [...base, "user_id", "designated"]) && userId && typeof value.designated === "boolean"
				? done({ action, userId, designated: value.designated })
				: invalid;
		}
		case "submit_intake":
		case "request_exception": {
			if (!exactKeys(value, [...base, "fields"])) return invalid;
			const fields = fieldObject(value.fields, action === "submit_intake" ? INTAKE_FIELDS : EXCEPTION_FIELDS);
			if (!fields) return { ok: false, error: "invalid_fields" };
			if (action === "submit_intake" && (!fields.business_purpose ||
				(!fields.asset_id && (!fields.asset_type || !fields.identifier || !fields.name)))) {
				return { ok: false, error: "invalid_fields" };
			}
			if (action === "request_exception" && (!fields.asset_id || !fields.justification || !fields.expires_at)) {
				return { ok: false, error: "invalid_fields" };
			}
			return done({ action, fields });
		}
		case "decide_intake":
		case "decide_policy_change": {
			const requestId = uuid(value.request_id);
			const decided = decision(value);
			if (!exactKeys(value, [...base, "request_id", "decision", "reason"]) || !requestId) return invalid;
			if (!decided) return { ok: false, error: "invalid_reason" };
			return done({ action, requestId, ...decided });
		}
		case "decide_exception": {
			const exceptionId = uuid(value.exception_id);
			const decided = decision(value);
			if (!exactKeys(value, [...base, "exception_id", "decision", "reason"]) || !exceptionId) return invalid;
			if (!decided) return { ok: false, error: "invalid_reason" };
			return done({ action, exceptionId, ...decided });
		}
		case "revoke_exception": {
			const exceptionId = uuid(value.exception_id);
			const reason = boundedText(value.reason, 500);
			if (!exactKeys(value, [...base, "exception_id", "reason"]) || !exceptionId) return invalid;
			return reason ? done({ action, exceptionId, reason }) : { ok: false, error: "invalid_reason" };
		}
		case "cancel_request": {
			const requestId = uuid(value.request_id);
			const kind = value.kind;
			return exactKeys(value, [...base, "kind", "request_id"]) && requestId &&
				(kind === "intake" || kind === "exception" || kind === "policy_change")
				? done({ action, kind, requestId })
				: invalid;
		}
		case "update_settings": {
			if (!exactKeys(value, base, ["policy_four_eyes", "default_review_days"])) return invalid;
			const fourEyes = value.policy_four_eyes === undefined ? null : value.policy_four_eyes;
			const days = value.default_review_days === undefined ? null : value.default_review_days;
			if ((fourEyes !== null && typeof fourEyes !== "boolean") ||
				(days !== null && (!Number.isSafeInteger(days) || (days as number) < 30 || (days as number) > 730)) ||
				(fourEyes === null && days === null)) return invalid;
			return done({ action, policyFourEyes: fourEyes as boolean | null, defaultReviewDays: days as number | null });
		}
		case "update_browser_guard_settings":
			return exactKeys(value, [...base, "require_native_ner"]) && typeof value.require_native_ner === "boolean"
				? done({ action, requireNativeNer: value.require_native_ner })
				: invalid;
	}
	return invalid;
}

/** Error codes the RPCs raise that the dashboard can explain; anything else is generic. */
const KNOWN_RPC_ERRORS = new Set([
	"ai_governance_forbidden", "four_eyes_self_approval", "governance_four_eyes_required",
	"governance_reviewer_scope", "policy_forbidden", "ai_asset_not_found", "ai_asset_exists",
	"ai_asset_version_conflict", "ai_asset_identity_immutable", "ai_asset_owner_not_member",
	"ai_asset_prohibited", "ai_asset_already_approved", "ai_asset_evidence_not_found",
	"ai_asset_evidence_source_not_found", "ai_asset_evidence_quota", "ai_governance_enforcement_quota",
	"ai_governance_register_quota", "ai_intake_request_not_found", "ai_intake_request_pending",
	"ai_intake_request_quota", "ai_governance_exception_not_found", "ai_governance_exception_not_restricted",
	"ai_governance_exception_quota", "ai_governance_exception_scope_member", "ai_governance_exception_scope_agent",
	"ai_governance_reviewer_not_member", "ai_governance_reviewer_quota", "ai_governance_request_not_found",
	"four_eyes_requires_two_approvers", "policy_change_request_not_found", "policy_change_request_pending",
	"policy_change_request_quota", "invalid_ai_governance_field", "browser_guard_four_eyes_required",
]);

/** First snake_case token of a Postgres error message, when it is a known code. */
export function governanceErrorCode(message: unknown): string | null {
	if (typeof message !== "string") return null;
	const token = /^([a-z][a-z0-9_]{0,63})/.exec(message)?.[1] ?? null;
	return token && KNOWN_RPC_ERRORS.has(token) ? token : null;
}

export function governanceRpcStatus(code: string | undefined): number {
	switch (code) {
		case "42501":
			return 403;
		case "P0002":
			return 404;
		case "PT409":
		case "23505":
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
