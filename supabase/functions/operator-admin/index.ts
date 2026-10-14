// Supabase Edge Function: POST /functions/v1/operator-admin
//
// Auth: Authorization: Bearer <supabase_access_token> (AAL2 required)
//
// Platform-operator control surface: deployment admission mode, GA legal
// documents, licensed tenant admission and a minimal tenant directory. The
// caller must hold an active, unexpired row in public.platform_operators. Every
// action runs one `operator_*` SQL wrapper that re-checks that row inside the
// transaction, delegates to the existing admission RPC and writes an
// actor-attributed admin_audit_logs receipt atomically with the change.
//
// Licensed grants additionally require the tenant-scoped admission_operators
// row enforced by grant_licensed_tenant_admission: platform-operator status
// alone never admits a tenant.
//
// Signed license import (C11/B9): `list_license_imports` shows licenses tenant
// admins staged; `apply_license` re-verifies an aidr-license-v1 document
// against the deployment's trust registry (AIDR_LICENSE_PUBLIC_KEYS_B64) with
// the server clock and applies its signed seats, plan, license id and
// admission end (expires_at + grace_days) through the same grant path.
//
// Callers: scripts/operator-admin.mjs and the dashboard Operator console
// (/operator). Browser calls pass the shared CORS allowlist (AIDR_ALLOWED_ORIGINS);
// the origin check is not an authorization control — every check above still
// runs on each request, and an unlisted origin is refused before any of them.

import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { configFailure, type EnvReader, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { checkLicenseDocument, licenseSummary, MAX_LICENSE_DOCUMENT_BYTES } from "../_shared/license.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
// Large enough for a signed license document plus the action envelope.
const MAX_BODY_BYTES = MAX_LICENSE_DOCUMENT_BYTES + 8 * 1024;
const DEFAULT_PAGE_SIZE = 50;
const MAX_PAGE_SIZE = 200;
const MAX_SEATS = 100_000;

export const OPERATOR_ACTIONS = [
	"configure_admission_mode",
	"configure_legal_documents",
	"grant_license",
	"revoke_license",
	"list_tenants",
	"tenant_usage",
	"list_license_imports",
	"apply_license",
] as const;
export type OperatorAction = (typeof OPERATOR_ACTIONS)[number];

// Route-local schema until generated types include Edge tables and RPCs.
type OperatorRpc = { Args: Record<string, unknown>; Returns: unknown };
type OperatorAdminDatabase = {
	public: {
		Tables: {
			platform_operators: {
				Row: { user_id: string; expires_at: string; revoked_at: string | null };
				Insert: never;
				Update: never;
				Relationships: [];
			};
		};
		Views: Record<string, never>;
		Functions: {
			operator_configure_admission_mode: OperatorRpc;
			operator_configure_legal_documents: OperatorRpc;
			operator_grant_license: OperatorRpc;
			operator_revoke_license: OperatorRpc;
			operator_list_tenants: OperatorRpc;
			operator_tenant_usage: OperatorRpc;
			operator_list_license_imports: OperatorRpc;
			operator_apply_license: OperatorRpc;
		};
		Enums: Record<string, never>;
		CompositeTypes: Record<string, never>;
	};
};
type RpcName = keyof OperatorAdminDatabase["public"]["Functions"];

export interface OperatorAdminDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: SupabaseClient<OperatorAdminDatabase>;
	now?: () => number;
	/** Overrides the environment (license trust registry); used by the contract suite. */
	env?: EnvReader;
}

type Rpc = { name: RpcName; args: Record<string, unknown> };
type Invalid = { error: string };
type Body = Record<string, unknown>;

type Reply = (status: number, body: Record<string, unknown>) => Response;

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const PLAN_ID = /^[a-z][a-z0-9_-]{0,31}$/;
const DOCUMENT_VERSION = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const SHA256 = /^[a-f0-9]{64}$/i;
// Mirrors the app.ga_legal_documents CHECK constraints, which stay authoritative.
const HTTPS_URL = /^https:\/\/[A-Za-z0-9][A-Za-z0-9.-]*(:[0-9]{1,5})?(\/[^#\s]*)?$/;
// Mirrors the SQL `[[:cntrl:]]` bound on references and reasons.
const CONTROL = /[\u0000-\u001f\u007f]/;

function uuid(value: unknown): string | null {
	return typeof value === "string" && UUID.test(value.trim()) ? value.trim().toLowerCase() : null;
}

/** A bounded, single-line operator reference (grant, approval, revocation reason). */
function reference(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	return trimmed.length >= 1 && trimmed.length <= 200 && !CONTROL.test(value) ? trimmed : null;
}

function httpsUrl(value: unknown): string | null {
	if (typeof value !== "string" || value.length < 12 || value.length > 2048) return null;
	if (!HTTPS_URL.test(value) || value.includes("\\")) return null;
	try {
		const parsed = new URL(value);
		return parsed.protocol === "https:" && !parsed.username && !parsed.password ? value : null;
	} catch {
		return null;
	}
}

function legalDocument(value: unknown): { version: string; sha256: string; url: string } | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const doc = value as Record<string, unknown>;
	const url = httpsUrl(doc.url);
	if (typeof doc.version !== "string" || !DOCUMENT_VERSION.test(doc.version)) return null;
	if (typeof doc.sha256 !== "string" || !SHA256.test(doc.sha256) || !url) return null;
	return { version: doc.version, sha256: doc.sha256.toLowerCase(), url };
}

/** Validates one action's body and builds the single RPC that performs it. */
export function planOperatorAction(
	action: OperatorAction,
	body: Body,
	actorId: string,
	now: number,
): Rpc | Invalid {
	switch (action) {
		case "configure_admission_mode": {
			const mode = body.mode;
			if (mode !== "cloud" && mode !== "onprem" && mode !== "pilot") return { error: "invalid_mode" };
			return {
				name: "operator_configure_admission_mode",
				args: { p_actor_user_id: actorId, p_mode: mode },
			};
		}
		case "configure_legal_documents": {
			const terms = legalDocument(body.terms);
			const privacy = legalDocument(body.privacy);
			const approval = reference(body.approval_reference);
			if (!terms || !privacy || !approval) return { error: "invalid_legal_documents" };
			return {
				name: "operator_configure_legal_documents",
				args: {
					p_actor_user_id: actorId,
					p_terms_version: terms.version,
					p_terms_sha256: terms.sha256,
					p_terms_url: terms.url,
					p_privacy_version: privacy.version,
					p_privacy_sha256: privacy.sha256,
					p_privacy_url: privacy.url,
					p_approval_reference: approval,
				},
			};
		}
		case "grant_license": {
			const tenantId = uuid(body.tenant_id);
			if (!tenantId) return { error: "invalid_tenant" };
			if (typeof body.plan_id !== "string" || !PLAN_ID.test(body.plan_id)) return { error: "invalid_plan" };
			const seats = body.seats;
			if (typeof seats !== "number" || !Number.isInteger(seats) || seats < 1 || seats > MAX_SEATS) {
				return { error: "invalid_seats" };
			}
			const expires = typeof body.expires_at === "string" ? Date.parse(body.expires_at) : Number.NaN;
			if (!Number.isFinite(expires) || expires <= now) return { error: "invalid_expiry" };
			const grantReference = reference(body.reference);
			if (!grantReference) return { error: "invalid_reference" };
			let ownerId: string | null = null;
			if (body.owner_user_id !== undefined && body.owner_user_id !== null) {
				ownerId = uuid(body.owner_user_id);
				if (!ownerId) return { error: "invalid_owner" };
			}
			return {
				name: "operator_grant_license",
				args: {
					p_actor_user_id: actorId,
					p_tenant_id: tenantId,
					p_plan_id: body.plan_id,
					p_seats: seats,
					p_expires_at: new Date(expires).toISOString(),
					p_grant_reference: grantReference,
					p_owner_user_id: ownerId,
				},
			};
		}
		case "revoke_license": {
			const tenantId = uuid(body.tenant_id);
			if (!tenantId) return { error: "invalid_tenant" };
			const reason = reference(body.reason);
			if (!reason) return { error: "invalid_reason" };
			return {
				name: "operator_revoke_license",
				args: { p_actor_user_id: actorId, p_tenant_id: tenantId, p_reason: reason },
			};
		}
		case "list_tenants": {
			const limit = body.limit ?? DEFAULT_PAGE_SIZE;
			if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
				return { error: "invalid_page" };
			}
			let after: string | null = null;
			if (body.after !== undefined && body.after !== null) {
				after = uuid(body.after);
				if (!after) return { error: "invalid_page" };
			}
			return {
				name: "operator_list_tenants",
				args: { p_actor_user_id: actorId, p_limit: limit, p_after: after },
			};
		}
		case "tenant_usage": {
			const tenantId = uuid(body.tenant_id);
			if (!tenantId) return { error: "invalid_tenant" };
			return {
				name: "operator_tenant_usage",
				args: { p_actor_user_id: actorId, p_tenant_id: tenantId },
			};
		}
		case "list_license_imports": {
			const limit = body.limit ?? DEFAULT_PAGE_SIZE;
			if (typeof limit !== "number" || !Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE_SIZE) {
				return { error: "invalid_page" };
			}
			return { name: "operator_list_license_imports", args: { p_actor_user_id: actorId, p_limit: limit } };
		}
		case "apply_license": {
			const tenantId = uuid(body.tenant_id);
			if (!tenantId) return { error: "invalid_tenant" };
			if (!isRecord(body.license)) return { error: "invalid_license" };
			let importId: string | null = null;
			if (body.import_id !== undefined && body.import_id !== null) {
				importId = uuid(body.import_id);
				if (!importId) return { error: "invalid_import" };
			}
			let ownerId: string | null = null;
			if (body.owner_user_id !== undefined && body.owner_user_id !== null) {
				ownerId = uuid(body.owner_user_id);
				if (!ownerId) return { error: "invalid_owner" };
			}
			// p_canonical_sha256 is filled in only after the signature verifies.
			return {
				name: "operator_apply_license",
				args: {
					p_actor_user_id: actorId,
					p_tenant_id: tenantId,
					p_import_id: importId,
					p_document: body.license,
					p_canonical_sha256: null,
					p_owner_user_id: ownerId,
				},
			};
		}
	}
}

/** SQL exception message -> caller-visible status and code. Anything else is 503. */
const RPC_ERRORS: Record<string, readonly [number, string]> = {
	platform_operator_forbidden: [403, "forbidden"],
	invalid_admission_mode: [400, "invalid_mode"],
	admission_mode_immutable: [409, "admission_mode_immutable"],
	admission_mode_not_licensed: [409, "admission_mode_not_licensed"],
	invalid_admission_grant: [400, "invalid_grant"],
	invalid_plan: [400, "invalid_plan"],
	tenant_not_found: [404, "tenant_not_found"],
	owner_required: [400, "owner_required"],
	admission_owner_forbidden: [409, "owner_not_eligible"],
	admission_operator_forbidden: [403, "admission_operator_required"],
	tenant_admission_closed: [409, "tenant_closed"],
	invalid_admission_revocation: [400, "invalid_reason"],
	invalid_page: [400, "invalid_page"],
	invalid_license_import: [400, "invalid_license"],
	invalid_license_document: [400, "invalid_license"],
	license_expired: [422, "license_expired"],
	license_not_yet_valid: [422, "license_not_yet_valid"],
	license_import_not_pending: [409, "license_import_not_pending"],
	license_import_mismatch: [409, "license_import_mismatch"],
	license_bound_to_other_tenant: [409, "license_bound_to_other_tenant"],
};

function rpcFailure(json: Reply, action: OperatorAction, error: { message?: unknown; code?: unknown }) {
	const mapped = typeof error.message === "string" ? RPC_ERRORS[error.message] : undefined;
	if (mapped) return json(mapped[0], { error: mapped[1] });
	// The legal-document table CHECK constraints are the authoritative bounds.
	if (action === "configure_legal_documents" && error.code === "23514") {
		return json(400, { error: "invalid_legal_documents" });
	}
	return json(503, { error: "operator_action_unavailable" });
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}

/** Rejects a result that does not match the action, so a drifted RPC never reads as success. */
function validResult(action: OperatorAction, args: Record<string, unknown>, data: unknown): boolean {
	if (!isRecord(data)) return false;
	switch (action) {
		case "configure_admission_mode":
			return (data.status === "configured" || data.status === "already_configured") && data.mode === args.p_mode;
		case "configure_legal_documents":
			return data.status === "configured";
		case "grant_license":
			return data.status === "granted" && data.tenant_id === args.p_tenant_id && data.plan_id === args.p_plan_id;
		case "revoke_license":
			return data.status === "not_active" || (data.status === "revoked" && data.tenant_id === args.p_tenant_id);
		case "list_tenants":
			return Array.isArray(data.tenants) && data.tenants.length <= (args.p_limit as number) &&
				(data.next_cursor === null || uuid(data.next_cursor) !== null);
		case "tenant_usage":
			return isRecord(data.tenant) && data.tenant.id === args.p_tenant_id;
		case "list_license_imports":
			return Array.isArray(data.imports) && data.imports.length <= (args.p_limit as number);
		case "apply_license":
			return data.status === "granted" && data.tenant_id === args.p_tenant_id && isRecord(data.import) &&
				data.import.status === "applied" && data.import.canonical_sha256 === args.p_canonical_sha256;
	}
}

export function createOperatorAdminHandler(deps: OperatorAdminDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		const json: Reply = (status, body) => corsJson(req, status, body);
		if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("operator-admin", config.error, json);
		const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

		const accessToken = getBearerToken(req);
		if (!accessToken) return json(401, { error: "missing_access_token" });

		const supabase = deps.db ?? createClient<OperatorAdminDatabase>(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
			auth: { persistSession: false },
		});
		const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
		if (userErr || !userData?.user?.id) return json(401, { error: "invalid_access_token" });
		const actorId = userData.user.id;
		const identity = await checkIdentityBarrier(supabase, accessToken, actorId);
		if (!identity.ok) return json(identity.status, { error: identity.error });

		const now = deps.now?.() ?? Date.now();
		const { data: operator, error: operatorError } = await supabase
			.from("platform_operators")
			.select("user_id,expires_at,revoked_at")
			.eq("user_id", actorId)
			.maybeSingle();
		if (operatorError) return json(503, { error: "authorization_unavailable" });
		const expiresAt = typeof operator?.expires_at === "string" ? Date.parse(operator.expires_at) : Number.NaN;
		if (!operator || operator.revoked_at !== null || !(expiresAt > now)) {
			return json(403, { error: "forbidden" });
		}

		// Platform-wide administration is always a step-up operation.
		const { data: assurance, error: assuranceError } =
			await supabase.auth.mfa.getAuthenticatorAssuranceLevel(accessToken);
		if (assuranceError || !assurance) return json(503, { error: "assurance_unavailable" });
		if (assurance.currentLevel !== "aal2") return json(403, { error: "mfa_required" });

		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return json(parsed.status, { error: parsed.error });
		if (!isRecord(parsed.value)) return json(400, { error: "invalid_json" });
		const body = parsed.value;

		const action = body.action;
		if (typeof action !== "string" || !(OPERATOR_ACTIONS as readonly string[]).includes(action)) {
			return json(400, { error: "invalid_action" });
		}
		const operatorAction = action as OperatorAction;
		const plan = planOperatorAction(operatorAction, body, actorId, now);
		if ("error" in plan) return json(400, { error: plan.error });

		let license: ReturnType<typeof licenseSummary> | null = null;
		if (operatorAction === "apply_license") {
			// Re-verify at apply time: the registry, a key's status or the clock
			// may have changed since the tenant admin staged the file.
			const check = await checkLicenseDocument(plan.args.p_document, deps.env ?? runtimeEnv, now, "apply");
			if (!check.ok) return json(check.status, { error: check.error, ...(check.reason ? { reason: check.reason } : {}) });
			plan.args.p_canonical_sha256 = check.verified.canonical_sha256;
			license = licenseSummary(check.verified);
		}

		const { data, error } = await supabase.rpc(plan.name, plan.args);
		if (error) return rpcFailure(json, operatorAction, error);
		if (!validResult(operatorAction, plan.args, data)) {
			return json(503, { error: "operator_action_unavailable" });
		}
		return json(200, {
			ok: true,
			action: operatorAction,
			result: license ? { ...(data as Record<string, unknown>), license } : data as Record<string, unknown>,
		});
	};
}

Deno.serve(createOperatorAdminHandler());
