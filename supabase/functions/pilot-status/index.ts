// Supabase Edge Function: GET /v1/pilot/status
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Returns current pilot application status for the authenticated user.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 2048;
const TENANT_ID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const makeClient = (url: string, key: string) => createClient(url, key, { auth: { persistSession: false } });

type Admission = {
	mode: "unconfigured" | "cloud" | "onprem" | "pilot";
	status: string;
	access_kind: "trial" | "licensed" | "pilot" | null;
	allowed_agents: number;
	expires_at: string | null;
	trial_available: boolean;
};

type LegalDocument = { version: string; sha256: string; url: string };
type LegalDocuments = { configured: boolean; terms: LegalDocument | null; privacy: LegalDocument | null };

function validLegalDocument(value: unknown): value is LegalDocument {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as Record<string, unknown>;
	return typeof row.version === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(row.version)
		&& typeof row.sha256 === "string" && /^[a-f0-9]{64}$/.test(row.sha256)
		&& typeof row.url === "string" && /^https:\/\//.test(row.url);
}

function validLegalDocuments(value: unknown): value is LegalDocuments {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as Record<string, unknown>;
	return row.configured === false && row.terms === null && row.privacy === null
		|| row.configured === true && validLegalDocument(row.terms) && validLegalDocument(row.privacy);
}

function validConsentDocument(value: unknown): value is Pick<LegalDocument, "version" | "sha256"> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as Record<string, unknown>;
	return Object.keys(row).length === 2
		&& typeof row.version === "string" && /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/.test(row.version)
		&& typeof row.sha256 === "string" && /^[a-f0-9]{64}$/.test(row.sha256);
}

function validAdmission(value: unknown): value is Admission {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const row = value as Record<string, unknown>;
	return ["unconfigured", "cloud", "onprem", "pilot"].includes(String(row.mode))
		&& typeof row.status === "string"
		&& (row.access_kind === null || ["trial", "licensed", "pilot"].includes(String(row.access_kind)))
		&& Number.isSafeInteger(row.allowed_agents) && Number(row.allowed_agents) >= 0
		&& (row.expires_at === null || typeof row.expires_at === "string")
		&& typeof row.trial_available === "boolean";
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

export interface PilotStatusDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: ReturnType<typeof makeClient>;
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createPilotStatusHandler(deps: PilotStatusDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("pilot-status", config.error, (status, body) => corsJson(req, status, body));
		}
		const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

		const accessToken = getBearerToken(req);
		if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

		const supabase = deps.db ?? makeClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
		const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
		if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
		const userId = userData.user.id;
		const identity = await checkIdentityBarrier(supabase, accessToken, userId);
		if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
		const requested = req.headers.get("X-AIDR-Tenant-ID")?.trim();
		if (req.method === "POST" && !requested) return corsJson(req, 400, { error: "tenant_required" });
		if (requested) {
			if (!TENANT_ID.test(requested)) return corsJson(req, 400, { error: "invalid_tenant" });
			const tenantIdentity = await checkIdentityBarrier(supabase, accessToken, userId, requested);
			if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error });
			const membership = await supabase.from("tenant_members").select("role,expires_at").eq("tenant_id", requested).eq("user_id", userId).maybeSingle();
			const state = await supabase.from("tenants").select("status").eq("id", requested).maybeSingle();
			if (membership.error || state.error) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (!membershipActive(membership.data) || state.data?.status !== "active") return corsJson(req, 403, { error: "tenant_access_denied" });
			if (req.method === "POST") {
				const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
				if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
				if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)
					|| (parsed.value as Record<string, unknown>).action !== "start_trial") {
					return corsJson(req, 400, { error: "invalid_action" });
				}
				const consent = parsed.value as Record<string, unknown>;
				if (Object.keys(consent).length !== 4 || consent.accepted !== true
					|| !validConsentDocument(consent.terms) || !validConsentDocument(consent.privacy)) {
					return corsJson(req, 400, { error: "legal_consent_required" });
				}
				if (membership.data?.role !== "owner") return corsJson(req, 403, { error: "tenant_role_insufficient" });
				const started = await supabase.rpc("start_verified_trial", { p_user_id: userId, p_tenant_id: requested, p_terms: consent.terms, p_privacy: consent.privacy });
				if (started.error) return corsJson(req, 503, { error: "trial_activation_unavailable" });
				const result = started.data && typeof started.data === "object" && !Array.isArray(started.data)
					? started.data as Record<string, unknown> : null;
				if (result?.status === "legal_not_configured") return corsJson(req, 403, { error: "trial_legal_unavailable" });
				if (result?.status === "legal_documents_changed") return corsJson(req, 409, { error: "legal_documents_changed" });
				if (result?.status === "disabled" || result?.status === "ineligible") {
					return corsJson(req, 403, { error: "trial_not_available" });
				}
				if (result?.status !== "started" && result?.status !== "existing") {
					return corsJson(req, 503, { error: "trial_activation_unavailable" });
				}
			}
			const admissionResult = await supabase.rpc("get_tenant_admission", { p_tenant_id: requested, p_user_id: userId });
			if (admissionResult.error || !validAdmission(admissionResult.data)) {
				return corsJson(req, 503, { error: "admission_unavailable" });
			}
			const admission = admissionResult.data;
			if (req.method === "POST") return corsJson(req, 200, { ok: true, admission });
			// GA admission is independent of the legacy pilot application table.
			// A paid/trial tenant must remain usable when no pilot intake exists.
			if (admission.mode !== "pilot") {
				if (admission.mode === "cloud" && admission.trial_available) {
					const legalResult = await supabase.rpc("get_ga_legal_documents");
					if (legalResult.error || !validLegalDocuments(legalResult.data)) {
						return corsJson(req, 503, { error: "trial_legal_unavailable" });
					}
					return corsJson(req, 200, { ok: true, status: "none", tenant_id: requested,
						admission: { ...admission, trial_available: admission.trial_available && legalResult.data.configured },
						legal: legalResult.data });
				}
				return corsJson(req, 200, { ok: true, status: "none", tenant_id: requested, admission });
			}
			const ownApplication = await supabase
				.from("pilot_applications")
				.select("status,cohort,tenant_id,created_at,updated_at")
				.eq("user_id", userId)
				.eq("tenant_id", requested)
				.maybeSingle();
			if (ownApplication.error) return corsJson(req, 503, { error: "pilot_status_unavailable" });

			// An approved tenant pilot is usable by any active member, even when
			// this caller also has an older pending/denied application in the tenant.
			const approval = await supabase
				.from("pilot_applications")
				.select("status,cohort,tenant_id,created_at,updated_at")
				.eq("tenant_id", requested)
				.eq("status", "approved")
				.limit(1)
				.maybeSingle();
			if (approval.error) return corsJson(req, 503, { error: "pilot_status_unavailable" });
			if (approval.data) return corsJson(req, 200, { ok: true, ...approval.data, admission });
			if (ownApplication.data) return corsJson(req, 200, { ok: true, ...ownApplication.data, admission });
			return corsJson(req, 200, { ok: true, status: "none", tenant_id: requested, admission });
		}

		const { data: applications, error: statusError } = await supabase
			.from("pilot_applications")
			.select("status,cohort,tenant_id,created_at,updated_at")
			.eq("user_id", userId)
			.limit(2);

		if (statusError) return corsJson(req, 503, { error: "pilot_status_unavailable" });
		if (!Array.isArray(applications)) return corsJson(req, 503, { error: "pilot_status_unavailable" });
		if (applications.length > 1) return corsJson(req, 400, { error: "tenant_required" });
		const data = applications[0];
		if (!data) return corsJson(req, 200, { ok: true, status: "none" });
		const tenantIdentity = await checkIdentityBarrier(supabase, accessToken, userId, data.tenant_id);
		if (!tenantIdentity.ok) return corsJson(req, tenantIdentity.status, { error: tenantIdentity.error });
		const membership = await supabase
			.from("tenant_members")
			.select("role,expires_at")
			.eq("tenant_id", data.tenant_id)
			.eq("user_id", userId)
			.maybeSingle();
		const tenant = await supabase.from("tenants").select("status").eq("id", data.tenant_id).maybeSingle();
		if (membership.error || tenant.error) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (!membershipActive(membership.data) || tenant.data?.status !== "active") {
			return corsJson(req, 403, { error: "tenant_access_denied" });
		}
		const approval = await supabase
			.from("pilot_applications")
			.select("status,cohort,tenant_id,created_at,updated_at")
			.eq("tenant_id", data.tenant_id)
			.eq("status", "approved")
			.limit(1)
			.maybeSingle();
		if (approval.error) return corsJson(req, 503, { error: "pilot_status_unavailable" });
		if (approval.data) return corsJson(req, 200, { ok: true, ...approval.data });
		return corsJson(req, 200, { ok: true, ...data });
	};
}

Deno.serve(createPilotStatusHandler());
