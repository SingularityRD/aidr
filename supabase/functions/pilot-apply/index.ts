// Supabase Edge Function: POST /v1/pilot/apply
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Creates or resets a pilot application for the authenticated user.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

// Same role set submit_pilot_application accepts.
const APPLICANT_ROLES: ReadonlySet<string> = new Set(["owner", "admin", "member", "viewer", "support_jit"]);

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

// Bounds for the intake body. The body carries no identity: the application is
// bound to the verified session below, so the schema accepts only the
// documented application fields and rejects anything else instead of ignoring
// it (a caller must not be able to assert user_id, tenant_id or status).
const MAX_BODY_BYTES = 4096;
const MAX_EMAIL_LENGTH = 320;
const MAX_ORG_LENGTH = 200;
const MAX_USE_CASE_LENGTH = 4000;
const UUID = /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i;
const INTAKE_FIELDS = new Set(["email", "org", "useCase"]);
const CONTROL_CHARACTERS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const EMAIL = /^[^\s@]+@[^\s@.]+(?:\.[^\s@.]+)+$/;
const makeClient = (url: string, key: string) => createClient(url, key, { auth: { persistSession: false } });

type IntakeResult =
	| { ok: true; email: string; org: string | null; useCase: string | null }
	| { ok: false; status: 400; error: string };

function boundedField(value: unknown, max: number): { ok: true; value: string | null } | { ok: false } {
	if (value === undefined || value === null) return { ok: true, value: null };
	if (typeof value !== "string") return { ok: false };
	if (value.length > max || CONTROL_CHARACTERS.test(value)) return { ok: false };
	const trimmed = value.trim();
	return { ok: true, value: trimmed === "" ? null : trimmed };
}

/**
 * Validate the documented intake body.
 *
 * `email` is checked for shape only and is never used to look up an account, so
 * the answer cannot confirm whether an address is already registered.
 */
function parseIntake(body: unknown): IntakeResult {
	if (!body || typeof body !== "object" || Array.isArray(body)) {
		return { ok: false, status: 400, error: "invalid_body" };
	}
	const record = body as Record<string, unknown>;
	for (const key of Object.keys(record)) {
		if (!INTAKE_FIELDS.has(key)) return { ok: false, status: 400, error: "unsupported_field" };
	}
	const email = boundedField(record.email, MAX_EMAIL_LENGTH);
	const org = boundedField(record.org, MAX_ORG_LENGTH);
	const useCase = boundedField(record.useCase, MAX_USE_CASE_LENGTH);
	if (!email.ok || !org.ok || !useCase.ok) return { ok: false, status: 400, error: "invalid_field" };
	if (!email.value || !EMAIL.test(email.value)) return { ok: false, status: 400, error: "invalid_email" };
	return { ok: true, email: email.value, org: org.value, useCase: useCase.value };
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

export interface PilotApplyDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: ReturnType<typeof makeClient>;
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createPilotApplyHandler(deps: PilotApplyDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });

		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("pilot-apply", config.error, (status, body) => corsJson(req, status, body));
		}
		const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

		const accessToken = getBearerToken(req);
		if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

		const supabase = deps.db ?? makeClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
		const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
		if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
		const userId = userData.user.id;
		const tenantId = req.headers.get("X-AIDR-Tenant-ID")?.trim();
		if (!tenantId || !UUID.test(tenantId)) return corsJson(req, 400, { error: "invalid_tenant" });

		const identity = await checkIdentityBarrier(supabase, accessToken, userId, tenantId);
		if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });

		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const intake = parseIntake(parsed.value);
		if (!intake.ok) return corsJson(req, intake.status, { error: intake.error });
		// Membership first: get_tenant_admission is a service-role read, so a
		// non-member must not learn a tenant's admission mode (pilot/cloud/trial)
		// by probing tenant UUIDs. Mirrors submit_pilot_application's own check.
		const [{ data: member, error: memberError }, { data: tenant, error: tenantError }] = await Promise.all([
			supabase.from("tenant_members").select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle(),
			supabase.from("tenants").select("status").eq("id", tenantId).maybeSingle(),
		]);
		if (memberError || tenantError) return corsJson(req, 503, { error: "pilot_application_unavailable" });
		if (!membershipActive(member) || !APPLICANT_ROLES.has(String(member?.role ?? "")) || tenant?.status !== "active") {
			return corsJson(req, 403, { error: "tenant_access_denied" });
		}
		const admission = await supabase.rpc("get_tenant_admission", { p_tenant_id: tenantId, p_user_id: userId });
		if (admission.error || !admission.data || typeof admission.data !== "object" || Array.isArray(admission.data)
			|| typeof admission.data.mode !== "string") {
			return corsJson(req, 503, { error: "pilot_mode_unavailable" });
		}
		if (admission.data.mode !== "pilot") return corsJson(req, 403, { error: "pilot_not_enabled" });
		const { data, error } = await supabase.rpc("submit_pilot_application", {
			p_user_id: userId,
			p_tenant_id: tenantId,
			p_notes: intake.useCase,
		});
		if (error?.message === "tenant_access_denied") {
			return corsJson(req, 403, { error: "tenant_access_denied" });
		}
		if (error?.message === "invalid_pilot_application_state") {
			return corsJson(req, 503, { error: "invalid_pilot_application_state" });
		}
		if (error || !data || !["pending", "approved", "denied"].includes(data.status)) {
			return corsJson(req, 503, { error: "pilot_application_unavailable" });
		}
		return corsJson(req, 200, { ok: true, status: data.status });
	};
}

Deno.serve(createPilotApplyHandler());
