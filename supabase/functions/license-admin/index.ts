// Supabase Edge Function: POST /functions/v1/license-admin
//
// Auth: Authorization: Bearer <supabase_access_token> (AAL2 required)
//
// Tenant side of the signed license import (C11, B9):
//   { action: "submit", tenant_id, license: <aidr-license-v1 document> }
//
// A tenant owner/admin uploads the vendor-signed license file. This function
// verifies the Ed25519 signature against the deployment's trust registry
// (AIDR_LICENSE_PUBLIC_KEYS_B64; unset or empty = refused) with the server's
// clock, refuses a license past its grace period, a license issued for
// another customer (when AIDR_LICENSE_CUSTOMER_ID is set) and any malformed
// or tampered document, then stores it as a PENDING import.
//
// Submitting never changes seats or expiry. A platform operator who is the
// tenant's admission operator and not a member of the tenant applies it from
// the Operator console (operator-admin `apply_license`), which re-verifies
// the document and goes through the existing licensed-admission grant path.
// That keeps the separation of duty of docs/operations/admission-operators.md.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, type EnvReader, loadConfig } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { checkLicenseDocument, licenseSummary, MAX_LICENSE_DOCUMENT_BYTES } from "../_shared/license.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = MAX_LICENSE_DOCUMENT_BYTES + 1024;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const readRuntimeEnv: EnvReader = (name) => {
	try {
		const value = Deno.env.get(name);
		if (value !== undefined && value !== null) return value;
	} catch {
		// Node contract tests use process.env when Deno is unavailable.
	}
	return (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.[name];
};

type DatabaseClient = ReturnType<typeof createClient<any, "public">>;

export interface LicenseAdminDeps {
	env?: EnvReader;
	client?: (url: string, key: string) => DatabaseClient;
	now?: () => number;
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return typeof value === "object" && value !== null && !Array.isArray(value);
}

function rpcFailure(req: Request, error: { code?: string; message?: string }): Response {
	const message = error.message ?? "";
	if (error.code === "42501" && message.includes("license_bound_to_other_tenant")) {
		return corsJson(req, 409, { error: "license_bound_to_other_tenant" });
	}
	if (error.code === "42501") return corsJson(req, 403, { error: "workspace_role_insufficient" });
	if (error.code === "22023") return corsJson(req, 422, { error: "license_rejected", reason: "invalid_document" });
	if (error.code === "40001") return corsJson(req, 409, { error: "license_import_conflict" });
	return corsJson(req, 503, { error: "license_import_unavailable" });
}

export function createLicenseAdminHandler(deps: LicenseAdminDeps = {}) {
	const runtimeEnv = deps.env ?? readRuntimeEnv;
	const now = deps.now ?? Date.now;
	const makeClient = deps.client ?? ((url, key) => createClient(url, key, {
		auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
	}));

	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) {
			return configFailure("license-admin", config.error, (status, body) => corsJson(req, status, body));
		}
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return corsJson(req, parsed.status, { error: parsed.error });
		const body = parsed.value;
		if (!isRecord(body) || body.action !== "submit" || typeof body.tenant_id !== "string" ||
			!UUID.test(body.tenant_id) || !isRecord(body.license) ||
			Object.keys(body).some((key) => !["action", "tenant_id", "license"].includes(key))) {
			return corsJson(req, 400, { error: "invalid_request" });
		}
		const tenantId = body.tenant_id.toLowerCase();

		try {
			const db = makeClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY);
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const barrier = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!barrier.ok) return corsJson(req, barrier.status, { error: barrier.error });

			const { data: member, error: memberError } = await db.from("tenant_members")
				.select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
			if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
			const role = String((member as { role?: unknown } | null)?.role ?? "");
			if (!membershipActive(member as { role?: string; expires_at?: string | null } | null, now())) {
				return corsJson(req, 403, { error: "workspace_forbidden" });
			}
			if (role !== "owner" && role !== "admin") return corsJson(req, 403, { error: "workspace_role_insufficient" });
			const { data: assurance, error: assuranceError } = await db.auth.mfa.getAuthenticatorAssuranceLevel(token);
			if (assuranceError || !assurance) return corsJson(req, 503, { error: "assurance_unavailable" });
			if (assurance.currentLevel !== "aal2") return corsJson(req, 403, { error: "mfa_required" });

			const rate = await consumeTenantRateLimit(db, {
				tenantId,
				subject: userId,
				endpoint: "license-admin",
				perSubject: 10,
				perTenant: 30,
			});
			if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));

			const check = await checkLicenseDocument(body.license, runtimeEnv, now(), "submit");
			if (!check.ok) {
				return corsJson(req, check.status, {
					error: check.error,
					...(check.reason ? { reason: check.reason } : {}),
				}, rateLimitHeaders(rate));
			}
			const { data, error } = await db.rpc("submit_license_import", {
				p_actor_user_id: userId,
				p_tenant_id: tenantId,
				p_document: body.license,
				p_canonical_sha256: check.verified.canonical_sha256,
			});
			if (error) return rpcFailure(req, error);
			if (!isRecord(data) || data.status !== "pending" || !isRecord(data.import) ||
				data.import.canonical_sha256 !== check.verified.canonical_sha256) {
				return corsJson(req, 503, { error: "license_import_unavailable" });
			}
			return corsJson(req, 200, {
				ok: true,
				status: "pending",
				import_id: data.import.id,
				license: licenseSummary(check.verified),
			}, rateLimitHeaders(rate));
		} catch {
			return corsJson(req, 503, { error: "license_import_unavailable" });
		}
	};
}

Deno.serve(createLicenseAdminHandler());
