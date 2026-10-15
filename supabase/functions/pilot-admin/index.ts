// Supabase Edge Function: POST /v1/pilot/admin
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// Admin-only pilot approvals. The caller must be listed in public.pilot_admins.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 16 * 1024;

export interface PilotAdminDeps {
	db?: ReturnType<typeof createClient<any, "public">>;
}

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

function isUuid(s: string): boolean {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
		s.trim(),
	);
}

export function createPilotAdminHandler(deps: PilotAdminDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		if (req.method !== "POST") return json(405, { error: "method_not_allowed" });

		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("pilot-admin", config.error, json);
		const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

		const accessToken = getBearerToken(req);
		if (!accessToken) return json(401, { error: "missing_access_token" });

		const supabase = deps.db ?? createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
			auth: { persistSession: false },
		});
		const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
		if (userErr || !userData?.user?.id) return json(401, { error: "invalid_access_token" });
		const actorId = userData.user.id;
		const identity = await checkIdentityBarrier(supabase, accessToken, actorId);
		if (!identity.ok) return json(identity.status, { error: identity.error });

		const { data: adminRow, error: adminError } = await supabase
			.from("pilot_admins")
			.select("user_id")
			.eq("user_id", actorId)
			.maybeSingle();
		if (adminError) return json(503, { error: "authorization_unavailable" });
		if (!adminRow) return json(403, { error: "forbidden" });

		// Platform-wide approval is always a step-up operation, independent of any
		// tenant's optional MFA policy.
		const { data: assurance, error: assuranceError } =
			await supabase.auth.mfa.getAuthenticatorAssuranceLevel(accessToken);
		if (assuranceError || !assurance) return json(503, { error: "assurance_unavailable" });
		if (assurance.currentLevel !== "aal2") return json(403, { error: "mfa_required" });

		const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsed.ok) return json(parsed.status, { error: parsed.error });
		if (!parsed.value || typeof parsed.value !== "object" || Array.isArray(parsed.value)) return json(400, { error: "invalid_json" });
		const body = parsed.value as Record<string, unknown>;

		const action = typeof body.action === "string" ? body.action.trim() : "";
		if (action !== "approve" && action !== "deny") return json(400, { error: "invalid_action" });

		let targetUserId =
			typeof body.user_id === "string" && isUuid(body.user_id) ? body.user_id.trim().toLowerCase() : "";

		if (!targetUserId) {
			const email = typeof body.email === "string" ? body.email.trim() : "";
			if (!email || !email.includes("@")) return json(400, { error: "missing_target" });
			const { data: mapped } = await supabase.rpc("user_id_by_email", { p_email: email });
			if (typeof mapped === "string" && isUuid(mapped)) targetUserId = mapped.trim().toLowerCase();
		}

		if (!targetUserId) return json(404, { error: "user_not_found" });

		const cohort = typeof body.cohort === "string" ? body.cohort.trim() : null;
		const notes = typeof body.notes === "string" ? body.notes.trim() : null;
		if (body.tenant_id !== undefined && (typeof body.tenant_id !== "string" || !isUuid(body.tenant_id))) {
			return json(400, { error: "invalid_tenant" });
		}
		const requestedTenantId = typeof body.tenant_id === "string" ? body.tenant_id.trim().toLowerCase() : null;
		const status = action === "approve" ? "approved" : "denied";
		const { data, error } = await supabase.rpc("decide_pilot_application", {
			p_actor_user_id: actorId,
			p_target_user_id: targetUserId,
			p_tenant_id: requestedTenantId,
			p_action: action,
			p_cohort: cohort,
			p_notes: notes,
		});
		if (error?.message === "tenant_required") return json(400, { error: "tenant_required" });
		if (error?.message === "tenant_access_denied" || error?.message === "pilot_admin_forbidden") {
			return json(403, { error: "tenant_access_denied" });
		}
		if (error?.message === "user_not_found") return json(404, { error: "user_not_found" });
		if (error || !data || typeof data.tenant_id !== "string" || !isUuid(data.tenant_id) ||
			data.status !== status || (requestedTenantId && data.tenant_id.toLowerCase() !== requestedTenantId)) {
			return json(503, { error: "pilot_application_unavailable" });
		}
		return json(200, { ok: true, user_id: targetUserId, tenant_id: data.tenant_id, status });
	};
}

Deno.serve(createPilotAdminHandler());
