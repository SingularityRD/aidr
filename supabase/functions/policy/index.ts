import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { consumeTenantRateLimit, rateLimitHeaders } from "../_shared/request-limits.ts";
import { canonicalPolicy, membershipActive, sha256, validateRuntimePolicy } from "../_shared/runtime-policy.ts";

const json = (status: number, body: Record<string, unknown>, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), {
	status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
});

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

Deno.serve(async (req) => {
	if (req.method !== "GET") return json(405, { error: "method_not_allowed" });
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("policy", config.error, json);
	const token = getBearerToken(req.headers.get("Authorization"));
	if (!token) return json(401, { error: "missing_api_key" });
	try {
		const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
		const { data: key, error } = await db.from("api_keys").select("user_id,tenant_id,revoked,agent_id").eq("key_hash", await sha256(token)).maybeSingle();
		if (error) return json(503, { error: "authorization_unavailable" });
		if (!key || key.revoked) return json(401, { error: "invalid_api_key" });
		const tenant = key.tenant_id;
		const { data: member, error: memberError } = await db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenant).eq("user_id", key.user_id).maybeSingle();
		const { data: state, error: stateError } = await db.from("tenants").select("status").eq("id", tenant).maybeSingle();
		if (memberError || stateError) return json(503, { error: "authorization_unavailable" });
		if (!membershipActive(member) || state?.status !== "active") return json(403, { error: "tenant_access_denied" });
		const rate = await consumeTenantRateLimit(db, {
			tenantId: tenant,
			subject: key.user_id,
			endpoint: "policy",
			perSubject: 300,
			perTenant: 10_000,
		});
		if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));
		let targetVersion: number | null = null;
		if (key.agent_id) {
			const assigned = await db.from("agent_policy_assignments").select("version").eq("tenant_id", tenant).eq("agent_id", key.agent_id).maybeSingle();
			if (assigned.error) return json(503, { error: "policy_unavailable" });
			targetVersion = assigned.data?.version ?? null;
		}
		const query = targetVersion === null ? db.from("tenant_runtime_policies").select("version,policy").eq("tenant_id", tenant) : db.from("runtime_policy_revisions").select("version,policy").eq("tenant_id", tenant).eq("version", targetVersion);
		const { data: policy, error: policyError } = await query.maybeSingle();
		if (policyError) return json(503, { error: "policy_unavailable" });
		if (!policy) return json(404, { error: "policy_not_published" });
		return json(200, { policy_version: String(policy.version), cache_seconds: 30, runtime_policy: validateRuntimePolicy(policy.policy), policy_sha256: await sha256(canonicalPolicy(policy.policy)), agent_bound: !!key.agent_id }, rateLimitHeaders(rate));
	} catch {
		return json(503, { error: "policy_unavailable" });
	}
});
