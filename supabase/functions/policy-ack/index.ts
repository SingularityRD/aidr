import { createClient } from "npm:@supabase/supabase-js@2";
import { authenticateTenantApiKey } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { canonicalPolicy, sha256 } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const json = (status: number, body: Record<string, unknown>, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });
Deno.serve(async (req) => {
  if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
  const config = loadConfig(runtimeEnv, REQUIRED_ENV);
  if (!config.ok) return configFailure("policy-ack", config.error, json);
  const token = getBearerToken(req.headers.get("Authorization"));
  if (!token) return json(401, { error: "missing_api_key" });
  try {
    const parsed = await readBoundedJson(req, 2048);
    if (!parsed.ok) return json(parsed.status, { error: parsed.error });
    const body = parsed.value as Record<string, unknown>;
    const version = body?.version;
    const policySha256 = body?.policy_sha256;
    if (typeof version !== "number" || !Number.isSafeInteger(version) || version < 1 || typeof policySha256 !== "string" || !/^[a-f0-9]{64}$/.test(policySha256)) return json(400, { error: "invalid_receipt" });
    const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
    const hash = await sha256(token);
    const tenantAuth = await authenticateTenantApiKey(db, token);
    if (!tenantAuth.ok) return json(tenantAuth.status, { error: tenantAuth.error });
    const rate = await consumeTenantRateLimit(db, { tenantId: tenantAuth.tenantId, subject: tenantAuth.userId, endpoint: "policy-ack", perSubject: 300, perTenant: 10_000 });
    if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));
    const { data: key, error } = await db.from("api_keys").select("tenant_id,agent_id,revoked").eq("key_hash", hash).maybeSingle();
    if (error) return json(503, { error: "authorization_unavailable" });
    if (!key || key.revoked) return json(401, { error: "invalid_api_key" });
    if (key.tenant_id !== tenantAuth.tenantId) return json(503, { error: "authorization_unavailable" });
    if (!key.agent_id) return json(403, { error: "agent_bound_key_required" });
    const revision = await db.from("runtime_policy_revisions").select("policy").eq("tenant_id", tenantAuth.tenantId).eq("version", version).maybeSingle();
    if (revision.error) return json(503, { error: "policy_unavailable" });
    if (!revision.data || await sha256(canonicalPolicy(revision.data.policy)) !== policySha256) return json(409, { error: "policy_receipt_mismatch" });
    const receipt = await db.rpc("record_policy_receipt", { p_key_hash: hash, p_version: version, p_policy_sha256: policySha256 });
    if (receipt.error) return json(503, { error: "receipt_unavailable" });
    return receipt.data === true ? json(200, { ok: true }, rateLimitHeaders(rate)) : json(409, { error: "receipt_rejected" });
  } catch { return json(503, { error: "receipt_unavailable" }); }
});
