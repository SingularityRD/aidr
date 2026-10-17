import { createClient, type SupabaseClient } from "npm:@supabase/supabase-js@2.116.0";
import { apiKeyRateSubject, authenticateTenantApiKeyBudgeted } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { canonicalPolicy, sha256, validateRuntimePolicy } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const UUID_PATTERN = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const json = (status: number, body: Record<string, unknown>, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers } });

type PolicyAckDatabase = {
  public: {
    Tables: { runtime_policy_revisions: { Row: { tenant_id: string; version: number; policy: unknown }; Insert: never; Update: never; Relationships: [] } };
    Views: Record<string, never>;
    Functions: { record_policy_receipt: { Args: { p_key_hash: string; p_version: number; p_policy_sha256: string }; Returns: boolean } };
    Enums: Record<string, never>;
    CompositeTypes: Record<string, never>;
  };
};

export interface PolicyAckDeps {
  /** Overrides the service-role client; used by the contract suite. */
  db?: SupabaseClient<PolicyAckDatabase>;
}

/** Build the receipt handler. The production entry point below uses this factory. */
export function createPolicyAckHandler(deps: PolicyAckDeps = {}) {
  return async function handle(req: Request): Promise<Response> {
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
      const db = deps.db ?? createClient<PolicyAckDatabase>(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
      const hash = await sha256(token);
      const tenantAuth = await authenticateTenantApiKeyBudgeted(db, token, "policy-ack");
      if (!tenantAuth.ok) return json(tenantAuth.status, { error: tenantAuth.error });
      const rate = await consumeTenantRateLimit(db, { tenantId: tenantAuth.tenantId, subject: apiKeyRateSubject(tenantAuth), endpoint: "policy-ack", perSubject: 300, perTenant: 10_000 });
      if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));
      const agentId = tenantAuth.agentId;
      if (typeof agentId !== "string" || !UUID_PATTERN.test(agentId)) return json(403, { error: "agent_bound_key_required" });
      const revision = await db.from("runtime_policy_revisions").select("policy").eq("tenant_id", tenantAuth.tenantId).eq("version", version).maybeSingle();
      if (revision.error) return json(503, { error: "policy_unavailable" });
      if (!revision.data) return json(409, { error: "policy_receipt_mismatch" });
      // Match the fetch endpoint's validation before recording adoption. A
      // malformed/corrupted revision must never get a "loaded" receipt merely
      // because its bytes happen to hash to the supplied digest.
      let policy: Record<string, unknown>;
      try { policy = validateRuntimePolicy(revision.data.policy); }
      catch { return json(503, { error: "policy_unavailable" }); }
      if (await sha256(canonicalPolicy(policy)) !== policySha256) return json(409, { error: "policy_receipt_mismatch" });
      const receipt = await db.rpc("record_policy_receipt", { p_key_hash: hash, p_version: version, p_policy_sha256: policySha256 });
      if (receipt.error) return json(503, { error: "receipt_unavailable" });
      return receipt.data === true ? json(200, { ok: true }, rateLimitHeaders(rate)) : json(409, { error: "receipt_rejected" });
    } catch { return json(503, { error: "receipt_unavailable" }); }
  };
}

Deno.serve(createPolicyAckHandler());
