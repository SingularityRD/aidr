import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { apiKeyRateSubject, authenticateTenantApiKeyBudgeted } from "../_shared/api-key-auth.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { consumeTenantRateLimit, rateLimitHeaders } from "../_shared/request-limits.ts";
import { canonicalPolicy, sha256, validateRuntimePolicy } from "../_shared/runtime-policy.ts";
import { POLICY_SIGNING_UNAVAILABLE, policySequence, resolvePolicySigning, type SignedPolicy, signRuntimePolicyEnvelope } from "../_shared/policy-signature.ts";
import { overlayIsEmpty, validateGovernanceOverlay } from "../_shared/governance-overlay.ts";
import { validateDetectionExceptionFeed } from "../_shared/detection-exceptions.ts";
import { type AdmitCredential, type TenantSlotRejection, tenantSlotGate, tenantSlotResponse, withTenantSlot } from "../_shared/tenant-concurrency.ts";

const json = (status: number, body: Record<string, unknown>, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), {
	status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
});

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

function overloaded(rejection: TenantSlotRejection): Response {
	const answer = tenantSlotResponse(rejection);
	return json(answer.status, answer.body, answer.headers);
}

export function createPolicyHandler(deps: {
	db?: ReturnType<typeof createClient>;
	now?: () => Date;
	admitTenantRequest?: AdmitCredential;
} = {}) {
	// Fair-share admission against the leases shared with ingest (AIDR_TENANT_INFLIGHT_*).
	const admitTenantRequest = deps.admitTenantRequest ?? tenantSlotGate(runtimeEnv);
	return async (req: Request): Promise<Response> => {
		if (req.method !== "GET") return json(405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("policy", config.error, json);
		// A half-configured signing key must not silently downgrade to an unsigned policy.
		const signing = resolvePolicySigning(runtimeEnv);
		if (!signing.ok) return json(503, { error: POLICY_SIGNING_UNAVAILABLE });
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return json(401, { error: "missing_api_key" });
		try {
			const db = deps.db ?? createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
			// Fair-share admission (../_shared/tenant-concurrency.ts) for the key
			// lookup and every database read after it.
			return await withTenantSlot(admitTenantRequest, db, token, async () => {
				// The shared hash-only API-key guard rejects revoked keys, expired
				// memberships and non-active tenants before any tenant data is read.
				const auth = await authenticateTenantApiKeyBudgeted(db, token, "policy");
				if (!auth.ok) return json(auth.status, { error: auth.error });
				const tenant = auth.tenantId;
				// The shared guard returns the binding from the row that authenticated the
				// presented hash, including a bounded retired-hash overlap.
				const agentId = typeof auth.agentId === "string" ? auth.agentId : null;
				const rate = await consumeTenantRateLimit(db, {
					tenantId: tenant,
					subject: apiKeyRateSubject(auth),
					endpoint: "policy",
					perSubject: 300,
					perTenant: 10_000,
				});
				if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));
				let targetVersion: number | null = null;
				let assignedAt: string | null = null;
				if (agentId) {
					const assigned = await db.from("agent_policy_assignments").select("version,assigned_at").eq("tenant_id", tenant).eq("agent_id", agentId).maybeSingle() as { data: { version: number; assigned_at?: string } | null; error: unknown };
					if (assigned.error) return json(503, { error: "policy_unavailable" });
					targetVersion = assigned.data?.version ?? null;
					assignedAt = assigned.data?.assigned_at ?? null;
				}
				const query = targetVersion === null ? db.from("tenant_runtime_policies").select("version,policy,updated_at").eq("tenant_id", tenant) : db.from("runtime_policy_revisions").select("version,policy,created_at").eq("tenant_id", tenant).eq("version", targetVersion);
				const { data: policy, error: policyError } = await query.maybeSingle() as { data: { version: number; policy: unknown; updated_at?: string; created_at?: string } | null; error: unknown };
				if (policyError) return json(503, { error: "policy_unavailable" });
				if (!policy) return json(404, { error: "policy_not_published" });
				const runtimePolicy = validateRuntimePolicy(policy.policy);
				const policyVersion = String(policy.version);
				const policySha256 = await sha256(canonicalPolicy(policy.policy));
				const rpc = db as unknown as { rpc(name: string, args: Record<string, unknown>): PromiseLike<{ data: unknown; error: unknown }> };
				// AI governance register bans/restrictions for this member or agent, on
				// top of (never inside) the published policy document. An unreadable
				// overlay fails closed: serving the policy without the bans would relax it.
				const overlayResult = await rpc.rpc("ai_governance_policy_overlay", { p_tenant_id: tenant, p_user_id: auth.userId, p_agent_id: agentId });
				if (overlayResult.error) return json(503, { error: "policy_unavailable" });
				const governance = validateGovernanceOverlay(overlayResult.data);
				// Digest of the overlay as served (the canonical empty overlay when none
				// applies); the signed envelope binds it so the bans cannot be stripped.
				const governanceSha256 = await sha256(canonicalPolicy(governance));
				let policySigned: SignedPolicy | null = null;
				let detectionExceptions: { list: unknown[]; sha256: string } | null = null;
				if (signing.config) {
					// Time-limited detection exceptions for this principal (user- and
					// agent-scoped ones only for the key bound to that user or agent).
					// They only ever relax detection, so they are served ONLY inside a
					// signed response: their digest is bound into the envelope. An
					// unreadable feed fails closed, because dropping it would also drop
					// its change time from the sequence and look like a rollback.
					const feedResult = await rpc.rpc("detection_exceptions_for_principal", { p_tenant_id: tenant, p_user_id: auth.userId, p_agent_id: agentId });
					if (feedResult.error) return json(503, { error: "policy_unavailable" });
					const feed = validateDetectionExceptionFeed(feedResult.data);
					if (!feed) return json(503, { error: "policy_unavailable" });
					if (feed.exceptions.length > 0) {
						detectionExceptions = { list: feed.exceptions, sha256: await sha256(canonicalPolicy(feed.exceptions)) };
					}
					// Monotonic: publish (or assignment) time, so re-publishing older content still advances it;
					// an exception created or revoked later advances it too.
					const sequence = policySequence(policy.updated_at, policy.created_at, assignedAt, feed.changedAt);
					if (sequence === null) return json(503, { error: POLICY_SIGNING_UNAVAILABLE });
					policySigned = await signRuntimePolicyEnvelope({
						tenantId: tenant, policyVersion, policySha256, sequence, governanceSha256, now: (deps.now ?? (() => new Date()))(),
						...(detectionExceptions ? { detectionExceptionsSha256: detectionExceptions.sha256 } : {}),
					}, signing.config);
					if (!policySigned) return json(503, { error: POLICY_SIGNING_UNAVAILABLE });
				}
				return json(200, {
					policy_version: policyVersion, cache_seconds: 30, runtime_policy: runtimePolicy,
					policy_sha256: policySha256, agent_bound: !!agentId,
					...(policySigned ? { policy_signed: policySigned } : {}),
					...(overlayIsEmpty(governance) ? {} : { governance, governance_sha256: governanceSha256 }),
					...(detectionExceptions ? { detection_exceptions: detectionExceptions.list, detection_exceptions_sha256: detectionExceptions.sha256 } : {}),
				}, rateLimitHeaders(rate));
			}, overloaded);
		} catch {
			return json(503, { error: "policy_unavailable" });
		}
	};
}

Deno.serve(createPolicyHandler());
