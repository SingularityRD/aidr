// GET /browser-guard-policy: the signed Browser Guard policy document for one tenant.
//
// Browser Guard installs call this with their telemetry key (an `ingest:browser_guard`
// key, or a tenant key) on every policy refresh. The response carries the tenant's
// Shadow AI allow/block decisions from the AI governance register, and the tenant's
// "require native NER" setting (`require_native_ner`, only when on), inside an Ed25519
// envelope signed with the runtime-policy key (_shared/policy-signature.ts); the
// extension applies it only after verifying the signature against the public keys an
// administrator pinned in its managed policy.
//
// Fail closed throughout: no signing key, an unreadable or malformed overlay or
// settings row, or any
// unexpected error is a 503 and never an unsigned or partial document. The browser
// keeps its last verified document (blocks only once it expires) in that case.
//
// Exceptions: a Browser Guard key is shared by every install it enrolls and is
// readable at chrome://policy, so it is not a member identity. Only tenant-wide
// exceptions (and, for an agent-bound tenant key, that agent's exceptions) apply;
// member-scoped exceptions never waive a ban for every browser.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { authenticateTenantApiKeyBudgeted, BROWSER_GUARD_INGEST_SCOPE } from "../_shared/api-key-auth.ts";
import { getBearerToken } from "../_shared/auth.ts";
import {
	BROWSER_GUARD_POLICY_VERSION,
	browserGuardPolicyFromOverlay,
	browserGuardSettingsFromRow,
} from "../_shared/browser-guard-policy.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { type PlanEntitlementDb, requireFeature } from "../_shared/plan-entitlements.ts";
import { POLICY_SIGNING_UNAVAILABLE, resolvePolicySigning, signRuntimePolicyEnvelope } from "../_shared/policy-signature.ts";
import { consumeTenantRateLimit, rateLimitHeaders } from "../_shared/request-limits.ts";
import { canonicalPolicy, sha256 } from "../_shared/runtime-policy.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
/** Browser Guard refreshes on its own schedule; this is advisory. */
const CACHE_SECONDS = 900;
const TENANT_REQUESTS_PER_MINUTE = 10_000;

const json = (status: number, body: Record<string, unknown>, headers: Record<string, string> = {}) => new Response(JSON.stringify(body), {
	status, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
});

type Result = PromiseLike<{ data: unknown; error: unknown }>;
type Rpc = { rpc(name: string, args: Record<string, unknown>): Result };
type Settings = {
	from(table: "tenant_ai_governance_settings"): {
		select(columns: string): { eq(column: string, value: string): { maybeSingle(): Result } };
	};
};

export function createBrowserGuardPolicyHandler(deps: { db?: ReturnType<typeof createClient>; now?: () => Date } = {}) {
	const now = deps.now ?? (() => new Date());
	return async (req: Request): Promise<Response> => {
		if (req.method !== "GET") return json(405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("browser-guard-policy", config.error, json);
		// The browser ignores an unsigned document, so an unsigned answer is never useful
		// and a half-configured key must not look like "no decisions".
		const signing = resolvePolicySigning(runtimeEnv);
		if (!signing.ok || !signing.config) return json(503, { error: POLICY_SIGNING_UNAVAILABLE });
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return json(401, { error: "missing_api_key" });
		try {
			const db = deps.db ?? createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
			const issuedAt = now();
			const auth = await authenticateTenantApiKeyBudgeted(db, token, "browser-guard-policy", issuedAt.getTime(), {
				allowedScopes: ["tenant", BROWSER_GUARD_INGEST_SCOPE],
			});
			if (!auth.ok) return json(auth.status, { error: auth.error });
			const browserKey = auth.scope === BROWSER_GUARD_INGEST_SCOPE;
			if (browserKey && !auth.apiKeyId) return json(403, { error: "api_key_scope_denied" });
			// Managed Browser Guard is a TEAM feature (_shared/plan-entitlements.ts):
			// checked once the key has bound the tenant, before any budget or read.
			// Fails closed: 402 plan_feature_required, 503 when the plan is unreadable.
			const plan = await requireFeature(db as unknown as PlanEntitlementDb, auth.tenantId, "browser_privacy_guard");
			if (!plan.ok) return json(plan.status, plan.body);
			// One shared Browser Guard key is one subject however many installs use it.
			const perSubject = browserKey ? Math.min(TENANT_REQUESTS_PER_MINUTE, Math.max(60, auth.installLimit ?? 60)) : 300;
			const rate = await consumeTenantRateLimit(db, {
				tenantId: auth.tenantId,
				subject: browserKey ? `api_key:${auth.apiKeyId}` : auth.userId,
				endpoint: "browser-guard-policy",
				perSubject,
				perTenant: TENANT_REQUESTS_PER_MINUTE,
				now: issuedAt.getTime(),
			});
			if (!rate.ok) return json(rate.status, { error: rate.error }, rateLimitHeaders(rate));

			const agentId = !browserKey && typeof auth.agentId === "string" ? auth.agentId : null;
			const [overlay, settings] = await Promise.all([
				(db as unknown as Rpc).rpc("ai_governance_policy_overlay", {
					p_tenant_id: auth.tenantId, p_user_id: null, p_agent_id: agentId,
				}),
				(db as unknown as Settings).from("tenant_ai_governance_settings")
					.select("browser_guard_require_native_ner").eq("tenant_id", auth.tenantId).maybeSingle(),
			]);
			if (overlay.error || settings.error) return json(503, { error: "policy_unavailable" }, rateLimitHeaders(rate));
			const document = browserGuardPolicyFromOverlay(overlay.data, browserGuardSettingsFromRow(settings.data));
			const policySha256 = await sha256(canonicalPolicy(document));
			// Issue time in ms: every fresh answer outranks any earlier one, so a replayed
			// older document is refused by the browser's high-water check.
			const policySigned = await signRuntimePolicyEnvelope({
				tenantId: auth.tenantId,
				policyVersion: BROWSER_GUARD_POLICY_VERSION,
				policySha256,
				sequence: issuedAt.getTime(),
				now: issuedAt,
			}, signing.config);
			if (!policySigned) return json(503, { error: POLICY_SIGNING_UNAVAILABLE }, rateLimitHeaders(rate));
			return json(200, {
				policy_version: BROWSER_GUARD_POLICY_VERSION,
				policy_sha256: policySha256,
				browser_guard: document,
				policy_signed: policySigned,
				cache_seconds: CACHE_SECONDS,
			}, rateLimitHeaders(rate));
		} catch {
			return json(503, { error: "policy_unavailable" });
		}
	};
}

Deno.serve(createBrowserGuardPolicyHandler());
