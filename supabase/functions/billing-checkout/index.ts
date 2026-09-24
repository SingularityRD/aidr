import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { consumeTenantRateLimit, rateLimitHeaders, readBoundedJson } from "../_shared/request-limits.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";
import { checkoutParameters } from "./checkout.ts";

const LEGACY_SELF_SERVICE_ENABLED =
	Deno.env.get("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING")?.trim().toLowerCase() === "true" &&
	Deno.env.get("AIDR_BILLING_PROVIDER")?.trim().toLowerCase() === "stripe";
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "STRIPE_SECRET_KEY", "AIDR_STRIPE_EXTRA_AGENT_PRICE_ID", "AIDR_DASHBOARD_URL"] as const;
const MAX_BODY_BYTES = 8192;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const VALIDATION_SETTLEMENT_ID = "00000000-0000-4000-8000-000000000000";

function checkoutUrl(value: unknown): string | null {
	if (typeof value !== "string") return null;
	try {
		const url = new URL(value);
		return url.origin === "https://checkout.stripe.com" && !url.username && !url.password ? value : null;
	} catch { return null; }
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
	if (!LEGACY_SELF_SERVICE_ENABLED) return corsJson(req, 410, { error: "disabled_for_direct_ga" });
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("billing-checkout", config.error, (status, body) => corsJson(req, status, body));
	try {
		const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, { auth: { persistSession: false } });
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });
		const { data: auth, error } = await db.auth.getUser(token);
		if (error || !auth.user) return corsJson(req, 401, { error: "invalid_access_token" });
		let body: Record<string, unknown>;
		const parsedBody = await readBoundedJson(req, MAX_BODY_BYTES);
		if (!parsedBody.ok) return corsJson(req, parsedBody.status, { error: parsedBody.error });
		body = parsedBody.value as Record<string, unknown>;
		if (!body || typeof body !== "object" || Array.isArray(body)) return corsJson(req, 400, { error: "invalid_request" });
		const tenant = body.tenant_id ?? auth.user.id;
		if (typeof tenant !== "string" || !UUID.test(tenant) || typeof body.request_id !== "string" || !/^[a-zA-Z0-9_-]{16,80}$/.test(body.request_id)) return corsJson(req, 400, { error: "invalid_checkout_request" });
		const identity = await checkIdentityBarrier(db, token, auth.user.id, tenant);
		if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
		const { data: member, error: memberError } = await db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenant).eq("user_id", auth.user.id).maybeSingle();
		if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (!membershipActive(member) || !["owner", "admin"].includes(member?.role)) return corsJson(req, 403, { error: "billing_forbidden" });
		const { data: tenantRow, error: tenantError } = await db.from("tenants").select("status").eq("id", tenant).maybeSingle();
		if (tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (tenantRow?.status !== "active") return corsJson(req, 403, { error: "tenant_inactive" });
		const plan = body.plan as string;
		const priceId = plan === "yearly"
			? runtimeEnv("AIDR_STRIPE_EXTRA_AGENT_YEARLY_PRICE_ID") ?? ""
			: config.values.AIDR_STRIPE_EXTRA_AGENT_PRICE_ID;
		const checkoutInput = { userId: auth.user.id, tenantId: tenant, requestId: body.request_id, seats: body.seats as number, plan, monthlyPrice: config.values.AIDR_STRIPE_EXTRA_AGENT_PRICE_ID, yearlyPrice: runtimeEnv("AIDR_STRIPE_EXTRA_AGENT_YEARLY_PRICE_ID") ?? undefined, dashboardUrl: config.values.AIDR_DASHBOARD_URL };
		try { checkoutParameters({ ...checkoutInput, settlementId: VALIDATION_SETTLEMENT_ID }); }
		catch (error) { return corsJson(req, 400, { error: error instanceof Error ? error.message : "invalid_checkout" }); }
		const rate = await consumeTenantRateLimit(db, {
			tenantId: tenant, subject: auth.user.id, endpoint: "billing-checkout",
			perSubject: 5, perTenant: 20,
		});
		if (!rate.ok) return corsJson(req, rate.status, { error: rate.error }, rateLimitHeaders(rate));
		const requestHash = await sha256(`${auth.user.id}\n${tenant}\n${body.request_id}\n${body.seats}\n${plan}\n${priceId}`);
		const { data: intent, error: intentError } = await db.rpc("claim_billing_checkout_intent", {
			p_tenant_id: tenant,
			p_actor_user_id: auth.user.id,
			p_request_id: body.request_id,
			p_request_hash: requestHash,
			p_seats: body.seats,
			p_billing_interval: plan,
			p_price_id: priceId,
		});
		if (intentError?.code === "23505") return corsJson(req, 409, { error: "billing_request_conflict" });
		if (intentError?.code === "42501") return corsJson(req, 403, { error: "billing_forbidden" });
		if (intentError?.code === "22023") return corsJson(req, 400, { error: "invalid_checkout_request" });
		const intentRecord = intent && typeof intent === "object" && !Array.isArray(intent)
			? intent as Record<string, unknown> : null;
		const settlementId = intentRecord?.settlement_id;
		if (intentError || typeof settlementId !== "string") return corsJson(req, 503, { error: "checkout_intent_unavailable" });
		if (intentRecord?.status === "paid") return corsJson(req, 409, { error: "checkout_already_paid" });
		const existingSessionId = intentRecord?.checkout_session_id;
		if (existingSessionId !== null && existingSessionId !== undefined) {
			if (typeof existingSessionId !== "string" || !/^cs_[A-Za-z0-9_]{1,252}$/.test(existingSessionId)) return corsJson(req, 503, { error: "checkout_intent_unavailable" });
			const existingResponse = await fetch(`https://api.stripe.com/v1/checkout/sessions/${existingSessionId}`, {
				method: "GET", redirect: "error", signal: AbortSignal.timeout(10000),
				headers: { Authorization: `Bearer ${config.values.STRIPE_SECRET_KEY}` },
			});
			if (!existingResponse.ok) return corsJson(req, 502, { error: "checkout_provider_unavailable" });
			const existing = await existingResponse.json();
			if (existing?.id !== existingSessionId || existing?.mode !== "subscription" || existing?.client_reference_id !== auth.user.id ||
				existing?.metadata?.user_id !== auth.user.id || existing?.metadata?.tenant_id !== tenant ||
				existing?.metadata?.settlement_id !== settlementId || existing?.metadata?.request_id !== body.request_id) {
				return corsJson(req, 502, { error: "invalid_checkout_response" });
			}
			if (existing.status === "complete") return corsJson(req, 409, { error: "checkout_already_completed" });
			if (existing.status !== "open" || !Number.isSafeInteger(existing.expires_at) || existing.expires_at <= Date.now() / 1000) {
				return corsJson(req, 409, { error: "checkout_session_expired", new_request_required: true });
			}
			const url = checkoutUrl(existing.url);
			if (!url) return corsJson(req, 502, { error: "invalid_checkout_response" });
			return corsJson(req, 200, { ok: true, settlement_id: settlementId, checkout_id: existingSessionId, checkout_url: url });
		}
		let form: URLSearchParams;
		try { form = checkoutParameters({ ...checkoutInput, settlementId }); }
		catch (error) { return corsJson(req, 400, { error: error instanceof Error ? error.message : "invalid_checkout" }); }
		const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
			method: "POST", redirect: "error", signal: AbortSignal.timeout(10000),
			headers: { Authorization: `Bearer ${config.values.STRIPE_SECRET_KEY}`, "Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": `aidr-${requestHash}` }, body: form,
		});
		if (!response.ok) return corsJson(req, 502, { error: "checkout_provider_unavailable" });
		const checkout = await response.json();
		const url = checkoutUrl(checkout?.url);
		if (typeof checkout?.id !== "string" || !url) return corsJson(req, 502, { error: "invalid_checkout_response" });
		const { data: bound, error: bindError } = await db.rpc("bind_billing_checkout_session", {
			p_tenant_id: tenant,
			p_actor_user_id: auth.user.id,
			p_settlement_id: settlementId,
			p_request_id: body.request_id,
			p_checkout_session_id: checkout.id,
		});
		if (bindError || bound !== true) return corsJson(req, 503, { error: "checkout_binding_unavailable" });
		return corsJson(req, 200, { ok: true, settlement_id: settlementId, checkout_id: checkout.id, checkout_url: url });
	} catch { return corsJson(req, 503, { error: "checkout_unavailable" }); }
});
