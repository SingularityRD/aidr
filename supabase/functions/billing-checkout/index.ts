import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive, sha256 } from "../_shared/runtime-policy.ts";
import { checkoutParameters } from "./checkout.ts";

const LEGACY_SELF_SERVICE_ENABLED = (Deno.env.get("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING") ?? "").trim().toLowerCase() === "true";
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "STRIPE_SECRET_KEY", "AIDR_STRIPE_EXTRA_AGENT_PRICE_ID", "AIDR_DASHBOARD_URL"] as const;

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
		try { body = await req.json(); } catch { return corsJson(req, 400, { error: "invalid_json" }); }
		if (!body || typeof body !== "object" || Array.isArray(body)) return corsJson(req, 400, { error: "invalid_request" });
		const tenant = body.tenant_id ?? auth.user.id;
		if (typeof tenant !== "string" || !/^[0-9a-f-]{36}$/i.test(tenant) || typeof body.request_id !== "string" || !/^[a-zA-Z0-9_-]{16,80}$/.test(body.request_id)) return corsJson(req, 400, { error: "invalid_checkout_request" });
		const identity = await checkIdentityBarrier(db, token, auth.user.id, tenant);
		if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
		const { data: member, error: memberError } = await db.from("tenant_members").select("role,expires_at").eq("tenant_id", tenant).eq("user_id", auth.user.id).maybeSingle();
		if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (!membershipActive(member) || !["owner", "admin"].includes(member?.role)) return corsJson(req, 403, { error: "billing_forbidden" });
		const { data: tenantRow, error: tenantError } = await db.from("tenants").select("status").eq("id", tenant).maybeSingle();
		if (tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
		if (tenantRow?.status !== "active") return corsJson(req, 403, { error: "tenant_inactive" });
		let form: URLSearchParams;
		try { form = checkoutParameters({ userId: auth.user.id, tenantId: tenant, seats: body.seats as number, plan: body.plan as string, monthlyPrice: config.values.AIDR_STRIPE_EXTRA_AGENT_PRICE_ID, yearlyPrice: runtimeEnv("AIDR_STRIPE_EXTRA_AGENT_YEARLY_PRICE_ID") ?? undefined, dashboardUrl: config.values.AIDR_DASHBOARD_URL }); }
		catch (error) { return corsJson(req, 400, { error: error instanceof Error ? error.message : "invalid_checkout" }); }
		const response = await fetch("https://api.stripe.com/v1/checkout/sessions", {
			method: "POST", redirect: "error", signal: AbortSignal.timeout(10000),
			headers: { Authorization: `Bearer ${config.values.STRIPE_SECRET_KEY}`, "Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": `aidr-${await sha256(`${auth.user.id}:${tenant}:${body.request_id}`)}` }, body: form,
		});
		if (!response.ok) return corsJson(req, 502, { error: "checkout_provider_unavailable" });
		const checkout = await response.json();
		if (typeof checkout.id !== "string" || typeof checkout.url !== "string" || new URL(checkout.url).origin !== "https://checkout.stripe.com") return corsJson(req, 502, { error: "invalid_checkout_response" });
		return corsJson(req, 200, { ok: true, checkout_id: checkout.id, checkout_url: checkout.url });
	} catch { return corsJson(req, 503, { error: "checkout_unavailable" }); }
});
