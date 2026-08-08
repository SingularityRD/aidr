// Supabase Edge Function: GET /v1/billing/checkout
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// v1: returns a configured Paddle checkout URL. The checkout itself is managed in Paddle.
// Webhooks will reconcile entitlements based on custom_data.user_id if present, otherwise best-effort by email.

import { createClient } from "npm:@supabase/supabase-js@2";
import { corsJson, handleCors } from "../_shared/cors.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

// Direct-GA is invoice/order based. Keep the historical checkout endpoint
// unreachable unless a separately approved commercial decision explicitly
// enables the legacy path in the deployed environment.
const LEGACY_SELF_SERVICE_ENABLED =
	(Deno.env.get("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING") ?? "").trim().toLowerCase() === "true";

const PADDLE_CHECKOUT_URL = (Deno.env.get("AIDR_PADDLE_CHECKOUT_URL") ?? "").trim();

function getBearerToken(req: Request): string | null {
	const header = req.headers.get("Authorization") ?? "";
	const m = header.match(/^Bearer\s+(.+)$/i);
	return m?.[1]?.trim() ? m[1].trim() : null;
}

Deno.serve(async (req) => {
	const preflight = handleCors(req);
	if (preflight) return preflight;
	if (req.method !== "GET") return corsJson(req, 405, { error: "method_not_allowed" });
	if (!LEGACY_SELF_SERVICE_ENABLED) return corsJson(req, 410, { error: "disabled_for_direct_ga" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return corsJson(req, 500, { error: "misconfigured_supabase_env" });
	if (!PADDLE_CHECKOUT_URL) return corsJson(req, 500, { error: "missing_checkout_url" });

	const accessToken = getBearerToken(req);
	if (!accessToken) return corsJson(req, 401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });

	return corsJson(req, 200, { ok: true, checkout_url: PADDLE_CHECKOUT_URL, user_id: userData.user.id, email: userData.user.email });
});
