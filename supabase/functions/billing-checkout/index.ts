// Supabase Edge Function: GET /v1/billing/checkout
//
// Auth: Authorization: Bearer <supabase_access_token>
//
// v1: returns a configured Paddle checkout URL. The checkout itself is managed in Paddle.
// Webhooks will reconcile entitlements based on custom_data.user_id if present, otherwise best-effort by email.

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const PADDLE_CHECKOUT_URL = (Deno.env.get("AIDR_PADDLE_CHECKOUT_URL") ?? "").trim();

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

Deno.serve(async (req) => {
	if (req.method !== "GET") return json(405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "misconfigured_supabase_env" });
	if (!PADDLE_CHECKOUT_URL) return json(500, { error: "missing_checkout_url" });

	const accessToken = getBearerToken(req);
	if (!accessToken) return json(401, { error: "missing_access_token" });

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const { data: userData, error: userErr } = await supabase.auth.getUser(accessToken);
	if (userErr || !userData?.user?.id) return json(401, { error: "invalid_access_token" });

	return json(200, { ok: true, checkout_url: PADDLE_CHECKOUT_URL, user_id: userData.user.id, email: userData.user.email });
});

