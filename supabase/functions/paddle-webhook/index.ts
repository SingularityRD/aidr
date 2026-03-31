// Supabase Edge Function: POST /v1/billing/webhook/paddle
//
// Verifies Paddle webhook signatures and updates:
// - public.subscriptions
// - public.billing_customers
// - public.entitlements.extra_agents
//
// This is a minimal v1 implementation intended for self-serve go-live.

import { createClient } from "npm:@supabase/supabase-js@2";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

const PADDLE_WEBHOOK_SECRET = (Deno.env.get("AIDR_PADDLE_WEBHOOK_SECRET") ?? "").trim();
const PADDLE_SIGNATURE_HEADER = "Paddle-Signature";
const PADDLE_TOLERANCE_SECONDS = Number(Deno.env.get("AIDR_PADDLE_WEBHOOK_TOLERANCE_SECONDS") ?? "300");
const EXTRA_AGENT_PRICE_ID = (Deno.env.get("AIDR_PADDLE_EXTRA_AGENT_PRICE_ID") ?? "").trim();

function json(status: number, body: Record<string, unknown>) {
	return new Response(JSON.stringify(body), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
	if (a.length !== b.length) return false;
	let diff = 0;
	for (let i = 0; i < a.length; i++) diff |= a[i]! ^ b[i]!;
	return diff === 0;
}

function parseSignatureHeader(header: string): { ts: string; h1: string } | null {
	// Example: "ts=1700000000;h1=<hex>"
	const parts = header
		.split(";")
		.map((p) => p.trim())
		.filter(Boolean);
	const kv = new Map<string, string>();
	for (const p of parts) {
		const idx = p.indexOf("=");
		if (idx <= 0) continue;
		kv.set(p.slice(0, idx).trim(), p.slice(idx + 1).trim());
	}
	const ts = kv.get("ts") ?? "";
	const h1 = kv.get("h1") ?? "";
	if (!ts || !h1) return null;
	return { ts, h1 };
}

async function hmacSha256Hex(secret: string, msg: string): Promise<string> {
	const key = await crypto.subtle.importKey(
		"raw",
		new TextEncoder().encode(secret),
		{ name: "HMAC", hash: "SHA-256" },
		false,
		["sign"],
	);
	const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(msg));
	const bytes = new Uint8Array(sig);
	return Array.from(bytes)
		.map((b) => b.toString(16).padStart(2, "0"))
		.join("");
}

function isUuid(s: string): boolean {
	return /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(
		s.trim(),
	);
}

type PaddleEvent = {
	event_id?: string;
	event_type?: string;
	occurred_at?: string;
	data?: Record<string, unknown>;
};

function extractUserId(evt: PaddleEvent): string | null {
	const data = evt.data ?? {};
	const cd = (data.custom_data ?? data.custom ?? null) as Record<string, unknown> | null;
	const fromCustom = cd && typeof cd.user_id === "string" ? cd.user_id : null;
	if (fromCustom && isUuid(fromCustom)) return fromCustom;
	const direct = typeof (data as Record<string, unknown>).user_id === "string" ? (data as any).user_id : null;
	if (direct && isUuid(direct)) return direct;
	return null;
}

function extractCustomerEmail(evt: PaddleEvent): string | null {
	const data = evt.data ?? {};
	const customer = (data.customer ?? null) as Record<string, unknown> | null;
	const email =
		(customer && typeof customer.email === "string" ? customer.email : null) ??
		(typeof (data as any).customer_email === "string" ? (data as any).customer_email : null);
	return typeof email === "string" && email.includes("@") ? email.trim() : null;
}

function extractSubscriptionId(evt: PaddleEvent): string | null {
	const data = evt.data ?? {};
	const id =
		(typeof (data as any).id === "string" ? (data as any).id : null) ??
		(typeof (data as any).subscription_id === "string" ? (data as any).subscription_id : null);
	return id ? id.trim() : null;
}

function extractStatus(evt: PaddleEvent): string {
	const data = evt.data ?? {};
	const st = typeof (data as any).status === "string" ? (data as any).status : "";
	return st.trim() || "unknown";
}

function extractPeriodEnd(evt: PaddleEvent): string | null {
	const data = evt.data ?? {};
	const ts =
		(typeof (data as any).current_billing_period?.ends_at === "string"
			? (data as any).current_billing_period.ends_at
			: null) ??
		(typeof (data as any).next_billed_at === "string" ? (data as any).next_billed_at : null);
	return typeof ts === "string" && ts ? ts : null;
}

function extractCancelAtPeriodEnd(evt: PaddleEvent): boolean {
	const data = evt.data ?? {};
	return Boolean((data as any).cancel_at_period_end ?? false);
}

function extractExtraAgents(evt: PaddleEvent): number {
	const data = evt.data ?? {};
	const items = (data.items ?? data.line_items ?? []) as unknown[];
	let sum = 0;
	for (const it of items) {
		if (!it || typeof it !== "object" || Array.isArray(it)) continue;
		const obj = it as Record<string, unknown>;
		const qty = Number(obj.quantity ?? 0);
		if (!Number.isFinite(qty) || qty <= 0) continue;
		const priceId =
			(typeof obj.price_id === "string" ? obj.price_id : null) ??
			(typeof (obj.price as any)?.id === "string" ? (obj.price as any).id : null);
		if (EXTRA_AGENT_PRICE_ID && priceId && priceId !== EXTRA_AGENT_PRICE_ID) continue;
		sum += Math.floor(qty);
	}
	return Math.max(0, sum);
}

Deno.serve(async (req) => {
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
	if (!SUPABASE_URL || !SUPABASE_SERVICE_ROLE_KEY) return json(500, { error: "misconfigured_supabase_env" });
	if (!PADDLE_WEBHOOK_SECRET) return json(500, { error: "missing_paddle_webhook_secret" });

	const sigHeader = req.headers.get(PADDLE_SIGNATURE_HEADER) ?? "";
	const sig = parseSignatureHeader(sigHeader);
	if (!sig) return json(401, { error: "missing_or_invalid_signature" });

	const rawBody = await req.text();
	const tsNum = Number(sig.ts);
	if (!Number.isFinite(tsNum)) return json(401, { error: "invalid_signature_timestamp" });
	const now = Math.floor(Date.now() / 1000);
	if (Math.abs(now - Math.floor(tsNum)) > Math.max(0, PADDLE_TOLERANCE_SECONDS)) {
		return json(401, { error: "signature_timestamp_out_of_range" });
	}

	const computed = await hmacSha256Hex(PADDLE_WEBHOOK_SECRET, `${sig.ts}:${rawBody}`);
	const a = new TextEncoder().encode(computed.toLowerCase());
	const b = new TextEncoder().encode(sig.h1.toLowerCase());
	if (!timingSafeEqual(a, b)) return json(401, { error: "invalid_signature" });

	let evt: PaddleEvent = {};
	try {
		evt = JSON.parse(rawBody) as PaddleEvent;
	} catch {
		return json(400, { error: "invalid_json" });
	}

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const eventId = (evt.event_id ?? "").trim();
	if (eventId) {
		const { data: existing } = await supabase
			.from("billing_webhook_events")
			.select("event_id")
			.eq("event_id", eventId)
			.maybeSingle();
		if (existing?.event_id) return json(200, { ok: true, dedup: true });

		await supabase.from("billing_webhook_events").insert({ provider: "paddle", event_id: eventId, payload: evt });
	}

	const eventType = (evt.event_type ?? "").trim();
	const userIdFromCustom = extractUserId(evt);
	let userId: string | null = userIdFromCustom;

	if (!userId) {
		const email = extractCustomerEmail(evt);
		if (email) {
			const { data: mapped } = await supabase.rpc("user_id_by_email", { p_email: email });
			if (typeof mapped === "string" && isUuid(mapped)) userId = mapped;
		}
	}

	if (!userId) {
		await supabase.from("admin_audit_logs").insert({
			action: "paddle.webhook.unlinked",
			detail: { event_type: eventType, event_id: eventId },
		});
		return json(200, { ok: true, unlinked: true });
	}

	const subId = extractSubscriptionId(evt);
	const status = extractStatus(evt);
	const extraAgents = extractExtraAgents(evt);
	const periodEnd = extractPeriodEnd(evt);
	const cancelAtPeriodEnd = extractCancelAtPeriodEnd(evt);

	if (subId) {
		await supabase.from("subscriptions").upsert(
			{
				user_id: userId,
				provider: "paddle",
				provider_subscription_id: subId,
				status,
				extra_agents: extraAgents,
				current_period_end: periodEnd,
				cancel_at_period_end: cancelAtPeriodEnd,
			},
			{ onConflict: "provider_subscription_id" },
		);
	}

	// Update entitlements as the single source of seat enforcement.
	await supabase.from("entitlements").update({ extra_agents: extraAgents }).eq("user_id", userId);

	await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		action: "paddle.webhook",
		target_user_id: userId,
		detail: { event_type: eventType, event_id: eventId, subscription_id: subId, extra_agents: extraAgents },
	});

	return json(200, { ok: true });
});

