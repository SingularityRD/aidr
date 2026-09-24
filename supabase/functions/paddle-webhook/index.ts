// Supabase Edge Function: POST /v1/billing/webhook/paddle
//
// Verifies Paddle webhook signatures and updates:
// - public.subscriptions
// - public.billing_customers
// - public.entitlements.extra_agents
//
// This is a minimal v1 implementation intended for self-serve go-live.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { readBoundedText } from "../_shared/request-limits.ts";

// Required configuration. Validated per request, before any auth or DB work, so
// a missing variable answers with an explicit 500 that names it instead of
// failing later with an empty credential (AIDR-011). The signature secret is
// required whenever the endpoint is enabled at all: without it no delivery can
// be verified, so the function must refuse rather than process unsigned input.
const REQUIRED_ENV = [
	"SUPABASE_URL",
	"SUPABASE_SERVICE_ROLE_KEY",
	"AIDR_PADDLE_WEBHOOK_SECRET",
	"AIDR_PADDLE_EXTRA_AGENT_PRICE_ID",
] as const;

const PADDLE_SIGNATURE_HEADER = "Paddle-Signature";
const PADDLE_TOLERANCE_RAW = Deno.env.get("AIDR_PADDLE_WEBHOOK_TOLERANCE_SECONDS") ?? "300";
const MAX_WEBHOOK_BODY_BYTES = 1024 * 1024;
const LEGACY_SELF_SERVICE_ENABLED =
	Deno.env.get("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING")?.trim().toLowerCase() === "true" &&
	Deno.env.get("AIDR_BILLING_PROVIDER")?.trim().toLowerCase() === "paddle";

// Paddle may include the last active line items on cancellation events.  Those
// items are not an entitlement signal once the provider has ended access.
const ACTIVE_SUBSCRIPTION_STATUSES = new Set(["active", "trialing"]);
const REVOKED_SUBSCRIPTION_STATUSES = new Set([
	"canceled",
	"cancelled",
	"deleted",
	"paused",
	"past_due",
]);
const HANDLED_EVENT_TYPES = new Set([
	"subscription.created", "subscription.updated", "subscription.activated",
	"subscription.trialing", "subscription.resumed", "subscription.paused",
	"subscription.past_due", "subscription.canceled",
]);
const EVENT_ID = /^[A-Za-z0-9_-]{1,255}$/;

function resolvePaddleToleranceSeconds(raw: string): number | null {
	if (!/^\d+$/.test(raw.trim())) return null;
	const parsed = Number(raw.trim());
	return Number.isSafeInteger(parsed) && parsed > 0 && parsed <= 3600 ? parsed : null;
}

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

function extractIdentifiers(evt: PaddleEvent): { userId: string | null; tenantId: string | null } {
	const data = evt.data ?? {};
	const cd = (data.custom_data ?? data.custom ?? null) as Record<string, unknown> | null;
	const fromCustom = cd && typeof cd.user_id === "string" ? cd.user_id : null;
	const fromTenant = cd && typeof cd.tenant_id === "string" ? cd.tenant_id : null;
	const userId = fromCustom && isUuid(fromCustom) ? fromCustom.trim() : null;
	const tenantId = fromTenant && isUuid(fromTenant) ? fromTenant.trim() : null;
	return { userId, tenantId };
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

function extractExtraAgents(evt: PaddleEvent, extraAgentPriceId: string): number | null {
	const data = evt.data ?? {};
	const items = data.items ?? data.line_items;
	if (!extraAgentPriceId || !Array.isArray(items)) return null;
	let sum = 0;
	for (const it of items) {
		if (!it || typeof it !== "object" || Array.isArray(it)) continue;
		const obj = it as Record<string, unknown>;
		const priceId =
			(typeof obj.price_id === "string" ? obj.price_id : null) ??
			(typeof (obj.price as any)?.id === "string" ? (obj.price as any).id : null);
		if (priceId !== extraAgentPriceId) continue;
		const qty = Number(obj.quantity);
		if (!Number.isSafeInteger(qty) || qty <= 0 || qty > 100000) return null;
		sum += qty;
		if (!Number.isSafeInteger(sum) || sum > 100000) return null;
	}
	return Math.max(0, sum);
}

Deno.serve(async (req) => {
	if (req.method !== "POST") return json(405, { error: "method_not_allowed" });
	if (!LEGACY_SELF_SERVICE_ENABLED) return json(410, { error: "disabled_for_direct_ga" });

	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) return configFailure("paddle-webhook", config.error, json);
	const {
		SUPABASE_URL,
		SUPABASE_SERVICE_ROLE_KEY,
		AIDR_PADDLE_WEBHOOK_SECRET,
		AIDR_PADDLE_EXTRA_AGENT_PRICE_ID,
	} = config.values;
	const toleranceSeconds = resolvePaddleToleranceSeconds(PADDLE_TOLERANCE_RAW);
	if (toleranceSeconds === null) return json(500, { error: "invalid_webhook_tolerance" });

	const sigHeader = req.headers.get(PADDLE_SIGNATURE_HEADER) ?? "";
	const sig = parseSignatureHeader(sigHeader);
	if (!sig) return json(401, { error: "missing_or_invalid_signature" });

	const rawResult = await readBoundedText(req, MAX_WEBHOOK_BODY_BYTES);
	if (!rawResult.ok) {
		return json(rawResult.status, {
			error: rawResult.error === "request_too_large" ? rawResult.error : "invalid_json",
		});
	}
	const rawBody = rawResult.value;
	const tsNum = Number(sig.ts);
	if (!Number.isFinite(tsNum)) return json(401, { error: "invalid_signature_timestamp" });
	const now = Math.floor(Date.now() / 1000);
	if (Math.abs(now - Math.floor(tsNum)) > toleranceSeconds) {
		return json(401, { error: "signature_timestamp_out_of_range" });
	}

	const computed = await hmacSha256Hex(AIDR_PADDLE_WEBHOOK_SECRET, `${sig.ts}:${rawBody}`);
	const a = new TextEncoder().encode(computed.toLowerCase());
	const b = new TextEncoder().encode(sig.h1.toLowerCase());
	if (!timingSafeEqual(a, b)) return json(401, { error: "invalid_signature" });

	let evt: PaddleEvent;
	try {
		const parsed: unknown = JSON.parse(rawBody);
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return json(400, { error: "invalid_json" });
		evt = parsed as PaddleEvent;
	} catch {
		return json(400, { error: "invalid_json" });
	}

	const eventId = typeof evt.event_id === "string" ? evt.event_id.trim() : "";
	if (!EVENT_ID.test(eventId)) return json(400, { error: "invalid_event_id" });
	const eventType = typeof evt.event_type === "string" ? evt.event_type.trim() : "";
	if (!HANDLED_EVENT_TYPES.has(eventType)) return json(200, { ok: true, ignored: true });
	const occurredAt = typeof evt.occurred_at === "string" && Number.isFinite(Date.parse(evt.occurred_at))
		? new Date(evt.occurred_at).toISOString()
		: null;
	if (!occurredAt) return json(400, { error: "invalid_event_timestamp" });
	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});

	const { data: recorded, error: recordErr } = await supabase.rpc("record_billing_webhook_event", {
		p_provider: "paddle",
		p_event_id: eventId,
		p_payload: evt,
		p_tenant_id: null,
	});
	if (recordErr) return json(500, { error: "webhook_dedup_unavailable" });
	if (recorded !== true) return json(200, { ok: true, dedup: true });
	const finishClaim = async (status: "completed" | "failed") => {
		const { data, error } = await supabase.rpc("finish_billing_webhook_event", {
			p_provider: "paddle",
			p_event_id: eventId,
			p_status: status,
		});
		if (error || data !== true) throw new Error("webhook_claim_update_failed");
	};

	const identifiers = extractIdentifiers(evt);
	const userId = identifiers.userId;
	const tenantId = identifiers.tenantId;

	if (!userId || !tenantId) {
		await supabase.from("admin_audit_logs").insert({
			action: "paddle.webhook.unlinked",
			detail: { event_type: eventType, event_id: eventId },
		});
		await finishClaim("completed");
		return json(200, { ok: true, unlinked: true });
	}
	await supabase.from("billing_webhook_events").update({ tenant_id: tenantId })
		.eq("provider", "paddle").eq("event_id", eventId);

	const subId = extractSubscriptionId(evt);
	if (!subId) {
		await finishClaim("failed");
		await supabase.from("admin_audit_logs").insert({
			actor_user_id: userId,
			tenant_id: tenantId,
			action: "paddle.webhook.missing_subscription",
			target_user_id: userId,
			detail: { event_type: eventType, event_id: eventId },
		});
		return json(422, { error: "missing_subscription_id" });
	}
	const status = extractStatus(evt).toLowerCase();
	// Paddle cancellation payloads can retain the last active line items. Never
	// derive seats until status is classified, and fail closed on new statuses.
	if (!ACTIVE_SUBSCRIPTION_STATUSES.has(status) && !REVOKED_SUBSCRIPTION_STATUSES.has(status)) {
		await finishClaim("failed");
		await supabase.from("admin_audit_logs").insert({
			actor_user_id: userId,
			tenant_id: tenantId,
			action: "paddle.webhook.unhandled_status",
			target_user_id: userId,
			detail: { event_type: eventType, event_id: eventId, subscription_id: subId, status },
		});
		return json(422, { error: "unsupported_subscription_status" });
	}
	const extraAgents = ACTIVE_SUBSCRIPTION_STATUSES.has(status)
		? extractExtraAgents(evt, AIDR_PADDLE_EXTRA_AGENT_PRICE_ID.trim())
		: 0;
	if (extraAgents === null) {
		await finishClaim("failed");
		return json(422, { error: "unattributable_subscription_items" });
	}
	const periodEnd = extractPeriodEnd(evt);
	const cancelAtPeriodEnd = extractCancelAtPeriodEnd(evt);

	const { data: transition, error: transitionError } = await supabase.rpc(
		"apply_billing_subscription_event",
		{
			p_provider: "paddle",
			p_event_id: eventId,
			p_event_created_at: occurredAt,
			p_user_id: userId,
			p_tenant_id: tenantId,
			p_subscription_id: subId,
			p_status: status,
			p_extra_agents: extraAgents,
			p_current_period_end: periodEnd,
			p_cancel_at_period_end: cancelAtPeriodEnd,
		},
	);
	if (transitionError) {
		await finishClaim("failed");
		return json(503, { error: "subscription_transition_unavailable" });
	}
	const applied = transition && typeof transition === "object" && !Array.isArray(transition)
		? (transition as Record<string, unknown>).applied
		: null;
	if (applied !== true) {
		await finishClaim("completed");
		return json(200, { ok: true, ignored: true });
	}

	await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		tenant_id: tenantId,
		action: "paddle.webhook",
		target_user_id: userId,
		detail: { event_type: eventType, event_id: eventId, subscription_id: subId, extra_agents: extraAgents },
	});

	await finishClaim("completed");
	return json(200, { ok: true });
});
