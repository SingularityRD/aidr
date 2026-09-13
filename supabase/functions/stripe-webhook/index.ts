// Supabase Edge Function: POST /functions/v1/stripe-webhook
//
// Verifies Stripe webhook signatures and reconciles billing state:
// - public.billing_customers   (customer <-> user linkage)
// - public.subscriptions       (provider_subscription_id is the upsert key)
// - public.entitlements        (extra_agents - the seat enforcement input)
// - public.admin_audit_logs    (append-only audit trail)
//
// Security contract (this replaces the removed Lemon Squeezy handler, which
// performed no signature verification at all):
//
//   1. The RAW body is read before any JSON parsing. Stripe signs the bytes it
//      sent; re-serialising the parsed object invalidates the HMAC.
//   2. The `Stripe-Signature` header is verified with HMAC-SHA256 over
//      `${t}.${rawBody}` using STRIPE_WEBHOOK_SECRET, compared in constant time
//      against every `v1` entry, inside a bounded replay window.
//   3. Missing secret / missing signature / invalid signature / stale timestamp
//      all return 400 and write nothing. Nothing is ever acknowledged with 200
//      before it has been verified.
//   4. Event ids are deduplicated through public.record_billing_webhook_event
//      BEFORE any write; a replay is a no-op. A claim is released when
//      processing fails so a Stripe retry is not lost to a transient error.
//   5. Only allow-listed event types are acted on, and entitlements are only
//      ever derived from a subscription status that is entitled plus a line
//      item that matches the configured extra-agent price.
//   6. The user/tenant is resolved from metadata that our own checkout path
//      set, never from client-supplied values in the webhook body.
//   7. Internal error text is logged, never returned to the caller, and no CORS
//      allowance is granted (webhooks are server-to-server).
//
// STATUS: implemented and unit-tested only. This function is NOT deployed and
// has NOT been exercised against a live Stripe account.

import { createClient } from "npm:@supabase/supabase-js@2";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import {
	claimStripeEvent,
	releaseStripeEvent,
	WebhookDedupUnavailableError,
	type WebhookEventRecorder,
} from "./dedup.ts";
import { evaluateStripeEvent, isStripeEventId, type StripeEventEvaluation } from "./events.ts";
import { verifyStripeWebhookSignature } from "./verify.ts";

// Required configuration. Validated per request, before any auth, body or DB
// work, so a missing variable answers with an explicit 500 that names it
// instead of failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;

// Not part of REQUIRED_ENV on purpose: an unprovisioned endpoint secret has its
// own, documented fail-closed path (`invalid_signature`, 400, no writes) because
// Stripe must not retry a delivery we could never verify.
const STRIPE_WEBHOOK_SECRET = (Deno.env.get("STRIPE_WEBHOOK_SECRET") ?? "").trim();
const STRIPE_SIGNATURE_HEADER = "Stripe-Signature";
const STRIPE_TOLERANCE_SECONDS = Deno.env.get("AIDR_STRIPE_WEBHOOK_TOLERANCE_SECONDS") ?? "300";
const EXTRA_AGENT_PRICE_ID = (Deno.env.get("AIDR_STRIPE_EXTRA_AGENT_PRICE_ID") ?? "").trim();

// Direct-GA is invoice/order based. Self-service billing stays unreachable until
// a separately approved commercial decision enables it, exactly like the
// Paddle endpoint and the dashboard's VITE_AIDR_COMMERCIAL_MODE gate.
const LEGACY_SELF_SERVICE_ENABLED =
	(Deno.env.get("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING") ?? "").trim().toLowerCase() === "true";

type SupabaseClient = ReturnType<typeof createClient>;

function json(status: number, body: Record<string, unknown>, requestId: string): Response {
	// Deliberately no Access-Control-Allow-* headers: Stripe calls this endpoint
	// server-to-server and a browser should never be able to read a response or
	// preflight this route.
	return new Response(JSON.stringify(body), {
		status,
		headers: {
			"Content-Type": "application/json",
			"X-Request-ID": requestId,
			"Cache-Control": "no-store",
		},
	});
}

function log(requestId: string, message: string, detail: Record<string, unknown> = {}): void {
	// Internal only. Never log the endpoint secret, the signature header, or the
	// raw payload.
	console.error(`[stripe-webhook] ${message}`, JSON.stringify({ request_id: requestId, ...detail }));
}

async function resolveUserIdFromMetadata(
	supabase: SupabaseClient,
	userId: string,
): Promise<string | null> {
	// The id came from metadata our checkout set, but it is still verified
	// against auth.users so a bad/forged metadata value cannot create seats for
	// a non-existent account.
	const { data, error } = await supabase.auth.admin.getUserById(userId);
	if (error || !data?.user?.id) return null;
	return data.user.id;
}

async function resolveUserIdFromCustomer(
	supabase: SupabaseClient,
	customerId: string,
): Promise<string | null> {
	const { data, error } = await supabase
		.from("billing_customers")
		.select("user_id")
		.eq("provider", "stripe")
		.eq("provider_customer_id", customerId)
		.maybeSingle();
	if (error || !data) return null;
	const userId = (data as { user_id?: unknown }).user_id;
	return typeof userId === "string" && userId ? userId : null;
}

async function tenantIsAllowed(
	supabase: SupabaseClient,
	tenantId: string,
	userId: string,
): Promise<boolean> {
	// A personal tenant is the user's own id. Any other tenant requires an
	// active membership row; metadata must not be able to move seats into an
	// unrelated tenant.
	if (tenantId === userId) return true;
	const { data, error } = await supabase
		.from("tenant_members")
		.select("tenant_id, expires_at")
		.eq("tenant_id", tenantId)
		.eq("user_id", userId)
		.maybeSingle();
	if (error || !data) return false;
	const expiresAt = (data as { expires_at?: unknown }).expires_at;
	if (typeof expiresAt === "string" && expiresAt) {
		const parsed = Date.parse(expiresAt);
		if (Number.isFinite(parsed) && parsed <= Date.now()) return false;
	}
	return true;
}

async function upsertBillingCustomer(
	supabase: SupabaseClient,
	requestId: string,
	userId: string,
	tenantId: string,
	customerId: string,
): Promise<boolean> {
	const { error } = await supabase
		.from("billing_customers")
		.upsert(
			{ user_id: userId, tenant_id: tenantId, provider: "stripe", provider_customer_id: customerId },
			{ onConflict: "user_id" },
		);
	if (error) {
		// The linkage is a convenience lookup for later events, not the security
		// boundary: log it and continue rather than failing the whole delivery
		// (a unique-constraint conflict must not turn into an endless retry).
		log(requestId, "billing customer linkage failed", { user_id: userId });
		return false;
	}
	return true;
}

async function upsertSubscription(
	supabase: SupabaseClient,
	userId: string,
	tenantId: string,
	evaluation: StripeEventEvaluation,
): Promise<boolean> {
	if (!evaluation.subscriptionId) return false;
	const { error } = await supabase.from("subscriptions").upsert(
		{
			user_id: userId,
			tenant_id: tenantId,
			provider: "stripe",
			provider_subscription_id: evaluation.subscriptionId,
			status: evaluation.status ?? "unknown",
			extra_agents: evaluation.extraAgents,
			current_period_end: evaluation.currentPeriodEnd,
			cancel_at_period_end: evaluation.cancelAtPeriodEnd,
		},
		{ onConflict: "provider_subscription_id" },
	);
	if (error) throw error;
	return true;
}

async function writeExtraAgents(
	supabase: SupabaseClient,
	userId: string,
	tenantId: string,
	extraAgents: number,
): Promise<"updated" | "inserted"> {
	const updated = await supabase
		.from("entitlements")
		.update({ extra_agents: extraAgents })
		.eq("tenant_id", tenantId)
		.select("tenant_id");
	if (updated.error) throw updated.error;
	if (Array.isArray(updated.data) && updated.data.length > 0) return "updated";

	// The per-user trigger normally creates this row. Insert only when it is
	// genuinely absent, so an existing owner (team tenant) is never overwritten.
	const inserted = await supabase
		.from("entitlements")
		.insert({ user_id: userId, tenant_id: tenantId, extra_agents: extraAgents })
		.select("tenant_id");
	if (inserted.error) throw inserted.error;
	return "inserted";
}

async function audit(
	supabase: SupabaseClient,
	action: string,
	userId: string | null,
	tenantId: string | null,
	detail: Record<string, unknown>,
): Promise<void> {
	const { error } = await supabase.from("admin_audit_logs").insert({
		actor_user_id: userId,
		tenant_id: tenantId,
		action,
		target_user_id: userId,
		detail,
	});
	if (error) throw error;
}

/**
 * Supabase-backed dedup recorder.
 *
 * `record` maps to the SECURITY DEFINER RPC the Paddle handler already uses:
 * `event_id` is the primary key, so a duplicate delivery inserts nothing and
 * the function returns false. `release` removes a claim whose processing
 * failed, letting Stripe's retry do the work.
 */
function createRecorder(supabase: SupabaseClient, requestId: string): WebhookEventRecorder {
	return {
		async record(provider: string, eventId: string, payload: unknown): Promise<boolean> {
			const { data, error } = await supabase.rpc("record_billing_webhook_event", {
				p_provider: provider,
				p_event_id: eventId,
				p_payload: payload,
				p_tenant_id: null,
			});
			if (error) {
				log(requestId, "dedup unavailable", { event_id: eventId });
				// Fail closed: without a dedup guarantee nothing may be written.
				throw new WebhookDedupUnavailableError();
			}
			return data === true;
		},
		async release(eventId: string): Promise<void> {
			await supabase.from("billing_webhook_events").delete().eq("event_id", eventId);
		},
	};
}

Deno.serve(async (req) => {
	const requestId = crypto.randomUUID();

	if (req.method !== "POST") return json(405, { error: "method_not_allowed" }, requestId);
	if (!LEGACY_SELF_SERVICE_ENABLED) {
		return json(410, { error: "disabled_for_direct_ga" }, requestId);
	}
	if (!STRIPE_WEBHOOK_SECRET) {
		// Fail closed: an unverifiable payload is never acknowledged and never
		// written. 400 tells Stripe not to retry a request we could never verify.
		log(requestId, "missing STRIPE_WEBHOOK_SECRET; rejecting without writes");
		return json(400, { error: "invalid_signature" }, requestId);
	}
	const config = loadConfig(runtimeEnv, REQUIRED_ENV);
	if (!config.ok) {
		return configFailure("stripe-webhook", config.error, (status, body) => json(status, body, requestId));
	}
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY } = config.values;

	// The RAW body must be read before anything parses it.
	const rawBody = await req.text();

	const verification = await verifyStripeWebhookSignature({
		rawBody,
		signatureHeader: req.headers.get(STRIPE_SIGNATURE_HEADER),
		secret: STRIPE_WEBHOOK_SECRET,
		toleranceSeconds: STRIPE_TOLERANCE_SECONDS,
	});
	if (!verification.ok) {
		log(requestId, "signature rejected", { reason: verification.reason });
		return json(400, { error: "invalid_signature" }, requestId);
	}

	let event: Record<string, unknown>;
	try {
		const parsed = JSON.parse(rawBody) as unknown;
		if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
			return json(400, { error: "invalid_json" }, requestId);
		}
		event = parsed as Record<string, unknown>;
	} catch {
		return json(400, { error: "invalid_json" }, requestId);
	}

	const eventId = typeof event.id === "string" ? event.id.trim() : "";
	if (!isStripeEventId(eventId)) {
		log(requestId, "missing or malformed event id");
		return json(400, { error: "invalid_event" }, requestId);
	}

	const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
		auth: { persistSession: false },
	});
	const recorder = createRecorder(supabase, requestId);

	try {
		// Deduplicate BEFORE any write. The RPC is the concurrency boundary: a
		// conflicting event_id inserts nothing and reports false.
		const claim = await claimStripeEvent(recorder, eventId, event);
		if (!claim.claimed) {
			return json(200, { ok: true, dedup: true }, requestId);
		}

		const evaluation = evaluateStripeEvent(event, {
			extraAgentPriceId: EXTRA_AGENT_PRICE_ID,
			extraAgentYearlyPriceId: Deno.env.get("AIDR_STRIPE_EXTRA_AGENT_YEARLY_PRICE_ID"),
		});

		if (evaluation.action === "ignore") {
			await audit(supabase, "stripe.webhook.ignored", null, null, {
				event_type: evaluation.eventType,
				event_id: eventId,
				reason: evaluation.reason,
				subscription_id: evaluation.subscriptionId,
				price_configured: EXTRA_AGENT_PRICE_ID !== "",
			});
			return json(200, { ok: true, ignored: true }, requestId);
		}

		// Resolve the tenant from metadata our checkout path set, or from a
		// customer linkage we recorded earlier. A customer email is deliberately
		// NOT used: it is typed by the customer in the hosted checkout page and is
		// therefore client-supplied.
		let userId: string | null = null;
		let resolvedVia = "";
		if (evaluation.userId) {
			userId = await resolveUserIdFromMetadata(supabase, evaluation.userId);
			resolvedVia = userId ? "metadata" : "metadata_unknown_user";
		}
		if (!userId && evaluation.customerId) {
			userId = await resolveUserIdFromCustomer(supabase, evaluation.customerId);
			resolvedVia = userId ? "customer_linkage" : resolvedVia;
		}

		if (!userId) {
			await audit(supabase, "stripe.webhook.unlinked", null, null, {
				event_type: evaluation.eventType,
				event_id: eventId,
				reason: resolvedVia || "missing_checkout_metadata",
				customer_id: evaluation.customerId,
				subscription_id: evaluation.subscriptionId,
			});
			return json(200, { ok: true, unlinked: true }, requestId);
		}

		const tenantId = evaluation.tenantId ?? userId;
		if (!(await tenantIsAllowed(supabase, tenantId, userId))) {
			await audit(supabase, "stripe.webhook.tenant_rejected", userId, null, {
				event_type: evaluation.eventType,
				event_id: eventId,
				tenant_id: tenantId,
			});
			return json(200, { ok: true, unlinked: true }, requestId);
		}

		const customerLinked = evaluation.customerId
			? await upsertBillingCustomer(supabase, requestId, userId, tenantId, evaluation.customerId)
			: false;

		if (evaluation.action === "record") {
			await audit(supabase, "stripe.webhook.recorded", userId, tenantId, {
				event_type: evaluation.eventType,
				event_id: eventId,
				reason: evaluation.reason,
				subscription_id: evaluation.subscriptionId,
				customer_id: evaluation.customerId,
				customer_linked: customerLinked,
				invoice: evaluation.invoice,
			});
			return json(200, { ok: true, recorded: true }, requestId);
		}

		// action === "reconcile": subscription state, then the seat entitlement.
		const subscriptionWritten = await upsertSubscription(supabase, userId, tenantId, evaluation);
		if (!subscriptionWritten || !evaluation.writeEntitlement) {
			await audit(supabase, "stripe.webhook.ignored", userId, tenantId, {
				event_type: evaluation.eventType,
				event_id: eventId,
				reason: "subscription_reference_missing",
			});
			return json(200, { ok: true, ignored: true }, requestId);
		}

		const entitlementMode = await writeExtraAgents(
			supabase,
			userId,
			tenantId,
			evaluation.extraAgents,
		);

		await audit(supabase, "stripe.webhook", userId, tenantId, {
			event_type: evaluation.eventType,
			event_id: eventId,
			reason: evaluation.reason,
			subscription_id: evaluation.subscriptionId,
			status: evaluation.status,
			entitled: evaluation.entitled,
			extra_agents: evaluation.extraAgents,
			entitlement_mode: entitlementMode,
			customer_linked: customerLinked,
			tenant_id: tenantId,
		});

		return json(200, { ok: true }, requestId);
	} catch (error) {
		// Log internally with the request id; return a generic body so an
		// unauthenticated caller learns nothing about internal state.
		log(requestId, "processing failed", {
			event_id: eventId,
			error: error instanceof Error ? error.message : String(error),
		});

		if (error instanceof WebhookDedupUnavailableError) {
			// No claim was taken, so there is nothing to release.
			return json(500, { error: "webhook_dedup_unavailable" }, requestId);
		}

		// Release the dedup claim so Stripe's retry can finish the work. Every
		// write below the claim is an idempotent upsert, so a retried attempt is
		// safe; without this, one transient database error would poison the event
		// id and the event would be dropped forever.
		await releaseStripeEvent(recorder, eventId);

		return json(500, { error: "webhook_processing_failed" }, requestId);
	}
});
