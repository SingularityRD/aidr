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

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { readBoundedText } from "../_shared/request-limits.ts";
import {
	claimStripeEvent,
	releaseStripeEvent,
	WebhookDedupUnavailableError,
	type WebhookEventRecorder,
} from "./dedup.ts";
import { isBoundZeroSeatTransition, selectStripeCustomerLinkage } from "./customer-linkage.ts";
import {
	evaluateStripeEvent,
	extractCheckoutIntentMetadata,
	invoicePaymentReferenceFromList,
	isStripeEventId,
	isUuid,
	type StripeEventEvaluation,
} from "./events.ts";
import { verifyStripeWebhookSignature } from "./verify.ts";

// Required configuration. Validated per request, before any auth, body or DB
// work, so a missing variable answers with an explicit 500 that names it
// instead of failing later with an empty credential (AIDR-011).
const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY", "STRIPE_SECRET_KEY"] as const;

// Not part of REQUIRED_ENV on purpose: an unprovisioned endpoint secret has its
// own, documented fail-closed path (`invalid_signature`, 400, no writes) because
// Stripe must not retry a delivery we could never verify.
const STRIPE_WEBHOOK_SECRET = (Deno.env.get("STRIPE_WEBHOOK_SECRET") ?? "").trim();
const STRIPE_SIGNATURE_HEADER = "Stripe-Signature";
const STRIPE_TOLERANCE_SECONDS = Deno.env.get("AIDR_STRIPE_WEBHOOK_TOLERANCE_SECONDS") ?? "300";
const EXTRA_AGENT_PRICE_ID = (Deno.env.get("AIDR_STRIPE_EXTRA_AGENT_PRICE_ID") ?? "").trim();
const MAX_WEBHOOK_BODY_BYTES = 1024 * 1024;

// Direct-GA is invoice/order based. Self-service billing stays unreachable until
// a separately approved commercial decision enables it, exactly like the
// Paddle endpoint and the dashboard's VITE_AIDR_COMMERCIAL_MODE gate.
const LEGACY_SELF_SERVICE_ENABLED =
	Deno.env.get("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING")?.trim().toLowerCase() === "true" &&
	Deno.env.get("AIDR_BILLING_PROVIDER")?.trim().toLowerCase() === "stripe";

type SupabaseClient = ReturnType<typeof createClient<any>>;

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

async function resolveCustomerLinkage(
	supabase: SupabaseClient,
	customerId: string,
	userIdHint: string | null,
	tenantIdHint: string | null,
): Promise<{ linkage: { userId: string; tenantId: string } | null; conflict: boolean }> {
	let query = supabase
		.from("billing_customers")
		.select("user_id, tenant_id")
		.eq("provider", "stripe")
		.eq("provider_customer_id", customerId);
	if (userIdHint) query = query.eq("user_id", userIdHint);
	if (tenantIdHint) query = query.eq("tenant_id", tenantIdHint);
	const { data, error } = await query.limit(2);
	if (error) throw error;
	const selected = selectStripeCustomerLinkage(data, { userId: userIdHint, tenantId: tenantIdHint });
	if (selected.linkage || selected.ambiguous || selected.conflict || (!userIdHint && !tenantIdHint)) {
		return { linkage: selected.linkage, conflict: selected.conflict };
	}
	// The same Stripe customer may legitimately serve another tenant. Only
	// reject a different stored user binding within the claimed tenant.
	if (!tenantIdHint) return { linkage: null, conflict: false };
	const { data: existing, error: existingError } = await supabase
		.from("billing_customers")
		.select("user_id, tenant_id")
		.eq("provider", "stripe")
		.eq("provider_customer_id", customerId)
		.eq("tenant_id", tenantIdHint)
		.limit(1);
	if (existingError) throw existingError;
	return { linkage: null, conflict: Array.isArray(existing) && existing.length > 0 };
}

async function tenantIsAllowed(
	supabase: SupabaseClient,
	tenantId: string,
	userId: string,
): Promise<boolean> {
	const { data: tenant, error: tenantError } = await supabase
		.from("tenants")
		.select("status")
		.eq("id", tenantId)
		.maybeSingle();
	if (tenantError || tenant?.status !== "active") return false;
	const { data, error } = await supabase
		.from("tenant_members")
		.select("tenant_id, role, expires_at")
		.eq("tenant_id", tenantId)
		.eq("user_id", userId)
		.maybeSingle();
	if (error || !data) return false;
	if (!["owner", "admin"].includes(String((data as { role?: unknown }).role))) return false;
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
			{ onConflict: "provider,provider_customer_id,tenant_id", ignoreDuplicates: true },
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

async function applySubscriptionEvent(
	supabase: SupabaseClient,
	eventId: string,
	userId: string,
	tenantId: string,
	evaluation: StripeEventEvaluation,
): Promise<{ applied: boolean; extraAgents: number }> {
	if (!evaluation.subscriptionId || !evaluation.eventCreatedAt) {
		return { applied: false, extraAgents: 0 };
	}
	const { data, error } = await supabase.rpc("apply_billing_subscription_event", {
		p_provider: "stripe",
		p_event_id: eventId,
		p_event_created_at: evaluation.eventCreatedAt,
		p_user_id: userId,
		p_tenant_id: tenantId,
		p_subscription_id: evaluation.subscriptionId,
		p_status: evaluation.status ?? "unknown",
		p_extra_agents: evaluation.extraAgents,
		p_current_period_end: evaluation.currentPeriodEnd,
		p_cancel_at_period_end: evaluation.cancelAtPeriodEnd,
	});
	if (error) throw error;
	const result = data && typeof data === "object" && !Array.isArray(data)
		? data as Record<string, unknown>
		: null;
	if (!result || typeof result.applied !== "boolean") throw new Error("invalid_subscription_transition");
	return {
		applied: result.applied,
		extraAgents: typeof result.extra_agents === "number" ? result.extra_agents : 0,
	};
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
 * the function returns false. `release` marks a claim failed so the lifecycle
 * RPC can admit a provider retry without deleting the replay record.
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
			const { data, error } = await supabase.rpc("finish_billing_webhook_event", {
				p_provider: "stripe",
				p_event_id: eventId,
				p_status: "failed",
			});
			if (error || data !== true) throw error ?? new Error("webhook_failure_update_unavailable");
		},
	};
}

async function completeStripeEvent(supabase: SupabaseClient, eventId: string): Promise<void> {
	const { data, error } = await supabase.rpc("finish_billing_webhook_event", {
		p_provider: "stripe",
		p_event_id: eventId,
		p_status: "completed",
	});
	if (error || data !== true) throw new Error("webhook_completion_unavailable");
}

async function recordStripePaymentEvidence(
	supabase: SupabaseClient,
	eventId: string,
	evaluation: StripeEventEvaluation,
	stripeSecretKey: string,
): Promise<boolean> {
	if (evaluation.eventType !== "invoice.paid" || !evaluation.invoice?.settlementId) return false;
	const invoice = evaluation.invoice;
	// A trial or full discount can produce a paid invoice without money moving.
	if (invoice.amountPaidCents === 0) return false;
	if (!invoice.paymentReference && /^in_[A-Za-z0-9_]{1,252}$/.test(invoice.id)) {
		const url = new URL("https://api.stripe.com/v1/invoice_payments");
		url.search = new URLSearchParams({ invoice: invoice.id, status: "paid", limit: "2" }).toString();
		const response = await fetch(url, {
			headers: { Authorization: `Bearer ${stripeSecretKey}` },
			redirect: "error",
			signal: AbortSignal.timeout(10000),
		});
		if (!response.ok) throw new Error("stripe_invoice_payment_lookup_unavailable");
		invoice.paymentReference = invoicePaymentReferenceFromList(
			await response.json(), invoice.id, invoice.amountPaidCents, invoice.currency,
		);
	}
	if (
		!evaluation.userId || !evaluation.tenantId || !evaluation.customerId ||
		!evaluation.subscriptionId || !evaluation.eventCreatedAt || !invoice.requestId ||
		!invoice.paymentReference || !invoice.id ||
		!Number.isSafeInteger(invoice.amountPaidCents) || invoice.amountPaidCents <= 0 ||
		!/^[a-z]{3}$/.test(invoice.currency)
	) {
		throw new Error("stripe_payment_evidence_incomplete");
	}
	const { data, error } = await supabase.rpc("record_stripe_payment_evidence", {
		p_event_id: eventId,
		p_event_created_at: evaluation.eventCreatedAt,
		p_settlement_id: invoice.settlementId,
		p_request_id: invoice.requestId,
		p_user_id: evaluation.userId,
		p_tenant_id: evaluation.tenantId,
		p_customer_id: evaluation.customerId,
		p_subscription_id: evaluation.subscriptionId,
		p_invoice_id: invoice.id,
		p_payment_kind: invoice.paymentReference.kind,
		p_payment_id: invoice.paymentReference.id,
		p_amount_minor: invoice.amountPaidCents,
		p_currency: invoice.currency,
	});
	if (error || data !== true) throw error ?? new Error("stripe_payment_evidence_unavailable");
	return true;
}

async function closeCheckoutIntent(
	supabase: SupabaseClient,
	input: {
		eventId: string;
		eventType: string;
		object: Record<string, unknown>;
		userId: string;
		tenantId: string;
		checkoutSessionId?: string;
		subscriptionId?: string;
	},
): Promise<boolean> {
	const binding = extractCheckoutIntentMetadata(input.object);
	if (!binding.userId || binding.userId !== input.userId ||
		!binding.tenantId || binding.tenantId !== input.tenantId ||
		!binding.settlementId || !binding.requestId) return false;
	const { data, error } = await supabase.rpc("close_billing_checkout_intent", {
		p_tenant_id: input.tenantId,
		p_actor_user_id: input.userId,
		p_settlement_id: binding.settlementId,
		p_request_id: binding.requestId,
		p_provider_event_id: input.eventId,
		p_event_type: input.eventType,
		p_checkout_session_id: input.checkoutSessionId ?? null,
		p_subscription_id: input.subscriptionId ?? null,
	});
	if (error) throw error;
	if (data !== true) {
		log(crypto.randomUUID(), "checkout intent closure was not confirmed", {
			event_id: input.eventId,
			event_type: input.eventType,
			settlement_id: binding.settlementId,
		});
	}
	return data === true;
}

async function closeTerminalSubscriptionIntent(
	supabase: SupabaseClient,
	input: {
		eventId: string;
		eventType: string;
		object: Record<string, unknown>;
		userId: string;
		tenantId: string;
		evaluation: StripeEventEvaluation;
	},
): Promise<void> {
	const { evaluation } = input;
	const terminal = evaluation.eventType === "customer.subscription.deleted" ||
		(evaluation.eventType === "customer.subscription.updated" &&
			["canceled", "cancelled", "deleted", "incomplete_expired"].includes(evaluation.status ?? ""));
	if (evaluation.extraAgents !== 0 || !evaluation.subscriptionId || !terminal) return;
	await closeCheckoutIntent(supabase, {
		eventId: input.eventId,
		eventType: input.eventType,
		object: input.object,
		userId: input.userId,
		tenantId: input.tenantId,
		subscriptionId: evaluation.subscriptionId,
	});
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
	const { SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, STRIPE_SECRET_KEY } = config.values;

	// The RAW body must be read before anything parses it.
	const rawResult = await readBoundedText(req, MAX_WEBHOOK_BODY_BYTES);
	if (!rawResult.ok) {
		return json(rawResult.status, {
			error: rawResult.error === "request_too_large" ? rawResult.error : "invalid_json",
		}, requestId);
	}
	const rawBody = rawResult.value;

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
		if (event.type === "checkout.session.expired") {
			const data = event.data && typeof event.data === "object" && !Array.isArray(event.data)
				? event.data as Record<string, unknown> : {};
			const object = data.object && typeof data.object === "object" && !Array.isArray(data.object)
				? data.object as Record<string, unknown> : {};
			const binding = extractCheckoutIntentMetadata(object);
			const sessionId = typeof object.id === "string" && /^cs_[A-Za-z0-9_]{1,252}$/.test(object.id)
				? object.id : null;
			if (sessionId && binding.userId && binding.tenantId && binding.settlementId && binding.requestId) {
				const closed = await closeCheckoutIntent(supabase, {
					eventId,
					eventType: "checkout.session.expired",
					object,
					userId: binding.userId,
					tenantId: binding.tenantId,
					checkoutSessionId: sessionId,
				});
				if (!closed) log(requestId, "expired checkout intent was not closed", {
					event_id: eventId, settlement_id: binding.settlementId,
				});
				await audit(supabase, "stripe.webhook.checkout_expired", binding.userId, binding.tenantId, {
					event_id: eventId, settlement_id: binding.settlementId, closed,
				});
			} else {
				await audit(supabase, "stripe.webhook.checkout_expired_unlinked", null, null, { event_id: eventId });
			}
			await completeStripeEvent(supabase, eventId);
			return json(200, { ok: true, recorded: true }, requestId);
		}

		if (evaluation.action === "ignore") {
			await audit(supabase, "stripe.webhook.ignored", null, null, {
				event_type: evaluation.eventType,
				event_id: eventId,
				reason: evaluation.reason,
				subscription_id: evaluation.subscriptionId,
				price_configured: EXTRA_AGENT_PRICE_ID !== "",
			});
			await completeStripeEvent(supabase, eventId);
			return json(200, { ok: true, ignored: true }, requestId);
		}

		// A checkout-created settlement is bound to the exact signed invoice
		// payment before any current-membership decision. Tenant/user/intent
		// ownership is re-validated atomically by the RPC, so offboarding after
		// checkout cannot erase financial evidence.
		const paymentEvidenceRecorded = await recordStripePaymentEvidence(
			supabase,
			eventId,
			evaluation,
			STRIPE_SECRET_KEY,
		);

		// Resolve the tenant from metadata our checkout path set, or from a
		// customer linkage we recorded earlier. A customer email is deliberately
		// NOT used: it is typed by the customer in the hosted checkout page and is
		// therefore client-supplied.
		let userId: string | null = null;
		let tenantId: string | null = evaluation.tenantId;
		let resolvedVia = "";
		const customerLinkageResult = evaluation.customerId
			? await resolveCustomerLinkage(supabase, evaluation.customerId, evaluation.userId, evaluation.tenantId)
			: null;
		const customerLinkage = customerLinkageResult?.linkage ?? null;
		if (evaluation.userId) {
			userId = await resolveUserIdFromMetadata(supabase, evaluation.userId);
			resolvedVia = userId ? "metadata" : "metadata_unknown_user";
		}
		if (customerLinkageResult?.conflict || (
			customerLinkage &&
			((evaluation.userId && customerLinkage.userId !== evaluation.userId) ||
				(tenantId && customerLinkage.tenantId !== tenantId))
		)) {
			resolvedVia = "customer_metadata_binding_conflict";
			userId = null;
			tenantId = null;
		} else if (customerLinkage) {
			userId ??= customerLinkage.userId;
			tenantId ??= customerLinkage.tenantId;
			resolvedVia = resolvedVia || "customer_linkage";
		}
		if ((!userId || !tenantId) && !customerLinkageResult?.conflict &&
			evaluation.eventType === "customer.subscription.deleted" &&
			evaluation.extraAgents === 0 && evaluation.customerId && evaluation.subscriptionId) {
			const { data: bound, error: bindingError } = await supabase.from("subscriptions")
				.select("provider,provider_subscription_id,user_id,tenant_id")
				.eq("provider", "stripe")
				.eq("provider_subscription_id", evaluation.subscriptionId).maybeSingle();
			if (bindingError) throw bindingError;
			if (bound?.provider === "stripe" && bound.provider_subscription_id === evaluation.subscriptionId &&
				isUuid(bound.user_id) && isUuid(bound.tenant_id)) {
				const match = await resolveCustomerLinkage(supabase, evaluation.customerId, bound.user_id, bound.tenant_id);
				if ((!evaluation.userId || evaluation.userId === bound.user_id) &&
					(!evaluation.tenantId || evaluation.tenantId === bound.tenant_id) &&
					match.linkage?.userId === bound.user_id && match.linkage.tenantId === bound.tenant_id) {
					userId = bound.user_id;
					tenantId = bound.tenant_id;
					resolvedVia = "bound_deleted_subscription";
				}
			}
		}

		if (!userId || !tenantId) {
			await audit(supabase, "stripe.webhook.unlinked", null, null, {
				event_type: evaluation.eventType,
				event_id: eventId,
				reason: resolvedVia || "missing_checkout_metadata",
				customer_id: evaluation.customerId,
				subscription_id: evaluation.subscriptionId,
			});
			await completeStripeEvent(supabase, eventId);
			return json(200, { ok: true, unlinked: true }, requestId);
		}

		let tenantAllowed = await tenantIsAllowed(supabase, tenantId, userId);
		if (!tenantAllowed && evaluation.action === "reconcile" && evaluation.extraAgents === 0 && evaluation.subscriptionId) {
			const { data: bound, error: bindingError } = await supabase.from("subscriptions")
				.select("provider,provider_subscription_id,user_id,tenant_id")
				.eq("provider_subscription_id", evaluation.subscriptionId).maybeSingle();
			if (bindingError) throw bindingError;
			tenantAllowed = isBoundZeroSeatTransition(evaluation, bound, userId, tenantId);
		}
		if (!tenantAllowed) {
			await audit(supabase, "stripe.webhook.tenant_rejected", userId, null, {
				event_type: evaluation.eventType,
				event_id: eventId,
				tenant_id: tenantId,
			});
			await completeStripeEvent(supabase, eventId);
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
				payment_evidence_recorded: paymentEvidenceRecorded,
			});
			await completeStripeEvent(supabase, eventId);
			return json(200, { ok: true, recorded: true }, requestId);
		}

		// action === "reconcile": subscription state, then the seat entitlement.
		if (!evaluation.writeEntitlement) {
			await audit(supabase, "stripe.webhook.ignored", userId, tenantId, {
				event_type: evaluation.eventType,
				event_id: eventId,
				reason: "subscription_reference_missing",
			});
			await completeStripeEvent(supabase, eventId);
			return json(200, { ok: true, ignored: true }, requestId);
		}

		const transition = await applySubscriptionEvent(supabase, eventId, userId, tenantId, evaluation);
		const eventData = event.data && typeof event.data === "object" && !Array.isArray(event.data)
			? event.data as Record<string, unknown> : {};
		const eventObject = eventData.object && typeof eventData.object === "object" && !Array.isArray(eventData.object)
			? eventData.object as Record<string, unknown> : {};
		await closeTerminalSubscriptionIntent(supabase, {
			eventId,
			eventType: evaluation.eventType,
			object: eventObject,
			userId,
			tenantId,
			evaluation,
		});
		if (!transition.applied) {
			await audit(supabase, "stripe.webhook.ignored", userId, tenantId, {
				event_type: evaluation.eventType,
				event_id: eventId,
				reason: "stale_provider_event",
			});
			await completeStripeEvent(supabase, eventId);
			return json(200, { ok: true, ignored: true }, requestId);
		}
		await audit(supabase, "stripe.webhook", userId, tenantId, {
			event_type: evaluation.eventType,
			event_id: eventId,
			reason: evaluation.reason,
			subscription_id: evaluation.subscriptionId,
			status: evaluation.status,
			entitled: evaluation.entitled,
			extra_agents: evaluation.extraAgents,
			entitlement_mode: "atomic_provider_transition",
			tenant_extra_agents: transition.extraAgents,
			customer_linked: customerLinked,
			tenant_id: tenantId,
		});

		await completeStripeEvent(supabase, eventId);
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

		// Mark the claim failed so Stripe's retry can finish the work. The atomic
		// subscription transition rejects stale or repeated provider events, so a
		// transient error cannot either poison the event id or apply it twice.
		await releaseStripeEvent(recorder, eventId);

		return json(500, { error: "webhook_processing_failed" }, requestId);
	}
});
