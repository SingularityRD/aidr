// Stripe billing client for the dashboard.
//
// SECURITY: the browser bundle must never hold `STRIPE_SECRET_KEY`. Creating a
// Checkout Session, reading a customer's subscriptions, cancelling a
// subscription and opening the billing portal are all *server-side* operations.
// The opt-in billing-checkout Edge Function creates Checkout Sessions with a
// tenant-bound authenticated request; portal and cancellation are still closed.
//
// Two deliberate omissions compared with the removed Lemon Squeezy client:
//
//   1. There is no client-side webhook signature helper. Webhook authenticity
//      is verified server-side only (supabase/functions/stripe-webhook); the
//      deleted `verifyWebhookSignature` returned `true` unconditionally and any
//      replacement in a browser bundle would be equally meaningless.
//   2. Nothing here reads a `STRIPE_*` secret from the environment.

import { supabase } from "../lib/supabase";
import { selfServiceCheckoutEnabled } from "./commercial";

export interface CheckoutResult {
	checkoutUrl: string;
	checkoutId: string;
}

/**
 * Direct-GA is invoice/order based: self-service checkout is an explicit
 * non-default opt-in and stays fail-closed until the server-side Checkout
 * Session endpoint exists.
 */
function assertSelfServiceEnabled(): void {
	if (!selfServiceCheckoutEnabled) {
		throw new Error(
			"Self-service checkout is disabled for the direct-GA release. Use the approved enterprise invoice workflow.",
		);
	}
}

export async function createCheckout(
	_userId: string,
	_email: string,
	seats: number,
	plan: "monthly" | "yearly",
	_referralCode?: string,
	tenantId?: string,
	requestId?: string,
): Promise<CheckoutResult> {
	assertSelfServiceEnabled();
	if (
		!tenantId ||
		!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(tenantId)
	) {
		throw new Error("A valid tenant is required for server-side checkout");
	}
	const stableRequestId = requestId ?? crypto.randomUUID();
	if (!/^[a-zA-Z0-9_-]{16,80}$/.test(stableRequestId))
		throw new Error("Invalid checkout request ID");
	const { data, error } = await supabase.functions.invoke("billing-checkout", {
		body: { tenant_id: tenantId, seats, plan, request_id: stableRequestId },
	});
	if (
		error ||
		data?.ok !== true ||
		typeof data.checkout_id !== "string" ||
		typeof data.checkout_url !== "string"
	)
		throw new Error("The server-side checkout could not be created.");
	const url = new URL(data.checkout_url);
	if (url.origin !== "https://checkout.stripe.com")
		throw new Error("Invalid server-side checkout URL");
	return { checkoutUrl: url.toString(), checkoutId: data.checkout_id };
}

export async function getUserSubscriptions(_userEmail: string): Promise<never> {
	assertSelfServiceEnabled();
	throw new Error(
		"Stripe subscription lookups must run server-side with STRIPE_SECRET_KEY; the dashboard never " +
			"holds the Stripe secret key.",
	);
}

export async function cancelSubscription(_subscriptionId: string): Promise<void> {
	assertSelfServiceEnabled();
	throw new Error(
		"Stripe subscription cancellation must run server-side with STRIPE_SECRET_KEY; the dashboard " +
			"never holds the Stripe secret key.",
	);
}

export async function createCustomerPortal(_customerId: string): Promise<string> {
	assertSelfServiceEnabled();
	throw new Error(
		"The Stripe billing portal session must be created server-side with STRIPE_SECRET_KEY; the " +
			"dashboard never holds the Stripe secret key.",
	);
}
