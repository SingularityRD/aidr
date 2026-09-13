// Payment providers barrel export
//
// Stripe replaces the removed Lemon Squeezy client. Webhook verification is
// server-side only (supabase/functions/stripe-webhook) and is deliberately not
// exported to the browser bundle.
export type { CheckoutResult } from "../stripe-client";
export {
	cancelSubscription,
	createCheckout,
	createCustomerPortal,
	getUserSubscriptions,
} from "../stripe-client";
