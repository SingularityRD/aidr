/**
 * Provider-agnostic licence types for the AIDR SDK.
 *
 * These were previously declared in `billing.ts` alongside a complete Lemon
 * Squeezy client. Lemon Squeezy has been removed from the product (its webhook
 * performed no signature verification), and the pure types are kept here so that
 * licence/entitlement logic does not depend on a payment provider.
 *
 * There is deliberately **no** payment-provider client in the SDK. Billing and
 * entitlement issuance are server-side concerns: the Stripe webhook Edge Function
 * (`supabase/functions/stripe-webhook/`) verifies signatures and writes
 * entitlements. A client-side or SDK-side webhook verifier cannot be made safe
 * (it either holds a secret in an unsafe place or skips verification), so none is
 * offered.
 */

/**
 * Result of validating a licence key or entitlement.
 */
export interface LicenseValidationResult {
	valid: boolean;
	seats: number;
	expiresAt?: Date;
}

/**
 * Usage information for the current billing period.
 */
export interface UsageInfo {
	used: number;
	total: number;
	resetDate: Date;
}
