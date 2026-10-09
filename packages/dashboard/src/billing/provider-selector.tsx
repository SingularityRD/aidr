import { selfServiceCheckoutEnabled } from "./commercial";
import type { ProviderType } from "./payment-router";

interface ProviderOption {
	id: ProviderType;
	name: string;
	icon: string;
	features: string[];
	recommended?: boolean;
}

/**
 * Build provider list - Stripe only.
 * Lemon Squeezy was removed (unverified webhook); iyzico/crypto were removed earlier.
 */
export function buildProviderList(_userLocation: string): ProviderOption[] {
	if (!selfServiceCheckoutEnabled) return [];
	return [
		{
			id: "stripe",
			name: "Stripe (Global)",
			icon: "/stripe-logo.svg",
			features: ["USD/EUR/GBP", "Subscription", "Checkout"],
			recommended: true,
		},
	];
}

/**
 * Get payment button text - invoice-first unless self-service is explicitly enabled
 */
export function getPaymentButtonText(_provider: ProviderType, _userLocation: string): string {
	if (!selfServiceCheckoutEnabled) return "Request enterprise invoice";
	return "Subscribe with Stripe";
}
