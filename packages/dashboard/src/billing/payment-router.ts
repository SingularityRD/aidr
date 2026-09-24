// Stripe-only payment router
// Lemon Squeezy was removed (its webhook had no signature verification); the
// legacy iyzico/crypto providers were removed earlier.

import { selfServiceCheckoutEnabled } from "./commercial";

import { cancelSubscription } from "./stripe-client";

export type ProviderType = "stripe";

interface PaymentResult {
	url: string;
	provider: ProviderType;
	checkoutId?: string;
}

interface Invoice {
	id: string;
	amount: number;
	currency: string;
	status: "succeeded" | "failed" | "pending" | "unknown";
	created_at: string;
	pdf_url: string | null;
}

export interface PaymentProvider {
	createSubscription(
		userId: string,
		seats: number,
		plan: "monthly" | "yearly",
	): Promise<PaymentResult>;
	cancelSubscription(subscriptionId: string): Promise<void>;
	getInvoices(userId: string): Promise<Invoice[]>;
}

interface UserLocation {
	country: string;
	region?: string;
	currency?: string;
}

interface ProviderConfig {
	primary: ProviderType;
	supportedCurrencies: string[];
	features: string[];
}

// Global Stripe configuration
const STRIPE_CONFIG: ProviderConfig = {
	primary: "stripe",
	supportedCurrencies: ["USD", "EUR", "GBP"],
	features: ["Subscription", "Checkout"],
};

/**
 * Get payment provider - now returns the Stripe client
 * Webhook authenticity is verified server-side only.
 */
export function getPaymentProvider(): PaymentProvider {
	return {
		async createSubscription(
			_userId: string,
			_seats: number,
			_plan: "monthly" | "yearly",
		): Promise<PaymentResult> {
			if (!selfServiceCheckoutEnabled) {
				throw new Error(
					"Self-service billing is disabled for the direct-GA release. Use the approved enterprise invoice workflow.",
				);
			}
			// Note: This requires user email which we don't have here
			// In real implementation, fetch user email from auth context
			throw new Error(
				"Use the authenticated billing-checkout Edge Function: Stripe sessions are created server-side.",
			);
		},
		async cancelSubscription(subscriptionId: string): Promise<void> {
			return cancelSubscription(subscriptionId);
		},
		async getInvoices(_userId: string): Promise<Invoice[]> {
			// An empty array would be interpreted as a successful reconciliation.
			// The invoice ledger is not available through this browser API.
			throw new Error(
				"Invoice records require the approved server-side finance reconciliation workflow.",
			);
		},
	};
}

/**
 * Get available providers - now returns only Stripe
 */
export function getAvailableProviders(): Array<{
	id: ProviderType;
	name: string;
	features: string[];
	recommended?: boolean;
}> {
	if (!selfServiceCheckoutEnabled) return [];
	return [
		{
			id: "stripe",
			name: "Stripe (Global)",
			features: ["USD/EUR/GBP", "Subscription", "Checkout"],
			recommended: true,
		},
	];
}

/**
 * Get provider configuration
 */
export function getRegionConfig(): ProviderConfig {
	return STRIPE_CONFIG;
}

export async function convertCurrency(amount: number, from: string, to: string): Promise<number> {
	if (!Number.isFinite(amount) || amount < 0) throw new Error("Invalid commercial amount");
	if (!/^[A-Z]{3}$/.test(from) || !/^[A-Z]{3}$/.test(to)) throw new Error("Invalid currency code");
	if (from === to) return amount;
	// Cross-currency terms belong to the Finance-approved order. The browser
	// cannot quote a converted price or silently invent a fallback exchange rate.
	throw new Error("Cross-currency amount requires an approved enterprise quote");
}

/**
 * Detect user location from various signals
 */
function detectUserLocation(
	_ip?: string,
	browserLocale?: string,
	explicitCountry?: string,
): UserLocation {
	// Explicit override takes precedence
	if (explicitCountry) {
		return { country: explicitCountry };
	}

	// Try browser locale
	if (browserLocale) {
		const country = browserLocale.split("-")[1];
		if (country) {
			return { country, currency: getCurrencyForCountry(country) };
		}
	}

	// Default to US if nothing else available
	return { country: "US", currency: "USD" };
}

function getCurrencyForCountry(country: string): string {
	const map: Record<string, string> = {
		TR: "TRY",
		US: "USD",
		GB: "GBP",
		DE: "EUR",
		FR: "EUR",
		JP: "JPY",
		CA: "CAD",
		AU: "AUD",
	};
	return map[country] || "USD";
}
