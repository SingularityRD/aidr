// LemonSqueezy-only payment router
// Removed: stripe, iyzico, crypto providers (user requested only LemonSqueezy)

import { cancelSubscription } from "./lemon-client";

export type ProviderType = "lemon-squeezy";

export interface PaymentResult {
	url: string;
	provider: ProviderType;
	checkoutId?: string;
}

export interface Invoice {
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

// Global LemonSqueezy configuration
const LEMON_CONFIG: ProviderConfig = {
	primary: "lemon-squeezy",
	supportedCurrencies: ["USD", "EUR", "GBP"],
	features: ["Subscription", "Checkout", "Customer Portal"],
};

/**
 * Get payment provider - now returns LemonSqueezy client
 * Legacy providers (stripe, iyzico, crypto) removed per user request
 */
export function getPaymentProvider(): PaymentProvider {
	return {
		async createSubscription(
			_userId: string,
			_seats: number,
			_plan: "monthly" | "yearly",
		): Promise<PaymentResult> {
			// Note: This requires user email which we don't have here
			// In real implementation, fetch user email from auth context
			throw new Error("Use createCheckout from lemon-client directly with user email");
		},
		async cancelSubscription(subscriptionId: string): Promise<void> {
			return cancelSubscription(subscriptionId);
		},
		async getInvoices(_userId: string): Promise<Invoice[]> {
			// LemonSqueezy doesn't have direct invoice API, return empty
			return [];
		},
	};
}

/**
 * Get available providers - now returns only LemonSqueezy
 */
export function getAvailableProviders(): Array<{
	id: ProviderType;
	name: string;
	features: string[];
	recommended?: boolean;
}> {
	return [
		{
			id: "lemon-squeezy",
			name: "LemonSqueezy (Global)",
			features: ["USD/EUR/GBP", "Subscription", "Checkout"],
			recommended: true,
		},
	];
}

/**
 * Get provider configuration
 */
export function getRegionConfig(): ProviderConfig {
	return LEMON_CONFIG;
}

/**
 * Currency conversion with caching
 */
interface ExchangeRates {
	rates: Record<string, number>;
	timestamp: number;
}

let cachedRates: ExchangeRates | null = null;
const CACHE_TTL = 60 * 60 * 1000; // 1 hour

export async function convertCurrency(amount: number, from: string, to: string): Promise<number> {
	if (from === to) return amount;

	// Check cache
	if (!cachedRates || Date.now() - cachedRates.timestamp > CACHE_TTL) {
		try {
			const response = await fetch(`https://api.exchangerate-api.com/v4/latest/${from}`);
			const data = await response.json();
			cachedRates = {
				rates: data.rates,
				timestamp: Date.now(),
			};
		} catch {
			// Fallback rates if API fails
			const fallbackRates: Record<string, number> = {
				USD: 1,
				EUR: 0.85,
				GBP: 0.73,
				TRY: 35,
				JPY: 150,
				CAD: 1.35,
				AUD: 1.52,
			};
			cachedRates = {
				rates: fallbackRates,
				timestamp: Date.now(),
			};
		}
	}

	const rate = cachedRates.rates[to];
	if (!rate) return amount; // Return original if rate not found

	// Round to nearest .99 for psychological pricing
	const converted = amount * rate;
	return Math.floor(converted) + 0.99;
}

/**
 * Detect user location from various signals
 */
export function detectUserLocation(
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
