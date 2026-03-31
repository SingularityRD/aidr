import { CryptoProvider } from "./providers/crypto-provider";
import { IyzicoProvider } from "./providers/iyzico-provider";
import { StripeProvider } from "./providers/stripe-provider";

export type ProviderType = "stripe" | "iyzico" | "crypto" | "paypal";

export interface PaymentResult {
	url: string;
	provider: ProviderType;
	session_id?: string;
	token?: string;
	conversation_id?: string;
	charge_id?: string;
	code?: string;
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
	fallback?: ProviderType;
	supportedCurrencies: string[];
	features: string[];
}

// Region-based provider configuration
const REGION_CONFIG: Record<string, ProviderConfig> = {
	TR: {
		primary: "iyzico",
		fallback: "stripe",
		supportedCurrencies: ["TRY", "USD", "EUR"],
		features: ["3D Secure", "Taksit", "TL Fatura", "KDV"],
	},
	EU: {
		primary: "stripe",
		fallback: "paypal",
		supportedCurrencies: ["EUR", "USD", "GBP"],
		features: ["SEPA", "VAT Moss"],
	},
	US: {
		primary: "stripe",
		fallback: "paypal",
		supportedCurrencies: ["USD", "EUR", "GBP"],
		features: ["Stripe Tax", "ACH"],
	},
	GLOBAL: {
		primary: "stripe",
		fallback: "paypal",
		supportedCurrencies: ["USD", "EUR", "GBP", "JPY", "AUD", "CAD"],
		features: ["Multi-currency", "Subscription"],
	},
};

// Privacy/crypto regions or preferences
const PRIVACY_PREFERRED_REGIONS = ["RU", "BY", "VE", "IR", "KP"];

/**
 * Get payment provider based on user location and preferences
 *
 * Strategy:
 * - Turkey (TR): iyzico primary for local payment methods (3D Secure, taksit)
 * - EU/US: Stripe primary for global coverage
 * - Privacy preference: Crypto for anonymity
 * - Explicit provider preference overrides auto-selection
 */
export function getPaymentProvider(
	userLocation: UserLocation | string,
	preference?: ProviderType | "privacy",
): PaymentProvider {
	const country = typeof userLocation === "string" ? userLocation : userLocation.country;

	// Privacy/crypto preference takes highest priority
	if (preference === "crypto" || preference === "privacy") {
		return new CryptoProvider();
	}

	// Explicit provider preference
	if (preference === "stripe") {
		return new StripeProvider();
	}
	if (preference === "iyzico") {
		return new IyzicoProvider();
	}

	// Auto-select based on country
	switch (country) {
		case "TR":
			return new IyzicoProvider();

		case "US":
		case "CA":
		case "GB":
		case "DE":
		case "FR":
		case "AU":
		case "JP":
			return new StripeProvider();

		default:
			// Privacy-preferring regions get crypto option prominently
			if (PRIVACY_PREFERRED_REGIONS.includes(country)) {
				// Still default to stripe but crypto should be highlighted in UI
				return new StripeProvider();
			}
			return new StripeProvider();
	}
}

/**
 * Get available providers for a user location
 * Used for UI selector display
 */
export function getAvailableProviders(
	userLocation: UserLocation | string,
): Array<{ id: ProviderType; name: string; features: string[]; recommended?: boolean }> {
	const country = typeof userLocation === "string" ? userLocation : userLocation.country;
	const providers: Array<{
		id: ProviderType;
		name: string;
		features: string[];
		recommended?: boolean;
	}> = [];

	if (country === "TR") {
		providers.push({
			id: "iyzico",
			name: "Kredi/Banka Kartı (Türkiye)",
			features: ["TL Fatura", "3D Secure", "Taksit", "%20 KDV"],
			recommended: true,
		});
	}

	providers.push(
		{
			id: "stripe",
			name: "Credit Card (Global)",
			features: ["USD/EUR/GBP", "Subscription", "Invoice"],
		},
		{
			id: "crypto",
			name: "Crypto (BTC/ETH/USDC)",
			features: ["Anonymous", "Privacy", "No KYC"],
		},
	);

	return providers;
}

/**
 * Get provider configuration for a region
 */
export function getRegionConfig(country: string): ProviderConfig {
	if (country === "TR") return REGION_CONFIG.TR;
	if (["DE", "FR", "IT", "ES", "NL", "BE", "AT", "PL", "SE", "DK"].includes(country)) {
		return REGION_CONFIG.EU;
	}
	if (["US", "CA"].includes(country)) return REGION_CONFIG.US;
	return REGION_CONFIG.GLOBAL;
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
	ip?: string,
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
