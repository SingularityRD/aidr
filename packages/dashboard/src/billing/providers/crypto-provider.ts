import type { PaymentProvider, PaymentResult } from "../payment-router";

interface CoinbaseCharge {
	data: {
		id: string;
		hosted_url: string;
		code: string;
		name: string;
		description: string;
		created_at: string;
		expires_at: string;
		pricing: {
			local: {
				amount: string;
				currency: string;
			};
		};
		metadata: Record<string, string>;
	};
}

export class CryptoProvider implements PaymentProvider {
	private apiKey: string;
	private baseUrl = "https://api.commerce.coinbase.com";

	constructor() {
		const apiKey = process.env.COINBASE_API_KEY;
		if (!apiKey) {
			throw new Error("COINBASE_API_KEY is not set");
		}
		this.apiKey = apiKey;
	}

	async createSubscription(
		userId: string,
		seats: number,
		plan: "monthly" | "yearly",
	): Promise<PaymentResult> {
		const usdPrice = plan === "yearly" ? seats * 20 : seats * 2;

		const response = await fetch(`${this.baseUrl}/charges`, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-CC-Api-Key": this.apiKey,
				"X-CC-Version": "2018-03-22",
			},
			body: JSON.stringify({
				name: `AIDR - ${seats} Agent Seats`,
				description: `AI Agent Security (${plan})`,
				local_price: {
					amount: usdPrice.toString(),
					currency: "USD",
				},
				pricing_type: "fixed_price",
				metadata: {
					user_id: userId,
					seats: seats.toString(),
					plan_type: plan,
				},
				redirect_url: `${process.env.NEXT_PUBLIC_URL}/billing/success`,
				cancel_url: `${process.env.NEXT_PUBLIC_URL}/billing/cancel`,
			}),
		});

		if (!response.ok) {
			const error = await response.text();
			throw new Error(`Coinbase API error: ${error}`);
		}

		const charge: CoinbaseCharge = await response.json();

		return {
			url: charge.data.hosted_url,
			provider: "crypto",
			charge_id: charge.data.id,
			code: charge.data.code,
		};
	}

	async cancelSubscription(subscriptionId: string): Promise<void> {
		// Coinbase Commerce charges are one-time
		// For subscription-like behavior, we would create new charges periodically
		// Cancel is a no-op here as charges can't be cancelled once created
		console.log(`Crypto payment reference: ${subscriptionId}`);
	}

	async getInvoices(userId: string): Promise<Invoice[]> {
		// Query charges from Coinbase API
		const response = await fetch(`${this.baseUrl}/charges`, {
			method: "GET",
			headers: {
				"X-CC-Api-Key": this.apiKey,
				"X-CC-Version": "2018-03-22",
			},
		});

		if (!response.ok) {
			return [];
		}

		const result = await response.json();
		const charges = result.data || [];

		// Filter charges for this user
		return charges
			.filter((charge: CoinbaseCharge["data"]) => charge.metadata?.user_id === userId)
			.map((charge: CoinbaseCharge["data"]) => ({
				id: charge.id,
				amount: parseFloat(charge.pricing.local.amount),
				currency: charge.pricing.local.currency,
				status: "succeeded" as const,
				created_at: charge.created_at,
				pdf_url: null,
			}));
	}

	// Webhook handler for Coinbase events
	async handleWebhook(payload: unknown, signature: string): Promise<boolean> {
		const webhookSecret = process.env.COINBASE_WEBHOOK_SECRET;
		if (!webhookSecret) {
			throw new Error("COINBASE_WEBHOOK_SECRET is not set");
		}

		// Verify webhook signature
		const crypto = await import("crypto");
		const hmac = crypto.createHmac("sha256", webhookSecret);
		hmac.update(JSON.stringify(payload));
		const computed = hmac.digest("hex");

		return crypto.timingSafeEqual(Buffer.from(computed), Buffer.from(signature));
	}
}

export interface Invoice {
	id: string;
	amount: number;
	currency: string;
	status: "succeeded" | "failed" | "pending" | "unknown";
	created_at: string;
	pdf_url: string | null;
}
