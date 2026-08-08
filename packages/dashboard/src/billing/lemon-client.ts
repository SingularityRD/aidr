// Lemon Squeezy API client
import { selfServiceCheckoutEnabled } from "./commercial";

const LEMON_API_KEY = process.env.LEMON_SQUEEZY_API_KEY;
const LEMON_STORE_ID = process.env.LEMON_SQUEEZY_STORE_ID;

// Önceden oluşturulmuş Lemon Squeezy ürünleri
const PRODUCTS = {
	"agent-seat-monthly": {
		variantId: process.env.LEMON_SQUEEZY_VARIANT_MONTHLY || "123456", // Lemon Squeezy variant ID
		price: 2, // $2/month per agent
		name: "AIDR Agent Seat - Monthly",
	},
	"agent-seat-yearly": {
		variantId: process.env.LEMON_SQUEEZY_VARIANT_YEARLY || "123457",
		price: 20, // $20/year per agent (2 months free)
		name: "AIDR Agent Seat - Yearly",
	},
};

export interface CheckoutResult {
	checkoutUrl: string;
	checkoutId: string;
}

export async function createCheckout(
	userId: string,
	email: string,
	seats: number,
	plan: "monthly" | "yearly",
	referralCode?: string,
): Promise<CheckoutResult> {
	if (!selfServiceCheckoutEnabled) {
		throw new Error(
			"Self-service checkout is disabled for the direct-GA release. Use the approved enterprise invoice workflow.",
		);
	}
	if (!LEMON_API_KEY) {
		throw new Error("LEMON_SQUEEZY_API_KEY is not set");
	}
	if (!LEMON_STORE_ID) {
		throw new Error("LEMON_SQUEEZY_STORE_ID is not set");
	}

	const product = PRODUCTS[`agent-seat-${plan}`];

	const response = await fetch("https://api.lemonsqueezy.com/v1/checkouts", {
		method: "POST",
		headers: {
			Accept: "application/vnd.api+json",
			"Content-Type": "application/vnd.api+json",
			Authorization: `Bearer ${LEMON_API_KEY}`,
		},
		body: JSON.stringify({
			data: {
				type: "checkouts",
				attributes: {
					checkout_data: {
						email: email,
						custom: {
							user_id: userId,
							seats: seats.toString(),
							referral_code: referralCode || null,
						},
					},
				},
				relationships: {
					store: {
						data: {
							type: "stores",
							id: LEMON_STORE_ID,
						},
					},
					variant: {
						data: {
							type: "variants",
							id: product.variantId,
						},
					},
				},
			},
		}),
	});

	if (!response.ok) {
		const errorData = await response.json().catch(() => ({}));
		throw new Error(`Lemon Squeezy API error: ${response.status} - ${JSON.stringify(errorData)}`);
	}

	const data = await response.json();
	return {
		checkoutUrl: data.data.attributes.url,
		checkoutId: data.data.id,
	};
}

// Kullanıcının subscription'larını getir
export async function getUserSubscriptions(userEmail: string) {
	if (!LEMON_API_KEY) {
		throw new Error("LEMON_SQUEEZY_API_KEY is not set");
	}
	if (!LEMON_STORE_ID) {
		throw new Error("LEMON_SQUEEZY_STORE_ID is not set");
	}

	const response = await fetch(
		`https://api.lemonsqueezy.com/v1/subscriptions?filter[store_id]=${LEMON_STORE_ID}&filter[user_email]=${encodeURIComponent(userEmail)}`,
		{
			headers: {
				Accept: "application/vnd.api+json",
				Authorization: `Bearer ${LEMON_API_KEY}`,
			},
		},
	);

	if (!response.ok) {
		const errorData = await response.json().catch(() => ({}));
		throw new Error(`Lemon Squeezy API error: ${response.status} - ${JSON.stringify(errorData)}`);
	}

	return await response.json();
}

// Subscription iptal et
export async function cancelSubscription(subscriptionId: string) {
	if (!LEMON_API_KEY) {
		throw new Error("LEMON_SQUEEZY_API_KEY is not set");
	}

	const response = await fetch(`https://api.lemonsqueezy.com/v1/subscriptions/${subscriptionId}`, {
		method: "DELETE",
		headers: {
			Accept: "application/vnd.api+json",
			Authorization: `Bearer ${LEMON_API_KEY}`,
		},
	});

	if (!response.ok) {
		const errorData = await response.json().catch(() => ({}));
		throw new Error(`Lemon Squeezy API error: ${response.status} - ${JSON.stringify(errorData)}`);
	}
}

// Müşteri portal URL'si oluştur (Lemon Squeezy müşteri portalı)
export async function createCustomerPortal(_customerId: string): Promise<string> {
	// Lemon Squeezy'de doğrudan müşteri portalı yok, ancak müşteriler
	// kendi subscription yönetim URL'lerini email üzerinden alırlar
	// Alternatif olarak customer'ı yönetmek için API kullanılabilir
	return `https://${process.env.LEMON_SQUEEZY_STORE_SLUG || "store"}.lemonsqueezy.com/billing`;
}

// Webhook doğrulama (Lemon Squeezy webhook secret ile)
export function verifyWebhookSignature(
	_payload: string,
	_signature: string,
	_secret: string,
): boolean {
	// Lemon Squeezy webhook imza doğrulama implementasyonu
	// Gerçek implementasyonda crypto ile HMAC doğrulaması yapılır
	// Şu an için basit placeholder
	return true;
}
