import Iyzipay from "iyzipay";
import type { PaymentProvider, PaymentResult } from "../payment-router";

export class IyzicoProvider implements PaymentProvider {
	private iyzipay: Iyzipay;

	constructor() {
		const apiKey = process.env.IYZICO_API_KEY;
		const secretKey = process.env.IYZICO_SECRET_KEY;

		if (!apiKey || !secretKey) {
			throw new Error("IYZICO_API_KEY or IYZICO_SECRET_KEY is not set");
		}

		this.iyzipay = new Iyzipay({
			apiKey,
			secretKey,
			uri:
				process.env.IYZICO_SANDBOX === "true"
					? "https://sandbox-api.iyzipay.com"
					: "https://api.iyzipay.com",
		});
	}

	async createSubscription(
		userId: string,
		seats: number,
		plan: "monthly" | "yearly",
	): Promise<PaymentResult> {
		// TL conversion (1 USD ≈ 35 TL, 2026 estimated)
		const usdPrice = plan === "yearly" ? seats * 20 : seats * 2;
		const tryPrice = Math.round(usdPrice * 35);

		const request: Iyzipay.PaymentRequest = {
			locale: Iyzipay.LOCALE.TR,
			conversationId: userId,
			price: tryPrice.toString(),
			paidPrice: tryPrice.toString(),
			currency: Iyzipay.CURRENCY.TRY,
			paymentGroup: Iyzipay.PAYMENT_GROUP.SUBSCRIPTION,
			callbackUrl: `${process.env.NEXT_PUBLIC_URL}/api/payment/iyzico-callback`,
			buyer: {
				id: userId,
				name: "Kullanici", // Will be updated with actual user data
				surname: "Adi",
				email: "user@example.com", // Fetch from user profile
				identityNumber: "11111111111", // Required for 3D Secure
				registrationAddress: "Turkey",
				ip: "85.34.78.112", // Will be replaced with actual IP
				city: "Istanbul",
				country: "Turkey",
				zipCode: "34000",
			},
			shippingAddress: {
				contactName: "Kullanici Adi",
				city: "Istanbul",
				country: "Turkey",
				address: "Turkey",
				zipCode: "34000",
			},
			billingAddress: {
				contactName: "Kullanici Adi",
				city: "Istanbul",
				country: "Turkey",
				address: "Turkey",
				zipCode: "34000",
			},
			basketItems: [
				{
					id: "agent-seat",
					name: `AIDR Güvenlik - ${seats} Agent Koltuğu`,
					category1: "Yazılım",
					category2: "Güvenlik",
					itemType: Iyzipay.BASKET_ITEM_TYPE.VIRTUAL,
					price: tryPrice.toString(),
				},
			],
			enabledInstallments: [1, 2, 3, 6, 9, 12], // Taksit seçenekleri
		};

		return new Promise((resolve, reject) => {
			this.iyzipay.checkoutFormInitialize.create(
				request,
				(err: Error | null, result: Iyzipay.CheckoutFormInitializeResult) => {
					if (err) {
						reject(err);
						return;
					}

					if (result.status === "failure") {
						reject(new Error(result.errorMessage || "iyzico payment initialization failed"));
						return;
					}

					resolve({
						url: result.paymentPageUrl,
						provider: "iyzico",
						token: result.token,
						conversation_id: userId,
					});
				},
			);
		});
	}

	async cancelSubscription(subscriptionId: string): Promise<void> {
		// iyzico doesn't have native subscriptions like Stripe
		// We'll cancel in our database and notify iyzico if needed
		// For recurring payments, we would cancel the subscription via their API
		console.log(`Cancelling iyzico subscription reference: ${subscriptionId}`);
	}

	async getInvoices(userId: string): Promise<Invoice[]> {
		// iyzico doesn't provide a direct invoice list API
		// We'll query our own database for payment history
		return [];
	}

	// Handle iyzico callback/webhook
	async handleCallback(token: string): Promise<Iyzipay.CheckoutFormResult> {
		return new Promise((resolve, reject) => {
			this.iyzipay.checkoutForm.retrieve(
				{
					locale: Iyzipay.LOCALE.TR,
					conversationId: "callback-retrieve",
					token,
				},
				(err: Error | null, result: Iyzipay.CheckoutFormResult) => {
					if (err) {
						reject(err);
						return;
					}
					resolve(result);
				},
			);
		});
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
