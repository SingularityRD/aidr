import Stripe from "stripe";
import type { PaymentProvider, PaymentResult } from "../payment-router";

export class StripeProvider implements PaymentProvider {
	private stripe: Stripe;

	constructor() {
		const apiKey = process.env.STRIPE_SECRET_KEY;
		if (!apiKey) {
			throw new Error("STRIPE_SECRET_KEY is not set");
		}
		this.stripe = new Stripe(apiKey, { apiVersion: "2024-12-18.acacia" });
	}

	async createSubscription(
		userId: string,
		seats: number,
		plan: "monthly" | "yearly",
	): Promise<PaymentResult> {
		const price = plan === "yearly" ? seats * 20 : seats * 2; // $20/year or $2/month per seat

		const session = await this.stripe.checkout.sessions.create({
			mode: "subscription",
			line_items: [
				{
					price_data: {
						currency: "usd",
						product_data: {
							name: `AIDR - ${seats} Agent Seats`,
							description: `AI Agent Detection & Response security for ${seats} agent seats`,
						},
						unit_amount: price * 100, // Stripe uses cents
						recurring: {
							interval: plan === "yearly" ? "year" : "month",
						},
					},
					quantity: 1,
				},
			],
			success_url: `${process.env.NEXT_PUBLIC_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
			cancel_url: `${process.env.NEXT_PUBLIC_URL}/billing/cancel`,
			client_reference_id: userId,
			metadata: {
				user_id: userId,
				seats: seats.toString(),
				plan_type: plan,
			},
		});

		if (!session.url) {
			throw new Error("Failed to create Stripe checkout session");
		}

		return {
			url: session.url,
			provider: "stripe",
			session_id: session.id,
		};
	}

	async cancelSubscription(subscriptionId: string): Promise<void> {
		await this.stripe.subscriptions.cancel(subscriptionId);
	}

	async getInvoices(userId: string): Promise<Invoice[]> {
		const invoices = await this.stripe.invoices.list({
			customer: userId,
			limit: 100,
		});

		return invoices.data.map((inv) => ({
			id: inv.id,
			amount: inv.amount_due / 100,
			currency: inv.currency.toUpperCase(),
			status: inv.status === "paid" ? "succeeded" : inv.status || "unknown",
			created_at: new Date(inv.created * 1000).toISOString(),
			pdf_url: inv.invoice_pdf || null,
		}));
	}

	// Webhook handler for Stripe events
	async handleWebhook(payload: string, signature: string): Promise<Stripe.Event> {
		const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;
		if (!webhookSecret) {
			throw new Error("STRIPE_WEBHOOK_SECRET is not set");
		}

		return this.stripe.webhooks.constructEvent(payload, signature, webhookSecret);
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
