import { createHmac } from "node:crypto";
import type { Logger } from "./client.js";

/**
 * Lemon Squeezy Billing Configuration
 */
export interface BillingConfig {
	lemonSqueezyApiKey: string;
	storeId: string;
	productId: string;
	webhookSecret?: string;
}

/**
 * License validation result
 */
export interface LicenseValidationResult {
	valid: boolean;
	seats: number;
	expiresAt?: Date;
}

/**
 * Usage information
 */
export interface UsageInfo {
	used: number;
	total: number;
	resetDate: Date;
}

/**
 * Checkout data returned from Lemon Squeezy
 */
export interface CheckoutData {
	url: string;
	id: string;
}

/**
 * Lemon Squeezy API response types
 */
interface LemonSqueezyCheckoutResponse {
	data: {
		id: string;
		attributes: {
			url: string;
			product_id: number;
			store_id: number;
			status: string;
		};
	};
}

interface LemonSqueezyLicenseResponse {
	activated: boolean;
	license_key: {
		id: number;
		key: string;
		status: string;
		activation_limit: number;
		activations_count: number;
		expires_at: string | null;
	};
	error?: string;
}

interface LemonSqueezySubscriptionResponse {
	data: {
		id: string;
		attributes: {
			status: string;
			product_id: number;
			variant_id: number;
			card_brand: string;
			card_last_four: string;
			renews_at: string;
			ends_at: string | null;
			trial_ends_at: string | null;
			test_mode: boolean;
		};
	}[];
}

/**
 * Lemon Squeezy Billing integration class
 */
export class LemonSqueezyBilling {
	private readonly apiKey: string;
	private readonly storeId: string;
	private readonly productId: string;
	private readonly webhookSecret?: string;
	private readonly baseUrl = "https://api.lemonsqueezy.com/v1";

	constructor(
		private config: BillingConfig,
		private logger?: Logger,
	) {
		this.apiKey = config.lemonSqueezyApiKey;
		this.storeId = config.storeId;
		this.productId = config.productId;
		this.webhookSecret = config.webhookSecret;
	}

	/**
	 * Make an authenticated request to the Lemon Squeezy API
	 */
	private async request<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
		const url = `${this.baseUrl}${endpoint}`;
		const headers: Record<string, string> = {
			Accept: "application/vnd.api+json",
			Authorization: `Bearer ${this.apiKey}`,
			"Content-Type": "application/vnd.api+json",
			...((options.headers as Record<string, string>) || {}),
		};

		try {
			const response = await fetch(url, { ...options, headers });

			if (!response.ok) {
				const errorText = await response.text();
				throw new Error(`Lemon Squeezy API error (${response.status}): ${errorText}`);
			}

			return (await response.json()) as T;
		} catch (error) {
			this.logger?.error?.(
				`Lemon Squeezy API request failed: ${error instanceof Error ? error.message : String(error)}`,
				{ endpoint },
			);
			throw error;
		}
	}

	/**
	 * Create a checkout URL for a user to purchase a license
	 */
	async createCheckout(
		userId: string,
		options?: {
			variantId?: string;
			customPrice?: number;
			redirectUrl?: string;
		},
	): Promise<string> {
		const payload = {
			data: {
				type: "checkouts",
				attributes: {
					custom_price: options?.customPrice,
					product_options: {
						redirect_url: options?.redirectUrl,
						receipt_link_url: options?.redirectUrl,
						receipt_button_text: "Return to AIDR",
					},
					checkout_options: {
						embed: false,
						media: true,
						logo: true,
					},
					checkout_data: {
						custom: {
							user_id: userId,
						},
					},
				},
				relationships: {
					store: {
						data: {
							type: "stores",
							id: this.storeId,
						},
					},
					variant: options?.variantId
						? {
								data: {
									type: "variants",
									id: options.variantId,
								},
							}
						: undefined,
					product: !options?.variantId
						? {
								data: {
									type: "products",
									id: this.productId,
								},
							}
						: undefined,
				},
			},
		};

		// Clean undefined values
		const cleanPayload = JSON.parse(JSON.stringify(payload));

		const response = await this.request<LemonSqueezyCheckoutResponse>("/checkouts", {
			method: "POST",
			body: JSON.stringify(cleanPayload),
		});

		this.logger?.info?.(`Checkout created for user ${userId}`, { checkoutId: response.data.id });

		return response.data.attributes.url;
	}

	/**
	 * Validate a license key with Lemon Squeezy
	 */
	async validateLicense(licenseKey: string): Promise<LicenseValidationResult> {
		try {
			const response = await fetch("https://api.lemonsqueezy.com/v1/licenses/validate", {
				method: "POST",
				headers: {
					Accept: "application/json",
					"Content-Type": "application/x-www-form-urlencoded",
				},
				body: new URLSearchParams({
					license_key: licenseKey,
					instance_name: "AIDR-SDK",
				}),
			});

			const data = (await response.json()) as LemonSqueezyLicenseResponse;

			if (data.error) {
				return {
					valid: false,
					seats: 0,
				};
			}

			const isValid = data.activated && data.license_key.status === "active";
			const seats = data.license_key.activation_limit;
			const expiresAt = data.license_key.expires_at
				? new Date(data.license_key.expires_at)
				: undefined;

			// Check if expired
			if (expiresAt && expiresAt < new Date()) {
				return {
					valid: false,
					seats,
					expiresAt,
				};
			}

			this.logger?.info?.(`License validated: ${licenseKey.slice(0, 8)}...`, { valid: isValid });

			return {
				valid: isValid,
				seats,
				expiresAt,
			};
		} catch (error) {
			this.logger?.error?.(
				`License validation failed: ${error instanceof Error ? error.message : String(error)}`,
				{ licenseKey: licenseKey.slice(0, 8) + "..." },
			);
			throw error;
		}
	}

	/**
	 * Get subscription information for a customer
	 */
	async getSubscription(customerId: string): Promise<{
		id: string;
		status: string;
		renewsAt?: Date;
		endsAt?: Date;
		variantId?: string;
	} | null> {
		const response = await this.request<LemonSqueezySubscriptionResponse>(
			`/subscriptions?filter[store_id]=${this.storeId}&filter[customer_id]=${customerId}`,
		);

		if (!response.data || response.data.length === 0) {
			return null;
		}

		const subscription = response.data[0];
		if (!subscription) {
			return null;
		}

		return {
			id: subscription.id,
			status: subscription.attributes.status,
			renewsAt: subscription.attributes.renews_at
				? new Date(subscription.attributes.renews_at)
				: undefined,
			endsAt: subscription.attributes.ends_at
				? new Date(subscription.attributes.ends_at)
				: undefined,
			variantId: String(subscription.attributes.variant_id),
		};
	}

	/**
	 * Get current usage for a license
	 * Note: This is a placeholder - actual implementation depends on your usage tracking
	 */
	async getUsage(licenseKey: string): Promise<UsageInfo> {
		// This would typically fetch from your own database
		// Lemon Squeezy doesn't provide usage tracking out of the box
		// For now, return placeholder - SDK users should override this
		this.logger?.warn?.("getUsage() is a placeholder. Implement your own usage tracking.");

		return {
			used: 0,
			total: 1000, // Default limit
			resetDate: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000), // 30 days from now
		};
	}

	/**
	 * Process a Lemon Squeezy webhook payload
	 */
	async processWebhook(
		payload: unknown,
		signature: string,
	): Promise<{
		event: string;
		data: unknown;
	}> {
		// Verify webhook signature if secret is configured
		if (this.webhookSecret) {
			const isValid = this.verifyWebhookSignature(payload, signature);
			if (!isValid) {
				throw new Error("Invalid webhook signature");
			}
		}

		// Parse the payload
		const event = payload as {
			meta: { event_name: string };
			data: unknown;
		};

		const eventName = event.meta?.event_name || "unknown";

		this.logger?.info?.(`Processing webhook: ${eventName}`);

		// Handle different event types
		switch (eventName) {
			case "order_created":
				await this.handleOrderCreated(event.data);
				break;
			case "subscription_created":
				await this.handleSubscriptionCreated(event.data);
				break;
			case "subscription_updated":
				await this.handleSubscriptionUpdated(event.data);
				break;
			case "subscription_cancelled":
				await this.handleSubscriptionCancelled(event.data);
				break;
			case "subscription_expired":
				await this.handleSubscriptionExpired(event.data);
				break;
			case "license_key_created":
				await this.handleLicenseCreated(event.data);
				break;
			case "license_key_updated":
				await this.handleLicenseUpdated(event.data);
				break;
			default:
				this.logger?.warn?.(`Unhandled webhook event type: ${eventName}`);
		}

		return {
			event: eventName,
			data: event.data,
		};
	}

	/**
	 * Verify webhook signature
	 */
	private verifyWebhookSignature(payload: unknown, signature: string): boolean {
		if (!this.webhookSecret) {
			return true; // Skip verification if no secret configured
		}

		try {
			const payloadString = typeof payload === "string" ? payload : JSON.stringify(payload);
			const expectedSignature = createHmac("sha256", this.webhookSecret)
				.update(payloadString)
				.digest("hex");

			return signature === expectedSignature;
		} catch {
			return false;
		}
	}

	/**
	 * Handle order_created webhook
	 */
	private async handleOrderCreated(data: unknown): Promise<void> {
		this.logger?.info?.(`Order created: ${JSON.stringify(data)}`);
		// SDK users should override this to handle order creation
	}

	/**
	 * Handle subscription_created webhook
	 */
	private async handleSubscriptionCreated(data: unknown): Promise<void> {
		this.logger?.info?.(`Subscription created: ${JSON.stringify(data)}`);
		// SDK users should override this to handle subscription creation
	}

	/**
	 * Handle subscription_updated webhook
	 */
	private async handleSubscriptionUpdated(data: unknown): Promise<void> {
		this.logger?.info?.(`Subscription updated: ${JSON.stringify(data)}`);
		// SDK users should override this to handle subscription updates
	}

	/**
	 * Handle subscription_cancelled webhook
	 */
	private async handleSubscriptionCancelled(data: unknown): Promise<void> {
		this.logger?.info?.(`Subscription cancelled: ${JSON.stringify(data)}`);
		// SDK users should override this to handle subscription cancellation
	}

	/**
	 * Handle subscription_expired webhook
	 */
	private async handleSubscriptionExpired(data: unknown): Promise<void> {
		this.logger?.info?.(`Subscription expired: ${JSON.stringify(data)}`);
		// SDK users should override this to handle subscription expiration
	}

	/**
	 * Handle license_key_created webhook
	 */
	private async handleLicenseCreated(data: unknown): Promise<void> {
		this.logger?.info?.(`License key created: ${JSON.stringify(data)}`);
		// SDK users should override this to handle license creation
	}

	/**
	 * Handle license_key_updated webhook
	 */
	private async handleLicenseUpdated(data: unknown): Promise<void> {
		this.logger?.info?.(`License key updated: ${JSON.stringify(data)}`);
		// SDK users should override this to handle license updates
	}
}
