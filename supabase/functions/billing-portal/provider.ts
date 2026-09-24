/**
 * Billing provider adapters for the self-service subscription portal.
 *
 * Two rules:
 *
 *   1. The provider customer id is a server fact. It is resolved by looking up
 *      the *authenticated* tenant against our own ledger/customer table; a
 *      request body can never supply one.
 *   2. A provider that is not fully configured fails with
 *      `provider_not_configured`. It never returns a synthetic customer id, a
 *      synthetic subscription or a success receipt, because a synthetic
 *      identifier would silently re-point a tenant's billing at nothing.
 */

export interface ProviderSubscription {
	subscriptionId: string;
	/** Seats the provider will bill for, or `null` when it cannot be read. */
	quantity: number | null;
	status: string;
}

export interface ProviderRefundResult {
	ok: boolean;
	refundId: string | null;
	reason: string;
}

export interface BillingProvider {
	readonly id: "provider_fixture" | "stripe";
	/** Resolve (or create) the provider customer for a tenant. Never client-supplied. */
	ensureCustomer(input: { tenantId: string; existingCustomerId: string | null }): Promise<string>;
	readSubscription(subscriptionId: string): Promise<ProviderSubscription | null>;
	updateQuantity(
		subscriptionId: string,
		quantity: number,
		idempotencyKey: string,
	): Promise<ProviderSubscription | null>;
	cancelSubscription(subscriptionId: string, idempotencyKey: string): Promise<boolean>;
	refund(input: {
		providerCustomerId: string;
		providerSubscriptionId: string | null;
		providerPaymentKind?: "payment_intent" | "charge" | null;
		providerPaymentId?: string | null;
		amountMinor: number;
		currency: string;
		idempotencyKey: string;
	}): Promise<ProviderRefundResult>;
}

export class ProviderNotConfiguredError extends Error {
	readonly code = "provider_not_configured";
	constructor(provider: string, missing: string) {
		super(`billing provider ${provider} is not configured: ${missing}`);
	}
}

export class ProviderUnavailableError extends Error {
	readonly code = "provider_unavailable";
}

function shapeSubscription(value: unknown): ProviderSubscription | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const record = value as Record<string, unknown>;
	if (typeof record.id !== "string" || record.id === "") return null;
	const rawQuantity = record.quantity;
	const quantity =
		typeof rawQuantity === "number" && Number.isSafeInteger(rawQuantity) && rawQuantity >= 0
			? rawQuantity
			: null;
	return {
		subscriptionId: record.id,
		quantity,
		status: typeof record.status === "string" ? record.status : "unknown",
	};
}

/**
 * Local provider fixture.
 *
 * This exists so the portal's contract (identity binding, idempotency, state
 * machine, reconciliation) is executable without a live Stripe account. It is
 * explicitly *not* a payment processor: it records nothing durable, moves no
 * money and produces no externally valid receipt. Every receipt it participates
 * in keeps `externalValidation: false`.
 */
export class FixtureBillingProvider implements BillingProvider {
	readonly id = "provider_fixture" as const;
	#subscriptions = new Map<string, ProviderSubscription>();
	#customers = new Map<string, string>();

	ensureCustomer(input: { tenantId: string; existingCustomerId: string | null }): Promise<string> {
		if (input.existingCustomerId) return Promise.resolve(input.existingCustomerId);
		const existing = this.#customers.get(input.tenantId);
		if (existing) return Promise.resolve(existing);
		const customerId = `cus_fixture_${input.tenantId.replaceAll("-", "").slice(0, 24)}`;
		this.#customers.set(input.tenantId, customerId);
		return Promise.resolve(customerId);
	}

	readSubscription(subscriptionId: string): Promise<ProviderSubscription | null> {
		return Promise.resolve(this.#subscriptions.get(subscriptionId) ?? null);
	}

	updateQuantity(
		subscriptionId: string,
		quantity: number,
		_idempotencyKey: string,
	): Promise<ProviderSubscription | null> {
		if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 10000) {
			throw new ProviderUnavailableError("invalid_fixture_quantity");
		}
		const subscription = this.#subscriptions.get(subscriptionId) ?? {
			subscriptionId,
			quantity: 0,
			status: "active",
		};
		const next = { ...subscription, quantity, status: "active" };
		this.#subscriptions.set(subscriptionId, next);
		return Promise.resolve(next);
	}

	cancelSubscription(subscriptionId: string, _idempotencyKey: string): Promise<boolean> {
		const subscription = this.#subscriptions.get(subscriptionId);
		if (!subscription) return Promise.resolve(false);
		this.#subscriptions.set(subscriptionId, { ...subscription, status: "canceled" });
		return Promise.resolve(true);
	}

	refund(input: {
		providerCustomerId: string;
		providerSubscriptionId: string | null;
		providerPaymentKind?: "payment_intent" | "charge" | null;
		providerPaymentId?: string | null;
		amountMinor: number;
		currency: string;
		idempotencyKey: string;
	}): Promise<ProviderRefundResult> {
		if (input.idempotencyKey.length < 16) {
			return Promise.resolve({ ok: false, refundId: null, reason: "invalid_idempotency_key" });
		}
		return Promise.resolve({
			ok: true,
			refundId: `re_fixture_${input.idempotencyKey.slice(0, 24)}`,
			reason: "fixture_refund_recorded",
		});
	}

	/** Test seam: seed a subscription the fixture should report. */
	seed(subscriptionId: string, quantity: number, status = "active"): void {
		this.#subscriptions.set(subscriptionId, { subscriptionId, quantity, status });
	}
}

export interface StripeProviderOptions {
	secretKey: string;
	/** `price_…` id of the per-seat line item. */
	seatPriceId: string;
	/** Optional yearly per-seat price; a subscription must contain exactly one matching line. */
	yearlySeatPriceId?: string;
	/** Injectable fetch, so tests can pin request shapes without network access. */
	fetcher?: typeof fetch;
}

/**
 * Stripe provider adapter.
 *
 * Reads are unconditional; writes carry an `Idempotency-Key` derived from our
 * tenant-bound operation hash so a retried portal action cannot double-charge or
 * double-refund. The adapter deliberately refuses to guess: an unreadable
 * response becomes `null` or an explicit failure, never a default quantity.
 */
export class StripeBillingProvider implements BillingProvider {
	readonly id = "stripe" as const;
	#secretKey: string;
	#seatPriceIds: readonly string[];
	#fetch: typeof fetch;

	constructor(options: StripeProviderOptions) {
		if (!options.secretKey) throw new ProviderNotConfiguredError("stripe", "STRIPE_SECRET_KEY");
		if (!/^price_[A-Za-z0-9]+$/.test(options.seatPriceId)) {
			throw new ProviderNotConfiguredError("stripe", "AIDR_STRIPE_EXTRA_AGENT_PRICE_ID");
		}
		const yearlyPriceId = options.yearlySeatPriceId?.trim();
		if (yearlyPriceId && (!/^price_[A-Za-z0-9]+$/.test(yearlyPriceId) || yearlyPriceId === options.seatPriceId)) {
			throw new ProviderNotConfiguredError("stripe", "AIDR_STRIPE_EXTRA_AGENT_YEARLY_PRICE_ID");
		}
		this.#secretKey = options.secretKey;
		this.#seatPriceIds = yearlyPriceId ? [options.seatPriceId, yearlyPriceId] : [options.seatPriceId];
		this.#fetch = options.fetcher ?? fetch;
	}

	async #request(
		path: string,
		init: { method: "GET" | "POST"; form?: URLSearchParams; idempotencyKey?: string },
	): Promise<Record<string, unknown>> {
		let response: Response;
		try {
			response = await this.#fetch(`https://api.stripe.com/v1/${path}`, {
				method: init.method,
				redirect: "error",
				signal: AbortSignal.timeout(10000),
				headers: {
					Authorization: `Bearer ${this.#secretKey}`,
					...(init.form ? { "Content-Type": "application/x-www-form-urlencoded" } : {}),
					...(init.idempotencyKey ? { "Idempotency-Key": init.idempotencyKey } : {}),
				},
				...(init.form ? { body: init.form } : {}),
			});
		} catch {
			throw new ProviderUnavailableError("stripe_transport_failed");
		}
		if (!response.ok) throw new ProviderUnavailableError(`stripe_http_${response.status}`);
		try {
			const parsed: unknown = await response.json();
			if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
				throw new ProviderUnavailableError("stripe_response_not_object");
			}
			return parsed as Record<string, unknown>;
		} catch (error) {
			if (error instanceof ProviderUnavailableError) throw error;
			throw new ProviderUnavailableError("stripe_response_not_json");
		}
	}

	async ensureCustomer(input: { tenantId: string; existingCustomerId: string | null }): Promise<string> {
		if (input.existingCustomerId) {
			if (!/^cus_[A-Za-z0-9_]{1,254}$/.test(input.existingCustomerId)) {
				throw new ProviderUnavailableError("stored_customer_id_invalid");
			}
			return input.existingCustomerId;
		}
		const form = new URLSearchParams();
		form.set("metadata[tenant_id]", input.tenantId);
		const created = await this.#request("customers", {
			method: "POST",
			form,
			idempotencyKey: `aidr-customer-${input.tenantId}`,
		});
		const id = created.id;
		if (typeof id !== "string" || !/^cus_[A-Za-z0-9_]{1,254}$/.test(id)) {
			throw new ProviderUnavailableError("stripe_customer_response_invalid");
		}
		return id;
	}

	async readSubscription(subscriptionId: string): Promise<ProviderSubscription | null> {
		if (!/^sub_[A-Za-z0-9_]{1,254}$/.test(subscriptionId)) return null;
		const body = await this.#request(`subscriptions/${subscriptionId}`, { method: "GET" });
		const shaped = shapeSubscription({
			id: body.id,
			status: body.status,
			quantity: quantityOf(body, this.#seatPriceIds),
		});
		return shaped;
	}

	async updateQuantity(
		subscriptionId: string,
		quantity: number,
		idempotencyKey: string,
	): Promise<ProviderSubscription | null> {
		if (!Number.isSafeInteger(quantity) || quantity < 1 || quantity > 10000) {
			throw new ProviderUnavailableError("invalid_quantity");
		}
		if (!/^[0-9a-f]{64}$/.test(idempotencyKey)) {
			throw new ProviderUnavailableError("invalid_idempotency_key");
		}
		const current = await this.#request(`subscriptions/${subscriptionId}`, { method: "GET" });
		const itemId = firstItemId(current, this.#seatPriceIds);
		if (!itemId) throw new ProviderUnavailableError("subscription_item_not_found");
		const form = new URLSearchParams();
		form.set("items[0][id]", itemId);
		form.set("items[0][quantity]", String(quantity));
		form.set("proration_behavior", "create_prorations");
		const updated = await this.#request(`subscriptions/${subscriptionId}`, {
			method: "POST",
			form,
			idempotencyKey: `aidr-seats-${idempotencyKey}`,
		});
		return shapeSubscription({
			id: updated.id,
			status: updated.status,
			quantity: quantityOf(updated, this.#seatPriceIds),
		});
	}

	async cancelSubscription(subscriptionId: string, idempotencyKey: string): Promise<boolean> {
		if (!/^[0-9a-f]{64}$/.test(idempotencyKey)) {
			throw new ProviderUnavailableError("invalid_idempotency_key");
		}
		// Stripe deletes a subscription with DELETE, not POST. `#request` only
		// advertises the two methods with a body; issue the delete explicitly so
		// the wire method is never silently POSTed.
		let response: Response;
		try {
			response = await this.#fetch(
				`https://api.stripe.com/v1/subscriptions/${encodeURIComponent(subscriptionId)}`,
				{
					method: "DELETE",
					redirect: "error",
					signal: AbortSignal.timeout(10000),
					headers: {
						Authorization: `Bearer ${this.#secretKey}`,
						"Idempotency-Key": `aidr-cancel-${idempotencyKey}`,
					},
				},
			);
		} catch {
			throw new ProviderUnavailableError("stripe_transport_failed");
		}
		if (!response.ok) throw new ProviderUnavailableError(`stripe_http_${response.status}`);
		return true;
	}

	async refund(input: {
		providerCustomerId: string;
		providerSubscriptionId: string | null;
		providerPaymentKind?: "payment_intent" | "charge" | null;
		providerPaymentId?: string | null;
		amountMinor: number;
		currency: string;
		idempotencyKey: string;
	}): Promise<ProviderRefundResult> {
		const paymentId = input.providerPaymentId;
		if (typeof paymentId !== "string") {
			return { ok: false, refundId: null, reason: "provider_payment_reference_required" };
		}
		if (
			(input.providerPaymentKind === "payment_intent" && !/^pi_[A-Za-z0-9_]{1,252}$/.test(paymentId)) ||
			(input.providerPaymentKind === "charge" && !/^ch_[A-Za-z0-9_]{1,252}$/.test(paymentId)) ||
			(input.providerPaymentKind !== "payment_intent" && input.providerPaymentKind !== "charge")
		) {
			return { ok: false, refundId: null, reason: "provider_payment_reference_required" };
		}
		if (!Number.isSafeInteger(input.amountMinor) || input.amountMinor < 1 || !/^[0-9a-f]{64}$/.test(input.idempotencyKey)) {
			return { ok: false, refundId: null, reason: "invalid_refund_request" };
		}
		const form = new URLSearchParams({ amount: String(input.amountMinor) });
		form.set(input.providerPaymentKind, paymentId);
		const refund = await this.#request("refunds", {
			method: "POST",
			form,
			idempotencyKey: `aidr-refund-${input.idempotencyKey}`,
		});
		const refundId = refund.id;
		if (typeof refundId !== "string" || !/^re_[A-Za-z0-9_]{1,252}$/.test(refundId)) {
			throw new ProviderUnavailableError("stripe_refund_response_invalid");
		}
		return { ok: true, refundId, reason: "stripe_refund_confirmed" };
	}
}

function itemsOf(body: Record<string, unknown>): Array<Record<string, unknown>> {
	const container = body.items;
	if (!container || typeof container !== "object" || Array.isArray(container)) return [];
	if ((container as Record<string, unknown>).has_more === true) return [];
	const data = (container as Record<string, unknown>).data;
	if (!Array.isArray(data)) return [];
	return data.filter(
		(entry): entry is Record<string, unknown> =>
			!!entry && typeof entry === "object" && !Array.isArray(entry),
	);
}

function priceIdOf(item: Record<string, unknown>): string | null {
	const price = item.price;
	if (typeof price === "string") return price;
	if (price && typeof price === "object" && !Array.isArray(price)) {
		const id = (price as Record<string, unknown>).id;
		return typeof id === "string" ? id : null;
	}
	return null;
}

function seatItemOf(body: Record<string, unknown>, seatPriceIds: readonly string[]): Record<string, unknown> | null {
	const matches = itemsOf(body).filter((entry) => seatPriceIds.includes(priceIdOf(entry) ?? ""));
	return matches.length === 1 ? matches[0] : null;
}

function quantityOf(body: Record<string, unknown>, seatPriceIds: readonly string[]): number | null {
	const item = seatItemOf(body, seatPriceIds);
	if (!item) return null;
	const quantity = item.quantity;
	return typeof quantity === "number" && Number.isSafeInteger(quantity) && quantity >= 0 ? quantity : null;
}

function firstItemId(body: Record<string, unknown>, seatPriceIds: readonly string[]): string | null {
	const item = seatItemOf(body, seatPriceIds);
	if (!item) return null;
	return typeof item.id === "string" && item.id !== "" ? item.id : null;
}

/**
 * Select the provider for this deployment.
 *
 * `AIDR_BILLING_PROVIDER` is unset in the direct-GA invoice profile, so the
 * portal answers `self_service_disabled` and never contacts a provider. A
 * misconfigured `stripe` selection throws, which the handler turns into a
 * `provider_not_configured` 503 rather than a silent fallback to the fixture.
 */
export function createBillingProvider(
	env: (name: string) => string | undefined | null,
	fetcher?: typeof fetch,
): BillingProvider | null {
	const selected = (env("AIDR_BILLING_PROVIDER") ?? "").trim().toLowerCase();
	if (selected === "") return null;
	if (selected === "provider_fixture") return new FixtureBillingProvider();
	if (selected !== "stripe") throw new ProviderNotConfiguredError(selected, "AIDR_BILLING_PROVIDER");
	return new StripeBillingProvider({
		secretKey: (env("STRIPE_SECRET_KEY") ?? "").trim(),
		seatPriceId: (env("AIDR_STRIPE_EXTRA_AGENT_PRICE_ID") ?? "").trim(),
		yearlySeatPriceId: (env("AIDR_STRIPE_EXTRA_AGENT_YEARLY_PRICE_ID") ?? "").trim(),
		fetcher,
	});
}
