// Pure Stripe webhook event evaluation (no Deno, Node, or SDK imports).
//
// The Edge Function handler in ./index.ts uses these functions to decide what a
// verified Stripe event is allowed to do. Two rules drive the whole module:
//
//   1. Only an explicit allow-list of event types is acted on.
//   2. Entitlements (`entitlements.extra_agents`) are only ever derived from a
//      *subscription* object whose status is entitled, and only from line items
//      whose price id is the configured extra-agent price. Everything else
//      (cancelled, past_due, unpaid, paused, deleted, unexpected price) revokes
//      or leaves the entitlement untouched - it never grants and never
//      preserves paid seats.

/** Event types this endpoint acts on. Anything else is acknowledged and ignored. */
export const STRIPE_HANDLED_EVENT_TYPES = [
	"checkout.session.completed",
	"customer.subscription.created",
	"customer.subscription.updated",
	"customer.subscription.deleted",
	"invoice.paid",
	"invoice.payment_failed",
] as const;

export type StripeHandledEventType = (typeof STRIPE_HANDLED_EVENT_TYPES)[number];

/** Stripe subscription statuses that may hold paid seats. */
export const ENTITLED_SUBSCRIPTION_STATUSES = ["active", "trialing"] as const;

export type StripeAction = "ignore" | "record" | "reconcile";

export interface StripeInvoiceSummary {
	id: string;
	number: string | null;
	status: string;
	currency: string;
	amountPaidCents: number;
	amountDueCents: number;
	hostedInvoiceUrl: string | null;
}

export interface StripeEventEvaluation {
	/** What the handler is allowed to do with this event. */
	action: StripeAction;
	/** Machine-readable audit reason (never sent to the caller). */
	reason: string;
	eventType: string;
	/** User id taken only from metadata our own checkout path set. */
	userId: string | null;
	/** Tenant id from our own metadata; defaults to the user's personal tenant. */
	tenantId: string | null;
	customerId: string | null;
	subscriptionId: string | null;
	customerEmail: string | null;
	/** Stripe subscription status when the event carries one. */
	status: string | null;
	/** True only for an allow-listed subscription event with an entitled status. */
	entitled: boolean;
	/** True when the handler may write `entitlements.extra_agents`. */
	writeEntitlement: boolean;
	extraAgents: number;
	currentPeriodEnd: string | null;
	cancelAtPeriodEnd: boolean;
	invoice: StripeInvoiceSummary | null;
}

export interface StripeEventEvaluationOptions {
	/**
	 * Stripe price id of the paid extra-agent line item
	 * (`AIDR_STRIPE_EXTRA_AGENT_PRICE_ID`). When empty, no seat count can be
	 * attributed, so the handler refuses to grant and writes nothing.
	 */
	extraAgentPriceId?: string | null;
	extraAgentYearlyPriceId?: string | null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
const EVENT_ID = /^[A-Za-z0-9_]{1,255}$/;

export function isUuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value.trim());
}

export function isStripeEventId(value: unknown): value is string {
	return typeof value === "string" && EVENT_ID.test(value.trim());
}

export function isEntitledSubscriptionStatus(status: string | null | undefined): boolean {
	if (typeof status !== "string") return false;
	return (ENTITLED_SUBSCRIPTION_STATUSES as readonly string[]).includes(status.trim().toLowerCase());
}

function asRecord(value: unknown): Record<string, unknown> | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	return value as Record<string, unknown>;
}

function asString(value: unknown): string | null {
	if (typeof value !== "string") return null;
	const trimmed = value.trim();
	return trimmed === "" ? null : trimmed;
}

/** Stripe expands relations either to an id string or to the full object. */
function idOf(value: unknown): string | null {
	const direct = asString(value);
	if (direct) return direct;
	const record = asRecord(value);
	return record ? asString(record.id) : null;
}

function metadataOf(value: unknown): Record<string, unknown> {
	const record = asRecord(value);
	return asRecord(record?.metadata) ?? {};
}

/** Read a UUID-valued metadata field, rejecting anything malformed. */
function metadataUuid(source: unknown, key: string): string | null {
	const value = metadataOf(source)[key];
	return isUuid(value) ? (value as string).trim() : null;
}

/** Epoch seconds (number or numeric string) to an ISO timestamp. */
function toIsoTimestamp(value: unknown): string | null {
	const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
	if (!Number.isFinite(numeric) || numeric <= 0) return null;
	return new Date(Math.floor(numeric) * 1000).toISOString();
}

/**
 * Read the AIDR identifiers from metadata that *our* checkout path set.
 *
 * Stripe echoes `metadata` onto the objects it creates, so this is the only
 * trusted source of a user/tenant id. A webhook body can never supply these
 * directly: an unauthenticated caller cannot forge them without the endpoint
 * secret, and even with a valid signature the values must be well-formed UUIDs.
 */
export function extractCheckoutIdentifiers(object: Record<string, unknown> | null): {
	userId: string | null;
	tenantId: string | null;
	clientReferenceId: string | null;
} {
	if (!object) return { userId: null, tenantId: null, clientReferenceId: null };
	const metadata = metadataOf(object);
	const rawUser = metadata.user_id ?? metadata.userId;
	const userId = isUuid(rawUser) ? (rawUser as string).trim() : null;

	// `client_reference_id` is Stripe's own checkout-session correlation field and
	// is also set server-side when the session is created.
	const clientReferenceId = asString(object.client_reference_id);
	const fromClientReference = isUuid(clientReferenceId) ? (clientReferenceId as string).trim() : null;

	const rawTenant = metadata.tenant_id ?? metadata.tenantId;
	const tenantId = isUuid(rawTenant) ? (rawTenant as string).trim() : null;
	return {
		userId: userId ?? fromClientReference,
		tenantId,
		clientReferenceId,
	};
}

/**
 * Sum the quantity of line items whose price is the configured extra-agent
 * price.
 *
 * Returns `null` when the line items cannot be inspected at all (the caller
 * must then leave entitlements untouched) and `0` when the subscription
 * provably carries no extra-agent line item.
 */
export function sumExtraAgentQuantity(
	items: unknown,
	extraAgentPriceId: string,
	extraAgentYearlyPriceId?: string | null,
): number | null {
	const container = asRecord(items);
	const data = container?.data;
	if (!Array.isArray(data)) return null;

	let total = 0;
	for (const entry of data) {
		const item = asRecord(entry);
		if (!item) continue;
		const priceId = idOf(item.price);
		if (!priceId || (priceId !== extraAgentPriceId && priceId !== extraAgentYearlyPriceId)) continue;
		const quantity = typeof item.quantity === "number" ? item.quantity : Number(item.quantity);
		if (!Number.isFinite(quantity) || quantity <= 0) continue;
		total += Math.floor(quantity);
	}
	return Math.max(0, total);
}

function normalizeStatus(value: unknown): string {
	const status = asString(value);
	return status ? status.toLowerCase() : "unknown";
}

function emptyEvaluation(
	eventType: string,
	action: StripeAction,
	reason: string,
): StripeEventEvaluation {
	return {
		action,
		reason,
		eventType,
		userId: null,
		tenantId: null,
		customerId: null,
		subscriptionId: null,
		customerEmail: null,
		status: null,
		entitled: false,
		writeEntitlement: false,
		extraAgents: 0,
		currentPeriodEnd: null,
		cancelAtPeriodEnd: false,
		invoice: null,
	};
}

/**
 * Decide what a verified Stripe event may do.
 *
 * This function performs no I/O and never throws for malformed input; unknown
 * or unsupported shapes degrade to `ignore`.
 */
export function evaluateStripeEvent(
	event: unknown,
	options: StripeEventEvaluationOptions = {},
): StripeEventEvaluation {
	const envelope = asRecord(event);
	const eventType = asString(envelope?.type) ?? "";

	if (!(STRIPE_HANDLED_EVENT_TYPES as readonly string[]).includes(eventType)) {
		return emptyEvaluation(eventType || "unknown", "ignore", "event_type_not_allowlisted");
	}

	const data = asRecord(envelope?.data);
	const object = asRecord(data?.object);
	if (!object) return emptyEvaluation(eventType, "ignore", "missing_event_object");

	const extraAgentPriceId = (options.extraAgentPriceId ?? "").trim();
	const identifiers = extractCheckoutIdentifiers(object);
	const base: StripeEventEvaluation = {
		...emptyEvaluation(eventType, "record", "recorded_only"),
		userId: identifiers.userId,
		tenantId: identifiers.tenantId,
		customerId: idOf(object.customer),
		subscriptionId: idOf(object.subscription),
		customerEmail:
			asString(object.customer_email) ?? asString(asRecord(object.customer_details)?.email),
	};

	if (eventType.startsWith("customer.subscription.")) {
		const subscriptionId = asString(object.id);
		const status = normalizeStatus(object.status);
		const currentPeriodEnd =
			toIsoTimestamp(object.current_period_ends_at) ??
			toIsoTimestamp(object.current_period_end) ??
			toIsoTimestamp(object.trial_end);
		const cancelAtPeriodEnd = object.cancel_at_period_end === true;

		// A deletion always revokes, whatever the status field happens to say.
		const deleted = eventType === "customer.subscription.deleted";
		const entitled = !deleted && isEntitledSubscriptionStatus(status);

		if (!entitled) {
			return {
				...base,
				action: "reconcile",
				reason: deleted ? "subscription_deleted" : `subscription_status_${status}`,
				subscriptionId,
				status,
				entitled: false,
				writeEntitlement: true,
				extraAgents: 0,
				currentPeriodEnd,
				cancelAtPeriodEnd,
			};
		}

		const seats = extraAgentPriceId
			? sumExtraAgentQuantity(object.items, extraAgentPriceId, options.extraAgentYearlyPriceId)
			: null;

		if (seats === null) {
			// Fail closed: no attributable seat count means no entitlement write.
			return {
				...base,
				action: "ignore",
				reason: extraAgentPriceId
					? "subscription_items_unavailable"
					: "extra_agent_price_not_configured",
				subscriptionId,
				status,
				entitled: true,
				writeEntitlement: false,
				extraAgents: 0,
				currentPeriodEnd,
				cancelAtPeriodEnd,
			};
		}

		return {
			...base,
			action: "reconcile",
			reason: "subscription_entitled",
			subscriptionId,
			status,
			entitled: true,
			writeEntitlement: true,
			extraAgents: seats,
			currentPeriodEnd,
			cancelAtPeriodEnd,
		};
	}

	if (eventType === "checkout.session.completed") {
		// Records the customer/subscription linkage only. The following
		// `customer.subscription.*` event carries the authoritative status, so a
		// completed checkout never grants seats by itself.
		return {
			...base,
			action: "record",
			reason: "checkout_completed_linkage_only",
			subscriptionId: base.subscriptionId ?? asString(object.subscription),
			customerEmail:
				base.customerEmail ?? asString(asRecord(object.customer_details)?.email),
		};
	}

	// invoice.paid / invoice.payment_failed: recorded for audit and reconciliation,
	// never applied to entitlements. An invoice cannot prove the *current*
	// subscription status, and a late `invoice.paid` for a cancelled subscription
	// must not preserve paid seats.
	const invoiceRecord = asRecord(object);
	const invoice: StripeInvoiceSummary = {
		id: asString(object.id) ?? "",
		number: asString(object.number),
		status: normalizeStatus(object.status),
		currency: asString(object.currency) ?? "unknown",
		amountPaidCents: Number.isFinite(Number(object.amount_paid)) ? Number(object.amount_paid) : 0,
		amountDueCents: Number.isFinite(Number(object.amount_due)) ? Number(object.amount_due) : 0,
		hostedInvoiceUrl: asString(object.hosted_invoice_url),
	};

	const parentSubscription = asRecord(asRecord(invoiceRecord?.parent)?.subscription_details);
	const legacySubscriptionDetails = asRecord(invoiceRecord?.subscription_details);
	const subscriptionId =
		base.subscriptionId ??
		idOf(legacySubscriptionDetails?.subscription) ??
		idOf(parentSubscription?.subscription);
	// Stripe moved subscription metadata under `parent.subscription_details` in
	// newer API versions; support both shapes.
	const metadataUserId = base.userId ?? metadataUuid(parentSubscription, "user_id") ??
		metadataUuid(legacySubscriptionDetails, "user_id");
	const metadataTenantId = base.tenantId ?? metadataUuid(parentSubscription, "tenant_id") ??
		metadataUuid(legacySubscriptionDetails, "tenant_id");

	return {
		...base,
		action: "record",
		reason: eventType === "invoice.paid" ? "invoice_paid_recorded" : "invoice_payment_failed_recorded",
		userId: metadataUserId,
		tenantId: metadataTenantId,
		subscriptionId,
		invoice,
		writeEntitlement: false,
		extraAgents: 0,
	};
}
