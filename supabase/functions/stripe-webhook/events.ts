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

/** Stripe subscription statuses that may hold paid seats. */
const ENTITLED_SUBSCRIPTION_STATUSES = ["active", "trialing"] as const;

type StripeAction = "ignore" | "record" | "reconcile";

interface StripeInvoiceSummary {
	id: string;
	number: string | null;
	status: string;
	currency: string;
	amountPaidCents: number;
	amountDueCents: number;
	hostedInvoiceUrl: string | null;
	settlementId: string | null;
	requestId: string | null;
	paymentReference: { kind: "payment_intent" | "charge"; id: string } | null;
}

export interface StripeEventEvaluation {
	/** What the handler is allowed to do with this event. */
	action: StripeAction;
	/** Machine-readable audit reason (never sent to the caller). */
	reason: string;
	eventType: string;
	/** Provider creation time used to reject reordered state transitions. */
	eventCreatedAt: string | null;
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
const REQUEST_ID = /^[A-Za-z0-9_-]{16,80}$/;
const PAYMENT_INTENT_ID = /^pi_[A-Za-z0-9_]{1,252}$/;
const CHARGE_ID = /^ch_[A-Za-z0-9_]{1,252}$/;

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

function metadataRequestId(source: unknown): string | null {
	const value = metadataOf(source).request_id;
	return typeof value === "string" && REQUEST_ID.test(value) ? value : null;
}

export function extractCheckoutIntentMetadata(source: unknown): {
	userId: string | null;
	tenantId: string | null;
	settlementId: string | null;
	requestId: string | null;
} {
	return {
		userId: metadataUuid(source, "user_id"),
		tenantId: metadataUuid(source, "tenant_id"),
		settlementId: metadataUuid(source, "settlement_id"),
		requestId: metadataRequestId(source),
	};
}

function paymentReferenceOf(invoice: Record<string, unknown>): StripeInvoiceSummary["paymentReference"] {
	const candidates: Array<{ kind: "payment_intent" | "charge"; value: unknown }> = [
		{ kind: "payment_intent", value: invoice.payment_intent },
		{ kind: "charge", value: invoice.charge },
	];
	const payments = asRecord(invoice.payments)?.data;
	if (Array.isArray(payments)) {
		for (const entry of payments) {
			const payment = asRecord(asRecord(entry)?.payment) ?? asRecord(entry);
			candidates.push(
				{ kind: "payment_intent", value: payment?.payment_intent },
				{ kind: "charge", value: payment?.charge },
			);
		}
	}
	for (const candidate of candidates) {
		const id = idOf(candidate.value);
		if (candidate.kind === "payment_intent" && id && PAYMENT_INTENT_ID.test(id)) return { kind: candidate.kind, id };
		if (candidate.kind === "charge" && id && CHARGE_ID.test(id)) return { kind: candidate.kind, id };
	}
	return null;
}

/** Accept exactly one paid, fully attributed invoice payment from Stripe. */
export function invoicePaymentReferenceFromList(
	response: unknown,
	invoiceId: string,
	amountPaidCents: number,
	currency: string,
): StripeInvoiceSummary["paymentReference"] {
	const list = asRecord(response);
	if (list?.has_more !== false || !Array.isArray(list.data) || list.data.length !== 1) return null;
	const payment = asRecord(list.data[0]);
	if (payment?.invoice !== invoiceId || payment.status !== "paid" ||
		payment.amount_paid !== amountPaidCents || payment.currency !== currency) return null;
	return paymentReferenceOf({ payments: { data: [payment] } });
}

/** Epoch seconds (number or numeric string) to an ISO timestamp. */
function toIsoTimestamp(value: unknown): string | null {
	const numeric = typeof value === "number" ? value : typeof value === "string" ? Number(value) : Number.NaN;
	if (!Number.isFinite(numeric) || numeric <= 0) return null;
	const date = new Date(Math.floor(numeric) * 1000);
	return Number.isNaN(date.getTime()) ? null : date.toISOString();
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
	if (!Array.isArray(data) || container?.has_more === true) return null;

	let total = 0;
	for (const entry of data) {
		const item = asRecord(entry);
		if (!item) continue;
		const priceId = idOf(item.price);
		if (!priceId || (priceId !== extraAgentPriceId && priceId !== extraAgentYearlyPriceId)) continue;
		const quantity = typeof item.quantity === "number" ? item.quantity : Number(item.quantity);
		if (!Number.isSafeInteger(quantity) || quantity < 0 || quantity > 100000) return null;
		total += quantity;
		if (!Number.isSafeInteger(total) || total > 100000) return null;
	}
	return Math.max(0, total);
}

/** Undefined means a legacy payload with no item periods; null means an unsafe mixed/invalid period. */
function purchasedItemPeriodEnd(
	items: unknown,
	extraAgentPriceId: string,
	extraAgentYearlyPriceId?: string | null,
): string | null | undefined {
	const data = asRecord(items)?.data;
	if (!Array.isArray(data)) return null;
	let earliest: string | undefined;
	let missing = false;
	for (const entry of data) {
		const item = asRecord(entry);
		if (!item || Number(item.quantity) <= 0) continue;
		const priceId = idOf(item.price);
		if (priceId !== extraAgentPriceId && priceId !== extraAgentYearlyPriceId) continue;
		if (!("current_period_end" in item)) {
			missing = true;
			continue;
		}
		const periodEnd = toIsoTimestamp(item.current_period_end);
		if (!periodEnd) return null;
		if (!earliest || periodEnd < earliest) earliest = periodEnd;
	}
	return missing && earliest ? null : earliest;
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
		eventCreatedAt: null,
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
	const eventCreatedAt = toIsoTimestamp(envelope?.created);
	if (!eventCreatedAt) return emptyEvaluation(eventType, "ignore", "missing_event_created_at");

	const extraAgentPriceId = (options.extraAgentPriceId ?? "").trim();
	const identifiers = extractCheckoutIdentifiers(object);
	const base: StripeEventEvaluation = {
		...emptyEvaluation(eventType, "record", "recorded_only"),
		eventCreatedAt,
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
		const legacyPeriodEnd =
			toIsoTimestamp(object.current_period_ends_at) ??
			toIsoTimestamp(object.current_period_end);
		const trialEnd = status === "trialing" ? toIsoTimestamp(object.trial_end) : null;
		const currentPeriodEnd = legacyPeriodEnd && trialEnd
			? (legacyPeriodEnd < trialEnd ? legacyPeriodEnd : trialEnd)
			: legacyPeriodEnd ?? trialEnd;
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

		// `send_invoice` can be active before its invoice is paid. Unknown
		// collection modes cannot prove an automatically collected purchase.
		if (seats > 0 && object.collection_method !== "charge_automatically") {
			return {
				...base,
				action: "ignore",
				reason: "subscription_collection_unverified",
				subscriptionId,
				status,
				entitled: false,
				writeEntitlement: false,
				extraAgents: 0,
				currentPeriodEnd,
				cancelAtPeriodEnd,
			};
		}

		const itemPeriodEnd = seats > 0
			? purchasedItemPeriodEnd(object.items, extraAgentPriceId, options.extraAgentYearlyPriceId)
			: undefined;
		const purchasedPeriodEnd = itemPeriodEnd === undefined ? currentPeriodEnd : itemPeriodEnd;
		const verifiedPeriodEnd = purchasedPeriodEnd && trialEnd
			? (purchasedPeriodEnd < trialEnd ? purchasedPeriodEnd : trialEnd)
			: purchasedPeriodEnd;
		if (seats > 0 && !verifiedPeriodEnd) {
			return {
				...base,
				action: "ignore",
				reason: "subscription_period_unavailable",
				subscriptionId,
				status,
				entitled: false,
				writeEntitlement: false,
				extraAgents: 0,
				currentPeriodEnd: null,
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
			currentPeriodEnd: verifiedPeriodEnd,
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
	const invoiceRecord = object;
	const parentSubscription = asRecord(asRecord(invoiceRecord?.parent)?.subscription_details);
	const legacySubscriptionDetails = asRecord(invoiceRecord?.subscription_details);
	const settlementId = metadataUuid(invoiceRecord, "settlement_id") ??
		metadataUuid(parentSubscription, "settlement_id") ??
		metadataUuid(legacySubscriptionDetails, "settlement_id");
	const requestId = metadataRequestId(invoiceRecord) ?? metadataRequestId(parentSubscription) ??
		metadataRequestId(legacySubscriptionDetails);
	const invoice: StripeInvoiceSummary = {
		id: asString(object.id) ?? "",
		number: asString(object.number),
		status: normalizeStatus(object.status),
		currency: asString(object.currency) ?? "unknown",
		amountPaidCents: Number.isFinite(Number(object.amount_paid)) ? Number(object.amount_paid) : 0,
		amountDueCents: Number.isFinite(Number(object.amount_due)) ? Number(object.amount_due) : 0,
		hostedInvoiceUrl: asString(object.hosted_invoice_url),
		settlementId,
		requestId,
		paymentReference: paymentReferenceOf(invoiceRecord),
	};

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
