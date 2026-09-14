/**
 * Provider-of-record settlement state machine (BIL-03 / T33).
 *
 * This module is deliberately dependency-free: it is imported by the
 * `billing-portal` Edge Function (Deno), by the dashboard's server-side billing
 * client and by the Vitest suite. Nothing here performs I/O, reads the clock
 * implicitly, or trusts a client-supplied identifier.
 *
 * Two invariants drive the whole module:
 *
 *   1. A tenant identifier and a provider customer identifier are *server*
 *      facts. Every parser here validates a shape and rejects; none of them
 *      accept an identifier from a request body to decide ownership.
 *   2. An entitlement is derived only from a settlement that has reached
 *      `settled` for the *same* tenant, SKU, currency and quantity. Seat grants
 *      and revocations are computed from the settlement ledger, so replaying or
 *      reordering provider events cannot change the resulting seat count.
 *
 * `externalValidation: false` on every receipt is intentional and permanent
 * until a named finance owner and a live provider account exist: a
 * locally-produced receipt is bookkeeping, not an audited payment record.
 */

export const SETTLEMENT_STATUSES = [
	"quote_issued",
	"order_placed",
	"settlement_pending",
	"settled",
	"cancelled",
	"refunded",
] as const;

export type SettlementStatus = (typeof SETTLEMENT_STATUSES)[number];

/** Terminal states that no transition may leave. */
export const TERMINAL_SETTLEMENT_STATUSES: readonly SettlementStatus[] = ["refunded"];

/** Supported settlement currencies. Deliberately a closed set. */
export const SETTLEMENT_CURRENCIES = ["USD", "EUR", "GBP"] as const;
export type SettlementCurrency = (typeof SETTLEMENT_CURRENCIES)[number];

const TRANSITIONS: Readonly<Record<SettlementStatus, readonly SettlementStatus[]>> = {
	quote_issued: ["order_placed", "cancelled"],
	order_placed: ["settlement_pending", "cancelled"],
	settlement_pending: ["settled", "cancelled"],
	settled: ["cancelled", "refunded"],
	// A cancellation may still be refunded if money was captured before the
	// cancellation was recorded. It can never return to a settled state.
	cancelled: ["refunded"],
	refunded: [],
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[A-Za-z0-9_-]{16,80}$/;
const SKU = /^[a-z][a-z0-9_.-]{1,63}$/;
const RECEIPT_HASH = /^[0-9a-f]{64}$/;
/** Provider object ids (`cus_â€¦`, `sub_â€¦`, `in_â€¦`, `cs_â€¦`, `re_â€¦`). */
const PROVIDER_OBJECT_ID = /^[A-Za-z][A-Za-z0-9_]{2,254}$/;

export interface SettlementLine {
	sku: string;
	quantity: number;
	/** Unit price in integer minor units (cents). Never a float. */
	unitAmountMinor: number;
}

export interface SettlementReceipt {
	settlementId: string;
	tenantId: string;
	provider: "provider_fixture" | "stripe";
	/** Server-resolved provider customer id. Never taken from a request body. */
	providerCustomerId: string;
	providerSubscriptionId: string | null;
	requestId: string;
	status: SettlementStatus;
	currency: SettlementCurrency;
	lines: SettlementLine[];
	/** Sum of `quantity * unitAmountMinor` across lines, in minor units. */
	totalAmountMinor: number;
	/** Quote reference approved by Finance; required before `order_placed`. */
	quoteReference: string | null;
	/** Settlement amount actually captured, in minor units. */
	settledAmountMinor: number;
	refundedAmountMinor: number;
	occurredAt: string;
	recordedAt: string;
	sequence: number;
	/** Locally computed digest over the immutable fields of this receipt. */
	receiptHash: string;
	/**
	 * Always false until a named finance owner reconciles the receipt against a
	 * live provider. A `true` value must never be produced by this module.
	 */
	externalValidation: false;
}

export interface SettlementLedgerInput {
	receipts: readonly SettlementReceipt[];
	tenantId: string;
}

export interface SeatGrant {
	sku: string;
	seats: number;
}

export interface EntitlementProjection {
	status: "granted" | "revoked" | "unavailable";
	seats: SeatGrant[];
	/** Receipt ids that contributed, newest last, for the operator view. */
	sources: string[];
	reason: string;
}

export type ParseResult<T> = { ok: true; value: T } | { ok: false; error: string };

function ok<T>(value: T): ParseResult<T> {
	return { ok: true, value };
}

function err<T>(error: string): ParseResult<T> {
	return { ok: false, error };
}

export function isUuid(value: unknown): value is string {
	return typeof value === "string" && UUID.test(value);
}

export function isRequestId(value: unknown): value is string {
	return typeof value === "string" && REQUEST_ID.test(value);
}

export function isSettlementStatus(value: unknown): value is SettlementStatus {
	return typeof value === "string" && (SETTLEMENT_STATUSES as readonly string[]).includes(value);
}

export function isSettlementCurrency(value: unknown): value is SettlementCurrency {
	return typeof value === "string" && (SETTLEMENT_CURRENCIES as readonly string[]).includes(value);
}

export function mayTransition(from: SettlementStatus, to: SettlementStatus): boolean {
	return TRANSITIONS[from].includes(to);
}

export function allowedTransitions(from: SettlementStatus): readonly SettlementStatus[] {
	return TRANSITIONS[from];
}

/** A monotonic ISO timestamp. Rejects unparseable and pre-epoch values. */
function parseOccurredAt(value: unknown): ParseResult<string> {
	if (typeof value !== "string") return err("invalid_timestamp");
	const parsed = Date.parse(value);
	if (!Number.isFinite(parsed) || parsed <= 0) return err("invalid_timestamp");
	return ok(new Date(parsed).toISOString());
}

export function parseSettlementLine(value: unknown): ParseResult<SettlementLine> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return err("invalid_line");
	const line = value as Record<string, unknown>;
	if (typeof line.sku !== "string" || !SKU.test(line.sku)) return err("invalid_sku");
	if (!Number.isSafeInteger(line.quantity) || (line.quantity as number) < 1 || (line.quantity as number) > 100000) {
		return err("invalid_quantity");
	}
	if (
		!Number.isSafeInteger(line.unitAmountMinor) ||
		(line.unitAmountMinor as number) < 0 ||
		(line.unitAmountMinor as number) > 100_000_000
	) {
		return err("invalid_unit_amount");
	}
	return ok({
		sku: line.sku,
		quantity: line.quantity as number,
		unitAmountMinor: line.unitAmountMinor as number,
	});
}

export function sumLineAmounts(lines: readonly SettlementLine[]): number {
	return lines.reduce((total, line) => total + line.quantity * line.unitAmountMinor, 0);
}

/**
 * Canonical, order-stable encoding of the immutable portion of a receipt. The
 * digest is computed over this string so a reordered `lines` array cannot
 * change the hash of an otherwise identical receipt, while *any* change to a
 * bound field does.
 */
export function settlementHashInput(receipt: Omit<SettlementReceipt, "receiptHash" | "recordedAt">): string {
	const lines = [...receipt.lines]
		.map((line) => `${line.sku}:${line.quantity}:${line.unitAmountMinor}`)
		.sort()
		.join("|");
	return [
		"aidr-settlement-v1",
		receipt.settlementId,
		receipt.tenantId,
		receipt.provider,
		receipt.providerCustomerId,
		receipt.providerSubscriptionId ?? "-",
		receipt.requestId,
		receipt.status,
		receipt.currency,
		lines,
		String(receipt.totalAmountMinor),
		receipt.quoteReference ?? "-",
		String(receipt.settledAmountMinor),
		String(receipt.refundedAmountMinor),
		receipt.occurredAt,
		String(receipt.sequence),
		String(receipt.externalValidation),
	].join("\n");
}

/**
 * SHA-256 via WebCrypto (`crypto.subtle`), available in Deno, Node 18+ and
 * every supported browser. Kept async so callers cannot accidentally fire and
 * forget a verification step.
 */
export async function settlementReceiptHash(
	receipt: Omit<SettlementReceipt, "receiptHash" | "recordedAt">,
): Promise<string> {
	const bytes = new TextEncoder().encode(settlementHashInput(receipt));
	const digest = await crypto.subtle.digest("SHA-256", bytes);
	return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/**
 * Verify the integrity binding of a stored receipt.
 *
 * Returns `unavailable` - never a clean result - when the hash cannot be
 * computed, and `tampered` as soon as a bound field disagrees with the digest.
 * Callers must treat anything other than `intact` as fail-closed.
 */
export async function verifySettlementReceipt(
	value: unknown,
): Promise<{ status: "intact" | "tampered" | "unavailable"; reason: string }> {
	const parsed = parseSettlementReceipt(value);
	if (!parsed.ok) return { status: "unavailable", reason: parsed.error };
	const { receiptHash: _stored, recordedAt: _recorded, ...bound } = parsed.value;
	try {
		const expected = await settlementReceiptHash(bound);
		if (expected !== parsed.value.receiptHash) return { status: "tampered", reason: "receipt_hash_mismatch" };
		return { status: "intact", reason: "receipt_hash_matches" };
	} catch {
		return { status: "unavailable", reason: "hash_unavailable" };
	}
}

export function parseSettlementReceipt(value: unknown): ParseResult<SettlementReceipt> {
	if (!value || typeof value !== "object" || Array.isArray(value)) return err("invalid_receipt");
	const raw = value as Record<string, unknown>;
	if (!isUuid(raw.settlementId)) return err("invalid_settlement_id");
	if (!isUuid(raw.tenantId)) return err("invalid_tenant_id");
	if (raw.provider !== "provider_fixture" && raw.provider !== "stripe") return err("invalid_provider");
	if (typeof raw.providerCustomerId !== "string" || !PROVIDER_OBJECT_ID.test(raw.providerCustomerId)) {
		return err("invalid_provider_customer_id");
	}
	if (
		raw.providerSubscriptionId !== null &&
		(typeof raw.providerSubscriptionId !== "string" || !PROVIDER_OBJECT_ID.test(raw.providerSubscriptionId))
	) {
		return err("invalid_provider_subscription_id");
	}
	if (!isRequestId(raw.requestId)) return err("invalid_request_id");
	if (!isSettlementStatus(raw.status)) return err("invalid_status");
	if (!isSettlementCurrency(raw.currency)) return err("invalid_currency");
	if (!Array.isArray(raw.lines) || raw.lines.length === 0 || raw.lines.length > 32) return err("invalid_lines");
	const lines: SettlementLine[] = [];
	for (const entry of raw.lines) {
		const line = parseSettlementLine(entry);
		if (!line.ok) return err(line.error);
		lines.push(line.value);
	}
	const totalAmountMinor = sumLineAmounts(lines);
	if (raw.totalAmountMinor !== totalAmountMinor) return err("total_amount_mismatch");
	if (
		typeof raw.quoteReference !== "string" &&
		raw.quoteReference !== null
	) {
		return err("invalid_quote_reference");
	}
	if (typeof raw.quoteReference === "string" && raw.quoteReference.length > 120) return err("invalid_quote_reference");
	for (const key of ["settledAmountMinor", "refundedAmountMinor"] as const) {
		const amount = raw[key];
		if (!Number.isSafeInteger(amount) || (amount as number) < 0) return err(`invalid_${key}`);
	}
	if ((raw.refundedAmountMinor as number) > (raw.settledAmountMinor as number)) return err("refund_exceeds_settled");
	if (raw.status === "settled" && (raw.settledAmountMinor as number) !== totalAmountMinor) {
		return err("settled_amount_mismatch");
	}
	if (
		(raw.status === "quote_issued" || raw.status === "order_placed") &&
		(raw.settledAmountMinor as number) !== 0
	) {
		return err("unsettled_amount_mismatch");
	}
	const occurredAt = parseOccurredAt(raw.occurredAt);
	if (!occurredAt.ok) return err(occurredAt.error);
	if (typeof raw.recordedAt !== "string" || !Number.isFinite(Date.parse(raw.recordedAt))) {
		return err("invalid_recorded_at");
	}
	if (!Number.isSafeInteger(raw.sequence) || (raw.sequence as number) < 0) return err("invalid_sequence");
	if (typeof raw.receiptHash !== "string" || !RECEIPT_HASH.test(raw.receiptHash)) return err("invalid_receipt_hash");
	if (raw.externalValidation !== false) return err("external_validation_not_permitted");
	return ok({
		settlementId: raw.settlementId as string,
		tenantId: raw.tenantId as string,
		provider: raw.provider,
		providerCustomerId: raw.providerCustomerId,
		providerSubscriptionId: (raw.providerSubscriptionId as string | null) ?? null,
		requestId: raw.requestId,
		status: raw.status,
		currency: raw.currency,
		lines,
		totalAmountMinor,
		quoteReference: (raw.quoteReference as string | null) ?? null,
		settledAmountMinor: raw.settledAmountMinor as number,
		refundedAmountMinor: raw.refundedAmountMinor as number,
		occurredAt: occurredAt.value,
		recordedAt: raw.recordedAt,
		sequence: raw.sequence as number,
		receiptHash: raw.receiptHash,
		externalValidation: false,
	});
}

/**
 * Fold a tenant's settlement ledger into a seat projection.
 *
 * Ordering is by `(occurredAt, sequence, settlementId)` so two events that
 * arrive out of order - or arrive twice - produce the same projection. A
 * receipt belonging to another tenant, a currency mismatch against the ledger's
 * first receipt, a replayed row whose digest disagrees with the stored one, or a
 * transition the state machine forbids all collapse the projection to
 * `unavailable` rather than to a smaller (but confidently wrong) seat count.
 */
export function projectEntitlement(input: SettlementLedgerInput): EntitlementProjection {
	if (!isUuid(input.tenantId)) {
		return { status: "unavailable", seats: [], sources: [], reason: "invalid_tenant_id" };
	}
	const seen = new Map<string, SettlementReceipt>();
	const ordered: SettlementReceipt[] = [];
	for (const receipt of input.receipts) {
		if (receipt.tenantId !== input.tenantId) {
			return { status: "unavailable", seats: [], sources: [], reason: "cross_tenant_receipt" };
		}
		// One settlement is a *sequence* of immutable receipts, so the row key is
		// `(settlementId, sequence)` - the same key the ledger's unique constraint
		// uses. Replaying an identical row is a no-op; replaying a row whose
		// content disagrees with the stored digest is a conflict.
		const key = `${receipt.settlementId}#${receipt.sequence}`;
		const existing = seen.get(key);
		if (existing) {
			if (existing.receiptHash !== receipt.receiptHash) {
				return { status: "unavailable", seats: [], sources: [], reason: "duplicate_settlement_conflict" };
			}
			continue;
		}
		seen.set(key, receipt);
		ordered.push(receipt);
	}
	if (ordered.length === 0) {
		// No settlement on record is not "zero seats paid for"; it is an absence
		// of evidence. Fail closed and let the operator see the missing link.
		return { status: "unavailable", seats: [], sources: [], reason: "no_settlement_records" };
	}
	ordered.sort((a, b) => {
		if (a.occurredAt !== b.occurredAt) return a.occurredAt < b.occurredAt ? -1 : 1;
		if (a.sequence !== b.sequence) return a.sequence - b.sequence;
		return a.settlementId < b.settlementId ? -1 : 1;
	});

	const currency = ordered[0]?.currency as SettlementCurrency;
	for (const receipt of ordered) {
		if (receipt.currency !== currency) {
			return { status: "unavailable", seats: [], sources: [], reason: "currency_mismatch" };
		}
		if (receipt.status === "settled" && receipt.quoteReference === null) {
			return { status: "unavailable", seats: [], sources: [], reason: "settled_without_quote" };
		}
	}

	// Replay the state machine per settlement id and collect the seat set of the
	// final state of each settlement.
	const finalStatus = new Map<string, SettlementStatus>();
	const latest = new Map<string, SettlementReceipt>();
	for (const receipt of ordered) {
		const previous = finalStatus.get(receipt.settlementId);
		if (previous === undefined) {
			if (receipt.status !== "quote_issued" && receipt.status !== "order_placed") {
				return { status: "unavailable", seats: [], sources: [], reason: "ledger_does_not_start_at_quote" };
			}
		} else if (previous !== receipt.status && !mayTransition(previous, receipt.status)) {
			return { status: "unavailable", seats: [], sources: [], reason: `illegal_transition_${previous}_to_${receipt.status}` };
		}
		finalStatus.set(receipt.settlementId, receipt.status);
		latest.set(receipt.settlementId, receipt);
	}

	const seats = new Map<string, number>();
	let granted = 0;
	for (const [settlementId, status] of finalStatus) {
		const receipt = latest.get(settlementId);
		if (!receipt) continue;
		if (status === "settled") {
			for (const line of receipt.lines) {
				seats.set(line.sku, (seats.get(line.sku) ?? 0) + line.quantity);
			}
			granted += 1;
		}
	}
	const projection = [...seats.entries()]
		.map(([sku, quantity]) => ({ sku, seats: quantity }))
		.filter((entry) => entry.seats > 0)
		.sort((a, b) => (a.sku < b.sku ? -1 : a.sku > b.sku ? 1 : 0));
	return {
		status: granted > 0 ? "granted" : "revoked",
		seats: projection,
		sources: [...finalStatus.keys()].sort(),
		reason: granted > 0 ? "settled_settlements_present" : "no_settled_settlements",
	};
}

/**
 * Seat reconciliation between the provider-reported quantity and the locally
 * projected entitlement. Returns the *action* the control plane must take, so a
 * reconciler can be idempotent: the same inputs always produce the same action.
 */
export interface SeatReconciliation {
	action: "noop" | "grant" | "revoke" | "unavailable";
	sku: string;
	delta: number;
	reason: string;
}

export function reconcileSeat(
	projection: EntitlementProjection,
	sku: string,
	providerQuantity: number | null,
): SeatReconciliation {
	if (projection.status === "unavailable") {
		return { action: "unavailable", sku, delta: 0, reason: projection.reason };
	}
	if (providerQuantity === null) {
		return { action: "unavailable", sku, delta: 0, reason: "provider_quantity_unavailable" };
	}
	if (!Number.isSafeInteger(providerQuantity) || providerQuantity < 0 || providerQuantity > 100000) {
		return { action: "unavailable", sku, delta: 0, reason: "provider_quantity_invalid" };
	}
	const local = projection.seats.find((entry) => entry.sku === sku)?.seats ?? 0;
	const delta = providerQuantity - local;
	if (delta === 0) return { action: "noop", sku, delta, reason: "already_reconciled" };
	return delta > 0
		? { action: "grant", sku, delta, reason: "provider_reports_more_seats" }
		: { action: "revoke", sku, delta, reason: "provider_reports_fewer_seats" };
}

/**
 * Return-URL policy for a hosted provider redirect.
 *
 * Only an absolute HTTPS URL with no credentials, or a plain-HTTP loopback URL
 * for local development, is accepted. Anything else - including a
 * protocol-relative value, a `javascript:` URL, an unrelated origin or a
 * URL whose path escapes the configured dashboard root - is rejected.
 */
export function resolveReturnUrl(candidate: unknown, dashboardOrigin: string): ParseResult<string> {
	let allowed: URL;
	try {
		allowed = new URL(dashboardOrigin);
	} catch {
		return err("invalid_dashboard_origin");
	}
	if (allowed.protocol !== "https:" || allowed.username || allowed.password) {
		return err("invalid_dashboard_origin");
	}
	if (typeof candidate !== "string" || candidate.trim() === "") return err("missing_return_url");
	if (candidate.length > 2048) return err("return_url_too_long");
	if (/[\u0000-\u001f\u007f]/.test(candidate)) return err("invalid_return_url");
	let parsed: URL;
	try {
		parsed = new URL(candidate);
	} catch {
		return err("invalid_return_url");
	}
	if (parsed.username || parsed.password) return err("return_url_credentials_not_allowed");
	const loopback = parsed.hostname === "127.0.0.1" || parsed.hostname === "[::1]" || parsed.hostname === "localhost";
	if (parsed.protocol === "http:" && !loopback) return err("return_url_insecure");
	if (parsed.protocol !== "https:" && !(parsed.protocol === "http:" && loopback)) {
		return err("return_url_scheme_not_allowed");
	}
	if (parsed.origin !== allowed.origin && !loopback) return err("return_url_origin_not_allowed");
	return ok(parsed.toString());
}

export interface SeatChangeDecision {
	action: "allow" | "deny";
	code: string;
	/** Absolute change requested; never trusted for authorization by itself. */
	deltaSeats: number;
}

/**
 * Guard for a seat quantity change request.
 *
 * Authorization (active tenant, active membership, role) happens in the Edge
 * handler against the database. This function only enforces the arithmetic and
 * non-negative-floor invariants so a crafted body cannot produce a negative or
 * unbounded entitlement.
 */
export function evaluateSeatChange(
	currentSeats: number,
	requestedSeats: number,
	maxSeats = 10000,
): SeatChangeDecision {
	if (!Number.isSafeInteger(currentSeats) || currentSeats < 0) {
		return { action: "deny", code: "current_seats_invalid", deltaSeats: 0 };
	}
	if (!Number.isSafeInteger(requestedSeats) || requestedSeats < 1) {
		return { action: "deny", code: "requested_seats_invalid", deltaSeats: 0 };
	}
	if (requestedSeats > maxSeats) return { action: "deny", code: "requested_seats_over_limit", deltaSeats: 0 };
	return { action: "allow", code: "seat_change_permitted", deltaSeats: requestedSeats - currentSeats };
}

export interface CancelRefundDecision {
	action: "allow" | "deny";
	code: string;
	refundAmountMinor: number;
}

/**
 * Guard for cancel/refund. A refund may never exceed the amount actually
 * captured minus what has already been refunded, and a settled-but-unpaid
 * settlement cannot be "refunded".
 */
export function evaluateRefund(
	receipt: Pick<SettlementReceipt, "status" | "settledAmountMinor" | "refundedAmountMinor">,
	requestedAmountMinor: number,
): CancelRefundDecision {
	if (!["settled", "cancelled"].includes(receipt.status)) {
		return { action: "deny", code: "settlement_not_refundable", refundAmountMinor: 0 };
	}
	if (!Number.isSafeInteger(requestedAmountMinor) || requestedAmountMinor < 1) {
		return { action: "deny", code: "refund_amount_invalid", refundAmountMinor: 0 };
	}
	const outstanding = receipt.settledAmountMinor - receipt.refundedAmountMinor;
	if (outstanding <= 0) return { action: "deny", code: "nothing_left_to_refund", refundAmountMinor: 0 };
	if (requestedAmountMinor > outstanding) {
		return { action: "deny", code: "refund_exceeds_outstanding", refundAmountMinor: 0 };
	}
	return { action: "allow", code: "refund_permitted", refundAmountMinor: requestedAmountMinor };
}

/**
 * Verify that a settlement transition request is well formed before any
 * database or provider call. `current` must come from the stored ledger, never
 * from the request body.
 */
export function evaluateTransition(
	current: SettlementStatus,
	requested: unknown,
): { ok: true; next: SettlementStatus } | { ok: false; code: string } {
	if (!isSettlementStatus(requested)) return { ok: false, code: "invalid_target_status" };
	if (TERMINAL_SETTLEMENT_STATUSES.includes(current)) return { ok: false, code: "settlement_terminal" };
	if (!mayTransition(current, requested)) return { ok: false, code: `transition_not_allowed_${current}_to_${requested}` };
	return { ok: true, next: requested };
}
