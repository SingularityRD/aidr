/**
 * Approved-order reconciliation (BIL-03 follow-through).
 *
 * An enterprise invoice order is approved out of band by Finance and recorded by
 * `record_invoice_approval`; the money itself is only ever evidenced by the
 * append-only settlement ledger. Nothing correlated those two records, so this
 * module matches each *recorded approval* to the settled settlement ids that
 * quote the same reference and marks every row that does not line up.
 *
 * Two rules this module deliberately keeps:
 *
 *   - No figure is invented. An approved amount or currency that was not
 *     recorded stays absent (`null`) and is rendered as absent, never as zero.
 *     There is no price catalogue and no tax rate here, and none is derived.
 *   - A correlation failure is explicit. A settled settlement with no approved
 *     order is `unmatched`, and a settlement that exceeds what was approved is
 *     `over_limit`; neither is filtered out or shown as a pass.
 */

/** The only SKU whose quantity counts as protected-agent seats. */
export const RECONCILIATION_SEAT_SKU = "aidr.agent.seat";

export type ReconciliationStatus = "matched" | "unmatched" | "over_limit" | "currency_mismatch";

export const RECONCILIATION_LABELS: Record<ReconciliationStatus, string> = {
	matched: "Matched",
	unmatched: "Unmatched",
	over_limit: "Over limit",
	currency_mismatch: "Currency mismatch",
};

/** A recorded finance approval, as returned by the `invoice-entitlement` route. */
export interface ReconciliationApproval {
	orderId: string;
	requestId: string;
	quoteReference: string | null;
	status: string;
	approver: string;
	amountMinor: number | null;
	currency: string | null;
	evidenceSha256: string | null;
	agentsGranted: number | null;
	approvedAt: string;
}

/** A settlement ledger row, as returned by the billing portal. */
export interface ReconciliationSettlement {
	settlementId: string;
	status: string;
	currency: string;
	quoteReference: string | null;
	lines: Array<{ sku: string; quantity: number; unitAmountMinor: number }>;
	settledAmountMinor: number;
	sequence?: number;
}

export interface ReconciliationInput {
	approvals: readonly ReconciliationApproval[];
	settlements: readonly ReconciliationSettlement[];
}

export interface ReconciliationRow {
	/** Stable React key. */
	key: string;
	kind: "approved_order" | "settlement";
	orderId: string | null;
	requestId: string | null;
	quoteReference: string | null;
	approver: string | null;
	evidenceSha256: string | null;
	approvedAt: string | null;
	approvedAgents: number | null;
	approvedAmountMinor: number | null;
	currency: string | null;
	settlementIds: string[];
	settledAmountMinor: number | null;
	settledSeats: number | null;
	status: ReconciliationStatus;
	/** Machine-stable reason for the status. */
	reason: string;
}

/** Recorded seat quantity for one settlement, or `null` when no seat line exists. */
function seatTotal(lines: ReconciliationSettlement["lines"]): number | null {
	let total: number | null = null;
	for (const line of lines) {
		if (line?.sku !== RECONCILIATION_SEAT_SKU) continue;
		const quantity = Number(line.quantity);
		if (!Number.isSafeInteger(quantity) || quantity < 0) return null;
		total = (total ?? 0) + quantity;
	}
	return total;
}

/** One row per settlement id: the latest settled receipt wins. */
function latestSettled(settlements: readonly ReconciliationSettlement[]): ReconciliationSettlement[] {
	const byId = new Map<string, ReconciliationSettlement>();
	for (const row of settlements) {
		if (row.status !== "settled") continue;
		const current = byId.get(row.settlementId);
		if (!current || (row.sequence ?? 0) >= (current.sequence ?? 0)) byId.set(row.settlementId, row);
	}
	return [...byId.values()];
}

function approvedRow(
	approval: ReconciliationApproval,
	matches: ReconciliationSettlement[],
): ReconciliationRow {
	const settlementIds = [...new Set(matches.map((match) => match.settlementId))].sort();
	const base = {
		key: `order:${approval.orderId}`,
		kind: "approved_order" as const,
		orderId: approval.orderId,
		requestId: approval.requestId,
		quoteReference: approval.quoteReference,
		approver: approval.approver,
		evidenceSha256: approval.evidenceSha256,
		approvedAt: approval.approvedAt,
		approvedAgents: approval.agentsGranted,
		approvedAmountMinor: approval.amountMinor,
		currency: approval.currency,
		settlementIds,
	};

	if (approval.quoteReference === null) {
		return {
			...base,
			settledAmountMinor: null,
			settledSeats: null,
			status: "unmatched",
			reason: "approved_order_without_quote_reference",
		};
	}
	if (matches.length === 0) {
		return {
			...base,
			settledAmountMinor: null,
			settledSeats: null,
			status: "unmatched",
			reason: "no_settled_settlement",
		};
	}

	const seatTotals = matches.map((match) => seatTotal(match.lines));
	const settledSeats = seatTotals.every((total) => total !== null)
		? (seatTotals as number[]).reduce((sum, total) => sum + total, 0)
		: null;
	const comparable =
		approval.currency !== null && matches.every((match) => match.currency === approval.currency);
	if (!comparable) {
		return {
			...base,
			settledAmountMinor: null,
			settledSeats,
			status: "currency_mismatch",
			reason: "settlement_currency_differs_from_approved_currency",
		};
	}
	const settledAmountMinor = matches.reduce(
		(sum, match) =>
			sum + (Number.isSafeInteger(match.settledAmountMinor) ? match.settledAmountMinor : 0),
		0,
	);
	if (settledSeats !== null && approval.agentsGranted !== null && settledSeats > approval.agentsGranted) {
		return {
			...base,
			settledAmountMinor,
			settledSeats,
			status: "over_limit",
			reason: "settled_seats_exceed_approved_agents",
		};
	}
	if (
		approval.amountMinor !== null &&
		settledAmountMinor > approval.amountMinor
	) {
		return {
			...base,
			settledAmountMinor,
			settledSeats,
			status: "over_limit",
			reason: "settled_amount_exceeds_approved_amount",
		};
	}
	return {
		...base,
		settledAmountMinor,
		settledSeats,
		status: "matched",
		reason: "settled_settlement_matches_approved_order",
	};
}

/**
 * Match every recorded approval to the settled settlements that quote it, then
 * report the settled settlements that no approval claims.
 */
export function reconcileApprovedOrders(input: ReconciliationInput): ReconciliationRow[] {
	const approvals = input.approvals.filter((approval) => approval.status === "paid");
	const settled = latestSettled(input.settlements);
	const claimed = new Set<string>();
	const rows: ReconciliationRow[] = [];

	for (const approval of approvals) {
		const matches =
			approval.quoteReference === null
				? []
				: settled.filter((row) => row.quoteReference === approval.quoteReference);
		for (const match of matches) claimed.add(match.settlementId);
		rows.push(approvedRow(approval, matches));
	}

	const orphans = settled
		.filter((row) => !claimed.has(row.settlementId))
		.sort((a, b) => a.settlementId.localeCompare(b.settlementId));
	for (const orphan of orphans) {
		rows.push({
			key: `settlement:${orphan.settlementId}`,
			kind: "settlement",
			orderId: null,
			requestId: null,
			quoteReference: orphan.quoteReference,
			approver: null,
			evidenceSha256: null,
			approvedAt: null,
			approvedAgents: null,
			approvedAmountMinor: null,
			currency: orphan.currency,
			settlementIds: [orphan.settlementId],
			settledAmountMinor: Number.isSafeInteger(orphan.settledAmountMinor)
				? orphan.settledAmountMinor
				: null,
			settledSeats: seatTotal(orphan.lines),
			status: "unmatched",
			reason: "no_approved_order",
		});
	}

	return rows;
}
