/**
 * Dashboard client for the server-side billing portal (BIL-03 / T33).
 *
 * Every authorization decision happens in the `billing-portal` Edge Function:
 * the tenant comes from the verified membership list, and the provider customer
 * id is resolved server-side from the stored tenant linkage. This module
 * therefore never accepts, stores or forwards a provider customer id, and it
 * rejects any response that is not bound to the tenant the operator is viewing.
 */

import { supabase } from "../lib/supabase";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[a-zA-Z0-9_-]{16,80}$/;
const SKU = /^[a-z][a-z0-9_.-]{1,63}$/;
const HASH = /^[0-9a-f]{64}$/;
const SETTLEMENT_STATUSES = [
	"quote_issued",
	"order_placed",
	"settlement_pending",
	"settled",
	"cancelled",
	"refunded",
] as const;

export type SettlementStatus = (typeof SETTLEMENT_STATUSES)[number];

export interface PortalSettlement {
	settlementId: string;
	requestId: string;
	provider: string;
	status: SettlementStatus;
	currency: string;
	lines: Array<{ sku: string; quantity: number; unitAmountMinor: number }>;
	totalAmountMinor: number;
	settledAmountMinor: number;
	refundedAmountMinor: number;
	quoteReference: string | null;
	occurredAt: string;
	sequence: number;
	receiptHash: string;
	/** Always false: a locally produced receipt is not an audited payment record. */
	externalValidation: false;
}

export interface PortalProjection {
	sku: string;
	seats: number;
	sources: unknown;
}

export interface PortalSnapshot {
	tenantId: string;
	settlements: PortalSettlement[];
	projection: PortalProjection[];
	selfService: boolean;
}

export interface SeatChangeResult {
	providerQuantity: number;
	action: "noop" | "grant" | "revoke" | "unavailable";
	delta: number;
}

function assertTenant(tenantId: string): void {
	if (!UUID.test(tenantId)) throw new Error("A valid tenant is required for the billing portal");
}

function parseSettlement(value: unknown, tenantId: string): PortalSettlement {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("Invalid billing settlement response");
	}
	const row = value as Record<string, unknown>;
	if (
		typeof row.settlementId !== "string" ||
		!UUID.test(row.settlementId) ||
		typeof row.requestId !== "string" ||
		!REQUEST_ID.test(row.requestId) ||
		typeof row.status !== "string" ||
		!(SETTLEMENT_STATUSES as readonly string[]).includes(row.status) ||
		typeof row.currency !== "string" ||
		!Array.isArray(row.lines) ||
		typeof row.receiptHash !== "string" ||
		!HASH.test(row.receiptHash) ||
		row.externalValidation !== false ||
		!Number.isSafeInteger(row.sequence)
	) {
		throw new Error("Invalid billing settlement response");
	}
	if (row.tenantId !== undefined && row.tenantId !== tenantId) {
		throw new Error("Billing response belongs to a different tenant");
	}
	return {
		settlementId: row.settlementId,
		requestId: row.requestId,
		provider: typeof row.provider === "string" ? row.provider : "unknown",
		status: row.status as SettlementStatus,
		currency: row.currency,
		lines: (row.lines as unknown[]).map((line) => {
			const entry = line as Record<string, unknown>;
			return {
				sku: String(entry?.sku ?? ""),
				quantity: Number(entry?.quantity ?? 0),
				unitAmountMinor: Number(entry?.unitAmountMinor ?? 0),
			};
		}),
		totalAmountMinor: Number(row.totalAmountMinor ?? 0),
		settledAmountMinor: Number(row.settledAmountMinor ?? 0),
		refundedAmountMinor: Number(row.refundedAmountMinor ?? 0),
		quoteReference: typeof row.quoteReference === "string" ? row.quoteReference : null,
		occurredAt: typeof row.occurredAt === "string" ? row.occurredAt : "",
		sequence: row.sequence as number,
		receiptHash: row.receiptHash,
		externalValidation: false,
	};
}

export async function loadBillingPortal(tenantId: string): Promise<PortalSnapshot> {
	assertTenant(tenantId);
	const { data, error } = await supabase.functions.invoke("billing-portal", {
		method: "GET",
		headers: { "X-AIDR-Tenant-ID": tenantId },
	});
	if (error || data?.ok !== true || data.tenant_id !== tenantId || !Array.isArray(data.settlements)) {
		throw new Error("The billing portal is unavailable for this tenant");
	}
	return {
		tenantId,
		settlements: data.settlements.map((row: unknown) => parseSettlement(row, tenantId)),
		projection: Array.isArray(data.projection)
			? data.projection.map((row: Record<string, unknown>) => ({
					sku: String(row?.sku ?? ""),
					seats: Number(row?.seats ?? 0),
					sources: row?.sources ?? [],
				}))
			: [],
		selfService: data.self_service === true,
	};
}

export async function requestSeats(
	tenantId: string,
	requestId: string,
	seats: number,
	sku = "aidr.agent.seat",
): Promise<SeatChangeResult> {
	assertTenant(tenantId);
	if (!REQUEST_ID.test(requestId)) throw new Error("Invalid billing request ID");
	if (!Number.isSafeInteger(seats) || seats < 1 || seats > 10000) {
		throw new Error("Seat count must be between 1 and 10,000");
	}
	if (!SKU.test(sku)) throw new Error("Invalid SKU");
	const { data, error } = await supabase.functions.invoke("billing-portal", {
		body: { action: "request_seats", tenant_id: tenantId, request_id: requestId, seats, sku },
	});
	if (error || data?.ok !== true || !Number.isSafeInteger(data.provider_quantity)) {
		throw new Error("The seat change was not accepted");
	}
	return {
		providerQuantity: data.provider_quantity,
		action: data.reconciliation?.action ?? "unavailable",
		delta: Number(data.reconciliation?.delta ?? 0),
	};
}

export async function cancelSettlement(
	tenantId: string,
	requestId: string,
	settlementId: string,
): Promise<void> {
	assertTenant(tenantId);
	if (!REQUEST_ID.test(requestId)) throw new Error("Invalid billing request ID");
	if (!UUID.test(settlementId)) throw new Error("Invalid settlement ID");
	const { data, error } = await supabase.functions.invoke("billing-portal", {
		body: {
			action: "cancel",
			tenant_id: tenantId,
			request_id: requestId,
			settlement_id: settlementId,
		},
	});
	if (error || data?.ok !== true) throw new Error("The cancellation was not accepted");
	if (data.status !== "cancelled") throw new Error("Unexpected cancellation status");
}

export async function refundSettlement(
	tenantId: string,
	requestId: string,
	settlementId: string,
	amountMinor: number,
): Promise<{ refundedAmountMinor: number }> {
	assertTenant(tenantId);
	if (!REQUEST_ID.test(requestId)) throw new Error("Invalid billing request ID");
	if (!UUID.test(settlementId)) throw new Error("Invalid settlement ID");
	if (!Number.isSafeInteger(amountMinor) || amountMinor < 1) {
		throw new Error("Refund amount must be a positive integer in minor units");
	}
	const { data, error } = await supabase.functions.invoke("billing-portal", {
		body: {
			action: "refund",
			tenant_id: tenantId,
			request_id: requestId,
			settlement_id: settlementId,
			amount_minor: amountMinor,
		},
	});
	if (error || data?.ok !== true || !Number.isSafeInteger(data.refunded_amount_minor)) {
		throw new Error("The refund was not accepted");
	}
	return { refundedAmountMinor: data.refunded_amount_minor };
}

/** Total settled seats across the projected SKUs, or `null` when unknown. */
export function projectedSeats(snapshot: PortalSnapshot, sku = "aidr.agent.seat"): number | null {
	if (snapshot.settlements.length === 0) return null;
	return snapshot.projection.find((row) => row.sku === sku)?.seats ?? 0;
}
