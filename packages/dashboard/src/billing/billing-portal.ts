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
const CURRENCIES = new Set(["USD", "EUR", "GBP"]);
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

interface PortalProjection {
	sku: string;
	seats: number;
	sources: string[];
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

export class BillingRecoveryError extends Error {
	constructor(
		readonly requestId: string,
		readonly action: string,
		readonly detail: Readonly<Record<string, unknown>>,
	) {
		super(`Billing recovery required: retry ${action} request ${requestId}`);
		this.name = "BillingRecoveryError";
	}
}

async function throwRecovery(error: unknown, data: unknown): Promise<void> {
	let body = data;
	if ((!body || typeof body !== "object") && error && typeof error === "object") {
		const context = (error as { context?: unknown }).context;
		if (context instanceof Response) {
			try {
				body = await context.clone().json();
			} catch {
				// The generic caller error remains the safe fallback.
			}
		}
	}
	if (!body || typeof body !== "object" || Array.isArray(body)) return;
	const recovery = body as Record<string, unknown>;
	if (recovery.error === "billing_reconciliation_pending") {
		throw new Error(
			"Cancellation reconciliation is pending. The portal has not confirmed a final status; refresh or retry after reconciliation completes.",
		);
	}
	if (
		recovery.error === "billing_recovery_required" &&
		typeof recovery.recovery_request_id === "string" &&
		REQUEST_ID.test(recovery.recovery_request_id) &&
		typeof recovery.recovery_action === "string"
	)
		throw new BillingRecoveryError(recovery.recovery_request_id, recovery.recovery_action, {
			...recovery,
		});
}

function assertTenant(tenantId: string): void {
	if (!UUID.test(tenantId)) throw new Error("A valid tenant is required for the billing portal");
}

function nonnegativeSafeInteger(value: unknown): value is number {
	return Number.isSafeInteger(value) && (value as number) >= 0;
}

function parseTimestamp(value: unknown): string {
	if (
		typeof value !== "string" ||
		!/^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?)(?:Z|[+-]\d{2}:\d{2})$/.test(value) ||
		!Number.isFinite(Date.parse(value))
	) {
		throw new Error("Invalid billing settlement timestamp");
	}
	return value;
}

function parseProjection(value: unknown): PortalProjection[] {
	if (!Array.isArray(value)) throw new Error("Invalid billing projection response");
	return value.map((item) => {
		if (!item || typeof item !== "object" || Array.isArray(item)) {
			throw new Error("Invalid billing projection response");
		}
		const row = item as Record<string, unknown>;
		if (
			typeof row.sku !== "string" ||
			!SKU.test(row.sku) ||
			!nonnegativeSafeInteger(row.seats) ||
			!Array.isArray(row.sources) ||
			!row.sources.every((source) => typeof source === "string" && UUID.test(source))
		) {
			throw new Error("Invalid billing projection response");
		}
		return { sku: row.sku, seats: row.seats, sources: row.sources as string[] };
	});
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
		!CURRENCIES.has(row.currency) ||
		(row.provider !== "stripe" && row.provider !== "provider_fixture") ||
		!Array.isArray(row.lines) ||
		typeof row.receiptHash !== "string" ||
		!HASH.test(row.receiptHash) ||
		row.externalValidation !== false ||
		!nonnegativeSafeInteger(row.sequence) ||
		!nonnegativeSafeInteger(row.totalAmountMinor) ||
		!nonnegativeSafeInteger(row.settledAmountMinor) ||
		!nonnegativeSafeInteger(row.refundedAmountMinor) ||
		(row.quoteReference !== null &&
			(typeof row.quoteReference !== "string" || row.quoteReference.length > 120 || /[\x00-\x1f\x7f]/.test(row.quoteReference)))
	) {
		throw new Error("Invalid billing settlement response");
	}
	if (row.tenantId !== undefined && row.tenantId !== tenantId) {
		throw new Error("Billing response belongs to a different tenant");
	}
	const lines = row.lines.map((line) => {
		if (!line || typeof line !== "object" || Array.isArray(line)) {
			throw new Error("Invalid billing settlement line");
		}
		const entry = line as Record<string, unknown>;
		if (
			typeof entry.sku !== "string" ||
			!SKU.test(entry.sku) ||
			!Number.isSafeInteger(entry.quantity) ||
			(entry.quantity as number) < 1 ||
			(entry.quantity as number) > 100000 ||
			!nonnegativeSafeInteger(entry.unitAmountMinor) ||
			(entry.unitAmountMinor as number) > 100_000_000
		) {
			throw new Error("Invalid billing settlement line");
		}
		return {
			sku: entry.sku,
			quantity: entry.quantity as number,
			unitAmountMinor: entry.unitAmountMinor as number,
		};
	});
	const expectedTotal = lines.reduce(
		(total, line) => total + line.quantity * line.unitAmountMinor,
		0,
	);
	if (
		lines.length === 0 || lines.length > 32 ||
		!Number.isSafeInteger(expectedTotal) ||
		expectedTotal !== row.totalAmountMinor ||
		(row.refundedAmountMinor as number) > (row.settledAmountMinor as number) ||
		(row.status === "settled" && row.settledAmountMinor !== row.totalAmountMinor) ||
		((row.status === "quote_issued" || row.status === "order_placed") && row.settledAmountMinor !== 0)
	) {
		throw new Error("Invalid billing settlement amounts");
	}
	return {
		settlementId: row.settlementId,
		requestId: row.requestId,
		provider: row.provider,
		status: row.status as SettlementStatus,
		currency: row.currency,
		lines,
		totalAmountMinor: row.totalAmountMinor as number,
		settledAmountMinor: row.settledAmountMinor as number,
		refundedAmountMinor: row.refundedAmountMinor as number,
		quoteReference: typeof row.quoteReference === "string" ? row.quoteReference : null,
		occurredAt: parseTimestamp(row.occurredAt),
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
	if (
		error ||
		data?.ok !== true ||
		data.tenant_id !== tenantId ||
		!Array.isArray(data.settlements) ||
		!Array.isArray(data.projection)
	) {
		throw new Error("The billing portal is unavailable for this tenant");
	}
	return {
		tenantId,
		settlements: data.settlements.map((row: unknown) => parseSettlement(row, tenantId)),
		projection: parseProjection(data.projection),
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
	await throwRecovery(error, data);
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
	await throwRecovery(error, data);
	if (error || data?.ok !== true) throw new Error("The cancellation was not accepted");
	if (data.status !== "cancelled") throw new Error("Unexpected cancellation status");
}

async function refundSettlement(
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
	await throwRecovery(error, data);
	if (error || data?.ok !== true || !Number.isSafeInteger(data.refunded_amount_minor)) {
		throw new Error("The refund was not accepted");
	}
	return { refundedAmountMinor: data.refunded_amount_minor };
}

/** Total settled seats across the projected SKUs, or `null` when unknown. */
export function projectedSeats(snapshot: PortalSnapshot, sku = "aidr.agent.seat"): number | null {
	return snapshot.projection.find((row) => row.sku === sku)?.seats ?? null;
}
