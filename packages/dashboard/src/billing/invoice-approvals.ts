/**
 * Dashboard client for the recorded finance approvals.
 *
 * An approval is a server fact: the approver identity, the approved amount, the
 * currency and the evidence digest are recorded by the `invoice-entitlement`
 * Edge Function from operator input and are never re-derived here. This module
 * only reads them back, bound to the tenant the operator is viewing, and fails
 * closed on any record that does not describe a complete paid decision.
 */

import { supabase } from "../lib/supabase";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[a-zA-Z0-9_-]{16,80}$/;
const EVIDENCE_SHA256 = /^[0-9a-f]{64}$/;
const CURRENCIES = ["USD", "EUR", "GBP"] as const;

export interface InvoiceApproval {
	orderId: string;
	tenantId: string;
	requestId: string;
	quoteReference: string | null;
	status: "paid";
	approver: string;
	amountMinor: number;
	currency: string;
	evidenceSha256: string;
	agentsGranted: number;
	approvedAt: string;
}

function parseApproval(value: unknown, tenantId: string): InvoiceApproval {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		throw new Error("Invalid invoice approval response");
	}
	const row = value as Record<string, unknown>;
	if (
		typeof row.order_id !== "string" ||
		!UUID.test(row.order_id) ||
		row.tenant_id !== tenantId ||
		typeof row.request_id !== "string" ||
		!REQUEST_ID.test(row.request_id) ||
		!(row.quote_reference === null || typeof row.quote_reference === "string") ||
		row.status !== "paid" ||
		typeof row.approver !== "string" ||
		row.approver.trim() === "" ||
		!Number.isSafeInteger(row.amount_minor) ||
		(row.amount_minor as number) < 1 ||
		!(CURRENCIES as readonly unknown[]).includes(row.currency) ||
		typeof row.evidence_sha256 !== "string" ||
		!EVIDENCE_SHA256.test(row.evidence_sha256) ||
		!Number.isSafeInteger(row.agents_granted) ||
		(row.agents_granted as number) < 1 ||
		(row.agents_granted as number) > 100000 ||
		typeof row.approved_at !== "string" ||
		!Number.isFinite(Date.parse(row.approved_at))
	) {
		throw new Error("Invalid invoice approval response");
	}
	return {
		orderId: row.order_id,
		tenantId,
		requestId: row.request_id,
		quoteReference: row.quote_reference as string | null,
		status: "paid",
		approver: row.approver,
		amountMinor: row.amount_minor as number,
		currency: row.currency as string,
		evidenceSha256: row.evidence_sha256,
		agentsGranted: row.agents_granted as number,
		approvedAt: row.approved_at,
	};
}

export async function listInvoiceApprovals(tenantId: string): Promise<InvoiceApproval[]> {
	if (!UUID.test(tenantId)) throw new Error("A valid tenant is required for invoice approvals");
	const { data, error } = await supabase.functions.invoke("invoice-entitlement", {
		method: "GET",
		headers: { "X-AIDR-Tenant-ID": tenantId },
	});
	if (error || data?.ok !== true || !Array.isArray(data.approvals)) {
		throw new Error("Invoice approvals are unavailable");
	}
	return data.approvals.map((row: unknown) => parseApproval(row, tenantId));
}
