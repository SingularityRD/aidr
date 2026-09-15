// Finance-approval contract for the invoice-only commercial flow.
//
// This is deliberately a *second*, separate contract from `contract.ts`: the
// intake ledger stays pending_finance-only and no field defined here may ever
// be accepted by the intake body parser. The approval decision is human and
// external; the authenticated finance operator supplies the approved amount,
// currency and digest, never the approver identity. Nothing in
// this module derives a price, a tax figure or an approval.

/** The only action that may enter the paid state. */
export const APPROVAL_ACTION = "record_invoice_approval";

export const APPROVAL_CURRENCIES = ["USD", "EUR", "GBP"] as const;

export type InvoiceApprovalCurrency = (typeof APPROVAL_CURRENCIES)[number];

export type InvoiceApprovalRequest = {
	orderId: string;
	amountMinor: number;
	currency: InvoiceApprovalCurrency;
	evidenceSha256: string;
};

export type InvoiceApproval = {
	order_id: string;
	tenant_id: string;
	request_id: string;
	quote_reference: string | null;
	status: "paid";
	approver: string;
	amount_minor: number;
	currency: InvoiceApprovalCurrency;
	evidence_sha256: string;
	agents_granted: number;
	approved_at: string;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[A-Za-z0-9_-]{16,80}$/;
const EVIDENCE_SHA256 = /^[0-9a-f]{64}$/;
const APPROVAL_FIELDS = new Set([
	"action",
	"order_id",
	"amount_minor",
	"currency",
	"evidence_sha256",
]);

/** A control character would make an approver identity unverifiable in an audit read. */
function validApprover(value: unknown): value is string {
	return typeof value === "string" && value.length >= 1 && value.length <= 200 && !/[\x00-\x1f\x7f]/.test(value);
}

/**
 * Parse what the finance operator approved, with no default amount or evidence.
 * The authenticated actor UUID is resolved by the Edge handler; claimed approver
 * fields are rejected rather than accepted as labels or authorization inputs.
 */
export function parseInvoiceApprovalRequest(value: unknown): InvoiceApprovalRequest {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_invoice_approval");
	const body = value as Record<string, unknown>;
	if (Object.keys(body).some((key) => !APPROVAL_FIELDS.has(key))) {
		throw new Error("unsupported_invoice_approval_field");
	}
	if (body.action !== APPROVAL_ACTION) throw new Error("unsupported_action");
	if (typeof body.order_id !== "string" || !UUID.test(body.order_id)) throw new Error("invalid_order_id");
	if (!Number.isSafeInteger(body.amount_minor) || (body.amount_minor as number) < 1) {
		throw new Error("invalid_amount_minor");
	}
	if (!(APPROVAL_CURRENCIES as readonly unknown[]).includes(body.currency)) {
		throw new Error("invalid_currency");
	}
	if (typeof body.evidence_sha256 !== "string" || !EVIDENCE_SHA256.test(body.evidence_sha256)) {
		throw new Error("invalid_evidence_sha256");
	}
	return {
		orderId: body.order_id.toLowerCase(),
		amountMinor: body.amount_minor as number,
		currency: body.currency as InvoiceApprovalCurrency,
		evidenceSha256: body.evidence_sha256,
	};
}

/**
 * Never emit a malformed or cross-tenant approval from a privileged response.
 * A row that does not describe a recorded, digest-backed decision by this
 * tenant is refused rather than shown as a paid order.
 */
export function projectInvoiceApproval(value: unknown, expectedTenantId: string): InvoiceApproval | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const row = value as Record<string, unknown>;
	if (
		typeof row.order_id !== "string" ||
		!UUID.test(row.order_id) ||
		row.tenant_id !== expectedTenantId ||
		typeof row.request_id !== "string" ||
		!REQUEST_ID.test(row.request_id) ||
		!(
			row.quote_reference === null ||
			(typeof row.quote_reference === "string" &&
				row.quote_reference.length >= 1 &&
				row.quote_reference.length <= 120 &&
				!/[\x00-\x1f\x7f]/.test(row.quote_reference))
		) ||
		row.status !== "paid" ||
		!validApprover(row.approver) ||
		!Number.isSafeInteger(row.amount_minor) ||
		(row.amount_minor as number) < 1 ||
		!(APPROVAL_CURRENCIES as readonly unknown[]).includes(row.currency) ||
		typeof row.evidence_sha256 !== "string" ||
		!EVIDENCE_SHA256.test(row.evidence_sha256) ||
		!Number.isSafeInteger(row.agents_granted) ||
		(row.agents_granted as number) < 1 ||
		(row.agents_granted as number) > 100000 ||
		typeof row.approved_at !== "string" ||
		!Number.isFinite(Date.parse(row.approved_at))
	) {
		return null;
	}
	return {
		order_id: row.order_id,
		tenant_id: expectedTenantId,
		request_id: row.request_id,
		quote_reference: row.quote_reference as string | null,
		status: "paid",
		approver: row.approver,
		amount_minor: row.amount_minor as number,
		currency: row.currency as InvoiceApprovalCurrency,
		evidence_sha256: row.evidence_sha256,
		agents_granted: row.agents_granted as number,
		approved_at: row.approved_at,
	};
}
