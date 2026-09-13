export type InvoiceOrderRequest = {
	requestId: string;
	requestedAgents: number;
	quoteReference: string | null;
};

export type InvoiceOrder = {
	id: string;
	tenant_id: string;
	request_id: string;
	requested_agents: number;
	quote_reference: string | null;
	status: "pending_finance";
	created_at: string;
	updated_at: string;
};

const TENANT_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[A-Za-z0-9_-]{16,80}$/;
const ALLOWED_FIELDS = new Set(["request_id", "requested_agents", "quote_reference"]);

export function parseTenantId(value: string | null): string {
	if (!value || !TENANT_ID.test(value.trim())) throw new Error("invalid_tenant_id");
	return value.trim().toLowerCase();
}

/** A request is only an order intake record. Caller-provided paid or entitlement state is forbidden. */
export function parseInvoiceOrderRequest(value: unknown): InvoiceOrderRequest {
	if (!value || typeof value !== "object" || Array.isArray(value)) throw new Error("invalid_invoice_order_request");
	const body = value as Record<string, unknown>;
	if (Object.keys(body).some((key) => !ALLOWED_FIELDS.has(key))) throw new Error("unsupported_invoice_order_field");
	if (typeof body.request_id !== "string" || !REQUEST_ID.test(body.request_id)) throw new Error("invalid_request_id");
	if (!Number.isSafeInteger(body.requested_agents) || (body.requested_agents as number) < 1 || (body.requested_agents as number) > 100000) {
		throw new Error("invalid_requested_agents");
	}
	let quoteReference: string | null = null;
	if (body.quote_reference !== undefined && body.quote_reference !== null) {
		if (typeof body.quote_reference !== "string") throw new Error("invalid_quote_reference");
		if (/[\x00-\x1f\x7f]/.test(body.quote_reference)) throw new Error("invalid_quote_reference");
		quoteReference = body.quote_reference.trim() || null;
		if (quoteReference && quoteReference.length > 120) throw new Error("invalid_quote_reference");
	}
	return { requestId: body.request_id, requestedAgents: body.requested_agents as number, quoteReference };
}

/** Never emit a malformed or cross-tenant record from a privileged DB response. */
export function projectInvoiceOrder(value: unknown, expectedTenantId: string): InvoiceOrder | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return null;
	const row = value as Record<string, unknown>;
	if (row.status !== "pending_finance" || typeof row.id !== "string" || !TENANT_ID.test(row.id)
		|| row.tenant_id !== expectedTenantId
		|| typeof row.request_id !== "string" || !REQUEST_ID.test(row.request_id)
		|| !Number.isSafeInteger(row.requested_agents) || (row.requested_agents as number) < 1
		|| (row.requested_agents as number) > 100000
		|| (row.quote_reference !== null && typeof row.quote_reference !== "string")
		|| typeof row.created_at !== "string" || !Number.isFinite(Date.parse(row.created_at))
		|| typeof row.updated_at !== "string" || !Number.isFinite(Date.parse(row.updated_at))) return null;
	return {
		id: row.id,
		tenant_id: expectedTenantId,
		request_id: row.request_id,
		requested_agents: row.requested_agents as number,
		quote_reference: row.quote_reference as string | null,
		status: "pending_finance",
		created_at: row.created_at,
		updated_at: row.updated_at,
	};
}

/** A successful POST must describe the exact request accepted by the database. */
export function projectRequestedInvoiceOrder(
	value: unknown,
	expectedTenantId: string,
	request: InvoiceOrderRequest,
): InvoiceOrder | null {
	const order = projectInvoiceOrder(value, expectedTenantId);
	if (!order || order.request_id !== request.requestId
		|| order.requested_agents !== request.requestedAgents
		|| order.quote_reference !== request.quoteReference) return null;
	return order;
}
