import { supabase } from "../lib/supabase";

export interface EnterpriseOrder {
	id: string;
	tenant_id: string;
	request_id: string;
	requested_agents: number;
	quote_reference: string | null;
	status: string;
	created_at: string;
	updated_at: string;
}

export interface EnterpriseOrderRequest {
	request_id: string;
	requested_agents: number;
	quote_reference?: string;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const REQUEST_ID = /^[a-zA-Z0-9_-]{16,80}$/;
const FINANCE_STATUS = /^[a-z][a-z_]{0,31}$/;

export function newBillingRequestId(): string | null {
	const browserCrypto = globalThis.crypto;
	if (typeof browserCrypto?.randomUUID === "function") return browserCrypto.randomUUID();
	if (typeof browserCrypto?.getRandomValues !== "function") return null;
	const bytes = browserCrypto.getRandomValues(new Uint8Array(16));
	bytes[6] = ((bytes[6] ?? 0) & 0x0f) | 0x40;
	bytes[8] = ((bytes[8] ?? 0) & 0x3f) | 0x80;
	const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
	return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function assertTenantId(tenantId: string): void {
	if (!UUID.test(tenantId)) throw new Error("A valid tenant is required for an enterprise order");
}

function parseOrder(value: unknown, tenantId: string): EnterpriseOrder {
	if (!value || typeof value !== "object" || Array.isArray(value))
		throw new Error("Invalid enterprise order response");
	const order = value as Record<string, unknown>;
	if (
		typeof order.id !== "string" ||
		!UUID.test(order.id) ||
		order.tenant_id !== tenantId ||
		typeof order.request_id !== "string" ||
		!REQUEST_ID.test(order.request_id) ||
		!Number.isSafeInteger(order.requested_agents) ||
		(order.requested_agents as number) < 1 ||
		(order.requested_agents as number) > 100000 ||
		!(order.quote_reference === null || typeof order.quote_reference === "string") ||
		typeof order.status !== "string" ||
		!FINANCE_STATUS.test(order.status) ||
		typeof order.created_at !== "string" ||
		!Number.isFinite(Date.parse(order.created_at)) ||
		typeof order.updated_at !== "string" ||
		!Number.isFinite(Date.parse(order.updated_at))
	)
		throw new Error("Invalid enterprise order response");
	return order as unknown as EnterpriseOrder;
}

export async function listEnterpriseOrders(tenantId: string): Promise<EnterpriseOrder[]> {
	assertTenantId(tenantId);
	const { data, error } = await supabase.functions.invoke("invoice-entitlement", {
		method: "GET",
		headers: { "X-AIDR-Tenant-ID": tenantId },
	});
	if (error || data?.ok !== true || !Array.isArray(data.orders)) {
		throw new Error("Enterprise order status is unavailable");
	}
	return data.orders.map((order: unknown) => parseOrder(order, tenantId));
}

export async function requestEnterpriseOrder(
	tenantId: string,
	request: EnterpriseOrderRequest,
): Promise<EnterpriseOrder> {
	assertTenantId(tenantId);
	if (!REQUEST_ID.test(request.request_id)) throw new Error("Invalid enterprise order request ID");
	if (
		!Number.isSafeInteger(request.requested_agents) ||
		request.requested_agents < 1 ||
		request.requested_agents > 100000
	) {
		throw new Error("Requested agent count must be between 1 and 100,000");
	}
	const quoteReference = request.quote_reference?.trim();
	if (
		quoteReference &&
		(quoteReference.length > 120 || /[\u0000-\u001f\u007f]/.test(quoteReference))
	) {
		throw new Error("Invalid quote reference");
	}
	const { data, error } = await supabase.functions.invoke("invoice-entitlement", {
		method: "POST",
		headers: { "X-AIDR-Tenant-ID": tenantId },
		body: {
			request_id: request.request_id,
			requested_agents: request.requested_agents,
			...(quoteReference ? { quote_reference: quoteReference } : {}),
		},
	});
	if (error || data?.ok !== true) throw new Error("Enterprise order request was not accepted");
	const order = parseOrder(data.order, tenantId);
	// Creating a request must never be presented as a paid invoice or an
	// entitlement grant. Finance reconciliation remains a separate control.
	if (order.status !== "pending_finance") throw new Error("Unexpected enterprise order status");
	return order;
}
