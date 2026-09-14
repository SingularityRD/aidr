// Enterprise order intake for the invoice-only commercial flow.
//
// The intake path (a body without `action`) cannot mark an invoice paid or
// issue an entitlement: it only ever writes the pending_finance ledger. The
// paid state is entered exclusively through the separate
// `action: "record_invoice_approval"` path below, which records an
// operator-supplied finance decision (approver identity, approved amount,
// currency and evidence digest). This route never decides an approval; it
// records one that already happened out of band.

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
import {
	APPROVAL_ACTION,
	parseInvoiceApprovalRequest,
	projectInvoiceApproval,
	type InvoiceApprovalRequest,
} from "./approval.ts";
import { parseInvoiceOrderRequest, parseTenantId, projectInvoiceOrder, projectRequestedInvoiceOrder } from "./contract.ts";

const REQUIRED_ENV = ["SUPABASE_URL", "SUPABASE_SERVICE_ROLE_KEY"] as const;
const MAX_BODY_BYTES = 8192;

async function boundedJson(req: Request): Promise<unknown> {
	const reader = req.body?.getReader();
	if (!reader) throw new Error("invalid_json");
	const chunks: Uint8Array[] = [];
	let size = 0;
	while (true) {
		const { value, done } = await reader.read();
		if (done) break;
		size += value.byteLength;
		if (size > MAX_BODY_BYTES) {
			await reader.cancel();
			throw new Error("request_too_large");
		}
		chunks.push(value);
	}
	const bytes = new Uint8Array(size);
	let offset = 0;
	for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
	try { return JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)); }
	catch { throw new Error("invalid_json"); }
}

export interface InvoiceEntitlementDeps {
	/** Overrides the service-role client; used by the contract suite. */
	db?: ReturnType<typeof createClient>;
}

interface ApprovalContext {
	db: ReturnType<typeof createClient>;
	tenantId: string;
	userId: string;
}

/**
 * Record an operator-supplied finance approval. This is the only path that can
 * move an order out of `pending_finance`, and it never invents any part of the
 * decision: the approver, the approved amount, the currency and the evidence
 * digest all have to be supplied. A second approval for the same order is a
 * machine-readable conflict, not a silent re-application.
 */
async function recordApproval(req: Request, ctx: ApprovalContext, body: unknown): Promise<Response> {
	let approvalRequest: InvoiceApprovalRequest;
	try {
		approvalRequest = parseInvoiceApprovalRequest(body);
	} catch (error) {
		const code = error instanceof Error ? error.message : "invalid_invoice_approval";
		return corsJson(req, 400, { error: code });
	}

	const { data: quota, error: quotaError } = await ctx.db.rpc("consume_tenant_rate_limit", {
		p_tenant_id: ctx.tenantId, p_subject: ctx.userId, p_endpoint: "invoice-approval",
		p_window_start: Math.floor(Date.now() / 60000), p_subject_limit: 10,
		p_tenant_limit: 50, p_cost: 1,
	});
	if (quotaError || !Array.isArray(quota) || quota.length !== 1) {
		return corsJson(req, 503, { error: "rate_limit_unavailable" });
	}
	if (quota[0]?.allowed !== true) return corsJson(req, 429, { error: "rate_limited" });

	// The transition RPC takes an order id only, so the order is resolved first
	// under the same active-tenant/active-role recheck the intake route uses:
	// an operator can only approve an order of the tenant it is authenticated
	// for, never one reached by naming another tenant's order id.
	const { data: orderRow, error: orderError } = await ctx.db.rpc(
		"get_enterprise_invoice_order_for_approval",
		{ p_tenant_id: ctx.tenantId, p_actor_user_id: ctx.userId, p_order_id: approvalRequest.orderId },
	);
	if (orderError?.code === "42501") return corsJson(req, 403, { error: "billing_forbidden" });
	if (orderError) return corsJson(req, 503, { error: "invoice_approval_unavailable" });
	const scopedOrder = projectInvoiceOrder(orderRow, ctx.tenantId);
	if (!scopedOrder || scopedOrder.id !== approvalRequest.orderId) {
		return corsJson(req, 404, { error: "invoice_order_not_found" });
	}

	const { data, error } = await ctx.db.rpc("record_invoice_approval", {
		p_order_id: approvalRequest.orderId,
		p_approver: approvalRequest.approver,
		p_amount_minor: approvalRequest.amountMinor,
		p_currency: approvalRequest.currency,
		p_evidence_sha256: approvalRequest.evidenceSha256,
	});
	if (error) {
		if (error.code === "23505" && error.message.includes("invoice_approval_conflict")) {
			return corsJson(req, 409, { error: "invoice_approval_conflict" });
		}
		if (error.code === "P0002") return corsJson(req, 404, { error: "invoice_order_not_found" });
		if (error.code === "42501") return corsJson(req, 403, { error: "billing_forbidden" });
		if (error.code === "22023") return corsJson(req, 400, { error: "invalid_invoice_approval" });
		return corsJson(req, 503, { error: "invoice_approval_unavailable" });
	}
	const approval = projectInvoiceApproval(data, ctx.tenantId);
	if (!approval || approval.order_id !== approvalRequest.orderId) {
		return corsJson(req, 503, { error: "invalid_invoice_approval_state" });
	}
	return corsJson(req, 200, { ok: true, approval, external_validation: false });
}

/** Build the request handler. Exported so the contract suite can drive it. */
export function createInvoiceEntitlementHandler(deps: InvoiceEntitlementDeps = {}) {
	return async function handle(req: Request): Promise<Response> {
		const preflight = handleCors(req);
		if (preflight) return preflight;
		if (req.method !== "GET" && req.method !== "POST") return corsJson(req, 405, { error: "method_not_allowed" });
		const config = loadConfig(runtimeEnv, REQUIRED_ENV);
		if (!config.ok) return configFailure("invoice-entitlement", config.error, (status, body) => corsJson(req, status, body));

		let tenantId: string;
		try { tenantId = parseTenantId(req.headers.get("X-AIDR-Tenant-ID")); }
		catch { return corsJson(req, 400, { error: "invalid_tenant_id" }); }
		const token = getBearerToken(req.headers.get("Authorization"));
		if (!token) return corsJson(req, 401, { error: "missing_access_token" });

		try {
			const db = deps.db ??
				createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
					auth: { persistSession: false },
				});
			const { data: auth, error: authError } = await db.auth.getUser(token);
			if (authError || !auth.user?.id) return corsJson(req, 401, { error: "invalid_access_token" });
			const userId = auth.user.id;
			const identity = await checkIdentityBarrier(db, token, userId, tenantId);
			if (!identity.ok) return corsJson(req, identity.status, { error: identity.error });
			const { data: member, error: memberError } = await db.from("tenant_members")
				.select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
			if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (!membershipActive(member) || !["owner", "admin"].includes(member?.role)) {
				return corsJson(req, 403, { error: "billing_forbidden" });
			}
			const { data: tenant, error: tenantError } = await db.from("tenants")
				.select("status").eq("id", tenantId).maybeSingle();
			if (tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (tenant?.status !== "active") return corsJson(req, 403, { error: "tenant_inactive" });

			if (req.method === "GET") {
				const { data, error } = await db.rpc("list_enterprise_invoice_orders", {
					p_tenant_id: tenantId, p_actor_user_id: userId,
				});
				if (error?.code === "42501") return corsJson(req, 403, { error: "billing_forbidden" });
				if (error || !Array.isArray(data)) return corsJson(req, 503, { error: "invoice_orders_unavailable" });
				const orders = data.map((row) => projectInvoiceOrder(row, tenantId));
				if (orders.some((row) => row === null)) return corsJson(req, 503, { error: "invalid_invoice_order_state" });
				// The recorded finance decisions travel with the intake ledger so
				// the dashboard can reconcile approved orders against settled
				// settlements without a second privileged read.
				const { data: approvalRows, error: approvalListError } = await db.rpc(
					"list_enterprise_invoice_approvals",
					{ p_tenant_id: tenantId, p_actor_user_id: userId },
				);
				if (approvalListError?.code === "42501") return corsJson(req, 403, { error: "billing_forbidden" });
				if (approvalListError || !Array.isArray(approvalRows)) {
					return corsJson(req, 503, { error: "invoice_approvals_unavailable" });
				}
				const approvals = approvalRows.map((row) => projectInvoiceApproval(row, tenantId));
				if (approvals.some((row) => row === null)) {
					return corsJson(req, 503, { error: "invalid_invoice_approval_state" });
				}
				return corsJson(req, 200, { ok: true, orders, approvals });
			}

			let rawBody: unknown;
			try { rawBody = await boundedJson(req); }
			catch (error) {
				const code = error instanceof Error ? error.message : "invalid_json";
				return corsJson(req, code === "request_too_large" ? 413 : 400, { error: code });
			}
			// A body may only carry an action when it names the one separate,
			// audited approval transition. The intake parser below never accepts
			// an `action` field, so an intake request cannot reach the paid state.
			const action = rawBody && typeof rawBody === "object" && !Array.isArray(rawBody)
				? (rawBody as Record<string, unknown>).action
				: undefined;
			if (action !== undefined) {
				if (action !== APPROVAL_ACTION) return corsJson(req, 400, { error: "unsupported_action" });
				return await recordApproval(req, { db, tenantId, userId }, rawBody);
			}

			let orderRequest: ReturnType<typeof parseInvoiceOrderRequest>;
			try { orderRequest = parseInvoiceOrderRequest(rawBody); }
			catch (error) {
				const code = error instanceof Error ? error.message : "invalid_invoice_order_request";
				return corsJson(req, code === "request_too_large" ? 413 : 400, { error: code });
			}
			const { data: quota, error: quotaError } = await db.rpc("consume_tenant_rate_limit", {
				p_tenant_id: tenantId, p_subject: userId, p_endpoint: "invoice-entitlement",
				p_window_start: Math.floor(Date.now() / 60000), p_subject_limit: 10,
				p_tenant_limit: 50, p_cost: 1,
			});
			if (quotaError || !Array.isArray(quota) || quota.length !== 1) return corsJson(req, 503, { error: "rate_limit_unavailable" });
			if (quota[0]?.allowed !== true) return corsJson(req, 429, { error: "rate_limited" });
			const { data: order, error: orderError } = await db.rpc("request_enterprise_invoice_order", {
				p_tenant_id: tenantId,
				p_actor_user_id: userId,
				p_request_id: orderRequest.requestId,
				p_requested_agents: orderRequest.requestedAgents,
				p_quote_reference: orderRequest.quoteReference,
			});
			if (orderError) {
				if (orderError.code === "23505" && orderError.message.includes("invoice_order_request_conflict")) {
					return corsJson(req, 409, { error: "invoice_order_request_conflict" });
				}
				if (orderError.code === "42501") return corsJson(req, 403, { error: "billing_forbidden" });
				if (orderError.code === "22023") return corsJson(req, 400, { error: "invalid_invoice_order_request" });
				return corsJson(req, 503, { error: "invoice_order_unavailable" });
			}
			const responseOrder = projectRequestedInvoiceOrder(order, tenantId, orderRequest);
			if (!responseOrder) return corsJson(req, 503, { error: "invalid_invoice_order_state" });
			return corsJson(req, 200, { ok: true, order: responseOrder });
		} catch {
			return corsJson(req, 503, { error: "invoice_order_unavailable" });
		}
	};
}

Deno.serve(createInvoiceEntitlementHandler());
