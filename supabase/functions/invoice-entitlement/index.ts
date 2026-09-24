// Enterprise order intake for the invoice-only commercial flow.
//
// The intake path (a body without `action`) cannot mark an invoice paid or
// issue an entitlement: it only ever writes the pending_finance ledger. The
// paid state is entered exclusively through the separate
// `action: "record_invoice_approval"` path below, which records an
// authenticated finance operator's decision (approved amount, currency and
// evidence digest). Approver identity is never body-supplied. This route never decides an approval; it
// records one that already happened out of band.

import { createClient } from "npm:@supabase/supabase-js@2.116.0";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { readBoundedJson } from "../_shared/request-limits.ts";
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
	const parsed = await readBoundedJson(req, MAX_BODY_BYTES);
	if (!parsed.ok) throw new Error(parsed.error);
	return parsed.value;
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
 * decision: a separately provisioned finance actor supplies amount, currency
 * and evidence. The session supplies actor identity. A second approval for the same order is a
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

	// Reject customer self-approval before any RPC, even the order preflight.
	const { data: operator, error: operatorError } = await ctx.db.from("invoice_finance_operators")
		.select("user_id,revoked_at,expires_at").eq("tenant_id", ctx.tenantId).eq("user_id", ctx.userId).maybeSingle();
	if (operatorError) return corsJson(req, 503, { error: "authorization_unavailable" });
	if (operator?.user_id !== ctx.userId || operator.revoked_at !== null || !membershipActive(operator)) {
		return corsJson(req, 403, { error: "billing_forbidden" });
	}

	// Independently provisioned finance authority is required before any mutation
	// (including quota). Customer owner/admin membership is not approval authority.
	// The write RPC repeats this check with actor + tenant inside its transaction.
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

	const { data: quota, error: quotaError } = await ctx.db.rpc("consume_tenant_rate_limit", {
		p_tenant_id: ctx.tenantId, p_subject: ctx.userId, p_endpoint: "invoice-approval",
		p_window_start: Math.floor(Date.now() / 60000), p_subject_limit: 10,
		p_tenant_limit: 50, p_cost: 1,
	});
	if (quotaError || !Array.isArray(quota) || quota.length !== 1) {
		return corsJson(req, 503, { error: "rate_limit_unavailable" });
	}
	if (quota[0]?.allowed !== true) return corsJson(req, 429, { error: "rate_limited" });

	const { data, error } = await ctx.db.rpc("record_invoice_approval", {
		p_tenant_id: ctx.tenantId,
		p_actor_user_id: ctx.userId,
		p_order_id: approvalRequest.orderId,
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
	if (!approval || approval.order_id !== approvalRequest.orderId || approval.approver !== ctx.userId) {
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
			const { data: tenant, error: tenantError } = await db.from("tenants")
				.select("status").eq("id", tenantId).maybeSingle();
			if (tenantError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (tenant?.status !== "active") return corsJson(req, 403, { error: "tenant_inactive" });

			let rawBody: unknown;
			if (req.method === "POST") {
				try { rawBody = await boundedJson(req); }
				catch (error) {
					const code = error instanceof Error ? error.message : "invalid_json";
					return corsJson(req, code === "request_too_large" ? 413 : 400, { error: code });
				}
				const action = rawBody && typeof rawBody === "object" && !Array.isArray(rawBody)
					? (rawBody as Record<string, unknown>).action : undefined;
				if (action !== undefined) {
					if (action !== APPROVAL_ACTION) return corsJson(req, 400, { error: "unsupported_action" });
					// Finance authority is independent of customer membership. The
					// ordinary intake/read paths retain their owner/admin requirement.
					return await recordApproval(req, { db, tenantId, userId }, rawBody);
				}
			}

			const { data: member, error: memberError } = await db.from("tenant_members")
				.select("role,expires_at").eq("tenant_id", tenantId).eq("user_id", userId).maybeSingle();
			if (memberError) return corsJson(req, 503, { error: "authorization_unavailable" });
			if (!membershipActive(member) || !["owner", "admin"].includes(member?.role)) {
				return corsJson(req, 403, { error: "billing_forbidden" });
			}
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
