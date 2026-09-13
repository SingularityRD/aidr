// Enterprise order intake for the invoice-only commercial flow.
// No request to this route can mark an invoice paid or issue an entitlement.

import { createClient } from "npm:@supabase/supabase-js@2";
import { getBearerToken } from "../_shared/auth.ts";
import { checkIdentityBarrier } from "../_shared/identity-barrier.ts";
import { configFailure, loadConfig, runtimeEnv } from "../_shared/config.ts";
import { corsJson, handleCors } from "../_shared/cors.ts";
import { membershipActive } from "../_shared/runtime-policy.ts";
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

Deno.serve(async (req) => {
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
		const db = createClient(config.values.SUPABASE_URL, config.values.SUPABASE_SERVICE_ROLE_KEY, {
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
			return corsJson(req, 200, { ok: true, orders });
		}

		let orderRequest: ReturnType<typeof parseInvoiceOrderRequest>;
		try { orderRequest = parseInvoiceOrderRequest(await boundedJson(req)); }
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
});
