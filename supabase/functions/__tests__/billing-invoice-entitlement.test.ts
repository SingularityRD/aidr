// Contract suite for the invoice-only enterprise order intake route
// (`invoice-entitlement`).
//
// This file is named in the edge-function contract manifest
// (`docs/production-readiness/edge-function-contract-manifest.json`) so the
// browser-invoked Edge Function
// (`packages/dashboard/src/billing/enterprise-orders.ts`) can never ship
// without an executable contract. The route's *intake path* is deliberately an
// order intake ledger: no intake request may mark an invoice paid, and no
// intake request may issue an entitlement. The separate
// `record_invoice_approval` action records an operator-supplied finance
// decision and is the only path into the paid state.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
	parseInvoiceApprovalRequest,
	projectInvoiceApproval,
} from "../invoice-entitlement/approval.ts";
import {
	parseInvoiceOrderRequest,
	parseTenantId,
	projectInvoiceOrder,
	projectRequestedInvoiceOrder,
} from "../invoice-entitlement/contract.ts";

// The Edge Function imports Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The runtime factory only needs to exist, and
// it must never be reached: the suite always injects `deps.db`.
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through InvoiceEntitlementDeps.db");
	},
}));

// The Edge runtime provides `Deno.env` and `Deno.serve`; the test process does
// not. The env stub delegates to `process.env` so `vi.stubEnv` drives the same
// values the production `runtimeEnv` reader would see, and `serve` is a no-op
// because the suite drives the exported handler factory directly.
(globalThis as unknown as { Deno: unknown }).Deno = {
	env: {
		get: (name: string) => process.env[name],
	},
	serve: () => undefined,
};

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");
const migration = readFileSync(
	join(ROOT, "supabase", "migrations", "20260913000003_invoice_entitlement.sql"),
	"utf8",
);

// The approval -> paid transition ships as an append-only follow-up migration.
// It is read separately so an assertion on it can never be satisfied by the
// shipped intake ledger, and vice versa.
const APPROVAL_MIGRATION_PATH = join(
	ROOT,
	"supabase",
	"migrations",
	"20260914000000_invoice_approval_transition.sql",
);
const approvalMigration = readFileSync(APPROVAL_MIGRATION_PATH, "utf8");
const APPROVAL_TABLE =
	approvalMigration.split("create table public.enterprise_invoice_approvals (")[1]?.split("\n);")[0] ?? "";
const APPROVAL_RPC =
	approvalMigration.split("create function public.record_invoice_approval(")[1]?.split("\n$$;")[0] ?? "";

// The migration's three contract surfaces, split out so an assertion cannot be
// satisfied by an unrelated statement elsewhere in the file.
const ORDER_TABLE = migration.split("create table public.enterprise_invoice_orders (")[1]?.split("\n);")[0] ?? "";
const REQUEST_RPC =
	migration.split("create function public.request_enterprise_invoice_order(")[1]?.split("\n$$;")[0] ?? "";
const LIST_RPC = migration.split("create function public.list_enterprise_invoice_orders(")[1]?.split("\n$$;")[0] ?? "";

const TENANT = "22222222-2222-4222-8222-222222222222";
const OTHER_TENANT = "33333333-3333-4333-8333-333333333333";
const USER = "11111111-1111-4111-8111-111111111111";
const ORDER_ID = "55555555-5555-4555-8555-555555555555";
const REQUEST_ID = "order_request_1234567890ab";
const QUOTE = "QUOTE-2026-0001";
const EVIDENCE = "a1b2c3d4".repeat(8);
const FINANCE_USER = "44444444-4444-4444-8444-444444444444";
const APPROVER = FINANCE_USER;
// No customer role confers this independently provisioned authority.
const FINANCE_OPERATOR = { user_id: FINANCE_USER, revoked_at: null, expires_at: null };
const FINANCE_FIXTURE = { userId: FINANCE_USER, member: null, financeOperator: FINANCE_OPERATOR };

/** The exact wire request the dashboard consumer sends for a new order. */
const BODY = { request_id: REQUEST_ID, requested_agents: 25, quote_reference: QUOTE };

/** The exact wire request an operator sends to record a finance approval. */
const APPROVAL_BODY = {
	action: "record_invoice_approval",
	order_id: ORDER_ID,
	amount_minor: 125000,
	currency: "USD",
	evidence_sha256: EVIDENCE,
};

/** A database row shaped exactly like `public.enterprise_invoice_orders`. */
function invoiceRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		id: ORDER_ID,
		tenant_id: TENANT,
		request_id: REQUEST_ID,
		requested_agents: 25,
		quote_reference: QUOTE,
		status: "pending_finance",
		created_at: "2026-09-13T00:00:00.000Z",
		updated_at: "2026-09-13T00:01:00.000Z",
		...overrides,
	};
}

/** A row shaped exactly like the `record_invoice_approval` / list projection. */
function approvalRow(overrides: Record<string, unknown> = {}): Record<string, unknown> {
	return {
		order_id: ORDER_ID,
		tenant_id: TENANT,
		request_id: REQUEST_ID,
		quote_reference: QUOTE,
		status: "paid",
		approver: APPROVER,
		amount_minor: 125000,
		currency: "USD",
		evidence_sha256: EVIDENCE,
		agents_granted: 25,
		approved_at: "2026-09-13T02:00:00.000Z",
		...overrides,
	};
}

describe("invoice order request contract", () => {
	it("accepts a well-formed request and normalizes the optional quote reference", () => {
		expect(parseInvoiceOrderRequest(BODY)).toEqual({
			requestId: REQUEST_ID,
			requestedAgents: 25,
			quoteReference: QUOTE,
		});
		expect(parseInvoiceOrderRequest({ ...BODY, quote_reference: `  ${QUOTE}  ` }).quoteReference).toBe(QUOTE);
		expect(parseInvoiceOrderRequest({ ...BODY, quote_reference: "   " }).quoteReference).toBeNull();
		expect(parseInvoiceOrderRequest({ ...BODY, quote_reference: null }).quoteReference).toBeNull();
		expect(parseInvoiceOrderRequest({ request_id: REQUEST_ID, requested_agents: 1 }).quoteReference).toBeNull();
	});

	it("rejects a body that is not a JSON object and any client-supplied state field", () => {
		for (const value of [null, undefined, [], "request", 7, true]) {
			expect(() => parseInvoiceOrderRequest(value)).toThrow("invalid_invoice_order_request");
		}
		// A browser must not be able to assert payment, status, tenant or
		// entitlement state through this route.
		for (const extra of [
			{ status: "paid_verified" },
			{ paid: true },
			{ entitlement: { included_agents: 5000 } },
			{ tenant_id: OTHER_TENANT },
			{ invoice_reference: "INV-1" },
		]) {
			expect(() => parseInvoiceOrderRequest({ ...BODY, ...extra })).toThrow("unsupported_invoice_order_field");
		}
	});

	it("rejects malformed request ids", () => {
		for (const requestId of [
			"",
			"short",
			"a".repeat(81),
			"order/1234567890123456",
			"order request 12345678",
			"order_request_1234567890ab\n",
			42,
			null,
			undefined,
		]) {
			expect(() => parseInvoiceOrderRequest({ ...BODY, request_id: requestId })).toThrow("invalid_request_id");
		}
		expect(() => parseInvoiceOrderRequest({ requested_agents: 25 })).toThrow("invalid_request_id");
	});

	it("rejects a non-integer or out-of-range requested agent count", () => {
		for (const agents of [0, -1, 100001, 1.5, 2 ** 53, Number.NaN, Number.POSITIVE_INFINITY, "25", null, undefined]) {
			expect(() => parseInvoiceOrderRequest({ ...BODY, requested_agents: agents })).toThrow(
				"invalid_requested_agents",
			);
		}
		// The bounds are inclusive and are the only quantities the ledger accepts.
		expect(parseInvoiceOrderRequest({ ...BODY, requested_agents: 1 }).requestedAgents).toBe(1);
		expect(parseInvoiceOrderRequest({ ...BODY, requested_agents: 100000 }).requestedAgents).toBe(100000);
	});

	it("rejects a quote reference carrying control characters or exceeding the column bound", () => {
		for (const quote of [
			`${QUOTE}\u0000`,
			`${QUOTE}\n`,
			"\tQ-1",
			"Q\u007f-1",
			"x".repeat(121),
			1,
			{ value: QUOTE },
		]) {
			expect(() => parseInvoiceOrderRequest({ ...BODY, quote_reference: quote })).toThrow("invalid_quote_reference");
		}
		expect(parseInvoiceOrderRequest({ ...BODY, quote_reference: "x".repeat(120) }).quoteReference).toBe(
			"x".repeat(120),
		);
	});

	it("requires an explicit, well-formed tenant identifier and lowercases it", () => {
		expect(parseTenantId(TENANT)).toBe(TENANT);
		expect(parseTenantId(`  ${TENANT.toUpperCase()}  `)).toBe(TENANT);
		for (const tenant of [null, "", "   ", "alice", "12345678-1234-1234-1234-123456789abc/other",
			`${TENANT}0`, `${TENANT}x`]) {
			expect(() => parseTenantId(tenant)).toThrow("invalid_tenant_id");
		}
	});
});

describe("invoice order projection", () => {
	it("projects only a well-formed pending order for the authenticated tenant", () => {
		expect(projectInvoiceOrder({ ...invoiceRow(), secret_internal_note: "never returned" }, TENANT)).toEqual(
			invoiceRow(),
		);
		expect(projectInvoiceOrder(invoiceRow({ tenant_id: OTHER_TENANT }), TENANT)).toBeNull();
		for (const broken of [
			null,
			undefined,
			[],
			"row",
			invoiceRow({ id: "not-a-uuid" }),
			invoiceRow({ request_id: "short" }),
			invoiceRow({ requested_agents: 0 }),
			invoiceRow({ requested_agents: 100001 }),
			invoiceRow({ requested_agents: "25" }),
			invoiceRow({ quote_reference: 7 }),
			invoiceRow({ created_at: "nonsense" }),
			invoiceRow({ updated_at: "nonsense" }),
		]) {
			expect(projectInvoiceOrder(broken, TENANT)).toBeNull();
		}
	});

	it("refuses every status other than pending_finance", () => {
		for (const status of [
			"paid",
			"paid_verified",
			"settled",
			"entitled",
			"active",
			"invoiced",
			"cancelled",
			"refunded",
			"pending",
			"PENDING_FINANCE",
			"",
			null,
			7,
		]) {
			expect(projectInvoiceOrder(invoiceRow({ status }), TENANT)).toBeNull();
		}
	});

	it("presents a created order as pending_finance only, and never with paid or entitlement state", () => {
		const parsed = parseInvoiceOrderRequest(BODY);
		const order = projectRequestedInvoiceOrder(invoiceRow(), TENANT, parsed);
		expect(order).not.toBeNull();
		expect(order?.status).toBe("pending_finance");
		// The projection is a closed shape: a paid/entitled field can never be
		// smuggled into a browser response.
		expect(Object.keys(order ?? {}).sort()).toEqual([
			"created_at",
			"id",
			"quote_reference",
			"request_id",
			"requested_agents",
			"status",
			"tenant_id",
			"updated_at",
		]);
		for (const status of ["paid", "paid_verified", "settled", "entitled", "provisioned", "active"]) {
			expect(projectRequestedInvoiceOrder(invoiceRow({ status }), TENANT, parsed), status).toBeNull();
		}
	});

	it("accepts a POST result only when it echoes the exact requested order", () => {
		const parsed = parseInvoiceOrderRequest(BODY);
		for (const mismatch of [
			invoiceRow({ request_id: "order_request_0987654321ab" }),
			invoiceRow({ requested_agents: 26 }),
			invoiceRow({ quote_reference: "QUOTE-2026-0002" }),
			invoiceRow({ quote_reference: null }),
			invoiceRow({ tenant_id: OTHER_TENANT }),
			invoiceRow({ status: "paid" }),
		]) {
			expect(projectRequestedInvoiceOrder(mismatch, TENANT, parsed)).toBeNull();
		}
		// A request without a quote reference must not accept one either.
		const noQuote = parseInvoiceOrderRequest({ request_id: REQUEST_ID, requested_agents: 25 });
		expect(projectRequestedInvoiceOrder(invoiceRow({ quote_reference: null }), TENANT, noQuote)).not.toBeNull();
		expect(projectRequestedInvoiceOrder(invoiceRow(), TENANT, noQuote)).toBeNull();
	});
});

describe("invoice-entitlement Edge handler", () => {
	type RpcCall = { name: string; args: Record<string, unknown> };
	interface DbOptions {
		userId?: string;
		financeOperator?: { user_id: string; revoked_at: string | null; expires_at: string | null } | null;
		financeError?: boolean;
		member?: { role: string; expires_at: string | null } | null;
		memberError?: boolean;
		tenantStatus?: string | null;
		tenantError?: boolean;
		rateLimit?: { data: unknown; error: unknown };
		order?: unknown;
		orderError?: { code: string; message: string } | null;
		orders?: unknown;
		listError?: { code: string; message: string } | null;
		approvalOrder?: unknown;
		approvalOrderError?: { code: string; message: string } | null;
		approval?: unknown;
		approvalError?: { code: string; message: string } | null;
		approvals?: unknown;
		approvalsError?: { code: string; message: string } | null;
	}

	function database(options: DbOptions = {}) {
		const rpcCalls: RpcCall[] = [];
		const filters: Array<{ table: string; column: string; value: unknown }> = [];
		// Minimal PostgREST-shaped query builder: chainable and
		// `.maybeSingle()`-terminated, which is how the handler reads the
		// identity barrier, the membership and the tenant row.
		const builder = (table: string) => {
			const query = {
				select: () => query,
				eq: (column: string, value: unknown) => { filters.push({ table, column, value }); return query; },
				maybeSingle: async () => {
					if (table === "identity_user_session_state") return { data: { revoked_before: null }, error: null };
					if (table === "tenant_identity_policies") return { data: { require_mfa: false }, error: null };
					if (table === "invoice_finance_operators") {
						return { data: options.financeOperator ?? null, error: options.financeError ? new Error("db_down") : null };
					}
					if (table === "tenant_members") {
						return {
							data: options.member === undefined
								? { role: "owner", expires_at: null }
								: options.member,
							error: options.memberError ? new Error("db_down") : null,
						};
					}
					if (table === "tenants") {
						return {
							data: options.tenantStatus === null ? null : { status: options.tenantStatus ?? "active" },
							error: options.tenantError ? new Error("db_down") : null,
						};
					}
					return { data: null, error: null };
				},
			};
			return query;
		};
		return {
			db: {
				auth: {
					getUser: vi.fn(async (token: string) =>
						token === "valid-token"
							? { data: { user: { id: options.userId ?? USER } }, error: null }
							: { data: { user: null }, error: new Error("invalid") },
					),
				},
				from: vi.fn((table: string) => builder(table)),
				rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
					rpcCalls.push({ name, args });
					if (name === "consume_tenant_rate_limit") {
						return options.rateLimit ?? { data: [{ allowed: true }], error: null };
					}
					if (name === "request_enterprise_invoice_order") {
						return {
							data: options.order === undefined ? invoiceRow() : options.order,
							error: options.orderError ?? null,
						};
					}
					if (name === "list_enterprise_invoice_orders") {
						return {
							data: options.orders === undefined ? [] : options.orders,
							error: options.listError ?? null,
						};
					}
					if (name === "get_enterprise_invoice_order_for_approval") {
						return {
							data: options.approvalOrder === undefined ? invoiceRow() : options.approvalOrder,
							error: options.approvalOrderError ?? null,
						};
					}
					if (name === "record_invoice_approval") {
						return {
							data: options.approval === undefined ? approvalRow() : options.approval,
							error: options.approvalError ?? null,
						};
					}
					if (name === "list_enterprise_invoice_approvals") {
						return {
							data: options.approvals === undefined ? [] : options.approvals,
							error: options.approvalsError ?? null,
						};
					}
					return { data: null, error: null };
				}),
			},
			rpcCalls,
			filters,
		};
	}

	beforeEach(() => {
		vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
		vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "service-role-key");
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	async function handlerWith(options: DbOptions = {}) {
		const { db, rpcCalls, filters } = database(options);
		const mod = await import("../invoice-entitlement/index.ts");
		return {
			handle: mod.createInvoiceEntitlementHandler({ db: db as never }),
			db,
			rpcCalls,
			filters,
		};
	}

	const URL_ = "https://project.supabase.co/functions/v1/invoice-entitlement";

	function post(body: unknown, headers: Record<string, string> = {}): Request {
		return new Request(URL_, {
			method: "POST",
			headers: {
				Authorization: "Bearer valid-token",
				"X-AIDR-Tenant-ID": TENANT,
				"Content-Type": "application/json",
				...headers,
			},
			body: typeof body === "string" ? body : JSON.stringify(body),
		});
	}

	function get(headers: Record<string, string> = {}): Request {
		return new Request(URL_, {
			method: "GET",
			headers: { Authorization: "Bearer valid-token", "X-AIDR-Tenant-ID": TENANT, ...headers },
		});
	}

	it("calls the request RPC with the verified identity and answers 200 with a pending order", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(post(BODY));
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.ok).toBe(true);
		expect(body.order).toMatchObject({
			id: ORDER_ID,
			tenant_id: TENANT,
			request_id: REQUEST_ID,
			requested_agents: 25,
			quote_reference: QUOTE,
			status: "pending_finance",
		});

		// The tenant and the actor are server facts: the header names the
		// tenant, the bearer token names the actor, and the body names neither.
		const order = rpcCalls.find((call) => call.name === "request_enterprise_invoice_order");
		expect(order?.args).toEqual({
			p_tenant_id: TENANT,
			p_actor_user_id: USER,
			p_request_id: REQUEST_ID,
			p_requested_agents: 25,
			p_quote_reference: QUOTE,
		});
	});

	it("rejects a body that tries to name the tenant instead of trusting the client", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(post({ ...BODY, tenant_id: OTHER_TENANT }));
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "unsupported_invoice_order_field" });
		expect(rpcCalls).toEqual([]);
	});

	it("rejects an unauthenticated request before any client, RPC or table call", async () => {
		const { handle, db, rpcCalls } = await handlerWith();
		for (const request of [post(BODY, { Authorization: "" }), post(BODY, { Authorization: "Basic abc" })]) {
			const response = await handle(request);
			expect(response.status).toBe(401);
			expect(await response.json()).toMatchObject({ error: "missing_access_token" });
		}
		const invalid = await handle(post(BODY, { Authorization: "Bearer wrong-token" }));
		expect(invalid.status).toBe(401);
		expect(await invalid.json()).toMatchObject({ error: "invalid_access_token" });

		// The unusable credential was verified and rejected, and nothing else
		// (neither a table read nor an RPC) was reached.
		expect(db.auth.getUser.mock.calls).toEqual([["wrong-token"]]);
		expect(db.from).not.toHaveBeenCalled();
		expect(rpcCalls).toEqual([]);
	});

	it("rejects a malformed tenant header with 400 and no database work", async () => {
		const { handle, db, rpcCalls } = await handlerWith();
		for (const tenant of ["", "not-a-uuid", `${TENANT}/other`]) {
			const response = await handle(post(BODY, { "X-AIDR-Tenant-ID": tenant }));
			expect(response.status).toBe(400);
			expect(await response.json()).toMatchObject({ error: "invalid_tenant_id" });
		}
		const missing = await handle(post(BODY, { "X-AIDR-Tenant-ID": "undefined" }));
		expect(missing.status).toBe(400);
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(db.from).not.toHaveBeenCalled();
		expect(rpcCalls).toEqual([]);
	});

	it("rejects a malformed body with 400 before any RPC", async () => {
		const { handle, rpcCalls } = await handlerWith();
		for (const body of [
			"{not json",
			JSON.stringify({ ...BODY, request_id: "short" }),
			JSON.stringify({ ...BODY, requested_agents: 0 }),
			JSON.stringify({ ...BODY, requested_agents: 2.5 }),
			JSON.stringify({ ...BODY, quote_reference: "Q\u0000-1" }),
			JSON.stringify({ ...BODY, status: "paid" }),
		]) {
			const response = await handle(post(body));
			expect(response.status, body).toBe(400);
		}
		expect(rpcCalls).toEqual([]);
	});

	it("rejects an oversized body with 413", async () => {
		const { handle, rpcCalls } = await handlerWith();
		const response = await handle(post({ ...BODY, padding: "x".repeat(9000) }));
		expect(response.status).toBe(413);
		expect(await response.json()).toMatchObject({ error: "request_too_large" });
		expect(rpcCalls).toEqual([]);
	});

	it("maps a Postgres failure on the order RPC to the declared status", async () => {
		const cases: Array<[{ code: string; message: string }, number, string]> = [
			[{ code: "42501", message: "invoice_order_forbidden" }, 403, "billing_forbidden"],
			[{ code: "22023", message: "invalid_invoice_order_request" }, 400, "invalid_invoice_order_request"],
			[
				{ code: "23505", message: "invoice_order_request_conflict" },
				409,
				"invoice_order_request_conflict",
			],
			// A unique violation that is *not* the declared conflict is not a
			// client-visible conflict; every other failure is unavailable.
			[{ code: "23505", message: "duplicate key value violates unique constraint" }, 503, "invoice_order_unavailable"],
			[{ code: "08006", message: "connection failure" }, 503, "invoice_order_unavailable"],
			[{ code: "P0001", message: "raise_exception" }, 503, "invoice_order_unavailable"],
		];
		for (const [orderError, status, error] of cases) {
			const { handle } = await handlerWith({ orderError });
			const response = await handle(post(BODY));
			expect(response.status, orderError.message).toBe(status);
			expect(await response.json(), orderError.message).toMatchObject({ error });
		}
	});

	it("never answers 200 for an order row that is not the requested pending_finance order", async () => {
		for (const order of [
			invoiceRow({ status: "paid" }),
			invoiceRow({ status: "entitled" }),
			invoiceRow({ tenant_id: OTHER_TENANT }),
			invoiceRow({ request_id: "order_request_0987654321ab" }),
			invoiceRow({ requested_agents: 26 }),
			invoiceRow({ quote_reference: null }),
			null,
		]) {
			const { handle } = await handlerWith({ order });
			const response = await handle(post(BODY));
			expect(response.status).toBe(503);
			expect(await response.json()).toMatchObject({ error: "invalid_invoice_order_state" });
		}
	});

	it("refuses a member without the owner/admin role, an expired membership and a non-active tenant", async () => {
		for (const member of [
			{ role: "viewer", expires_at: null },
			{ role: "member", expires_at: null },
			{ role: "billing", expires_at: null },
			{ role: "", expires_at: null },
			{ role: "owner", expires_at: "2000-01-01T00:00:00.000Z" },
			{ role: "admin", expires_at: "2000-01-01T00:00:00.000Z" },
			null,
		]) {
			const { handle, rpcCalls } = await handlerWith({ member });
			const response = await handle(post(BODY));
			expect(response.status, JSON.stringify(member)).toBe(403);
			expect(await response.json()).toMatchObject({ error: "billing_forbidden" });
			expect(rpcCalls).toEqual([]);
		}

		for (const tenantStatus of ["suspended", "closing", "closed", "pending", null]) {
			const { handle, rpcCalls } = await handlerWith({ tenantStatus });
			const response = await handle(post(BODY));
			expect(response.status, String(tenantStatus)).toBe(403);
			expect(await response.json()).toMatchObject({ error: "tenant_inactive" });
			expect(rpcCalls).toEqual([]);
		}
	});

	it("answers 503, never 403, when authorization state cannot be read", async () => {
		const member = await handlerWith({ memberError: true });
		expect((await member.handle(post(BODY))).status).toBe(503);
		const tenant = await handlerWith({ tenantError: true });
		expect((await tenant.handle(post(BODY))).status).toBe(503);
		const quota = await handlerWith({ rateLimit: { data: null, error: { code: "08006" } } });
		const quotaResponse = await quota.handle(post(BODY));
		expect(quotaResponse.status).toBe(503);
		expect(await quotaResponse.json()).toMatchObject({ error: "rate_limit_unavailable" });
	});

	it("answers 405 for a method the route does not implement", async () => {
		const { handle, db } = await handlerWith();
		const response = await handle(
			new Request(URL_, { method: "DELETE", headers: { Authorization: "Bearer valid-token", "X-AIDR-Tenant-ID": TENANT } }),
		);
		expect(response.status).toBe(405);
		expect(db.from).not.toHaveBeenCalled();
	});

	it("lists only pending_finance orders for the header tenant and fails closed otherwise", async () => {
		const { handle, rpcCalls } = await handlerWith({ orders: [invoiceRow()] });
		const response = await handle(get());
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.ok).toBe(true);
		expect(body.orders).toEqual([invoiceRow()]);
		expect(rpcCalls.find((call) => call.name === "list_enterprise_invoice_orders")?.args).toEqual({
			p_tenant_id: TENANT,
			p_actor_user_id: USER,
		});

		const forbidden = await handlerWith({ listError: { code: "42501", message: "invoice_order_forbidden" } });
		expect((await forbidden.handle(get())).status).toBe(403);

		const broken = await handlerWith({ orders: [invoiceRow({ status: "paid" })] });
		const brokenResponse = await broken.handle(get());
		expect(brokenResponse.status).toBe(503);
		expect(await brokenResponse.json()).toMatchObject({ error: "invalid_invoice_order_state" });

		const unavailable = await handlerWith({ orders: null });
		expect((await unavailable.handle(get())).status).toBe(503);
	});

	it("lists recorded finance approvals with the intake ledger and fails closed otherwise", async () => {
		const listed = await handlerWith({ orders: [invoiceRow()], approvals: [approvalRow()] });
		const response = await listed.handle(get());
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.ok).toBe(true);
		expect(body.approvals).toEqual([approvalRow()]);
		expect(listed.rpcCalls.find((call) => call.name === "list_enterprise_invoice_approvals")?.args).toEqual({
			p_tenant_id: TENANT,
			p_actor_user_id: USER,
		});

		// A read that cannot be completed is never reported as "nothing approved".
		const failed = await handlerWith({ approvalsError: { code: "HY000" } });
		const failedResponse = await failed.handle(get());
		expect(failedResponse.status).toBe(503);
		expect(await failedResponse.json()).toMatchObject({ error: "invoice_approvals_unavailable" });

		const forbidden = await handlerWith({
			approvalsError: { code: "42501", message: "invoice_order_forbidden" },
		});
		expect((await forbidden.handle(get())).status).toBe(403);

		const broken = await handlerWith({ approvals: [approvalRow({ status: "pending_finance" })] });
		const brokenResponse = await broken.handle(get());
		expect(brokenResponse.status).toBe(503);
		expect(await brokenResponse.json()).toMatchObject({ error: "invalid_invoice_approval_state" });

		const crossTenant = await handlerWith({ approvals: [approvalRow({ tenant_id: OTHER_TENANT })] });
		expect((await crossTenant.handle(get())).status).toBe(503);
	});

	it.each(["owner", "admin"])("rejects active customer %s self-approval before every RPC", async (role) => {
		const { handle, rpcCalls } = await handlerWith({ member: { role, expires_at: null } });
		const response = await handle(post(APPROVAL_BODY));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "billing_forbidden" });
		expect(rpcCalls).toEqual([]);
		const spoof = await handle(post({ ...APPROVAL_BODY, approver: FINANCE_USER }));
		expect(spoof.status).toBe(400);
		expect(rpcCalls).toEqual([]);
	});

	it("fails closed for revoked, expired, mismatched or unreadable finance grants before RPC", async () => {
		for (const financeOperator of [
			null,
			{ ...FINANCE_OPERATOR, revoked_at: "2026-01-01T00:00:00Z" },
			{ ...FINANCE_OPERATOR, expires_at: "2000-01-01T00:00:00Z" },
			{ ...FINANCE_OPERATOR, expires_at: "not-a-date" },
			{ ...FINANCE_OPERATOR, user_id: USER },
		]) {
			const { handle, rpcCalls } = await handlerWith({ ...FINANCE_FIXTURE, financeOperator });
			expect((await handle(post(APPROVAL_BODY))).status).toBe(403);
			expect(rpcCalls).toEqual([]);
		}
		const unavailable = await handlerWith({ ...FINANCE_FIXTURE, financeError: true });
		expect((await unavailable.handle(post(APPROVAL_BODY))).status).toBe(503);
		expect(unavailable.rpcCalls).toEqual([]);
	});

	it("honors revoked authority or tenant suspension at the transactional recheck", async () => {
		const { handle, rpcCalls } = await handlerWith({
			...FINANCE_FIXTURE,
			approvalError: { code: "42501", message: "invoice_approval_forbidden" },
		});
		const response = await handle(post(APPROVAL_BODY));
		expect(response.status).toBe(403);
		expect(await response.json()).toEqual({ error: "billing_forbidden" });
		expect(rpcCalls.map((call) => call.name)).toEqual([
			"get_enterprise_invoice_order_for_approval", "consume_tenant_rate_limit", "record_invoice_approval",
		]);
		expect(rpcCalls[2].args.p_actor_user_id).toBe(FINANCE_USER);
	});

	it("grants entitlement only through a recorded finance approval with an evidence digest", async () => {
		const { handle, rpcCalls, db, filters } = await handlerWith(FINANCE_FIXTURE);
		const response = await handle(post(APPROVAL_BODY));
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body.ok).toBe(true);
		expect(body.approval).toMatchObject({
			order_id: ORDER_ID,
			tenant_id: TENANT,
			request_id: REQUEST_ID,
			quote_reference: QUOTE,
			status: "paid",
			approver: APPROVER,
			amount_minor: 125000,
			currency: "USD",
			evidence_sha256: EVIDENCE,
			agents_granted: 25,
		});
		// The local system did not independently validate the payment, so it must
		// never present the recorded decision as externally validated.
		expect(body.external_validation).toBe(false);

		// Only amount, currency and digest are body inputs. Tenant and finance
		// actor UUID are server facts rechecked by the transaction, not labels.
		const transition = rpcCalls.find((call) => call.name === "record_invoice_approval");
		expect(transition?.args).toEqual({
			p_tenant_id: TENANT,
			p_actor_user_id: FINANCE_USER,
			p_order_id: ORDER_ID,
			p_amount_minor: 125000,
			p_currency: "USD",
			p_evidence_sha256: EVIDENCE,
		});
		expect(transition?.args).not.toHaveProperty("p_approver");
		expect(db.from).toHaveBeenCalledWith("invoice_finance_operators");
		expect(filters.filter(({ table }) => table === "invoice_finance_operators")).toEqual([
			{ table: "invoice_finance_operators", column: "tenant_id", value: TENANT },
			{ table: "invoice_finance_operators", column: "user_id", value: FINANCE_USER },
		]);
		expect(db.auth.getUser).toHaveBeenCalledWith("valid-token");
		expect(rpcCalls.map((call) => call.name)).toEqual([
			"get_enterprise_invoice_order_for_approval", "consume_tenant_rate_limit", "record_invoice_approval",
		]);

		// The order is scoped to the authenticated tenant before the transition.
		expect(
			rpcCalls.find((call) => call.name === "get_enterprise_invoice_order_for_approval")?.args,
		).toEqual({ p_tenant_id: TENANT, p_actor_user_id: FINANCE_USER, p_order_id: ORDER_ID });
		expect(rpcCalls.find((call) => call.name === "consume_tenant_rate_limit")?.args).toMatchObject({
			p_tenant_id: TENANT,
			p_subject: FINANCE_USER,
			p_endpoint: "invoice-approval",
		});
	});

	it("rejects a transaction response with a claimed label or a different actor", async () => {
		for (const approver of [USER, "finance.operator@example.invalid"]) {
			const { handle } = await handlerWith({ ...FINANCE_FIXTURE, approval: approvalRow({ approver }) });
			const response = await handle(post(APPROVAL_BODY));
			expect(response.status).toBe(503);
			expect(await response.json()).toEqual({ error: "invalid_invoice_approval_state" });
		}
	});

	it("refuses claimed approvers or missing amount, currency or evidence digest", async () => {
		const { handle, rpcCalls } = await handlerWith(FINANCE_FIXTURE);
		for (const approval of [
			{ ...APPROVAL_BODY, approver: APPROVER },
			{ ...APPROVAL_BODY, approver: null },
			{ ...APPROVAL_BODY, approver_user_id: FINANCE_USER },
			{ ...APPROVAL_BODY, actor_user_id: FINANCE_USER },
			{ ...APPROVAL_BODY, approver: "   " },
			{ ...APPROVAL_BODY, approver: `${APPROVER}\nX-Injected: 1` },
			{ ...APPROVAL_BODY, approver: "x".repeat(201) },
			{ ...APPROVAL_BODY, amount_minor: undefined },
			{ ...APPROVAL_BODY, amount_minor: 0 },
			{ ...APPROVAL_BODY, amount_minor: 12.5 },
			{ ...APPROVAL_BODY, amount_minor: "125000" },
			{ ...APPROVAL_BODY, currency: "usd" },
			{ ...APPROVAL_BODY, currency: "JPY" },
			{ ...APPROVAL_BODY, evidence_sha256: undefined },
			{ ...APPROVAL_BODY, evidence_sha256: "A".repeat(64) },
			{ ...APPROVAL_BODY, evidence_sha256: "a".repeat(63) },
			{ ...APPROVAL_BODY, order_id: "not-a-uuid" },
			{ ...APPROVAL_BODY, tenant_id: OTHER_TENANT },
			{ ...APPROVAL_BODY, status: "paid" },
			{ ...APPROVAL_BODY, agents_granted: 5000 },
			{ ...APPROVAL_BODY, action: "approve_everything" },
			{ ...APPROVAL_BODY, paid: true },
		]) {
			const response = await handle(post(approval));
			expect(response.status, JSON.stringify(approval)).toBe(400);
		}
		// Nothing reached the database: no approval can be recorded from a body
		// that does not fully describe the decision.
		expect(rpcCalls).toEqual([]);
	});

	it("rejects a second approval for the same order", async () => {
		const conflicted = await handlerWith({
			...FINANCE_FIXTURE,
			approvalError: { code: "23505", message: "invoice_approval_conflict" },
		});
		const response = await conflicted.handle(post(APPROVAL_BODY));
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ error: "invoice_approval_conflict" });
		// The refusal is not retried and cannot apply the decision twice.
		expect(
			conflicted.rpcCalls.filter((call) => call.name === "record_invoice_approval"),
		).toHaveLength(1);

		// Any other failure is unavailable, never a second silent application.
		const unrelated = await handlerWith({
			...FINANCE_FIXTURE,
			approvalError: { code: "23505", message: "duplicate key value violates unique constraint" },
		});
		const unrelatedResponse = await unrelated.handle(post(APPROVAL_BODY));
		expect(unrelatedResponse.status).toBe(503);
		expect(await unrelatedResponse.json()).toMatchObject({ error: "invoice_approval_unavailable" });

		const missing = await handlerWith({ ...FINANCE_FIXTURE, approvalError: { code: "P0002", message: "not found" } });
		expect((await missing.handle(post(APPROVAL_BODY))).status).toBe(404);
	});

	it("cannot mark an invoice paid through the intake path", async () => {
		const rejected = await handlerWith();
		for (const body of [
			{ ...BODY, status: "paid" },
			{ ...BODY, status: "paid_verified" },
			{ ...BODY, paid: true },
			{ ...BODY, entitlement: { included_agents: 5000 } },
			{ ...BODY, approver: APPROVER },
			{ ...BODY, evidence_sha256: EVIDENCE },
			{ action: "request_order", ...BODY },
		]) {
			const response = await rejected.handle(post(body));
			expect(response.status, JSON.stringify(body)).toBe(400);
		}
		expect(rejected.rpcCalls).toEqual([]);

		// The intake transition that *is* reached records no approval and never
		// writes an entitlement through this route.
		const accepted = await handlerWith();
		expect((await accepted.handle(post(BODY))).status).toBe(200);
		expect(accepted.rpcCalls.map((call) => call.name)).toEqual([
			"consume_tenant_rate_limit",
			"request_enterprise_invoice_order",
		]);
	});
});

describe("invoice entitlement migration contract", () => {
	it("is a pending_finance-only ledger with no payment or entitlement column", () => {
		expect(ORDER_TABLE).toMatch(
			/status text not null default 'pending_finance'\s+check \(status = 'pending_finance'\)/,
		);
		// The status check admits exactly one value: no other status is
		// representable, so no route (or operator) can store a paid order.
		const statusLiterals = [...ORDER_TABLE.matchAll(/'([a-z_]+)'/g)].map((match) => match[1]);
		expect(new Set(statusLiterals)).toEqual(new Set(["pending_finance"]));
		expect(ORDER_TABLE).not.toMatch(/\bpaid\b/);
		expect(ORDER_TABLE).not.toMatch(/\bentitlement/);
		expect(ORDER_TABLE).toContain("requested_agents between 1 and 100000");
		expect(ORDER_TABLE).toContain("unique (tenant_id, request_id)");
	});

	it("is service-role only: revoked from public, anon and authenticated, granted to service_role", () => {
		expect(migration).toContain(
			"revoke all on public.enterprise_invoice_orders from public, anon, authenticated",
		);
		expect(migration).toContain("grant select, insert on public.enterprise_invoice_orders to service_role");
		expect(migration).not.toMatch(/grant\s+[^;]*\b(?:select|insert|update|delete)\b[^;]*\bto\s+authenticated\b/);
		expect(migration).not.toMatch(/grant\s+[^;]*\bto\s+(?:anon|public)\b/);
	});

	it("re-checks the active membership and role inside the writing transaction, under an advisory lock", () => {
		expect(REQUEST_RPC).toContain("public.tenant_members");
		expect(REQUEST_RPC).toContain("m.user_id = p_actor_user_id");
		expect(REQUEST_RPC).toContain("m.role in ('owner', 'admin')");
		expect(REQUEST_RPC).toContain("t.status = 'active'");
		expect(REQUEST_RPC).toContain("(m.expires_at is null or m.expires_at > now())");
		expect(REQUEST_RPC).toContain("for share of t, m");
		expect(REQUEST_RPC).toContain("pg_advisory_xact_lock(hashtextextended(");
		expect(REQUEST_RPC).toContain("2613");
		expect(REQUEST_RPC).toContain("using errcode = '42501'");
		expect(REQUEST_RPC).toContain("using errcode = '22023'");
		expect(REQUEST_RPC).toContain("using errcode = '23505'");
		expect(REQUEST_RPC).toContain("invoice_order_request_conflict");

		// Authorization must be settled before the row is written, and the
		// write must be audited in the same transaction.
		const authorize = REQUEST_RPC.indexOf("for share of t, m");
		const insert = REQUEST_RPC.indexOf("insert into public.enterprise_invoice_orders");
		const audit = REQUEST_RPC.indexOf("insert into public.admin_audit_logs");
		expect(authorize).toBeGreaterThan(-1);
		expect(insert).toBeGreaterThan(authorize);
		expect(audit).toBeGreaterThan(insert);
		expect(REQUEST_RPC).toContain("'invoice_order.requested'");
	});

	it("never lets the intake RPC change an entitlement", () => {
		expect(migration).not.toMatch(/insert into public\.entitlements/);
		expect(migration).not.toMatch(/update public\.entitlements/);
		expect(REQUEST_RPC).not.toContain("public.entitlements");
	});

	it("re-checks membership for the privileged list RPC as well", () => {
		expect(LIST_RPC).toContain("public.tenant_members");
		expect(LIST_RPC).toContain("m.user_id = p_actor_user_id");
		expect(LIST_RPC).toContain("m.role in ('owner', 'admin')");
		expect(LIST_RPC).toContain("t.status = 'active'");
		expect(LIST_RPC).toContain("for share of t, m");
		expect(LIST_RPC).toContain("using errcode = '42501'");
		expect(LIST_RPC).toContain("from public.enterprise_invoice_orders");
		expect(LIST_RPC.indexOf("for share of t, m")).toBeLessThan(
			LIST_RPC.indexOf("from public.enterprise_invoice_orders"),
		);
	});

	it("grants both RPCs to service_role only", () => {
		for (const signature of [
			"public.request_enterprise_invoice_order(uuid, uuid, text, integer, text)",
			"public.list_enterprise_invoice_orders(uuid, uuid)",
		]) {
			expect(migration).toContain(`revoke all on function ${signature}\n  from public, anon, authenticated`);
			expect(migration).toContain(`grant execute on function ${signature}\n  to service_role`);
		}
	});
});

describe("invoice approval contract", () => {
	it("accepts only a complete operator decision with no body-supplied identity", () => {
		expect(parseInvoiceApprovalRequest(APPROVAL_BODY)).toEqual({
			orderId: ORDER_ID,
			amountMinor: 125000,
			currency: "USD",
			evidenceSha256: EVIDENCE,
		});
		for (const approver of [APPROVER, `  ${APPROVER}  `, undefined, null]) {
			expect(() => parseInvoiceApprovalRequest({ ...APPROVAL_BODY, approver })).toThrow("unsupported_invoice_approval_field");
		}
		// An intake-shaped body is not an approval: the parser has no defaults,
		// so a missing amount, currency or digest cannot be fabricated.
		for (const value of [null, undefined, [], "approve", BODY, { action: "record_invoice_approval" }]) {
			expect(() => parseInvoiceApprovalRequest(value)).toThrow();
		}
	});

	it("refuses any client-supplied state beyond the recorded decision", () => {
		for (const extra of [
			{ tenant_id: OTHER_TENANT },
			{ status: "paid" },
			{ paid: true },
			{ agents_granted: 5000 },
			{ evidence: EVIDENCE },
			{ approver_user_id: USER },
		]) {
			expect(() => parseInvoiceApprovalRequest({ ...APPROVAL_BODY, ...extra })).toThrow(
				"unsupported_invoice_approval_field",
			);
		}
	});

	it("projects only a complete paid decision for the authenticated tenant", () => {
		expect(projectInvoiceApproval(approvalRow({ internal_note: "never returned" }), TENANT)).toEqual(
			approvalRow(),
		);
		expect(projectInvoiceApproval(approvalRow({ tenant_id: OTHER_TENANT }), TENANT)).toBeNull();
		for (const broken of [
			null,
			undefined,
			[],
			"row",
			approvalRow({ status: "pending_finance" }),
			approvalRow({ status: "settled" }),
			approvalRow({ approver: "" }),
			approvalRow({ amount_minor: 0 }),
			approvalRow({ amount_minor: 1.5 }),
			approvalRow({ currency: "JPY" }),
			approvalRow({ evidence_sha256: "zz" }),
			approvalRow({ order_id: "not-a-uuid" }),
			approvalRow({ request_id: "short" }),
			approvalRow({ agents_granted: 0 }),
			approvalRow({ approved_at: "nonsense" }),
		]) {
			expect(projectInvoiceApproval(broken, TENANT)).toBeNull();
		}
	});
});

describe("invoice approval migration contract", () => {
	it("keeps the paid state out of the shipped pending_finance ledger", () => {
		// The intake ledger is not altered at all: its single-value status check
		// still admits only pending_finance and no paid column is added.
		expect(approvalMigration).not.toMatch(/alter table public\.enterprise_invoice_orders/);
		expect(approvalMigration).not.toMatch(/drop constraint/);
		expect(approvalMigration).not.toContain("enterprise_invoice_orders\n  add column");
		expect(APPROVAL_TABLE).toMatch(/status text not null default 'paid'\s+check \(status = 'paid'\)/);
		expect(APPROVAL_TABLE).toContain("order_id uuid primary key");
		expect(APPROVAL_TABLE).toContain("amount_minor bigint not null check (amount_minor > 0)");
		expect(APPROVAL_TABLE).toContain("currency text not null check (currency in ('USD', 'EUR', 'GBP'))");
		expect(APPROVAL_TABLE).toContain("evidence_sha256 text not null check (evidence_sha256 ~ '^[0-9a-f]{64}$')");
	});

	it("is the only transition: audited, serialized per order and idempotent by refusal", () => {
		expect(APPROVAL_RPC).toContain("pg_advisory_xact_lock(hashtextextended(p_order_id::text, 2615))");
		expect(APPROVAL_RPC).toContain("for update");
		expect(APPROVAL_RPC).toContain("from public.enterprise_invoice_approvals where order_id = p_order_id");
		expect(APPROVAL_RPC).toContain("invoice_approval_conflict");
		expect(APPROVAL_RPC).toContain("using errcode = '23505'");
		expect(APPROVAL_RPC).toContain("using errcode = '22023'");
		expect(APPROVAL_RPC).toContain("using errcode = '42501'");
		expect(APPROVAL_RPC).toContain("insert into public.admin_audit_logs");
		expect(APPROVAL_RPC).toContain("'invoice_approval.recorded'");
		expect(APPROVAL_RPC).toContain("'evidence_sha256', v_approval.evidence_sha256");
		expect(APPROVAL_RPC).toContain("'approver', v_approval.approver");
		// The entitlement is granted from the recorded approvals only, and the
		// approval row is written before the audit and entitlement statements.
		expect(APPROVAL_RPC).toContain("insert into public.entitlements");
		expect(APPROVAL_RPC.indexOf("insert into public.enterprise_invoice_approvals")).toBeLessThan(
			APPROVAL_RPC.indexOf("insert into public.entitlements"),
		);
		expect(APPROVAL_RPC.indexOf("insert into public.entitlements")).toBeLessThan(
			APPROVAL_RPC.indexOf("insert into public.admin_audit_logs"),
		);
		// No hard-coded commercial figure: the amount and currency are parameters.
		expect(APPROVAL_RPC).not.toMatch(/amount_minor\s*:=\s*\d/);
		expect(APPROVAL_RPC).not.toMatch(/tax/i);
	});

	it("re-checks the tenant and role before the approval transition", () => {
		const scoping =
			approvalMigration.split("create function public.get_enterprise_invoice_order_for_approval(")[1]?.split(
				"\n$$;",
			)[0] ?? "";
		expect(scoping).toContain("public.tenant_members");
		expect(scoping).toContain("m.user_id = p_actor_user_id");
		expect(scoping).toContain("m.role in ('owner', 'admin')");
		expect(scoping).toContain("t.status = 'active'");
		expect(scoping).toContain("for share of t, m");
		expect(scoping).toContain("tenant_id = p_tenant_id");
	});

	it("is service-role only: the table and every RPC", () => {
		expect(approvalMigration).toContain(
			"revoke all on public.enterprise_invoice_approvals from public, anon, authenticated",
		);
		expect(approvalMigration).toContain(
			"grant select, insert on public.enterprise_invoice_approvals to service_role",
		);
		expect(approvalMigration).not.toMatch(/grant\s+[^;]*\bto\s+(?:anon|public)\b/);
		expect(approvalMigration).not.toMatch(
			/grant\s+[^;]*\b(?:select|insert|update|delete)\b[^;]*\bto\s+authenticated\b/,
		);
		for (const signature of [
			"public.record_invoice_approval(uuid, text, bigint, text, text)",
			"public.get_enterprise_invoice_order_for_approval(uuid, uuid, uuid)",
			"public.list_enterprise_invoice_approvals(uuid, uuid)",
		]) {
			expect(approvalMigration).toContain(
				`revoke all on function ${signature}\n  from public, anon, authenticated`,
			);
			expect(approvalMigration).toContain(`grant execute on function ${signature}\n  to service_role`);
		}
	});
});
