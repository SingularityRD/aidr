// Catalog plan checkout: the price comes only from AIDR_STRIPE_PRICE_MAP and
// the purchasable terms only from public.plans. Executes the real handler with
// Deno.serve stubbed and a recording database.
import { webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";
import { checkoutParameters } from "../billing-checkout/checkout.ts";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
const identity = vi.hoisted(() => ({ checkIdentityBarrier: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));
vi.mock("../_shared/identity-barrier.ts", () => ({ checkIdentityBarrier: identity.checkIdentityBarrier }));

const USER = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const SETTLEMENT = "33333333-3333-4333-8333-333333333333";
const REQUEST_ID = "request_id_plan_123456";
const PRICE_MAP = JSON.stringify({ price_teamMonthly: "team:monthly", price_teamYearly: "team:yearly", price_businessYearly: "business:yearly" });
const CATALOG: Record<string, Record<string, unknown>> = {
	team: { id: "team", active: true, self_serve: true, min_seats: 3, deployment: ["cloud"] },
	business: { id: "business", active: true, self_serve: false, min_seats: 25, deployment: ["cloud", "onprem"] },
};

type Handler = (request: Request) => Promise<Response>;

async function loadHandler(priceMap = PRICE_MAP): Promise<Handler> {
	let handler: Handler | undefined;
	for (const [key, value] of Object.entries({
		AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING: "true",
		AIDR_BILLING_PROVIDER: "stripe",
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
		STRIPE_SECRET_KEY: "test-stripe-secret-key",
		AIDR_STRIPE_EXTRA_AGENT_PRICE_ID: "price_extra",
		AIDR_DASHBOARD_URL: "https://aidr.example.test",
		AIDR_STRIPE_PRICE_MAP: priceMap,
	})) vi.stubEnv(key, value);
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (key: string) => process.env[key] },
		serve: (value: Handler) => { handler = value; },
	});
	vi.resetModules();
	await import("../billing-checkout/index.ts");
	if (!handler) throw new Error("billing-checkout did not register a handler");
	return handler;
}

function authorizedDb() {
	const rpc = vi.fn(async (name: string, args: Record<string, unknown>) => {
		if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 4 }, error: null };
		if (name === "claim_billing_checkout_intent") return { data: { settlement_id: SETTLEMENT, status: "claimed", checkout_session_id: null }, error: null };
		if (name === "bind_billing_checkout_session") return { data: args.p_checkout_session_id === "cs_plan", error: null };
		throw new Error(`unexpected RPC ${name}`);
	});
	const from = vi.fn((table: string) => {
		let id = "";
		const query = {
			select: () => query,
			eq: (key: string, value: string) => {
				if (key === "id") id = value;
				return query;
			},
			maybeSingle: async () => ({
				data: table === "tenant_members" ? { role: "owner", expires_at: null }
					: table === "plans" ? CATALOG[id] ?? null
						: { status: "active" },
				error: null,
			}),
		};
		return query;
	});
	const db = { auth: { getUser: vi.fn(async () => ({ data: { user: { id: USER } }, error: null })) }, from, rpc };
	sdk.createClient.mockReturnValue(db);
	identity.checkIdentityBarrier.mockResolvedValue({ ok: true });
	return db;
}

function checkout(body: Record<string, unknown>) {
	return new Request("https://project.supabase.co/functions/v1/billing-checkout", {
		method: "POST",
		headers: { "Content-Type": "application/json", Authorization: "Bearer test-access-token" },
		body: JSON.stringify({ tenant_id: TENANT, request_id: REQUEST_ID, ...body }),
	});
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
	identity.checkIdentityBarrier.mockReset();
});

describe("catalog plan checkout", () => {
	it("prices a self-serve plan from the server price map and records the plan price on the intent", async () => {
		const db = authorizedDb();
		const fetcher = vi.fn(async (_input: string, options: RequestInit) => {
			const form = new URLSearchParams(String(options.body));
			expect(form.get("line_items[0][price]")).toBe("price_teamYearly");
			expect(form.get("line_items[0][quantity]")).toBe("5");
			expect(form.get("subscription_data[metadata][catalog_plan]")).toBe("team");
			return Response.json({ id: "cs_plan", url: "https://checkout.stripe.com/c/pay/cs_plan" });
		});
		vi.stubGlobal("fetch", fetcher);
		const response = await (await loadHandler())(checkout({ seats: 5, plan: "yearly", catalog_plan: "team" }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ ok: true, checkout_id: "cs_plan" });
		expect(db.rpc).toHaveBeenCalledWith("claim_billing_checkout_intent", expect.objectContaining({
			p_price_id: "price_teamYearly", p_seats: 5, p_billing_interval: "yearly",
		}));
		expect(fetcher).toHaveBeenCalledTimes(1);
	});

	it.each([
		[{ seats: 2, plan: "monthly", catalog_plan: "team" }, 400, "seats_below_plan_minimum"],
		[{ seats: 30, plan: "yearly", catalog_plan: "business" }, 400, "plan_not_self_serve"],
		[{ seats: 30, plan: "monthly", catalog_plan: "business" }, 400, "billing_price_not_configured"],
		[{ seats: 5, plan: "monthly", catalog_plan: "enterprise" }, 400, "invalid_checkout_request"],
		[{ seats: 5, plan: "monthly", catalog_plan: "free" }, 400, "invalid_checkout_request"],
	])("refuses %j before any intent or Stripe call", async (body, status, error) => {
		const db = authorizedDb();
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const response = await (await loadHandler())(checkout(body));
		expect(response.status).toBe(status);
		expect(await response.json()).toEqual({ error });
		expect(db.rpc).not.toHaveBeenCalled();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("refuses every plan checkout when the price map is malformed", async () => {
		const db = authorizedDb();
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const response = await (await loadHandler("{broken"))(checkout({ seats: 5, plan: "monthly", catalog_plan: "team" }));
		expect(await response.json()).toEqual({ error: "billing_price_not_configured" });
		expect(db.rpc).not.toHaveBeenCalled();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("rejects an unknown catalog plan in checkout parameters", () => {
		expect(() => checkoutParameters({
			userId: USER, tenantId: TENANT, settlementId: SETTLEMENT, requestId: REQUEST_ID, seats: 3,
			plan: "monthly", monthlyPrice: "price_teamMonthly", dashboardUrl: "https://aidr.example.test",
			catalogPlan: "enterprise",
		})).toThrow("invalid_catalog_plan");
	});
});
