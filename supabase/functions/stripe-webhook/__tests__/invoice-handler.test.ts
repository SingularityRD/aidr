import { createHmac, webcrypto } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const SETTLEMENT = "33333333-3333-4333-8333-333333333333";
const SECRET = "whsec_test_invoice";

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

it("records a paid invoice only after binding its payment and accepts a zero-dollar invoice without payment evidence", async () => {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	for (const [key, value] of Object.entries({
		AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING: "true",
		AIDR_BILLING_PROVIDER: "stripe",
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
		STRIPE_SECRET_KEY: "synthetic-stripe-fixture-secret",
		STRIPE_WEBHOOK_SECRET: SECRET,
	})) vi.stubEnv(key, value);
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (key: string) => process.env[key] },
		serve: (value: typeof handler) => { handler = value; },
	});
	const rpc = vi.fn(async () => ({ data: true, error: null }));
	const query = {
		select: () => query, eq: () => query,
		limit: async () => ({ data: [], error: null }),
		maybeSingle: async () => ({ data: null, error: null }),
	};
	const db = {
		rpc,
		auth: { admin: { getUserById: async () => ({ data: { user: { id: USER } }, error: null }) } },
		from: (table: string) => table === "tenants"
			? { select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: { status: "active" }, error: null }) }) }) }
			: table === "tenant_members"
				? { select: () => ({ eq: () => ({ eq: () => ({ maybeSingle: async () => ({ data: { role: "owner", expires_at: null }, error: null }) }) }) }) }
				: table === "billing_customers"
					? { ...query, upsert: async () => ({ error: null }) }
					: { insert: async () => ({ error: null }) },
	};
	sdk.createClient.mockReturnValue(db);
	const fetcher = vi.fn(async () => new Response(JSON.stringify({
		data: [{
			invoice: "in_test_1", status: "paid", amount_paid: 2000, currency: "usd",
			payment: { type: "payment_intent", payment_intent: "pi_test_1" },
		}], has_more: false,
	}), { status: 200 }));
	vi.stubGlobal("fetch", fetcher);
	vi.resetModules();
	await import("../index.ts");
	if (!handler) throw new Error("stripe webhook did not register a handler");
	const event = {
		id: "evt_invoice_paid_1", created: Math.floor(Date.now() / 1000), type: "invoice.paid",
		data: { object: {
			id: "in_test_1", customer: "cus_test_1", subscription: "sub_test_1",
			amount_paid: 2000, currency: "usd", status: "paid",
			parent: { subscription_details: { subscription: "sub_test_1", metadata: {
				user_id: USER, tenant_id: TENANT, settlement_id: SETTLEMENT,
				request_id: "request_id_1234567890",
			} } },
		} },
	};
	const raw = JSON.stringify(event);
	const signature = createHmac("sha256", SECRET).update(`${event.created}.${raw}`).digest("hex");
	const response = await handler(new Request("https://project.supabase.co/functions/v1/stripe-webhook", {
		method: "POST", headers: { "Stripe-Signature": `t=${event.created},v1=${signature}` }, body: raw,
	}));
	expect(response.status).toBe(200);
	expect(fetcher).toHaveBeenCalledOnce();
	expect(String(fetcher.mock.calls[0]?.[0])).toContain("invoice=in_test_1");
	expect(rpc).toHaveBeenCalledWith("record_stripe_payment_evidence", expect.objectContaining({
		p_invoice_id: "in_test_1", p_payment_id: "pi_test_1", p_amount_minor: 2000,
		p_tenant_id: TENANT, p_settlement_id: SETTLEMENT,
	}));
	const freeEvent = { ...event, id: "evt_invoice_paid_free", data: { object: { ...event.data.object, amount_paid: 0 } } };
	const freeRaw = JSON.stringify(freeEvent);
	const freeSignature = createHmac("sha256", SECRET).update(`${freeEvent.created}.${freeRaw}`).digest("hex");
	const freeResponse = await handler(new Request("https://project.supabase.co/functions/v1/stripe-webhook", {
		method: "POST", headers: { "Stripe-Signature": `t=${freeEvent.created},v1=${freeSignature}` }, body: freeRaw,
	}));
	expect(freeResponse.status).toBe(200);
	expect(fetcher).toHaveBeenCalledOnce();
	expect(rpc.mock.calls.filter(([name]) => name === "record_stripe_payment_evidence")).toHaveLength(1);
	vi.stubEnv("AIDR_BILLING_PROVIDER", "paddle");
	vi.resetModules();
	await import("../index.ts");
	if (!handler) throw new Error("stripe webhook did not register a handler");
	const wrongProvider = await handler(new Request("https://project.supabase.co/functions/v1/stripe-webhook", {
		method: "POST", headers: { "Stripe-Signature": `t=${event.created},v1=${signature}` }, body: raw,
	}));
	expect(wrongProvider.status).toBe(410);
	expect(fetcher).toHaveBeenCalledOnce();
});
