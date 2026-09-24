import { createHmac, webcrypto } from "node:crypto";
import { afterEach, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const OTHER_TENANT = "44444444-4444-4444-8444-444444444444";
const SECRET = "whsec_test_deletion";

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

it("revokes only the exact bound subscription and never grants from ambiguous customer metadata", async () => {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	for (const [key, value] of Object.entries({
		AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING: "true",
		AIDR_BILLING_PROVIDER: "stripe",
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
		STRIPE_SECRET_KEY: ["sk", "test", "placeholder"].join("_"),
		STRIPE_WEBHOOK_SECRET: SECRET,
		AIDR_STRIPE_EXTRA_AGENT_PRICE_ID: "price_extra",
	})) vi.stubEnv(key, value);
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (key: string) => process.env[key] },
		serve: (value: typeof handler) => { handler = value; },
	});
	const bound = { provider: "stripe", provider_subscription_id: "sub_shared_1", user_id: USER, tenant_id: TENANT };
	const customerRows = [{ user_id: USER, tenant_id: TENANT }, { user_id: USER, tenant_id: OTHER_TENANT }];
	const customerQuery = { user: "", tenant: "", customer: "", select: () => customerQuery, eq(key: string, value: string) {
		if (key === "user_id") this.user = value;
		if (key === "tenant_id") this.tenant = value;
		if (key === "provider_customer_id") this.customer = value;
		return this;
	}, limit: async () => ({
		data: customerQuery.customer === "cus_shared_1" ? customerRows.filter((row) =>
			(!customerQuery.user || row.user_id === customerQuery.user) &&
			(!customerQuery.tenant || row.tenant_id === customerQuery.tenant)) : [],
		error: null,
	}) };
	const rpc = vi.fn(async (name: string) => name === "apply_billing_subscription_event"
		? { data: { applied: true, extra_agents: 0 }, error: null }
		: { data: true, error: null });
	const db = {
		rpc,
		auth: { admin: { getUserById: async () => ({ data: { user: { id: USER } }, error: null }) } },
		from: (table: string) => table === "billing_customers"
			? { select: () => { customerQuery.user = ""; customerQuery.tenant = ""; customerQuery.customer = ""; return customerQuery; }, upsert: async () => ({ error: null }) }
			: table === "subscriptions"
				? { select: () => ({ eq: () => ({ eq: () => ({ maybeSingle: async () => ({ data: bound, error: null }) }), maybeSingle: async () => ({ data: bound, error: null }) }) }) }
				: table === "tenants"
					? { select: () => ({ eq: () => ({ maybeSingle: async () => ({ data: { status: "inactive" }, error: null }) }) }) }
					: { insert: async () => ({ error: null }) },
	};
	sdk.createClient.mockReturnValue(db);
	vi.resetModules();
	await import("../index.ts");
	if (!handler) throw new Error("stripe webhook did not register a handler");
	const serve = handler;
	const send = (event: { created: number; [key: string]: unknown }) => {
		const raw = JSON.stringify(event);
		const signature = createHmac("sha256", SECRET).update(`${event.created}.${raw}`).digest("hex");
		return serve(new Request("https://project.supabase.co/functions/v1/stripe-webhook", {
			method: "POST", headers: { "Stripe-Signature": `t=${event.created},v1=${signature}` }, body: raw,
		}));
	};
	const event = {
		id: "evt_shared_deletion", created: Math.floor(Date.now() / 1000), type: "customer.subscription.deleted",
		data: { object: { id: "sub_shared_1", customer: "cus_shared_1", status: "active" } },
	};
	const response = await send(event);
	expect(response.status).toBe(200);
	expect(await response.json()).toEqual({ ok: true });
	expect(rpc).toHaveBeenCalledWith("apply_billing_subscription_event", expect.objectContaining({
		p_subscription_id: "sub_shared_1", p_user_id: USER, p_tenant_id: TENANT, p_extra_agents: 0,
	}));
	const wrongCustomer = await send({
		...event, id: "evt_wrong_customer_deletion",
		data: { object: { ...event.data.object, customer: "cus_unrelated" } },
	});
	expect(await wrongCustomer.json()).toEqual({ ok: true, unlinked: true });
	const positiveGrant = await send({
		...event, id: "evt_ambiguous_positive", type: "customer.subscription.updated",
		data: { object: { ...event.data.object, status: "active",
			collection_method: "charge_automatically", items: {
			data: [{ price: "price_extra", quantity: 5, current_period_end: 1_800_000_000 }], has_more: false,
		} } },
	});
	expect(await positiveGrant.json()).toEqual({ ok: true, unlinked: true });
	expect(rpc.mock.calls.filter(([name]) => name === "apply_billing_subscription_event")).toHaveLength(1);
	const userOnlyDeletion = await send({
		...event, id: "evt_user_only_deletion",
		data: { object: { ...event.data.object, metadata: { user_id: USER } } },
	});
	expect(await userOnlyDeletion.json()).toEqual({ ok: true });
	expect(rpc.mock.calls.filter(([name]) => name === "apply_billing_subscription_event")).toHaveLength(2);
});
