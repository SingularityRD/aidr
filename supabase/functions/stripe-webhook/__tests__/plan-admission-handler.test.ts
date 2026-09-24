// Executes the real Stripe webhook handler (Deno.serve stubbed) for catalog
// plan subscriptions. The database is a recording fake: these tests pin what
// the handler sends to public.apply_stripe_plan_subscription and when it
// refuses to call it. The SQL semantics of that RPC are covered by the
// migration contract test in supabase/functions/__tests__.
import { createHmac, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));

const USER = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const SECRET = "whsec_test_plan_admission";
const PRICE_MAP = JSON.stringify({ price_teamMonthly: "team:monthly", price_businessYearly: "business:yearly" });
const PERIOD_END = Math.floor(Date.now() / 1000) + 30 * 86400;

type Handler = (request: Request) => Promise<Response>;

interface FakeOptions {
	tenantStatus?: string;
	planResult?: { data: unknown; error: unknown };
	dedupClaimed?: boolean;
}

function fakeDb(options: FakeOptions = {}) {
	const audits: Array<Record<string, unknown>> = [];
	const rpc = vi.fn(async (name: string, _args?: Record<string, unknown>) => {
		if (name === "record_billing_webhook_event") return { data: options.dedupClaimed ?? true, error: null };
		if (name === "finish_billing_webhook_event") return { data: true, error: null };
		if (name === "apply_stripe_plan_subscription") {
			return options.planResult ?? {
				data: { applied: true, state: "granted", reason: "subscription_active", admission_changed: true },
				error: null,
			};
		}
		if (name === "apply_billing_subscription_event") return { data: { applied: true, extra_agents: 0 }, error: null };
		if (name === "close_billing_checkout_intent") return { data: true, error: null };
		throw new Error(`unexpected RPC ${name}`);
	});
	const single = (table: string) => {
		if (table === "tenants") return { data: { status: options.tenantStatus ?? "active" }, error: null };
		if (table === "tenant_members") return { data: { tenant_id: TENANT, role: "owner", expires_at: null }, error: null };
		return { data: null, error: null };
	};
	const from = vi.fn((table: string) => {
		const chain: Record<string, unknown> = {};
		chain.select = () => chain;
		chain.eq = () => chain;
		chain.limit = async () => ({ data: [], error: null });
		chain.maybeSingle = async () => single(table);
		chain.upsert = async () => ({ error: null });
		chain.insert = async (row: Record<string, unknown>) => {
			if (table === "admin_audit_logs") audits.push(row);
			return { error: null };
		};
		return chain;
	});
	const db = {
		rpc,
		from,
		auth: { admin: { getUserById: async (id: string) => ({ data: { user: { id } }, error: null }) } },
	};
	return { db, rpc, audits };
}

async function loadHandler(env: Record<string, string>): Promise<Handler> {
	let handler: Handler | undefined;
	for (const [key, value] of Object.entries({
		AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING: "true",
		AIDR_BILLING_PROVIDER: "stripe",
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "test-service-role-key",
		STRIPE_SECRET_KEY: ["sk", "test", "placeholder"].join("_"),
		STRIPE_WEBHOOK_SECRET: SECRET,
		...env,
	})) vi.stubEnv(key, value);
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (key: string) => process.env[key] },
		serve: (value: Handler) => { handler = value; },
	});
	vi.resetModules();
	await import("../index.ts");
	if (!handler) throw new Error("stripe webhook did not register a handler");
	return handler;
}

function signed(handler: Handler, event: Record<string, unknown>): Promise<Response> {
	const raw = JSON.stringify(event);
	const created = event.created as number;
	const signature = createHmac("sha256", SECRET).update(`${created}.${raw}`).digest("hex");
	return handler(new Request("https://project.supabase.co/functions/v1/stripe-webhook", {
		method: "POST",
		headers: { "Stripe-Signature": `t=${created},v1=${signature}` },
		body: raw,
	}));
}

function planEvent(
	type: string,
	object: Record<string, unknown> = {},
	id = "evt_plan_grant",
): Record<string, unknown> {
	return {
		id,
		created: Math.floor(Date.now() / 1000),
		type,
		data: {
			object: {
				id: "sub_plan_1",
				customer: "cus_plan_1",
				status: "active",
				collection_method: "charge_automatically",
				metadata: { user_id: USER, tenant_id: TENANT },
				items: {
					has_more: false,
					data: [{ price: { id: "price_teamMonthly" }, quantity: 5, current_period_end: PERIOD_END }],
				},
				...object,
			},
		},
	};
}

function planCalls(rpc: ReturnType<typeof fakeDb>["rpc"]) {
	return rpc.mock.calls.filter(([name]) => name === "apply_stripe_plan_subscription").map(([, args]) => args);
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
});

describe("stripe webhook catalog plan admission", () => {
	it("grants through the audited RPC with the signed subscription's plan, seats and period", async () => {
		const { db, rpc, audits } = fakeDb();
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: PRICE_MAP });
		const response = await signed(handler, planEvent("customer.subscription.created"));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true });
		expect(planCalls(rpc)).toEqual([expect.objectContaining({
			p_event_id: "evt_plan_grant",
			p_user_id: USER,
			p_tenant_id: TENANT,
			p_subscription_id: "sub_plan_1",
			p_plan_id: "team",
			p_billing_interval: "monthly",
			p_seats: 5,
			p_status: "active",
			p_current_period_end: new Date(PERIOD_END * 1000).toISOString(),
			p_action: "grant",
		})]);
		// No extra-agent price is configured, so the extra-agent path is untouched.
		expect(rpc.mock.calls.some(([name]) => name === "apply_billing_subscription_event")).toBe(false);
		const planAudit = audits.find((row) => row.action === "stripe.webhook.plan");
		expect(planAudit?.detail).toMatchObject({
			plan_action: "grant",
			plan_id: "team",
			plan_admission: { applied: true, state: "granted", admissionChanged: true },
		});
		expect(rpc.mock.calls.at(-1)).toEqual(["finish_billing_webhook_event", expect.objectContaining({ p_status: "completed" })]);
	});

	it("runs the plan RPC alongside the extra-agent reconciliation when both are configured", async () => {
		const { db, rpc } = fakeDb();
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: PRICE_MAP, AIDR_STRIPE_EXTRA_AGENT_PRICE_ID: "price_extra" });
		const response = await signed(handler, planEvent("customer.subscription.updated"));
		expect(response.status).toBe(200);
		const names = rpc.mock.calls.map(([name]) => name);
		expect(names.indexOf("record_billing_webhook_event")).toBeLessThan(names.indexOf("apply_stripe_plan_subscription"));
		expect(names).toContain("apply_billing_subscription_event");
		expect(planCalls(rpc)).toHaveLength(1);
	});

	it("holds a send_invoice subscription instead of granting it", async () => {
		const { db, rpc } = fakeDb({ planResult: { data: { applied: true, state: "held", reason: "status_active" }, error: null } });
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: PRICE_MAP });
		await signed(handler, planEvent("customer.subscription.updated", { collection_method: "send_invoice" }));
		expect(planCalls(rpc)).toEqual([expect.objectContaining({ p_action: "hold" })]);
	});

	it("revokes on deletion even after the buyer lost billing access", async () => {
		const { db, rpc, audits } = fakeDb({
			tenantStatus: "suspended",
			planResult: { data: { applied: true, state: "closed", reason: "subscription_ended", admission_changed: true }, error: null },
		});
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: PRICE_MAP });
		const response = await signed(handler, planEvent("customer.subscription.deleted", { status: "canceled" }, "evt_plan_delete"));
		expect(await response.json()).toEqual({ ok: true, unlinked: true });
		expect(planCalls(rpc)).toEqual([expect.objectContaining({ p_action: "revoke", p_seats: 0, p_tenant_id: TENANT })]);
		expect(audits.find((row) => row.action === "stripe.webhook.tenant_rejected")?.detail).toMatchObject({
			plan_admission: { state: "closed", admissionChanged: true },
		});
	});

	it("never grants to a tenant the buyer cannot administer", async () => {
		const { db, rpc } = fakeDb({ tenantStatus: "suspended" });
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: PRICE_MAP });
		const response = await signed(handler, planEvent("customer.subscription.created"));
		expect(await response.json()).toEqual({ ok: true, unlinked: true });
		expect(planCalls(rpc)).toEqual([]);
	});

	it("never grants without checkout metadata binding a tenant", async () => {
		const { db, rpc } = fakeDb();
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: PRICE_MAP });
		const response = await signed(handler, planEvent("customer.subscription.created", { metadata: {} }));
		expect(await response.json()).toEqual({ ok: true, unlinked: true });
		expect(planCalls(rpc)).toEqual([]);
	});

	it("does not re-apply a replayed event id", async () => {
		const { db, rpc } = fakeDb({ dedupClaimed: false });
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: PRICE_MAP });
		const response = await signed(handler, planEvent("customer.subscription.created"));
		expect(await response.json()).toEqual({ ok: true, dedup: true });
		expect(planCalls(rpc)).toEqual([]);
	});

	it("disables grants but keeps revocation when the price map is malformed", async () => {
		const { db, rpc, audits } = fakeDb();
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: "{not json" });
		const grant = await signed(handler, planEvent("customer.subscription.created"));
		expect(await grant.json()).toEqual({ ok: true, ignored: true });
		expect(planCalls(rpc)).toEqual([]);
		expect(audits.find((row) => row.action === "stripe.webhook.ignored")?.detail).toMatchObject({ price_map_valid: false });
		await signed(handler, planEvent("customer.subscription.deleted", { status: "canceled" }, "evt_plan_delete"));
		expect(planCalls(rpc)).toEqual([expect.objectContaining({ p_action: "revoke", p_plan_id: null, p_billing_interval: null })]);
	});

	it("leaves the plan path off when no price map is configured", async () => {
		const { db, rpc } = fakeDb();
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({});
		const response = await signed(handler, planEvent("customer.subscription.created"));
		expect(await response.json()).toEqual({ ok: true, ignored: true });
		expect(planCalls(rpc)).toEqual([]);
	});

	it.each([
		[{ data: null, error: { message: "db down" } }],
		[{ data: true, error: null }],
	])("fails the delivery and releases the claim when the plan RPC is unusable (%j)", async (planResult) => {
		const { db, rpc } = fakeDb({ planResult });
		sdk.createClient.mockReturnValue(db);
		const handler = await loadHandler({ AIDR_STRIPE_PRICE_MAP: PRICE_MAP });
		const response = await signed(handler, planEvent("customer.subscription.created"));
		expect(response.status).toBe(500);
		expect(await response.json()).toEqual({ error: "webhook_processing_failed" });
		expect(rpc.mock.calls.at(-1)).toEqual(["finish_billing_webhook_event", expect.objectContaining({ p_status: "failed" })]);
	});
});
