import { createHmac, webcrypto } from "node:crypto";
import { afterEach, describe, expect, it, vi } from "vitest";

const sdk = vi.hoisted(() => ({ createClient: vi.fn() }));
const identity = vi.hoisted(() => ({ checkIdentityBarrier: vi.fn() }));
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({ createClient: sdk.createClient }));
vi.mock("../_shared/identity-barrier.ts", () => ({ checkIdentityBarrier: identity.checkIdentityBarrier }));

const USER = "11111111-1111-4111-8111-111111111111";
const TENANT = "22222222-2222-4222-8222-222222222222";
const SETTLEMENT = "33333333-3333-4333-8333-333333333333";
const REQUEST_ID = "request_id_1234567890";
const WEBHOOK_SECRET = "test-paddle-webhook-secret";

async function loadHandler(name: "billing-checkout" | "paddle-webhook", enabled = false, provider = name === "billing-checkout" ? "stripe" : "paddle") {
	let handler: ((request: Request) => Promise<Response>) | undefined;
	vi.stubEnv("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING", enabled ? "true" : "");
	vi.stubEnv("AIDR_BILLING_PROVIDER", provider);
	vi.stubEnv("SUPABASE_URL", "https://project.supabase.co");
	vi.stubEnv("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");
	vi.stubEnv("STRIPE_SECRET_KEY", "test-stripe-secret-key");
	vi.stubEnv("AIDR_STRIPE_EXTRA_AGENT_PRICE_ID", "price_test");
	vi.stubEnv("AIDR_DASHBOARD_URL", "https://aidr.example.test");
	vi.stubEnv("AIDR_PADDLE_WEBHOOK_SECRET", WEBHOOK_SECRET);
	vi.stubEnv("AIDR_PADDLE_EXTRA_AGENT_PRICE_ID", "pri_test");
	vi.stubGlobal("crypto", webcrypto);
	vi.stubGlobal("Deno", {
		env: { get: (key: string) => process.env[key] },
		serve: (value: typeof handler) => { handler = value; },
	});
	vi.resetModules();
	if (name === "billing-checkout") await import("../billing-checkout/index.ts");
	else await import("../paddle-webhook/index.ts");
	if (!handler) throw new Error(`${name} did not register a handler`);
	return handler;
}

function checkout(body: unknown, token = "test-access-token") {
	return new Request("https://project.supabase.co/functions/v1/billing-checkout", {
		method: "POST",
		headers: { "Content-Type": "application/json", ...(token ? { Authorization: `Bearer ${token}` } : {}) },
		body: JSON.stringify(body),
	});
}

function authorizedCheckoutDb() {
	const intent = { settlement_id: SETTLEMENT, status: "claimed", checkout_session_id: null as string | null };
	const rpc = vi.fn(async (name: string, args: Record<string, unknown>) => {
		if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 4 }, error: null };
		if (name === "claim_billing_checkout_intent") return { data: { ...intent }, error: null };
		if (name === "bind_billing_checkout_session") {
			intent.status = "checkout_created";
			intent.checkout_session_id = args.p_checkout_session_id as string;
			return { data: true, error: null };
		}
		throw new Error(`unexpected RPC ${name}`);
	});
	const from = vi.fn((table: string) => {
		const query = {
			select: () => query,
			eq: () => query,
			maybeSingle: async () => ({ data: table === "tenant_members" ? { role: "owner", expires_at: null } : { status: "active" }, error: null }),
		};
		return query;
	});
	const db = { auth: { getUser: vi.fn(async () => ({ data: { user: { id: USER } }, error: null })) }, from, rpc, intent };
	sdk.createClient.mockReturnValue(db);
	identity.checkIdentityBarrier.mockResolvedValue({ ok: true });
	return db;
}

function paddle(raw: string, signature: string | null = null) {
	return new Request("https://project.supabase.co/functions/v1/paddle-webhook", {
		method: "POST",
		headers: signature ? { "Paddle-Signature": signature } : {},
		body: raw,
	});
}

function signed(raw: string) {
	const ts = Math.floor(Date.now() / 1000);
	const h1 = createHmac("sha256", WEBHOOK_SECRET).update(`${ts}:${raw}`).digest("hex");
	return `ts=${ts};h1=${h1}`;
}

afterEach(() => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	sdk.createClient.mockReset();
	identity.checkIdentityBarrier.mockReset();
});

describe("legacy billing Edge handlers", () => {
	it.each(["billing-checkout", "paddle-webhook"] as const)("defaults %s to 410 before any database or provider call", async (name) => {
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler(name);
		const response = await handler(name === "billing-checkout" ? checkout({ seats: 1 }) : paddle("{}"));
		expect(response.status).toBe(410);
		expect(await response.json()).toEqual({ error: "disabled_for_direct_ga" });
		expect(sdk.createClient).not.toHaveBeenCalled();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it.each([
		["billing-checkout", "paddle"],
		["paddle-webhook", "stripe"],
	] as const)("keeps %s closed when the configured provider is %s", async (name, provider) => {
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler(name, true, provider);
		const response = await handler(name === "billing-checkout" ? checkout({}) : paddle("{}"));
		expect(response.status).toBe(410);
		expect(sdk.createClient).not.toHaveBeenCalled();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("enabled checkout rejects missing authorization before reading customer state", async () => {
		const db = { auth: { getUser: vi.fn() } };
		sdk.createClient.mockReturnValue(db);
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const response = await (await loadHandler("billing-checkout", true))(checkout({ seats: 1 }, ""));
		expect(response.status).toBe(401);
		expect(db.auth.getUser).not.toHaveBeenCalled();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("enabled checkout rejects malformed request identity before billing intent or Stripe", async () => {
		const db = { auth: { getUser: vi.fn(async () => ({ data: { user: { id: USER } }, error: null })) }, rpc: vi.fn() };
		sdk.createClient.mockReturnValue(db);
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const response = await (await loadHandler("billing-checkout", true))(
			checkout({ tenant_id: TENANT, request_id: "short", seats: 1, plan: "monthly" }),
		);
		expect(response.status).toBe(400);
		expect(db.rpc).not.toHaveBeenCalled();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("enabled checkout refuses a tenant that the identity barrier denies", async () => {
		const db = { auth: { getUser: vi.fn(async () => ({ data: { user: { id: USER } }, error: null })) }, rpc: vi.fn() };
		sdk.createClient.mockReturnValue(db);
		identity.checkIdentityBarrier.mockResolvedValue({ ok: false, status: 403, error: "tenant_forbidden" });
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const response = await (await loadHandler("billing-checkout", true))(
			checkout({ tenant_id: TENANT, request_id: "request_id_1234567890", seats: 1, plan: "monthly" }),
		);
		expect(response.status).toBe(403);
		expect(identity.checkIdentityBarrier).toHaveBeenCalledWith(db, "test-access-token", USER, TENANT);
		expect(db.rpc).not.toHaveBeenCalled();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("rejects a malformed tenant UUID before the identity lookup", async () => {
		const db = authorizedCheckoutDb();
		const response = await (await loadHandler("billing-checkout", true))(
			checkout({ tenant_id: "------------------------------------", request_id: REQUEST_ID, seats: 1, plan: "monthly" }),
		);
		expect(response.status).toBe(400);
		expect(identity.checkIdentityBarrier).not.toHaveBeenCalled();
		expect(db.from).not.toHaveBeenCalled();
	});

	it("validates checkout inputs before claiming a durable intent", async () => {
		const db = authorizedCheckoutDb();
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler("billing-checkout", true);
		const response = await handler(checkout({ tenant_id: TENANT, request_id: REQUEST_ID, seats: "1", plan: "monthly" }));
		expect(response.status).toBe(400);
		expect(await response.json()).toEqual({ error: "invalid_seat_count" });
		expect(db.rpc).not.toHaveBeenCalled();
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("limits checkout before claiming a durable intent or calling Stripe", async () => {
		const db = authorizedCheckoutDb();
		db.rpc.mockImplementation(async (name: string) => {
			if (name === "consume_tenant_rate_limit") return { data: { allowed: false, remaining: 0 }, error: null };
			throw new Error(`unexpected RPC ${name}`);
		});
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler("billing-checkout", true);
		const response = await handler(checkout({ tenant_id: TENANT, request_id: REQUEST_ID, seats: 1, plan: "monthly" }));
		expect(response.status).toBe(429);
		expect(response.headers.get("Retry-After")).toBeTruthy();
		expect(await response.json()).toEqual({ error: "rate_limited" });
		expect(db.rpc.mock.calls.map(([name]) => name)).toEqual(["consume_tenant_rate_limit"]);
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("does not contact Stripe when the database rejects a competing billing channel", async () => {
		const db = authorizedCheckoutDb();
		db.rpc.mockImplementation(async (name: string) => {
			if (name === "consume_tenant_rate_limit") return { data: { allowed: true, remaining: 4 }, error: null };
			if (name === "claim_billing_checkout_intent") return { data: null, error: { code: "23505" } };
			throw new Error(`unexpected RPC ${name}`);
		});
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler("billing-checkout", true);
		const response = await handler(checkout({ tenant_id: TENANT, request_id: REQUEST_ID, seats: 1, plan: "monthly" }));
		expect(response.status).toBe(409);
		expect(await response.json()).toEqual({ error: "billing_request_conflict" });
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("reuses a bound open Stripe session on request replay without creating another", async () => {
		const db = authorizedCheckoutDb();
		const url = "https://checkout.stripe.com/c/pay/cs_existing";
		const fetcher = vi.fn(async (input: string, options: RequestInit) => {
			if (options.method === "POST") return Response.json({ id: "cs_existing", url });
			if (options.method === "GET" && input.endsWith("/cs_existing")) return Response.json({
				id: "cs_existing", url, mode: "subscription", status: "open", expires_at: Math.floor(Date.now() / 1000) + 3600,
				client_reference_id: USER,
				metadata: { user_id: USER, tenant_id: TENANT, settlement_id: SETTLEMENT, request_id: REQUEST_ID },
			});
			throw new Error("unexpected Stripe request");
		});
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler("billing-checkout", true);
		const request = () => checkout({ tenant_id: TENANT, request_id: REQUEST_ID, seats: 1, plan: "monthly" });
		const first = await handler(request());
		const replay = await handler(request());
		expect(first.status).toBe(200);
		expect(replay.status).toBe(200);
		expect(await replay.json()).toMatchObject({ checkout_id: "cs_existing", checkout_url: url });
		expect(fetcher.mock.calls.map(([, options]) => options.method)).toEqual(["POST", "GET"]);
		expect(db.rpc.mock.calls.map(([name]) => name)).toEqual([
			"consume_tenant_rate_limit", "claim_billing_checkout_intent", "bind_billing_checkout_session",
			"consume_tenant_rate_limit", "claim_billing_checkout_intent",
		]);
	});

	it("returns the same paid intent result for an exact checkout retry without contacting Stripe", async () => {
		const db = authorizedCheckoutDb();
		db.intent.status = "paid";
		db.intent.checkout_session_id = "cs_paid";
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler("billing-checkout", true);
		const request = () => checkout({ tenant_id: TENANT, request_id: REQUEST_ID, seats: 1, plan: "monthly" });

		const first = await handler(request());
		const replay = await handler(request());
		expect(first.status).toBe(409);
		expect(replay.status).toBe(409);
		expect(await first.json()).toEqual({ error: "checkout_already_paid" });
		expect(await replay.json()).toEqual({ error: "checkout_already_paid" });
		expect(fetcher).not.toHaveBeenCalled();
		expect(db.rpc.mock.calls.filter(([name]) => name === "claim_billing_checkout_intent")).toHaveLength(2);
	});

	it("does not return a bound Stripe session with foreign metadata", async () => {
		const db = authorizedCheckoutDb();
		const fetcher = vi.fn(async () => Response.json({
			id: "cs_existing", url: "https://checkout.stripe.com/c/pay/cs_existing", mode: "subscription",
			status: "open", expires_at: Math.floor(Date.now() / 1000) + 3600,
			client_reference_id: USER,
			metadata: { user_id: USER, tenant_id: "44444444-4444-4444-8444-444444444444", settlement_id: SETTLEMENT, request_id: REQUEST_ID },
		}));
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler("billing-checkout", true);
		db.intent.status = "checkout_created";
		db.intent.checkout_session_id = "cs_existing";
		const response = await handler(checkout({ tenant_id: TENANT, request_id: REQUEST_ID, seats: 1, plan: "monthly" }));
		expect(response.status).toBe(502);
		expect(fetcher).toHaveBeenCalledOnce();
		expect(db.rpc.mock.calls.map(([name]) => name)).toEqual(["consume_tenant_rate_limit", "claim_billing_checkout_intent"]);
	});

	it.each([
		["expired", "checkout_session_expired", true],
		["complete", "checkout_already_completed", false],
	] as const)("does not restart a %s bound Stripe session", async (status, error, newRequestRequired) => {
		const db = authorizedCheckoutDb();
		const fetcher = vi.fn(async () => Response.json({
			id: "cs_existing", url: "https://checkout.stripe.com/c/pay/cs_existing", mode: "subscription",
			status, expires_at: Math.floor(Date.now() / 1000) + 3600,
			client_reference_id: USER,
			metadata: { user_id: USER, tenant_id: TENANT, settlement_id: SETTLEMENT, request_id: REQUEST_ID },
		}));
		vi.stubGlobal("fetch", fetcher);
		const handler = await loadHandler("billing-checkout", true);
		db.intent.status = "checkout_created";
		db.intent.checkout_session_id = "cs_existing";
		const response = await handler(checkout({ tenant_id: TENANT, request_id: REQUEST_ID, seats: 1, plan: "monthly" }));
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ error, ...(newRequestRequired ? { new_request_required: true } : {}) });
		expect(fetcher.mock.calls.map(([, options]) => options.method)).toEqual(["GET"]);
	});

	it("enabled Paddle rejects absent and invalid signatures before database work", async () => {
		const handler = await loadHandler("paddle-webhook", true);
		for (const request of [paddle("{}"), paddle("{}", `ts=${Math.floor(Date.now() / 1000)};h1=${"0".repeat(64)}`)]) {
			const response = await handler(request);
			expect(response.status).toBe(401);
		}
		expect(sdk.createClient).not.toHaveBeenCalled();
	});

	it("enabled Paddle rejects a correctly signed malformed body before database work", async () => {
		const handler = await loadHandler("paddle-webhook", true);
		for (const [raw, error] of [["{not-json", "invalid_json"], ["null", "invalid_json"], ['{"event_id":123}', "invalid_event_id"]]) {
			const response = await handler(paddle(raw, signed(raw)));
			expect(response.status).toBe(400);
			expect(await response.json()).toEqual({ error });
		}
		expect(sdk.createClient).not.toHaveBeenCalled();
	});

	it("enabled Paddle records an unlinked event without changing subscription seats", async () => {
		const rpc = vi.fn(async () => ({ data: true, error: null }));
		const insert = vi.fn(async () => ({ error: null }));
		sdk.createClient.mockReturnValue({ rpc, from: () => ({ insert }) });
		const raw = JSON.stringify({
			event_id: "evt_unlinked", event_type: "subscription.updated", occurred_at: new Date().toISOString(),
			data: { id: "sub_unlinked", status: "active", custom_data: { user_id: USER, tenant_id: "not-a-uuid" } },
		});
		const response = await (await loadHandler("paddle-webhook", true))(paddle(raw, signed(raw)));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual({ ok: true, unlinked: true });
		expect(rpc.mock.calls.map(([name]) => name)).toEqual(["record_billing_webhook_event", "finish_billing_webhook_event"]);
		expect(insert).toHaveBeenCalledOnce();
	});

	it("enabled Paddle treats a rejected tenant transition as retryable, without granting seats", async () => {
		const rpc = vi.fn(async (name: string) => name === "apply_billing_subscription_event"
			? { data: null, error: { code: "42501" } }
			: { data: true, error: null });
		const query = { update: () => query, eq: () => query };
		sdk.createClient.mockReturnValue({ rpc, from: () => query });
		const raw = JSON.stringify({
			event_id: "evt_rejected", event_type: "subscription.updated", occurred_at: new Date().toISOString(),
			data: { id: "sub_rejected", status: "active", items: [{ price_id: "pri_test", quantity: 1 }],
				custom_data: { user_id: USER, tenant_id: TENANT } },
		});
		const response = await (await loadHandler("paddle-webhook", true))(paddle(raw, signed(raw)));
		expect(response.status).toBe(503);
		expect(await response.json()).toEqual({ error: "subscription_transition_unavailable" });
		expect(rpc).toHaveBeenCalledWith("apply_billing_subscription_event", expect.objectContaining({
			p_user_id: USER, p_tenant_id: TENANT, p_extra_agents: 1,
		}));
		expect(rpc).toHaveBeenCalledWith("finish_billing_webhook_event", expect.objectContaining({ p_status: "failed" }));
	});
});
