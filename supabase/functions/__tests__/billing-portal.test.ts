// Contract suite for the self-service billing portal (BIL-03 / T33).
//
// This file is named in the billing-portal contract manifest
// (`docs/production-readiness/edge-function-contract-manifest.json`) so a
// browser-invoked Edge Function can never ship without an executable contract.

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The Edge Function imports Supabase through Deno's `npm:` specifier, which a
// Node test runner cannot resolve. The default export is still type-checked
// against the real package; the runtime factory only needs to exist.
vi.mock("npm:@supabase/supabase-js@2", () => ({
	createClient: () => {
		throw new Error("createClient must be injected through BillingPortalDeps.db");
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
const MIGRATION = join(ROOT, "supabase", "migrations", "20260913000004_billing_settlement_portal.sql");
const migration = readFileSync(MIGRATION, "utf8");
const portalSource = readFileSync(
	join(ROOT, "supabase", "functions", "billing-portal", "index.ts"),
	"utf8",
);
// Bounded lifetime for the billing idempotency/webhook stores ships as an
// append-only follow-up migration, plus the maintenance job that runs it.
const pruningMigration = readFileSync(
	join(ROOT, "supabase", "migrations", "20260914000001_billing_retention_pruning.sql"),
	"utf8",
);
const maintenanceSource = readFileSync(
	join(ROOT, "scripts", "deployment-maintenance.mjs"),
	"utf8",
);

const settlement = await import("../billing-portal/settlement.ts");
const providerModule = await import("../billing-portal/provider.ts");

const TENANT = "22222222-2222-4222-8222-222222222222";
const OTHER_TENANT = "33333333-3333-4333-8333-333333333333";
const USER = "11111111-1111-4111-8111-111111111111";
const SETTLEMENT = "44444444-4444-4444-8444-444444444444";

type BoundReceipt = Omit<settlement.SettlementReceipt, "receiptHash" | "recordedAt">;

function boundReceipt(overrides: Partial<BoundReceipt> = {}): BoundReceipt {
	return {
		settlementId: SETTLEMENT,
		tenantId: TENANT,
		provider: "provider_fixture",
		providerCustomerId: "cus_fixture_tenant",
		providerSubscriptionId: "sub_fixture_1",
		requestId: "request_1234567890abcdef",
		status: "settled",
		currency: "USD",
		lines: [{ sku: "aidr.agent.seat", quantity: 5, unitAmountMinor: 1000 }],
		totalAmountMinor: 5000,
		quoteReference: "QUOTE-2026-0001",
		settledAmountMinor: 5000,
		refundedAmountMinor: 0,
		occurredAt: "2026-09-13T00:00:00.000Z",
		sequence: 3,
		externalValidation: false,
		...overrides,
	};
}

async function sealed(overrides: Partial<BoundReceipt> = {}): Promise<settlement.SettlementReceipt> {
	const bound = boundReceipt(overrides);
	const receiptHash = await settlement.settlementReceiptHash(bound);
	return { ...bound, receiptHash, recordedAt: "2026-09-13T00:00:01.000Z" };
}

/**
 * A ledger is only valid if it starts at `quote_issued`. Most tests need a
 * *valid* history, so this composes the quote -> order -> settled chain for one
 * settlement id and then lets a test append terminal rows.
 */
async function settledLedger(
	settlementId: string,
	overrides: Partial<BoundReceipt> = {},
): Promise<settlement.SettlementReceipt[]> {
	const base = { settlementId, ...overrides };
	return [
		await sealed({
			...base,
			status: "quote_issued",
			quoteReference: null,
			settledAmountMinor: 0,
			refundedAmountMinor: 0,
			sequence: 0,
			occurredAt: "2026-09-12T00:00:00.000Z",
		}),
		await sealed({
			...base,
			status: "order_placed",
			quoteReference: null,
			settledAmountMinor: 0,
			refundedAmountMinor: 0,
			sequence: 1,
			occurredAt: "2026-09-12T01:00:00.000Z",
		}),
		await sealed({
			...base,
			status: "settlement_pending",
			quoteReference: "QUOTE-2026-0001",
			settledAmountMinor: 0,
			refundedAmountMinor: 0,
			sequence: 2,
			occurredAt: "2026-09-12T02:00:00.000Z",
		}),
		await sealed({ ...base, sequence: 3, occurredAt: "2026-09-13T00:00:00.000Z" }),
	];
}

describe("settlement receipt integrity", () => {
	it("binds every immutable field into one digest and accepts the unmodified receipt", async () => {
		const receipt = await sealed();
		expect(receipt.receiptHash).toMatch(/^[0-9a-f]{64}$/);
		expect(await settlement.verifySettlementReceipt(receipt)).toEqual({
			status: "intact",
			reason: "receipt_hash_matches",
		});
	});

	it("reports tampered, not clean, for every field a customer must not be able to rewrite", async () => {
		const receipt = await sealed();
		const mutations: Array<Partial<settlement.SettlementReceipt>> = [
			{ tenantId: OTHER_TENANT },
			{ providerCustomerId: "cus_attacker" },
			{ providerSubscriptionId: "sub_attacker" },
			{ status: "refunded" },
			{ currency: "EUR" },
			{ totalAmountMinor: 1 },
			{ settledAmountMinor: 1 },
			{ refundedAmountMinor: 1 },
			{ quoteReference: "QUOTE-FORGED" },
			{ occurredAt: "2026-09-14T00:00:00.000Z" },
			{ sequence: 99 },
			{ lines: [{ sku: "aidr.agent.seat", quantity: 500, unitAmountMinor: 1000 }] },
		];
		for (const mutation of mutations) {
			const mutated = { ...receipt, ...mutation } as settlement.SettlementReceipt;
			const result = await settlement.verifySettlementReceipt(mutated);
			expect(result.status, JSON.stringify(mutation)).not.toBe("intact");
		}
	});

	it("reports unavailable, never clean, when the stored record is unreadable", async () => {
		for (const broken of [null, {}, { receiptHash: "z".repeat(64) }, { tenantId: TENANT }]) {
			const result = await settlement.verifySettlementReceipt(broken);
			expect(result.status).toBe("unavailable");
		}
	});

	it("refuses an externally validated receipt produced by this module's parser", async () => {
		const receipt = await sealed();
		const result = settlement.parseSettlementReceipt({ ...receipt, externalValidation: true });
		expect(result).toEqual({ ok: false, error: "external_validation_not_permitted" });
	});

	it("refuses a settled receipt whose amount does not match its lines", () => {
		const result = settlement.parseSettlementReceipt({
			...boundReceipt({ settledAmountMinor: 4999 }),
			receiptHash: "a".repeat(64),
			recordedAt: "2026-09-13T00:00:01.000Z",
		});
		expect(result.ok).toBe(false);
	});

	it("is order-insensitive over lines but sensitive to line content", async () => {
		const a = await settlement.settlementReceiptHash(
			boundReceipt({
				lines: [
					{ sku: "aidr.agent.seat", quantity: 2, unitAmountMinor: 1000 },
					{ sku: "aidr.premium.intel", quantity: 1, unitAmountMinor: 3000 },
				],
				totalAmountMinor: 5000,
			}),
		);
		const b = await settlement.settlementReceiptHash(
			boundReceipt({
				lines: [
					{ sku: "aidr.premium.intel", quantity: 1, unitAmountMinor: 3000 },
					{ sku: "aidr.agent.seat", quantity: 2, unitAmountMinor: 1000 },
				],
				totalAmountMinor: 5000,
			}),
		);
		expect(a).toBe(b);
		const c = await settlement.settlementReceiptHash(
			boundReceipt({
				lines: [
					{ sku: "aidr.premium.intel", quantity: 2, unitAmountMinor: 500 },
					{ sku: "aidr.agent.seat", quantity: 2, unitAmountMinor: 1000 },
				],
				totalAmountMinor: 3000,
			}),
		);
		expect(c).not.toBe(a);
	});
});

describe("provider-of-record state machine", () => {
	it("allows only the declared transitions and never leaves a terminal state", () => {
		expect(settlement.evaluateTransition("quote_issued", "order_placed")).toEqual({
			ok: true,
			next: "order_placed",
		});
		for (const [from, to] of [
			["quote_issued", "settled"],
			["order_placed", "settled"],
			["settlement_pending", "refunded"],
			["settled", "settlement_pending"],
			["cancelled", "settled"],
			["refunded", "settled"],
			["refunded", "cancelled"],
		] as const) {
			expect(settlement.evaluateTransition(from, to).ok, `${from}->${to}`).toBe(false);
		}
		expect(settlement.evaluateTransition("refunded", "refunded")).toEqual({
			ok: false,
			code: "settlement_terminal",
		});
		expect(settlement.evaluateTransition("settled", "settled")).toEqual({
			ok: false,
			code: "transition_not_allowed_settled_to_settled",
		});
		expect(settlement.evaluateTransition("settled", "PAID")).toEqual({
			ok: false,
			code: "invalid_target_status",
		});
	});

	it("rejects a refund above the outstanding captured amount and below the settled state", () => {
		expect(
			settlement.evaluateRefund({ status: "settled", settledAmountMinor: 5000, refundedAmountMinor: 0 }, 6000),
		).toEqual({ action: "deny", code: "refund_exceeds_outstanding", refundAmountMinor: 0 });
		expect(
			settlement.evaluateRefund({ status: "settled", settledAmountMinor: 5000, refundedAmountMinor: 5000 }, 1),
		).toEqual({ action: "deny", code: "nothing_left_to_refund", refundAmountMinor: 0 });
		expect(
			settlement.evaluateRefund({ status: "settlement_pending", settledAmountMinor: 0, refundedAmountMinor: 0 }, 1),
		).toEqual({ action: "deny", code: "settlement_not_refundable", refundAmountMinor: 0 });
		expect(
			settlement.evaluateRefund({ status: "settled", settledAmountMinor: 5000, refundedAmountMinor: 1000 }, 4000),
		).toEqual({ action: "allow", code: "refund_permitted", refundAmountMinor: 4000 });
	});

	it("bounds seat changes and refuses a non-positive or unbounded request", () => {
		expect(settlement.evaluateSeatChange(3, 7)).toEqual({
			action: "allow",
			code: "seat_change_permitted",
			deltaSeats: 4,
		});
		for (const [current, requested] of [
			[3, 0],
			[3, -1],
			[3, 1.5],
			[3, 10001],
			[-1, 3],
			[Number.NaN, 3],
		] as const) {
			expect(settlement.evaluateSeatChange(current, requested).action, `${current}/${requested}`).toBe("deny");
		}
	});
});

describe("seat projection and reconciliation", () => {
	it("grants seats only from settled receipts and revokes them on refund", async () => {
		const ledger = await settledLedger(SETTLEMENT);
		const granted = settlement.projectEntitlement({ tenantId: TENANT, receipts: ledger });
		expect(granted.status).toBe("granted");
		expect(granted.seats).toEqual([{ sku: "aidr.agent.seat", seats: 5 }]);

		const refunded = await sealed({
			status: "refunded",
			sequence: 4,
			refundedAmountMinor: 5000,
			occurredAt: "2026-09-13T01:00:00.000Z",
		});
		const revoked = settlement.projectEntitlement({ tenantId: TENANT, receipts: [...ledger, refunded] });
		expect(revoked.status).toBe("revoked");
		expect(revoked.seats).toEqual([]);
	});

	it("is order-independent and duplicate-tolerant for the same settlement", async () => {
		const ledger = await settledLedger(SETTLEMENT);
		const a = settlement.projectEntitlement({ tenantId: TENANT, receipts: ledger });
		const shuffled = [ledger[2], ledger[0], ledger[3], ledger[1], ledger[3]] as settlement.SettlementReceipt[];
		const b = settlement.projectEntitlement({ tenantId: TENANT, receipts: shuffled });
		expect(b.status).toBe("granted");
		expect(a).toEqual(b);
		expect(a.seats).toEqual([{ sku: "aidr.agent.seat", seats: 5 }]);
		expect(a.sources).toEqual([SETTLEMENT]);
	});

	it("fails closed for cross-tenant rows, conflicting duplicates and illegal replay", async () => {
		const ledger = await settledLedger(SETTLEMENT);
		const settled = ledger[ledger.length - 1] as settlement.SettlementReceipt;
		expect(
			settlement.projectEntitlement({ tenantId: TENANT, receipts: [{ ...settled, tenantId: OTHER_TENANT }] }),
		).toMatchObject({ status: "unavailable", reason: "cross_tenant_receipt" });
		expect(
			settlement.projectEntitlement({
				tenantId: TENANT,
				receipts: [...ledger, { ...settled, receiptHash: "b".repeat(64) }],
			}),
		).toMatchObject({ status: "unavailable", reason: "duplicate_settlement_conflict" });
		expect(settlement.projectEntitlement({ tenantId: TENANT, receipts: [] })).toMatchObject({
			status: "unavailable",
			reason: "no_settlement_records",
		});
		// A ledger that jumps straight to `settled` has no quote and no order.
		const jump = await sealed({ settlementId: "77777777-7777-4777-8777-777777777777" });
		expect(settlement.projectEntitlement({ tenantId: TENANT, receipts: [jump] })).toMatchObject({
			status: "unavailable",
			reason: "ledger_does_not_start_at_quote",
		});
		// A settled receipt without an approved quote is never a grant.
		const noQuoteId = "99999999-9999-4999-8999-999999999999";
		const quoted = await sealed({
			settlementId: noQuoteId,
			status: "quote_issued",
			quoteReference: null,
			settledAmountMinor: 0,
			sequence: 0,
		});
		const noQuote = await sealed({ settlementId: noQuoteId, quoteReference: null, sequence: 3 });
		expect(
			settlement.projectEntitlement({ tenantId: TENANT, receipts: [quoted, noQuote] }),
		).toMatchObject({ status: "unavailable", reason: "settled_without_quote" });
	});

	it("projects a mixed-currency ledger as unavailable rather than summing it", async () => {
		const usd = await sealed({
			settlementId: "88888888-8888-4888-8888-888888888888",
			status: "quote_issued",
			quoteReference: null,
			settledAmountMinor: 0,
			sequence: 0,
			currency: "USD",
		});
		const eur = await sealed({
			settlementId: "66666666-6666-4666-8666-666666666666",
			currency: "EUR",
		});
		expect(settlement.projectEntitlement({ tenantId: TENANT, receipts: [usd, eur] })).toMatchObject({
			status: "unavailable",
			reason: "currency_mismatch",
		});
	});

	it("computes an idempotent grant/revoke action from the provider quantity", () => {
		const granted = settlement.projectEntitlement({
			tenantId: TENANT,
			receipts: [],
		});
		expect(settlement.reconcileSeat(granted, "aidr.agent.seat", 5)).toEqual({
			action: "unavailable",
			sku: "aidr.agent.seat",
			delta: 0,
			reason: "no_settlement_records",
		});
		const projection = {
			status: "granted" as const,
			seats: [{ sku: "aidr.agent.seat", seats: 5 }],
			sources: [SETTLEMENT],
			reason: "settled_settlements_present",
		};
		expect(settlement.reconcileSeat(projection, "aidr.agent.seat", 5)).toEqual({
			action: "noop",
			sku: "aidr.agent.seat",
			delta: 0,
			reason: "already_reconciled",
		});
		expect(settlement.reconcileSeat(projection, "aidr.agent.seat", 8)).toMatchObject({
			action: "grant",
			delta: 3,
		});
		expect(settlement.reconcileSeat(projection, "aidr.agent.seat", 2)).toMatchObject({
			action: "revoke",
			delta: -3,
		});
		expect(settlement.reconcileSeat(projection, "aidr.agent.seat", null)).toMatchObject({
			action: "unavailable",
			reason: "provider_quantity_unavailable",
		});
	});
});

describe("return URL policy", () => {
	const origin = "https://app.aidr.example";

	it("accepts only an HTTPS URL on the configured origin or a loopback HTTP URL", () => {
		expect(settlement.resolveReturnUrl("https://app.aidr.example/settings", origin).ok).toBe(true);
		expect(settlement.resolveReturnUrl("http://127.0.0.1:5173/settings", origin).ok).toBe(true);
		expect(settlement.resolveReturnUrl("http://localhost:5173/settings", origin).ok).toBe(true);
		for (const candidate of [
			"http://app.aidr.example/settings",
			"https://evil.example/settings",
			"https://app.aidr.example.evil.example/settings",
			"javascript:alert(1)",
			"//evil.example/settings",
			"https://user:pass@app.aidr.example/settings",
			"",
			"a".repeat(3000),
			"https://app.aidr.example/settings\u0000",
		]) {
			expect(settlement.resolveReturnUrl(candidate, origin).ok, candidate.slice(0, 40)).toBe(false);
		}
		expect(settlement.resolveReturnUrl("https://app.aidr.example/settings", "http://app.aidr.example").ok).toBe(
			false,
		);
	});
});

describe("billing provider selection", () => {
	it("returns no provider in the default invoice profile, so the portal stays closed", () => {
		expect(providerModule.createBillingProvider(() => undefined)).toBeNull();
		expect(providerModule.createBillingProvider(() => "")).toBeNull();
	});

	it("refuses an unknown provider instead of falling back to the fixture", () => {
		expect(() => providerModule.createBillingProvider((name) => (name === "AIDR_BILLING_PROVIDER" ? "paddle" : ""))).toThrow(
			/not configured/i,
		);
	});

	it("fails closed when stripe is selected without a secret or seat price", () => {
		expect(() =>
			providerModule.createBillingProvider((name) =>
				name === "AIDR_BILLING_PROVIDER" ? "stripe" : name === "STRIPE_SECRET_KEY" ? "sk_test_x" : "",
			),
		).toThrow(/not configured/i);
		expect(() =>
			providerModule.createBillingProvider((name) => {
				if (name === "AIDR_BILLING_PROVIDER") return "stripe";
				if (name === "STRIPE_SECRET_KEY") return "sk_test_x";
				return "not-a-price";
			}),
		).toThrow(/not configured/i);
	});

	it("resolves and reuses a fixture customer deterministically without a client-supplied id", async () => {
		const fixture = new providerModule.FixtureBillingProvider();
		const first = await fixture.ensureCustomer({ tenantId: TENANT, existingCustomerId: null });
		expect(first).toMatch(/^cus_fixture_[0-9a-f]{24}$/);
		expect(await fixture.ensureCustomer({ tenantId: TENANT, existingCustomerId: null })).toBe(first);
		expect(await fixture.ensureCustomer({ tenantId: TENANT, existingCustomerId: "cus_stored" })).toBe("cus_stored");
		expect(await fixture.ensureCustomer({ tenantId: OTHER_TENANT, existingCustomerId: null })).not.toBe(first);
	});

	it("never reports a synthetic quantity for an unknown subscription", async () => {
		const fixture = new providerModule.FixtureBillingProvider();
		expect(await fixture.readSubscription("sub_missing")).toBeNull();
		fixture.seed("sub_1", 4);
		expect(await fixture.readSubscription("sub_1")).toEqual({
			subscriptionId: "sub_1",
			quantity: 4,
			status: "active",
		});
	});

	it("sends an idempotency key on a Stripe quantity update and refuses to invent an item", async () => {
		const calls: Array<{ url: string; method: string; idempotency: string | null }> = [];
		const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
			const headers = new Headers(init?.headers);
			calls.push({
				url: String(input),
				method: init?.method ?? "GET",
				idempotency: headers.get("Idempotency-Key"),
			});
			const body = String(init?.body ?? "");
			if ((init?.method ?? "GET") === "GET") {
				return new Response(
					JSON.stringify({
						id: "sub_live_1",
						status: "active",
						items: { data: [{ id: "si_1", price: { id: "price_seat" }, quantity: 2 }] },
					}),
					{ status: 200 },
				);
			}
			expect(body).toContain("items%5B0%5D%5Bquantity%5D=5");
			return new Response(
				JSON.stringify({
					id: "sub_live_1",
					status: "active",
					items: { data: [{ id: "si_1", price: { id: "price_seat" }, quantity: 5 }] },
				}),
				{ status: 200 },
			);
		}) as unknown as typeof fetch;

		const stripe = new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x",
			seatPriceId: "price_seat",
			fetcher,
		});
		const updated = await stripe.updateQuantity("sub_live_1", 5);
		expect(updated).toEqual({ subscriptionId: "sub_live_1", quantity: 5, status: "active" });
		expect(calls[1]?.idempotency).toBe("aidr-seats-sub_live_1-5");

		const noItem = new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x",
			seatPriceId: "price_other",
			fetcher: (async () =>
				new Response(JSON.stringify({ id: "sub_live_1", status: "active", items: { data: [] } }), {
					status: 200,
				})) as unknown as typeof fetch,
		});
		await expect(noItem.updateQuantity("sub_live_1", 5)).rejects.toThrow(/subscription_item_not_found/);
	});

	it("maps a provider HTTP failure to unavailable and never to a zero quantity", async () => {
		const stripe = new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x",
			seatPriceId: "price_seat",
			fetcher: (async () => new Response("nope", { status: 500 })) as unknown as typeof fetch,
		});
		await expect(stripe.readSubscription("sub_live_1")).rejects.toThrow(/stripe_http_500/);
	});
});

describe("billing-portal Edge handler", () => {
	const environment: Record<string, string> = {
		SUPABASE_URL: "https://project.supabase.co",
		SUPABASE_SERVICE_ROLE_KEY: "service-role-key",
		AIDR_DASHBOARD_URL: "https://app.aidr.example",
	};

	type RpcCall = { name: string; args: Record<string, unknown> };
	interface DbOptions {
		memberships?: Array<{ tenant_id: string; role: string; expires_at: string | null }>;
		tenantStatus?: string | null;
		memberError?: boolean;
		ledger?: unknown[];
		subscription?: { provider_subscription_id: string; status: string } | null;
		subscriptionError?: boolean;
		rpc?: (name: string, args: Record<string, unknown>) => { data: unknown; error: unknown };
	}

	function database(options: DbOptions = {}) {
		const rpcCalls: RpcCall[] = [];
		// Minimal PostgREST-shaped query builder: chainable, thenable, and
		// `.maybeSingle()`-terminated. `tenant_members` is read as
		// `select().eq()` (awaited directly) and the others as
		// `select().eq().maybeSingle()`.
		const builder = (table: string) => {
			const query = {
				select: () => query,
				eq: () => query,
				limit: () => query,
				maybeSingle: async () => {
					if (table === "identity_user_session_state") {
						return { data: { revoked_before: null }, error: null };
					}
					if (table === "tenant_identity_policies") {
						return { data: { require_mfa: false }, error: null };
					}
					if (table === "billing_customers") {
						return { data: null, error: null };
					}
					if (table === "subscriptions") {
						return {
							data: options.subscription ?? null,
							error: options.subscriptionError ? new Error("db_down") : null,
						};
					}
					return { data: { status: options.tenantStatus ?? "active" }, error: null };
				},
				then: (resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) =>
					Promise.resolve(
						table === "tenant_members"
							? {
									data:
										options.memberships ?? [
											{ tenant_id: TENANT, role: "owner", expires_at: null },
										],
									error: options.memberError ? new Error("db_down") : null,
								}
							: { data: null, error: null },
					).then(resolve, reject),
			};
			return query;
		};
		const db = {
			auth: {
				getUser: vi.fn(async (token: string) =>
					token === "valid-token"
						? { data: { user: { id: USER } }, error: null }
						: { data: { user: null }, error: new Error("invalid") },
				),
				mfa: {
					getAuthenticatorAssuranceLevel: vi.fn(async () => ({
						data: { currentLevel: "aal1" },
						error: null,
					})),
				},
			},
			from: (table: string) => builder(table),
			rpc: vi.fn(async (name: string, args: Record<string, unknown>) => {
				rpcCalls.push({ name, args });
				if (options.rpc) return options.rpc(name, args);
				if (name === "list_billing_settlements") return { data: options.ledger ?? [], error: null };
				if (name === "recompute_billing_projection") return { data: [], error: null };
				return { data: { hash_input: args.p_hash_input }, error: null };
			}),
		};
		return { db, rpcCalls };
	}

	beforeEach(() => {
		for (const [key, value] of Object.entries(environment)) vi.stubEnv(key, value);
		vi.stubEnv("AIDR_BILLING_PROVIDER", "");
	});
	afterEach(() => {
		vi.unstubAllEnvs();
		vi.resetModules();
	});

	async function handlerWith(options: DbOptions = {}, provider: unknown = new providerModule.FixtureBillingProvider()) {
		const { db } = database(options);
		const mod = await import("../billing-portal/index.ts");
		return {
			handle: mod.createBillingPortalHandler({ provider: provider as never, db: db as never }),
			db,
		};
	}

	function post(body: unknown, headers: Record<string, string> = {}): Request {
		return new Request("https://project.supabase.co/functions/v1/billing-portal", {
			method: "POST",
			headers: { Authorization: "Bearer valid-token", "Content-Type": "application/json", ...headers },
			body: JSON.stringify(body),
		});
	}

	it("rejects an unauthenticated request before any database work", async () => {
		const { handle } = await handlerWith();
		for (const request of [
			new Request("https://project.supabase.co/functions/v1/billing-portal"),
			post({ action: "cancel" }, { Authorization: "" }),
		]) {
			const response = await handle(request);
			expect(response.status).toBe(401);
			expect(await response.json()).toMatchObject({ ok: false, error: "missing_access_token" });
		}
	});

	it("ignores a client-supplied tenant_id and uses the verified membership tenant", async () => {
		const { handle, db } = await handlerWith();
		const response = await handle(post({ action: "cancel", tenant_id: OTHER_TENANT, request_id: "request_1234567890ab" }));
		expect(response.status).toBe(403);
		const rpcNames = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.map((call) => call[0]);
		expect(rpcNames).not.toContain("apply_billing_settlement");
	});

	it("refuses a member without the billing role and an inactive tenant", async () => {
		const viewer = await handlerWith({
			memberships: [{ tenant_id: TENANT, role: "viewer", expires_at: null }],
		});
		expect((await viewer.handle(post({ action: "cancel", request_id: "request_1234567890ab" }))).status).toBe(403);

		const expired = await handlerWith({
			memberships: [{ tenant_id: TENANT, role: "owner", expires_at: "2000-01-01T00:00:00.000Z" }],
		});
		expect((await expired.handle(post({ action: "cancel", request_id: "request_1234567890ab" }))).status).toBe(403);

		const suspended = await handlerWith({ tenantStatus: "suspended" });
		expect((await suspended.handle(post({ action: "cancel", request_id: "request_1234567890ab" }))).status).toBe(403);

		const unavailable = await handlerWith({ memberError: true });
		expect((await unavailable.handle(post({ action: "cancel", request_id: "request_1234567890ab" }))).status).toBe(503);
	});

	it("rejects a client-supplied customer id and a malformed settlement body", async () => {
		const { handle } = await handlerWith();
		const withCustomer = await handle(
			post({ action: "apply_settlement", receipt: { settlementId: SETTLEMENT, customer_id: "cus_attacker" } }),
		);
		expect(withCustomer.status).toBe(400);
		expect(await withCustomer.json()).toMatchObject({ error: "customer_id_must_not_be_supplied" });

		const withTenant = await handle(
			post({ action: "apply_settlement", receipt: { settlementId: SETTLEMENT, tenantId: OTHER_TENANT } }),
		);
		expect(withTenant.status).toBe(400);

		const unknown = await handle(post({ action: "delete_everything" }));
		expect(unknown.status).toBe(400);
		expect(await unknown.json()).toMatchObject({ error: "unsupported_action" });

		const withSubscription = await handle(
			post({
				action: "apply_settlement",
				receipt: {
					settlementId: SETTLEMENT,
					requestId: "request_1234567890abcdef",
					providerSubscriptionId: "sub_someone_else",
					status: "settled",
					currency: "USD",
					lines: [{ sku: "aidr.agent.seat", quantity: 1, unitAmountMinor: 1000 }],
					quoteReference: "QUOTE-1",
					settledAmountMinor: 1000,
					refundedAmountMinor: 0,
					occurredAt: "2026-09-13T00:00:00.000Z",
					sequence: 3,
				},
			}),
		);
		expect(withSubscription.status).toBe(409);
		expect(await withSubscription.json()).toMatchObject({
			error: "subscription_id_must_not_be_supplied",
		});
	});

	it("refuses a seat change when no subscription is linked to the tenant", async () => {
		const { handle, db } = await handlerWith();
		const response = await handle(
			post({ action: "request_seats", request_id: "request_1234567890abcdef", seats: 6 }),
		);
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ error: "subscription_not_linked" });
		const rpcNames = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.map((entry) => entry[0]);
		expect(rpcNames).not.toContain("recompute_billing_projection");
	});

	it("binds the provider customer id server-side and stores the bound receipt hash", async () => {
		const { handle, db } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
		});
		const response = await handle(
			post({
				action: "apply_settlement",
				receipt: {
					settlementId: SETTLEMENT,
					requestId: "request_1234567890abcdef",
					status: "settled",
					currency: "USD",
					lines: [{ sku: "aidr.agent.seat", quantity: 5, unitAmountMinor: 1000 }],
					quoteReference: "QUOTE-2026-0001",
					settledAmountMinor: 5000,
					refundedAmountMinor: 0,
					occurredAt: "2026-09-13T00:00:00.000Z",
					sequence: 3,
				},
			}),
		);
		expect(response.status).toBe(200);
		const body = (await response.json()) as Record<string, unknown>;
		expect(body).toMatchObject({ ok: true, external_validation: false });
		const call = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.find((entry) => entry[0] === "apply_billing_settlement");
		expect(call).toBeDefined();
		const args = call?.[1] as Record<string, unknown>;
		expect(args.p_provider_customer_id).toMatch(/^cus_fixture_/);
		expect(args.p_tenant_id).toBe(TENANT);
		expect(args.p_actor_user_id).toBe(USER);
		// The submitted hash input must be the canonical encoding of the
		// *server-bound* receipt, and the submitted digest must be its SHA-256.
		const canonicalInput = settlement.settlementHashInput(
			boundReceipt({
				providerCustomerId: args.p_provider_customer_id as string,
				requestId: "request_1234567890abcdef",
				status: "settled",
				currency: "USD",
				sequence: 3,
				quoteReference: "QUOTE-2026-0001",
				refundedAmountMinor: 0,
				occurredAt: "2026-09-13T00:00:00.000Z",
			}),
		);
		expect(args.p_hash_input).toBe(canonicalInput);
		expect(args.p_receipt_hash).toBe(await settlement.settlementReceiptHash(
			boundReceipt({
				providerCustomerId: args.p_provider_customer_id as string,
				requestId: "request_1234567890abcdef",
				status: "settled",
				currency: "USD",
				sequence: 3,
				quoteReference: "QUOTE-2026-0001",
				refundedAmountMinor: 0,
				occurredAt: "2026-09-13T00:00:00.000Z",
			}),
		));
		expect(args.p_hash_input).toContain(String(args.p_provider_customer_id));
		expect(args.p_hash_input).toContain(TENANT);
		expect(args.p_hash_input).toContain("aidr-settlement-v1");
	});

	it("reports a provider configuration failure instead of a synthetic success", async () => {
		const { handle } = await handlerWith({}, null);
		const response = await handle(
			post({
				action: "apply_settlement",
				receipt: {
					settlementId: SETTLEMENT,
					requestId: "request_1234567890abcdef",
					status: "settled",
					currency: "USD",
					lines: [{ sku: "aidr.agent.seat", quantity: 1, unitAmountMinor: 1000 }],
					quoteReference: "QUOTE-1",
					settledAmountMinor: 1000,
					refundedAmountMinor: 0,
					occurredAt: "2026-09-13T00:00:00.000Z",
					sequence: 3,
				},
			}),
		);
		expect(response.status).toBe(503);
		expect(await response.json()).toMatchObject({ error: "provider_not_configured" });
	});

	it("maps a conflicting request id to 409 and never writes twice", async () => {
		const { handle } = await handlerWith({
			rpc: (name) => (name === "apply_billing_settlement" ? { data: null, error: { code: "23505" } } : { data: [], error: null }),
		});
		const response = await handle(
			post({
				action: "apply_settlement",
				receipt: {
					settlementId: SETTLEMENT,
					requestId: "request_1234567890abcdef",
					status: "settled",
					currency: "USD",
					lines: [{ sku: "aidr.agent.seat", quantity: 1, unitAmountMinor: 1000 }],
					quoteReference: "QUOTE-1",
					settledAmountMinor: 1000,
					refundedAmountMinor: 0,
					occurredAt: "2026-09-13T00:00:00.000Z",
					sequence: 3,
				},
			}),
		);
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({ error: "billing_request_conflict" });
	});

	it("returns the ledger and refuses to invent seats when the ledger read fails", async () => {
		const empty = await handlerWith();
		const listed = await empty.handle(
			new Request("https://project.supabase.co/functions/v1/billing-portal", {
				headers: { Authorization: "Bearer valid-token" },
			}),
		);
		expect(listed.status).toBe(200);
		expect(await listed.json()).toMatchObject({ ok: true, settlements: [], external_validation: false });

		const failing = await handlerWith({
			rpc: (name) => (name === "list_billing_settlements" ? { data: null, error: { code: "HY000" } } : { data: [], error: null }),
		});
		const failed = await failing.handle(
			new Request("https://project.supabase.co/functions/v1/billing-portal", {
				headers: { Authorization: "Bearer valid-token" },
			}),
		);
		expect(failed.status).toBe(503);
		expect(await failed.json()).toMatchObject({ error: "billing_ledger_unavailable" });
	});

	it("rejects an oversized or malformed JSON body without touching the database", async () => {
		const { handle, db } = await handlerWith();
		const oversized = new Request("https://project.supabase.co/functions/v1/billing-portal", {
			method: "POST",
			headers: { Authorization: "Bearer valid-token" },
			body: JSON.stringify({ action: "cancel", padding: "x".repeat(20_000) }),
		});
		expect((await handle(oversized)).status).toBe(413);
		const malformed = new Request("https://project.supabase.co/functions/v1/billing-portal", {
			method: "POST",
			headers: { Authorization: "Bearer valid-token" },
			body: "{not json",
		});
		expect((await handle(malformed)).status).toBe(400);
		expect(db.rpc).not.toHaveBeenCalled();
	});
});

describe("billing settlement migration contract", () => {
	it("makes the ledger append-only and service-role only", () => {
		expect(migration).toContain("reject_billing_settlement_mutation");
		expect(migration).toContain("before update or delete on public.billing_settlements");
		expect(migration).toContain("revoke all on public.billing_settlements from public, anon, authenticated");
		expect(migration).toContain("grant select, insert on public.billing_settlements to service_role");
		expect(migration).not.toMatch(/grant (?:select|insert|update|delete)[^;]*to authenticated/);
	});

	it("re-checks the actor, active tenant and role inside the writing transaction", () => {
		const rpc = migration.split("create or replace function public.apply_billing_settlement(")[1] ?? "";
		expect(rpc).toContain("public.assert_billing_actor(p_tenant_id, p_actor_user_id");
		expect(rpc).toContain("pg_advisory_xact_lock");
		expect(rpc).toContain("billing_request_conflict");
		expect(rpc).toContain("billing_transition_not_allowed");
		expect(rpc).toContain("billing_settlement_terminal");
		expect(rpc).toContain("insert into public.admin_audit_logs");
	});

	it("never lets a stored receipt be externally validated from SQL", () => {
		expect(migration).toContain("external_validation boolean not null default false check (external_validation = false)");
	});

	it("purges settlement evidence on offboarding and tenant close", () => {
		expect(migration).toContain("purge_billing_settlements_at_commercial_retention");
		expect(migration).toContain("purge_billing_settlements_on_tenant_close");
		expect(migration).toContain("delete from public.billing_settlements where tenant_id = new.id");
	});
});

describe("billing retention migration contract", () => {
	it("prunes expired settlement requests without touching settled records", () => {
		// Both idempotency stores get an explicit, bounded lifetime.
		expect(pruningMigration).toMatch(
			/alter table public\.billing_settlement_requests\s+add column if not exists expires_at timestamptz not null default now\(\) \+ interval '90 days'/,
		);
		expect(pruningMigration).toMatch(
			/alter table public\.billing_webhook_events\s+add column if not exists expires_at timestamptz not null default now\(\) \+ interval '30 days'/,
		);
		expect(pruningMigration).toContain(
			"create index if not exists billing_settlement_requests_expiry_idx",
		);
		expect(pruningMigration).toContain("create index if not exists billing_webhook_events_expiry_idx");
		expect(pruningMigration).toContain(
			"create or replace function public.prune_expired_billing_records(",
		);

		const pruneRpc =
			pruningMigration
				.split("create or replace function public.prune_expired_billing_records(")[1]
				?.split("\n$$;")[0] ?? "";
		expect(pruneRpc).toContain("delete from public.billing_settlement_requests");
		expect(pruneRpc).toContain("delete from public.billing_webhook_events");
		expect(pruneRpc).toContain("where expires_at <= now()");
		// The settlement ledger is the append-only financial evidence: the
		// pruning function must never name it, so no settled record is reachable.
		expect(pruneRpc).not.toContain("public.billing_settlements");
		expect(pruneRpc).not.toContain("public.billing_entitlement_projections");
		expect(pruningMigration).not.toMatch(/delete from public\.billing_settlements/);
		expect(pruningMigration).not.toMatch(/update public\.billing_settlements/);

		// A dry run counts without deleting, and the deletion is the observable
		// part of the maintenance evidence.
		expect(pruneRpc).toContain("if p_apply then");
		expect(pruneRpc).toContain("'settlement_requests_eligible'");
		expect(pruneRpc).toContain("'webhook_events_eligible'");
		expect(pruneRpc).toContain("'settlement_requests_deleted'");
		expect(pruneRpc).toContain("'webhook_events_deleted'");
		expect(pruneRpc).toContain("get diagnostics v_requests_deleted = row_count");

		// Service-role only.
		expect(pruningMigration).toContain(
			"revoke all on function public.prune_expired_billing_records(integer, boolean)\n  from public, anon, authenticated",
		);
		expect(pruningMigration).toContain(
			"grant execute on function public.prune_expired_billing_records(integer, boolean)\n  to service_role",
		);

		// The scheduled maintenance job is what actually runs it, and its
		// evidence file carries both the counts and the scope statement.
		expect(maintenanceSource).toContain("/rest/v1/rpc/prune_expired_billing_records");
		expect(maintenanceSource).toContain("p_apply: apply");
		expect(maintenanceSource).toContain("billing_retention");
		expect(maintenanceSource).toContain("append-only settlement ledger is never touched");
	});
});

describe("billing portal handler source contract", () => {
	it("resolves tenant and customer identity server-side only", () => {
		expect(portalSource).toContain("resolveAuthorizedTenant");
		expect(portalSource).toContain("checkIdentityBarrier");
		expect(portalSource).toContain("tenant_id_must_not_be_supplied");
		expect(portalSource).toContain("customer_id_must_not_be_supplied");
		expect(portalSource).toContain('loadConfig(runtimeEnv, REQUIRED_ENV)');
		expect(portalSource).toContain("configFailure(");
		expect(portalSource).toContain("AIDR_DASHBOARD_URL");
		expect(portalSource).not.toMatch(/Deno\.env\.get\(\s*"SUPABASE_(URL|SERVICE_ROLE_KEY)"\s*\)/);
	});
});
