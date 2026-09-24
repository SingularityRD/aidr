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
vi.mock("npm:@supabase/supabase-js@2.116.0", () => ({
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
// Historical bounded lifetime migration; later consistency hardening made
// settlement request keys permanent and narrowed routine pruning to webhooks.
const pruningMigration = readFileSync(
	join(ROOT, "supabase", "migrations", "20260914000001_billing_retention_pruning.sql"),
	"utf8",
);
const hardeningMigration = readFileSync(
	join(ROOT, "supabase", "migrations", "20260922000003_billing_consistency_hardening.sql"),
	"utf8",
);
const offboardingRetentionMigration = readFileSync(
	join(
		ROOT,
		"supabase",
		"migrations",
		"20260916000008_billing_settlement_offboarding_retention.sql",
	),
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

function storedLedgerRow(receipt: settlement.SettlementReceipt) {
	return {
		settlement_id: receipt.settlementId,
		request_id: receipt.requestId,
		provider: receipt.provider,
		provider_customer_id: receipt.providerCustomerId,
		provider_subscription_id: receipt.providerSubscriptionId,
		status: receipt.status,
		currency: receipt.currency,
		lines: receipt.lines,
		total_amount_minor: receipt.totalAmountMinor,
		quote_reference: receipt.quoteReference,
		settled_amount_minor: receipt.settledAmountMinor,
		refunded_amount_minor: receipt.refundedAmountMinor,
		occurred_at: receipt.occurredAt,
		recorded_at: receipt.recordedAt,
		sequence: receipt.sequence,
		hash_input: settlement.settlementHashInput(receipt),
		receipt_hash: receipt.receiptHash,
		external_validation: receipt.externalValidation,
	};
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

	it("uses the immutable sequence when a later transition has an older provider clock", async () => {
		const ledger = await settledLedger(SETTLEMENT);
		const refunded = await sealed({
			status: "refunded",
			sequence: 4,
			refundedAmountMinor: 5000,
			occurredAt: "2020-01-01T00:00:00.000Z",
		});
		expect(
			settlement.projectEntitlement({ tenantId: TENANT, receipts: [...ledger, refunded] }),
		).toMatchObject({ status: "revoked", seats: [] });
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

	it("selects Stripe when the documented provider selector is coherent with the shared gate", () => {
		const provider = providerModule.createBillingProvider((name) => {
			if (name === "AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING") return "true";
			if (name === "AIDR_BILLING_PROVIDER") return "stripe";
			if (name === "STRIPE_SECRET_KEY") return "sk_test_x";
			if (name === "AIDR_STRIPE_EXTRA_AGENT_PRICE_ID") return "price_seat";
			return "";
		});
		expect(provider?.id).toBe("stripe");
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
		const updated = await stripe.updateQuantity("sub_live_1", 5, "a".repeat(64));
		expect(updated).toEqual({ subscriptionId: "sub_live_1", quantity: 5, status: "active" });
		expect(calls[1]?.idempotency).toBe(`aidr-seats-${"a".repeat(64)}`);

		const noItem = new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x",
			seatPriceId: "price_other",
			fetcher: (async () =>
				new Response(JSON.stringify({ id: "sub_live_1", status: "active", items: { data: [] } }), {
					status: 200,
				})) as unknown as typeof fetch,
		});
		await expect(
			noItem.updateQuantity("sub_live_1", 5, "a".repeat(64)),
		).rejects.toThrow(/subscription_item_not_found/);
	});

	it("reads and updates the configured yearly Stripe seat price", async () => {
		const forms: URLSearchParams[] = [];
		const fetcher = (async (_input: RequestInfo | URL, init?: RequestInit) => {
			if (init?.method === "POST") forms.push(new URLSearchParams(String(init.body)));
			return new Response(JSON.stringify({
				id: "sub_yearly_1", status: "active",
				items: { data: [{ id: "si_yearly", price: { id: "price_yearly" }, quantity: init?.method === "POST" ? 5 : 2 }] },
			}), { status: 200 });
		}) as unknown as typeof fetch;
		const env: Record<string, string> = {
			AIDR_BILLING_PROVIDER: "stripe", STRIPE_SECRET_KEY: "sk_test_x",
			AIDR_STRIPE_EXTRA_AGENT_PRICE_ID: "price_monthly",
			AIDR_STRIPE_EXTRA_AGENT_YEARLY_PRICE_ID: "price_yearly",
		};
		const stripe = providerModule.createBillingProvider((name) => env[name], fetcher);
		expect(await stripe?.readSubscription("sub_yearly_1")).toEqual({
			subscriptionId: "sub_yearly_1", quantity: 2, status: "active",
		});
		expect(await stripe?.updateQuantity("sub_yearly_1", 5, "a".repeat(64))).toEqual({
			subscriptionId: "sub_yearly_1", quantity: 5, status: "active",
		});
		expect(forms).toHaveLength(1);
		expect(forms[0]?.get("items[0][id]")).toBe("si_yearly");
		expect(forms[0]?.get("items[0][quantity]")).toBe("5");
	});

	it("refuses ambiguous or paginated Stripe seat lines", async () => {
		for (const items of [
			{ data: [{ id: "si_monthly", price: { id: "price_monthly" }, quantity: 2 },
				{ id: "si_yearly", price: { id: "price_yearly" }, quantity: 2 }] },
			{ data: [{ id: "si_yearly", price: { id: "price_yearly" }, quantity: 2 }], has_more: true },
		]) {
			const fetcher = vi.fn(async () => new Response(JSON.stringify({ id: "sub_live_1", status: "active", items }), { status: 200 }));
			const stripe = new providerModule.StripeBillingProvider({
				secretKey: "sk_test_x", seatPriceId: "price_monthly", yearlySeatPriceId: "price_yearly",
				fetcher: fetcher as unknown as typeof fetch,
			});
			expect((await stripe.readSubscription("sub_live_1"))?.quantity).toBeNull();
			await expect(stripe.updateQuantity("sub_live_1", 5, "a".repeat(64)))
				.rejects.toThrow(/subscription_item_not_found/);
			expect(fetcher).toHaveBeenCalledTimes(2);
		}
		expect(() => new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x", seatPriceId: "price_monthly", yearlySeatPriceId: "price_not-valid",
	})).toThrow(/not configured/i);
	});

	it("uses the tenant-bound operation hash, not the target quantity, for Stripe retry identity", async () => {
		const keys: string[] = [];
		const fetcher = (async (_input: RequestInfo | URL, init?: RequestInit) => {
			const key = new Headers(init?.headers).get("Idempotency-Key");
			if (key) keys.push(key);
			const quantity = Number(new URLSearchParams(String(init?.body ?? "")).get("items[0][quantity]") ?? 2);
			return new Response(
				JSON.stringify({
					id: "sub_live_1",
					status: "active",
					items: { data: [{ id: "si_1", price: { id: "price_seat" }, quantity }] },
				}),
				{ status: 200 },
			);
		}) as unknown as typeof fetch;
		const stripe = new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x",
			seatPriceId: "price_seat",
			fetcher,
		});

		await stripe.updateQuantity("sub_live_1", 5, "a".repeat(64));
		await stripe.updateQuantity("sub_live_1", 6, "b".repeat(64));
		await stripe.updateQuantity("sub_live_1", 5, "c".repeat(64));

		expect(keys).toEqual([
			`aidr-seats-${"a".repeat(64)}`,
			`aidr-seats-${"b".repeat(64)}`,
			`aidr-seats-${"c".repeat(64)}`,
		]);
	});

	it("maps a provider HTTP failure to unavailable and never to a zero quantity", async () => {
		const stripe = new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x",
			seatPriceId: "price_seat",
			fetcher: (async () => new Response("nope", { status: 500 })) as unknown as typeof fetch,
		});
		await expect(stripe.readSubscription("sub_live_1")).rejects.toThrow(/stripe_http_500/);
	});

	it("refuses a Stripe refund without an immutable charge or payment-intent binding", async () => {
		const fetcher = vi.fn(async () => new Response(JSON.stringify({ id: "re_unsafe" }), { status: 200 }));
		const stripe = new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x",
			seatPriceId: "price_seat",
			fetcher: fetcher as unknown as typeof fetch,
		});
		await expect(stripe.refund({
			providerCustomerId: "cus_tenant",
			providerSubscriptionId: "sub_live_1",
			amountMinor: 1000,
			currency: "USD",
			idempotencyKey: "d".repeat(64),
		})).resolves.toEqual({
			ok: false,
			refundId: null,
			reason: "provider_payment_reference_required",
		});
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("refunds only the exact stored Stripe PaymentIntent", async () => {
		const calls: Array<{ url: string; form: URLSearchParams; idempotency: string | null }> = [];
		const fetcher = (async (input: RequestInfo | URL, init?: RequestInit) => {
			calls.push({
				url: String(input),
				form: new URLSearchParams(String(init?.body ?? "")),
				idempotency: new Headers(init?.headers).get("Idempotency-Key"),
			});
			return new Response(JSON.stringify({ id: "re_exact_1" }), { status: 200 });
		}) as unknown as typeof fetch;
		const stripe = new providerModule.StripeBillingProvider({
			secretKey: "sk_test_x",
			seatPriceId: "price_seat",
			fetcher,
		});
		await expect(stripe.refund({
			providerCustomerId: "cus_tenant",
			providerSubscriptionId: "sub_live_1",
			providerPaymentKind: "payment_intent",
			providerPaymentId: "pi_exact_1",
			amountMinor: 1000,
			currency: "usd",
			idempotencyKey: "d".repeat(64),
		})).resolves.toMatchObject({ ok: true, refundId: "re_exact_1" });
		expect(calls).toHaveLength(1);
		expect(calls[0]?.url).toBe("https://api.stripe.com/v1/refunds");
		expect(calls[0]?.form.get("payment_intent")).toBe("pi_exact_1");
		expect(calls[0]?.form.get("charge")).toBeNull();
		expect(calls[0]?.idempotency).toBe(`aidr-refund-${"d".repeat(64)}`);
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
				if (name === "claim_billing_portal_operation") return {
					data: { state: "new", result: null, effective_request_id: args.p_request_id },
					error: null,
				};
				if (name === "complete_billing_portal_operation") return { data: true, error: null };
				if (name === "fail_billing_portal_operation") return { data: true, error: null };
				if (name === "get_billing_provider_payment") return { data: null, error: null };
				if (name === "record_billing_provider_refund") return { data: { refunded_amount_minor: args.p_amount_minor }, error: null };
				return { data: { hash_input: args.p_hash_input }, error: null };
			}),
		};
		return { db, rpcCalls };
	}

	beforeEach(() => {
		for (const [key, value] of Object.entries(environment)) vi.stubEnv(key, value);
		vi.stubEnv("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING", "true");
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

	it("blocks provider mutations when the shared self-service gate is disabled", async () => {
		vi.stubEnv("AIDR_ENABLE_LEGACY_SELF_SERVICE_BILLING", "false");
		const updateQuantity = vi.fn();
		const { handle } = await handlerWith({}, {
			id: "stripe",
			ensureCustomer: vi.fn(),
			readSubscription: vi.fn(),
			updateQuantity,
			cancelSubscription: vi.fn(),
			refund: vi.fn(),
		});
		const response = await handle(post({
			action: "request_seats",
			request_id: "request_1234567890ab",
			seats: 4,
		}));
		expect(response.status).toBe(410);
		expect(await response.json()).toMatchObject({ error: "disabled_for_direct_ga" });
		expect(updateQuantity).not.toHaveBeenCalled();
		const snapshot = await handle(new Request(
			"https://project.supabase.co/functions/v1/billing-portal",
			{ headers: { Authorization: "Bearer valid-token" } },
		));
		expect(snapshot.status).toBe(200);
		expect(await snapshot.json()).toMatchObject({ self_service: false });
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

	it("rejects browser-supplied cancellation and refund settlement transitions", async () => {
		const ensureCustomer = vi.fn(async () => "cus_fixture_tenant");
		const { handle, db } = await handlerWith({}, {
			id: "provider_fixture",
			ensureCustomer,
			readSubscription: vi.fn(),
			updateQuantity: vi.fn(),
			cancelSubscription: vi.fn(),
			refund: vi.fn(),
		});

		for (const status of ["cancelled", "refunded"] as const) {
			const response = await handle(post({
				action: "apply_settlement",
				receipt: {
					settlementId: SETTLEMENT,
					requestId: `request_${status}_123456`,
					status,
					currency: "USD",
					lines: [{ sku: "aidr.agent.seat", quantity: 1, unitAmountMinor: 1000 }],
					quoteReference: "QUOTE-1",
					settledAmountMinor: 1000,
					refundedAmountMinor: 1000,
					occurredAt: "2026-09-13T00:00:00.000Z",
					sequence: 4,
				},
			}));
			expect(response.status).toBe(409);
			expect(await response.json()).toMatchObject({
				error: "settlement_transition_requires_provider_confirmation",
			});
		}

		expect(ensureCustomer).not.toHaveBeenCalled();
		expect((db.rpc as ReturnType<typeof vi.fn>).mock.calls.some((entry) => entry[0] === "apply_billing_settlement")).toBe(false);
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

	it("rejects a SKU not backed by the configured provider seat price", async () => {
		const updateQuantity = vi.fn();
		const { handle, db } = await handlerWith(
			{ subscription: { provider_subscription_id: "sub_fixture_1", status: "active" } },
			{
				id: "stripe", ensureCustomer: vi.fn(), readSubscription: vi.fn(), updateQuantity,
				cancelSubscription: vi.fn(), refund: vi.fn(),
			},
		);
		const response = await handle(post({
			action: "request_seats", request_id: "unsupported_1234567890", seats: 6,
			sku: "aidr.premium.intel",
		}));
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "unsupported_sku" });
		expect(updateQuantity).not.toHaveBeenCalled();
		expect(db.rpc).not.toHaveBeenCalled();
	});

	it("passes the tenant-bound operation hash to the seat provider", async () => {
		const provider = new providerModule.FixtureBillingProvider();
		const update = vi.spyOn(provider, "updateQuantity");
		const { handle, db } = await handlerWith(
			{ subscription: { provider_subscription_id: "sub_fixture_1", status: "active" } },
			provider,
		);

		const response = await handle(
			post({ action: "request_seats", request_id: "request_1234567890abcdef", seats: 6 }),
		);

		expect(response.status).toBe(200);
		const claim = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.find(
			(entry) => entry[0] === "claim_billing_portal_operation",
		);
		const requestHash = (claim?.[1] as Record<string, unknown>)?.p_request_hash;
		expect(requestHash).toMatch(/^[0-9a-f]{64}$/);
		expect(update).toHaveBeenCalledWith("sub_fixture_1", 6, requestHash);
	});

	it("replays the persisted canonical result after a lost success response", async () => {
		const updateQuantity = vi.fn();
		const stored = { ok: true, request_id: "request_1234567890ab", provider_quantity: 6, status: "completed" };
		const { handle } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			rpc: (name, args) => {
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") return {
					data: { state: "completed", result: stored, effective_request_id: args.p_request_id }, error: null,
				};
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture", ensureCustomer: vi.fn(), readSubscription: vi.fn(), updateQuantity,
			cancelSubscription: vi.fn(), refund: vi.fn(),
		});
		const response = await handle(post({ action: "request_seats", request_id: "request_1234567890ab", seats: 6 }));
		expect(response.status).toBe(200);
		expect(await response.json()).toEqual(stored);
		expect(updateQuantity).not.toHaveBeenCalled();
	});

	it("refuses a completed operation without a confirmed result", async () => {
		const updateQuantity = vi.fn();
		const { handle } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			rpc: (name, args) => {
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") return {
					data: { state: "completed", result: null, effective_request_id: args.p_request_id }, error: null,
				};
				return { data: null, error: null };
			},
		}, {
			id: "stripe", ensureCustomer: vi.fn(), readSubscription: vi.fn(), updateQuantity,
			cancelSubscription: vi.fn(), refund: vi.fn(),
		});
		const response = await handle(post({ action: "request_seats", request_id: "request_1234567890ab", seats: 6 }));
		expect(response.status).toBe(503);
		expect(await response.json()).toMatchObject({ error: "invalid_billing_operation_state" });
		expect(updateQuantity).not.toHaveBeenCalled();
	});

	it("completes a stale same-operation retry under the durable original request id", async () => {
		const originalRequestId = "original_1234567890";
		const updateQuantity = vi.fn(async () => ({ subscriptionId: "sub_fixture_1", quantity: 6, status: "active" }));
		const { handle, db } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			rpc: (name) => {
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") return {
					data: { state: "retry", result: null, effective_request_id: originalRequestId }, error: null,
				};
				if (name === "recompute_billing_projection") return { data: [], error: null };
				if (name === "complete_billing_portal_operation") return { data: true, error: null };
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture", ensureCustomer: vi.fn(), readSubscription: vi.fn(), updateQuantity,
			cancelSubscription: vi.fn(), refund: vi.fn(),
		});
		const response = await handle(post({ action: "request_seats", request_id: "replacement_1234567", seats: 6 }));
		expect(response.status).toBe(200);
		const completion = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.find(
			(entry) => entry[0] === "complete_billing_portal_operation",
		);
		expect((completion?.[1] as Record<string, unknown>)?.p_request_id).toBe(originalRequestId);
	});

	it("fails a different stale operation closed with an actionable recovery request", async () => {
		const updateQuantity = vi.fn();
		const readSubscription = vi.fn(async () => null);
		const { handle } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			rpc: (name) => {
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") return { data: {
					state: "recovery_required", result: null,
					effective_request_id: "original_1234567890", recovery_action: "request_seats",
					recovery_request_hash: "a".repeat(64),
					recovery_payload: {
						provider: "provider_fixture",
						subscription_id: "sub_fixture_1",
						seats: 5,
						sku: "aidr.agent.seat",
					},
				}, error: null };
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture", ensureCustomer: vi.fn(), readSubscription, updateQuantity,
			cancelSubscription: vi.fn(), refund: vi.fn(),
		});
		const response = await handle(post({ action: "request_seats", request_id: "replacement_1234567", seats: 6 }));
		expect(response.status).toBe(409);
			expect(await response.json()).toMatchObject({
			error: "billing_recovery_required",
			recovery_request_id: "original_1234567890",
			recovery_action: "request_seats",
			recovery_payload: { subscription_id: "sub_fixture_1", seats: 5 },
		});
		expect(readSubscription).toHaveBeenCalledWith("sub_fixture_1");
		expect(updateQuantity).not.toHaveBeenCalled();
	});

	it("reconciles a lost seat response from provider state before a reload starts a new action", async () => {
		const originalRequestId = "original_1234567890";
		const replacementRequestId = "replacement_1234567";
		let originalHash = "";
		let claims = 0;
		let providerQuantity = 0;
		const sequence: string[] = [];
		const readSubscription = vi.fn(async () => {
			sequence.push("read-old-target");
			return { subscriptionId: "sub_fixture_1", quantity: providerQuantity, status: "active" };
		});
		const updateQuantity = vi.fn(async (_subscriptionId: string, quantity: number) => {
			providerQuantity = quantity;
			if (quantity === 5) {
				sequence.push("update-5-throw");
				throw new providerModule.ProviderUnavailableError("lost_provider_response");
			}
			sequence.push(`update-${quantity}`);
			return { subscriptionId: "sub_fixture_1", quantity, status: "active" };
		});
		const { handle, db } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			rpc: (name, args) => {
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") {
					claims += 1;
					if (claims === 1) {
						originalHash = String(args.p_request_hash);
						return { data: {
							state: "new", result: null, effective_request_id: args.p_request_id,
						}, error: null };
					}
					return claims === 2 ? { data: {
						state: "recovery_required",
						result: null,
						effective_request_id: originalRequestId,
						recovery_action: "request_seats",
						recovery_request_hash: originalHash,
						recovery_payload: {
							provider: "provider_fixture",
							subscription_id: "sub_fixture_1",
							seats: 5,
							sku: "aidr.agent.seat",
						},
					}, error: null } : { data: {
						state: "new", result: null, effective_request_id: args.p_request_id,
					}, error: null };
				}
				if (name === "recompute_billing_projection") return { data: [], error: null };
				if (name === "complete_billing_portal_operation") {
					sequence.push(`complete-${String(args.p_request_id)}`);
					return { data: true, error: null };
				}
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture", ensureCustomer: vi.fn(), readSubscription, updateQuantity,
			cancelSubscription: vi.fn(), refund: vi.fn(),
		});

		const lostResponse = await handle(post({
			action: "request_seats",
			request_id: originalRequestId,
			seats: 5,
		}));
		expect(lostResponse.status).toBe(503);
		expect(providerQuantity).toBe(5);

		const response = await handle(post({
			action: "request_seats",
			request_id: replacementRequestId,
			seats: 6,
		}));

		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({
			ok: true,
			request_id: replacementRequestId,
			provider_quantity: 6,
		});
		expect(readSubscription).toHaveBeenCalledWith("sub_fixture_1");
		expect(updateQuantity).toHaveBeenCalledTimes(2);
		expect(updateQuantity.mock.calls.map((call) => call[1])).toEqual([5, 6]);
		expect(sequence).toEqual([
			"update-5-throw",
			"read-old-target",
			`complete-${originalRequestId}`,
			"update-6",
			`complete-${replacementRequestId}`,
		]);
		const claimsMade = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.filter(
			(entry) => entry[0] === "claim_billing_portal_operation",
		);
		expect(claimsMade).toHaveLength(3);
		expect((claimsMade[1]?.[1] as Record<string, unknown>)?.p_request_payload).toEqual({
			provider: "provider_fixture",
			subscription_id: "sub_fixture_1",
			seats: 6,
			sku: "aidr.agent.seat",
		});
		const originalCompletion = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.find(
			(entry) => entry[0] === "complete_billing_portal_operation" &&
				(entry[1] as Record<string, unknown>)?.p_request_id === originalRequestId,
		);
		expect((originalCompletion?.[1] as Record<string, unknown>)?.p_result).toMatchObject({
			provider_quantity: 5,
			recovered: true,
		});
	});

	it("records a provider-confirmed stale cancellation before allowing another billing action", async () => {
		const oldRequestId = "cancel_original_123456";
		const newRequestId = "seats_replacement_123456";
		const ledger = (await settledLedger(SETTLEMENT)).map(storedLedgerRow);
		const sequence: string[] = [];
		let claims = 0;
		const readSubscription = vi.fn(async (subscriptionId: string) => {
			sequence.push("provider-read");
			return { subscriptionId, quantity: 5, status: "canceled" };
		});
		const updateQuantity = vi.fn(async (subscriptionId: string, quantity: number) => {
			sequence.push("seat-update");
			return { subscriptionId, quantity, status: "active" };
		});
		const { handle, db } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			ledger,
			rpc: (name, args) => {
				if (name === "list_billing_settlements") return { data: ledger, error: null };
				if (name === "claim_billing_portal_operation") {
					claims += 1;
					sequence.push(`claim-${claims}`);
					return claims === 1 ? { data: {
						state: "recovery_required",
						result: null,
						effective_request_id: oldRequestId,
						recovery_action: "cancel",
						recovery_request_hash: "b".repeat(64),
						recovery_payload: {
							provider: "provider_fixture",
							settlement_id: SETTLEMENT,
							subscription_id: "sub_fixture_1",
						},
					}, error: null } : { data: {
						state: "new",
						result: null,
						effective_request_id: args.p_request_id,
					}, error: null };
				}
				if (name === "apply_billing_settlement") {
					sequence.push("append-cancel");
					return { data: true, error: null };
				}
				if (name === "recompute_billing_projection") {
					sequence.push("projection");
					return { data: [], error: null };
				}
				if (name === "complete_billing_portal_operation") {
					sequence.push(`complete-${String(args.p_request_id)}`);
					return { data: true, error: null };
				}
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture",
			ensureCustomer: vi.fn(),
			readSubscription,
			updateQuantity,
			cancelSubscription: vi.fn(),
			refund: vi.fn(),
		});

		const response = await handle(post({
			action: "request_seats",
			request_id: newRequestId,
			seats: 6,
		}));

		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ provider_quantity: 6 });
		const cancellation = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.find(
			(entry) => entry[0] === "apply_billing_settlement",
		);
		expect(cancellation?.[1]).toMatchObject({
			p_settlement_id: SETTLEMENT,
			p_request_id: oldRequestId,
			p_status: "cancelled",
			p_sequence: 4,
		});
		expect(sequence).toEqual([
			"claim-1",
			"provider-read",
			"append-cancel",
			"projection",
			`complete-${oldRequestId}`,
			"claim-2",
			"seat-update",
			"projection",
			`complete-${newRequestId}`,
		]);
	});

	it("returns reconciliation pending when stale cancellation lacks provider confirmation", async () => {
		const ledger = (await settledLedger(SETTLEMENT)).map(storedLedgerRow);
		const updateQuantity = vi.fn();
		const { handle, db } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			ledger,
			rpc: (name) => {
				if (name === "list_billing_settlements") return { data: ledger, error: null };
				if (name === "claim_billing_portal_operation") return { data: {
					state: "recovery_required",
					result: null,
					effective_request_id: "cancel_original_123456",
					recovery_action: "cancel",
					recovery_request_hash: "b".repeat(64),
					recovery_payload: {
						provider: "provider_fixture",
						settlement_id: SETTLEMENT,
						subscription_id: "sub_fixture_1",
					},
				}, error: null };
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture",
			ensureCustomer: vi.fn(),
			readSubscription: vi.fn(async () => null),
			updateQuantity,
			cancelSubscription: vi.fn(),
			refund: vi.fn(),
		});

		const response = await handle(post({
			action: "request_seats",
			request_id: "seats_replacement_123456",
			seats: 6,
		}));

		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({
			error: "billing_reconciliation_pending",
			recovery_request_id: "cancel_original_123456",
			recovery_action: "cancel",
		});
		expect(updateQuantity).not.toHaveBeenCalled();
		const rpcNames = (db.rpc as ReturnType<typeof vi.fn>).mock.calls.map((entry) => entry[0]);
		expect(rpcNames).not.toContain("apply_billing_settlement");
		expect(rpcNames).not.toContain("complete_billing_portal_operation");
	});

	it("keeps a stale cancellation pending for a different billing action", async () => {
		const oldRequestId = "cancel_original_123456";
		const newRequestId = "seats_after_cancel_12345";
		const oldHash = "b".repeat(64);
		const ledger = (await settledLedger(SETTLEMENT)).map(storedLedgerRow);
		let claimCount = 0;
		const updateQuantity = vi.fn(async (subscriptionId: string, quantity: number) => ({
			subscriptionId, quantity, status: "active",
		}));
		const { handle, db } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			ledger,
			rpc: (name, args) => {
				if (name === "list_billing_settlements") return { data: ledger, error: null };
				if (name === "claim_billing_portal_operation") {
					claimCount++;
					return claimCount === 1 ? { data: {
						state: "recovery_required", result: null, effective_request_id: oldRequestId,
						recovery_action: "cancel", recovery_request_hash: oldHash,
						recovery_payload: {
							provider: "provider_fixture", settlement_id: SETTLEMENT, subscription_id: "sub_fixture_1",
						},
					}, error: null } : { data: {
						state: "new", result: null, effective_request_id: args.p_request_id,
					}, error: null };
				}
				if (name === "fail_billing_portal_operation") return { data: true, error: null };
				if (name === "recompute_billing_projection") return { data: [], error: null };
				if (name === "complete_billing_portal_operation") return { data: true, error: null };
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture", ensureCustomer: vi.fn(),
			readSubscription: vi.fn(async (subscriptionId: string) => ({
				subscriptionId, quantity: 5, status: "active",
			})),
			updateQuantity, cancelSubscription: vi.fn(), refund: vi.fn(),
		});

		const response = await handle(post({ action: "request_seats", request_id: newRequestId, seats: 6 }));
		expect(response.status).toBe(409);
		expect(await response.json()).toMatchObject({
			error: "billing_reconciliation_pending",
			recovery_request_id: oldRequestId,
		});
		expect(updateQuantity).not.toHaveBeenCalled();
		const calls = (db.rpc as ReturnType<typeof vi.fn>).mock.calls;
		expect(calls.some((call) => call[0] === "fail_billing_portal_operation")).toBe(false);
		expect(calls.some((call) => call[0] === "apply_billing_settlement")).toBe(false);
	});

	it("retries the exact stale cancellation when the provider still reports active", async () => {
		const requestId = "cancel_stale_retry_123456";
		const ledger = (await settledLedger(SETTLEMENT)).map(storedLedgerRow);
		let claimCount = 0;
		const operations: string[] = [];
		const cancelSubscription = vi.fn(async () => {
			operations.push("provider-cancel");
			return true;
		});
		const { handle, db } = await handlerWith({
			ledger,
			rpc: (name, args) => {
				if (name === "list_billing_settlements") return { data: ledger, error: null };
				if (name === "claim_billing_portal_operation") {
					claimCount++;
					operations.push(`claim-${claimCount}`);
					if (claimCount === 1) return { data: {
						state: "recovery_required", result: null, effective_request_id: requestId,
						recovery_action: "cancel", recovery_request_hash: args.p_request_hash,
						recovery_payload: {
							provider: "provider_fixture", settlement_id: SETTLEMENT,
							subscription_id: "sub_fixture_1",
						},
					}, error: null };
					return { data: { state: "retry", result: null, effective_request_id: requestId }, error: null };
				}
				if (name === "fail_billing_portal_operation") {
					operations.push("release-stale-claim");
					return { data: true, error: null };
				}
				if (name === "apply_billing_settlement") {
					operations.push("append-cancel");
					return { data: true, error: null };
				}
				if (name === "complete_billing_portal_operation") {
					operations.push("complete");
					return { data: true, error: null };
				}
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture", ensureCustomer: vi.fn(),
			readSubscription: vi.fn(async (subscriptionId: string) => ({
				subscriptionId, quantity: 5, status: "active",
			})),
			updateQuantity: vi.fn(), cancelSubscription, refund: vi.fn(),
		});

		const response = await handle(post({ action: "cancel", request_id: requestId, settlement_id: SETTLEMENT }));
		expect(response.status).toBe(200);
		expect(await response.json()).toMatchObject({ status: "cancelled" });
		expect(cancelSubscription).toHaveBeenCalledOnce();
		expect(operations).toEqual([
			"claim-1", "release-stale-claim", "claim-2", "provider-cancel", "append-cancel", "complete",
		]);
		const calls = (db.rpc as ReturnType<typeof vi.fn>).mock.calls;
		const retryClaim = calls.filter((call) => call[0] === "claim_billing_portal_operation")[1];
		expect(retryClaim?.[1]).toMatchObject({ p_request_id: requestId });
	});

	it("retries the same cancellation after a transport error when Stripe still reports active", async () => {
		const requestId = "cancel_retry_same_request";
		const requestHash: string[] = [];
		const ledger = (await settledLedger(SETTLEMENT)).map(storedLedgerRow);
		let operationStatus = "new";
		let cancelAttempts = 0;
		const readSubscription = vi.fn(async (subscriptionId: string) => ({
			subscriptionId, quantity: 5, status: "active",
		}));
		const cancelSubscription = vi.fn(async () => {
			cancelAttempts++;
			if (cancelAttempts === 1) throw new providerModule.ProviderUnavailableError("stripe_transport_failed");
			return true;
		});
		const { handle, db } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
			ledger,
			rpc: (name, args) => {
				if (name === "list_billing_settlements") return { data: ledger, error: null };
				if (name === "claim_billing_portal_operation") {
					requestHash.push(String(args.p_request_hash));
					const state = operationStatus === "failed" ? "retry" : "new";
					operationStatus = "processing";
					return { data: { state, result: null, effective_request_id: requestId }, error: null };
				}
				if (name === "fail_billing_portal_operation") {
					operationStatus = "failed";
					return { data: true, error: null };
				}
				if (name === "apply_billing_settlement") return { data: true, error: null };
				if (name === "complete_billing_portal_operation") {
					operationStatus = "completed";
					return { data: true, error: null };
				}
				return { data: null, error: null };
			},
		}, {
			id: "provider_fixture", ensureCustomer: vi.fn(), readSubscription, updateQuantity: vi.fn(),
			cancelSubscription, refund: vi.fn(),
		});
		const request = () => post({ action: "cancel", request_id: requestId, settlement_id: SETTLEMENT });

		const first = await handle(request());
		expect(first.status).toBe(503);
		expect(await first.json()).toMatchObject({ error: "provider_unavailable" });
		expect(operationStatus).toBe("failed");
		expect(readSubscription).toHaveBeenCalledOnce();
		expect((db.rpc as ReturnType<typeof vi.fn>).mock.calls.some((call) => call[0] === "apply_billing_settlement")).toBe(false);

		const retry = await handle(request());
		expect(retry.status).toBe(200);
		expect(await retry.json()).toMatchObject({ status: "cancelled" });
		expect(cancelSubscription).toHaveBeenCalledTimes(2);
		expect(requestHash).toHaveLength(2);
		expect(requestHash[1]).toBe(requestHash[0]);
		expect(cancelSubscription.mock.calls[1]?.[1]).toBe(cancelSubscription.mock.calls[0]?.[1]);
	});

	it("replays a full refund when completion acknowledgement was lost", async () => {
		let completed = false;
		const result = { ok: true, refund_id: "re_exact_1", refunded_amount_minor: 1000, external_validation: true };
		const payment = {
			provider: "stripe", provider_payment_kind: "payment_intent", provider_payment_id: "pi_exact_1",
			provider_customer_id: "cus_tenant", provider_subscription_id: "sub_live_1",
			amount_minor: 1000, refunded_amount_minor: 0, currency: "usd",
		};
		const refund = vi.fn(async () => ({ ok: true, refundId: "re_exact_1", reason: "confirmed" }));
		const { handle } = await handlerWith({
			rpc: (name, args) => {
				if (name === "get_billing_provider_payment") return { data: { ...payment, refunded_amount_minor: completed ? 1000 : 0 }, error: null };
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") return {
					data: completed ? { state: "completed", result, effective_request_id: args.p_request_id } : { state: "new", result: null, effective_request_id: args.p_request_id }, error: null,
				};
				if (name === "record_billing_provider_refund") { completed = true; return { data: { refunded_amount_minor: 1000 }, error: null }; }
				if (name === "complete_billing_portal_operation") return { data: null, error: new Error("lost") };
				return { data: null, error: null };
			},
		}, {
			id: "stripe", ensureCustomer: vi.fn(), readSubscription: vi.fn(), updateQuantity: vi.fn(),
			cancelSubscription: vi.fn(), refund,
		});
		const request = () => post({ action: "refund", request_id: "refund_1234567890abc", settlement_id: SETTLEMENT, provider_payment_id: "pi_exact_1", amount_minor: 1000 });
		expect((await handle(request())).status).toBe(503);
		const replay = await handle(request());
		expect(replay.status).toBe(200);
		expect(await replay.json()).toEqual(result);
		expect(refund).toHaveBeenCalledTimes(1);
	});

	it("retries a provider-confirmed refund after its local ledger write fails", async () => {
		let operationStatus = "new";
		let persistAttempts = 0;
		let refundedAmount = 0;
		const payment = {
			provider: "stripe", provider_payment_kind: "payment_intent", provider_payment_id: "pi_exact_1",
			provider_customer_id: "cus_tenant", provider_subscription_id: "sub_live_1",
			amount_minor: 1000, currency: "usd",
		};
		const refund = vi.fn(async () => ({ ok: true, refundId: "re_exact_1", reason: "confirmed" }));
		const { handle, db } = await handlerWith({
			rpc: (name, args) => {
				if (name === "get_billing_provider_payment") return { data: {
					...payment, refunded_amount_minor: refundedAmount,
				}, error: null };
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") {
					if (operationStatus === "completed") return { data: {
						state: "completed", result: { ok: true, refund_id: "re_exact_1", refunded_amount_minor: 1000, external_validation: true },
						effective_request_id: args.p_request_id,
					}, error: null };
					const state = operationStatus === "failed" ? "retry" : "new";
					operationStatus = "processing";
					return { data: { state, result: null, effective_request_id: args.p_request_id }, error: null };
				}
				if (name === "record_billing_provider_refund") {
					persistAttempts++;
					if (persistAttempts === 1) return { data: null, error: new Error("database temporarily unavailable") };
					refundedAmount = Number(args.p_amount_minor);
					operationStatus = "completed";
					return { data: { refunded_amount_minor: refundedAmount }, error: null };
				}
				if (name === "fail_billing_portal_operation") {
					operationStatus = "failed";
					return { data: true, error: null };
				}
				if (name === "complete_billing_portal_operation") {
					operationStatus = "completed";
					return { data: true, error: null };
				}
				return { data: null, error: null };
			},
		}, {
			id: "stripe", ensureCustomer: vi.fn(), readSubscription: vi.fn(), updateQuantity: vi.fn(),
			cancelSubscription: vi.fn(), refund,
		});
		const request = () => post({
			action: "refund", request_id: "refund_retry_1234567", settlement_id: SETTLEMENT,
			provider_payment_id: "pi_exact_1", amount_minor: 1000,
		});

		const first = await handle(request());
		expect(first.status).toBe(503);
		expect(await first.json()).toMatchObject({ error: "billing_refund_record_unavailable" });
		const second = await handle(request());
		expect(second.status).toBe(200);
		expect(await second.json()).toMatchObject({ refund_id: "re_exact_1", refunded_amount_minor: 1000 });
		expect(refund).toHaveBeenCalledTimes(2);
		expect(refund.mock.calls[1]?.[0].idempotencyKey).toBe(refund.mock.calls[0]?.[0].idempotencyKey);
		expect((db.rpc as ReturnType<typeof vi.fn>).mock.calls.map((call) => call[0]))
			.toContain("fail_billing_portal_operation");
	});

	it("uses distinct provider idempotency keys for distinct same-amount partial refunds", async () => {
		let refundedAmount = 0;
		const operations = new Map<string, { status: string; result?: Record<string, unknown> }>();
		const payment = {
			provider: "stripe", provider_payment_kind: "payment_intent", provider_payment_id: "pi_exact_1",
			provider_customer_id: "cus_tenant", provider_subscription_id: "sub_live_1",
			amount_minor: 5000, currency: "usd",
		};
		const refund = vi.fn(async (input: { idempotencyKey: string }) => ({
			ok: true,
			refundId: `re_${input.idempotencyKey.slice(0, 12)}`,
			reason: "confirmed",
		}));
		const { handle, db } = await handlerWith({
			rpc: (name, args) => {
				if (name === "get_billing_provider_payment") return { data: { ...payment, refunded_amount_minor: refundedAmount }, error: null };
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") {
					const requestId = String(args.p_request_id);
					const prior = operations.get(requestId);
					if (prior?.status === "completed") return { data: {
						state: "completed", result: prior.result, effective_request_id: requestId,
					}, error: null };
					operations.set(requestId, { status: "processing" });
					return { data: {
						state: prior ? "retry" : "new", result: null, effective_request_id: requestId,
					}, error: null };
				}
				if (name === "record_billing_provider_refund") {
					refundedAmount += Number(args.p_amount_minor);
					return { data: { refunded_amount_minor: refundedAmount }, error: null };
				}
				if (name === "complete_billing_portal_operation") {
					operations.set(String(args.p_request_id), { status: "completed", result: args.p_result as Record<string, unknown> });
					return { data: true, error: null };
				}
				return { data: null, error: null };
			},
		}, {
			id: "stripe", ensureCustomer: vi.fn(), readSubscription: vi.fn(), updateQuantity: vi.fn(),
			cancelSubscription: vi.fn(), refund,
		});
		const request = (requestId: string) => post({
			action: "refund", request_id: requestId, settlement_id: SETTLEMENT,
			provider_payment_id: "pi_exact_1", amount_minor: 1000,
		});

		const first = await handle(request("refund_partial_first_123"));
		const replay = await handle(request("refund_partial_first_123"));
		const second = await handle(request("refund_partial_second_123"));
		expect(first.status).toBe(200);
		expect(replay.status).toBe(200);
		expect(await replay.json()).toEqual(await first.clone().json());
		expect(second.status).toBe(200);
		expect(refundedAmount).toBe(2000);
		expect(refund).toHaveBeenCalledTimes(2);
		expect(refund.mock.calls[0]?.[0].idempotencyKey).not.toBe(refund.mock.calls[1]?.[0].idempotencyKey);
		const claims = (db.rpc as ReturnType<typeof vi.fn>).mock.calls
			.filter((call) => call[0] === "claim_billing_portal_operation");
		expect((claims[0]?.[1] as Record<string, unknown>).p_request_hash)
			.toBe((claims[1]?.[1] as Record<string, unknown>).p_request_hash);
		expect((claims[0]?.[1] as Record<string, unknown>).p_request_hash)
			.not.toBe((claims[2]?.[1] as Record<string, unknown>).p_request_hash);
	});

	it("releases a claimed operation after a deterministic refund denial", async () => {
		const refund = vi.fn();
		const { handle, db } = await handlerWith({
			rpc: (name, args) => {
				if (name === "get_billing_provider_payment") return { data: {
					provider: "stripe", provider_payment_kind: "payment_intent", provider_payment_id: "pi_exact_1",
					provider_customer_id: "cus_tenant", provider_subscription_id: "sub_live_1",
					amount_minor: 1000, refunded_amount_minor: 0, currency: "usd",
				}, error: null };
				if (name === "list_billing_settlements") return { data: [], error: null };
				if (name === "claim_billing_portal_operation") return { data: {
					state: "new", result: null, effective_request_id: args.p_request_id,
				}, error: null };
				if (name === "fail_billing_portal_operation") return { data: true, error: null };
				return { data: null, error: null };
			},
		}, {
			id: "stripe", ensureCustomer: vi.fn(), readSubscription: vi.fn(), updateQuantity: vi.fn(),
			cancelSubscription: vi.fn(), refund,
		});
		const response = await handle(post({ action: "refund", request_id: "refund_1234567890abc", settlement_id: SETTLEMENT, provider_payment_id: "pi_exact_1", amount_minor: 2000 }));
		expect(response.status).toBe(400);
		expect(await response.json()).toMatchObject({ error: "refund_exceeds_outstanding" });
		expect((db.rpc as ReturnType<typeof vi.fn>).mock.calls.some((entry) => entry[0] === "fail_billing_portal_operation")).toBe(true);
		expect(refund).not.toHaveBeenCalled();
	});

	it("binds the provider customer id server-side and stores the bound receipt hash", async () => {
		const { handle, db } = await handlerWith({
			subscription: { provider_subscription_id: "sub_fixture_1", status: "active" },
		});
		const settledResponse = await handle(
			post({
				action: "apply_settlement",
				receipt: {
					settlementId: SETTLEMENT,
					requestId: "request_settled_rejected",
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
		expect(settledResponse.status).toBe(409);
		expect(await settledResponse.json()).toMatchObject({ error: "settlement_requires_provider_confirmation" });

		const response = await handle(
			post({
				action: "apply_settlement",
				receipt: {
					settlementId: SETTLEMENT,
					requestId: "request_1234567890abcdef",
					status: "settlement_pending",
					currency: "USD",
					lines: [{ sku: "aidr.agent.seat", quantity: 5, unitAmountMinor: 1000 }],
					quoteReference: "QUOTE-2026-0001",
					settledAmountMinor: 0,
					refundedAmountMinor: 0,
					occurredAt: "2026-09-13T00:00:00.000Z",
					sequence: 2,
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
				status: "settlement_pending",
				settledAmountMinor: 0,
				currency: "USD",
				sequence: 2,
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
				status: "settlement_pending",
				settledAmountMinor: 0,
				currency: "USD",
				sequence: 2,
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
					status: "settlement_pending",
					currency: "USD",
					lines: [{ sku: "aidr.agent.seat", quantity: 1, unitAmountMinor: 1000 }],
					quoteReference: "QUOTE-1",
					settledAmountMinor: 0,
					refundedAmountMinor: 0,
					occurredAt: "2026-09-13T00:00:00.000Z",
					sequence: 2,
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
					status: "settlement_pending",
					currency: "USD",
					lines: [{ sku: "aidr.agent.seat", quantity: 1, unitAmountMinor: 1000 }],
					quoteReference: "QUOTE-1",
					settledAmountMinor: 0,
					refundedAmountMinor: 0,
					occurredAt: "2026-09-13T00:00:00.000Z",
					sequence: 2,
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

	it("records the legacy purge hooks superseded by the retention follow-up", () => {
		expect(migration).toContain("purge_billing_settlements_at_commercial_retention");
		expect(migration).toContain("purge_billing_settlements_on_tenant_close");
		expect(migration).toContain("delete from public.billing_settlements where tenant_id = new.id");
	});
});

describe("billing consistency hardening contract", () => {
	it("keeps portal request identity permanent and serializes provider side effects", () => {
		expect(hardeningMigration).toContain("create table if not exists public.billing_portal_operations");
		expect(hardeningMigration).toContain("primary key (tenant_id, request_id)");
		expect(hardeningMigration).toContain("billing_portal_operations_processing_resource_idx");
		expect(hardeningMigration).toContain("billing_operation_in_progress");
		expect(hardeningMigration).toContain("claim_updated_at < now() - interval '10 minutes'");
		expect(hardeningMigration).toContain("v_existing.action = p_action");
		expect(hardeningMigration).toContain("v_existing.request_hash = p_request_hash");
		expect(hardeningMigration).toContain("request_payload jsonb not null");
		expect(hardeningMigration).toContain("'recovery_payload', v_existing.request_payload");
		expect(hardeningMigration).toContain("'effective_request_id', v_existing.request_id");
		expect(portalSource).toContain("await ctx.provider.readSubscription(subscriptionId)");
		expect(hardeningMigration).toContain("result = coalesce(result, p_result)");
		expect(hardeningMigration).toContain("alter column expires_at set default 'infinity'::timestamptz");
		const pruneRpc = hardeningMigration.split(
			"create or replace function public.prune_expired_billing_records(",
		)[1] ?? "";
		expect(pruneRpc).not.toContain("delete from public.billing_settlement_requests");
	});

	it("orders provider events atomically and prevents invoice/provider overlap", () => {
		expect(hardeningMigration).toContain("provider_event_created_at");
		expect(hardeningMigration).toContain("provider_event_id = 'migration-bootstrap:' || provider_subscription_id");
		expect(hardeningMigration).toContain("missing_provider_event_cursor");
		expect(hardeningMigration).toContain("create or replace function public.apply_billing_subscription_event(");
		expect(hardeningMigration).toContain("p_event_created_at < v_existing.provider_event_created_at");
		expect(hardeningMigration).toContain("p_extra_agents >= v_existing.extra_agents");
		expect(hardeningMigration).toContain("existing_billing_channel_conflict");
		expect(hardeningMigration).toContain("invoice_entitlement_preserved");
		expect(hardeningMigration).toContain("enterprise_invoice_approvals_provider_overlap_guard");
	});

	it("uses the stored canonical input for receipt integrity", () => {
		expect(portalSource).toContain("ctx.hash(storedHashInput)");
		expect(portalSource).not.toContain('ctx.hash(stored.hash_input ?? "")');
	});

	it("binds each new Stripe checkout to immutable signed payment evidence", () => {
		expect(hardeningMigration).toContain("create table if not exists public.billing_checkout_intents");
		expect(hardeningMigration).toContain("unique (tenant_id, request_id)");
		expect(hardeningMigration).toContain("create table if not exists public.billing_provider_payments");
		expect(hardeningMigration).toContain("settlement_id uuid not null references public.billing_checkout_intents");
		expect(hardeningMigration).not.toContain("settlement_id uuid not null unique references public.billing_checkout_intents");
		expect(hardeningMigration).toContain("provider_event_id text not null unique");
		expect(hardeningMigration).toContain("if p_provider_payment_id is null and v_count > 1 then");
		expect(hardeningMigration).toContain("'selection_required', true");
		expect(hardeningMigration).toContain("create or replace function public.record_stripe_payment_evidence(");
		expect(hardeningMigration).toContain("stripe_payment_binding_conflict");
		expect(hardeningMigration).toContain("create or replace function public.record_billing_provider_refund(");
		expect(hardeningMigration).toContain("and provider_payment_id = p_provider_payment_id for update");
		expect(hardeningMigration).toContain("refund_exceeds_payment");
	});
});

describe("billing retention migration contract", () => {
	it("retains immutable settlement evidence while removing operational access", () => {
		expect(offboardingRetentionMigration).toContain("retain_immutable_evidence");
		expect(offboardingRetentionMigration).toContain("settlement_rows_retained");
		expect(offboardingRetentionMigration).toContain("settlement_retention_digest");
		expect(offboardingRetentionMigration).toContain("settlement_retention_owner_requirement");
		expect(offboardingRetentionMigration).toContain(
			"revoke select, insert on public.billing_settlements from service_role",
		);
		expect(offboardingRetentionMigration).toContain(
			"delete from public.billing_settlement_requests",
		);
		expect(offboardingRetentionMigration).toContain(
			"delete from public.billing_entitlement_projections",
		);
		const replacement =
			offboardingRetentionMigration
				.split("create or replace function public.purge_billing_settlements_at_commercial_retention()")[1]
				?.split("create trigger tenant_offboarding_retain_billing_settlements")[0] ?? "";
		expect(replacement).not.toMatch(/delete from public\.billing_settlements/);
		expect(offboardingRetentionMigration).not.toContain(
			"drop trigger if exists billing_settlements_append_only",
		);
	});

	it("records the historical bounded retention contract superseded by hardening", () => {
		// This migration originally assigned both stores a bounded lifetime.
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
