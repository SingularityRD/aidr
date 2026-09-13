// @vitest-environment jsdom

// Regression guards for the Lemon Squeezy -> Stripe migration.
//
// The removed Lemon Squeezy path shipped two defects: an Edge Function webhook
// with no signature verification and a client-side `verifyWebhookSignature`
// that returned `true` unconditionally. These tests pin the contract that
// replaced it: invoice-first default, Stripe as the only self-service provider,
// and no webhook "verification" reachable from the browser bundle.

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("../lib/supabase", () => ({
	supabase: { functions: { invoke: vi.fn() } },
}));

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

const billingModule = await import("../billing/providers");
const providerSelector = await import("../billing/provider-selector");
const paymentRouter = await import("../billing/payment-router");

afterEach(() => {
	vi.unstubAllEnvs();
	vi.resetModules();
	vi.clearAllMocks();
});

describe("billing provider selection (invoice-first default)", () => {
	it("advertises no self-service provider in the default invoice mode", () => {
		expect(providerSelector.buildProviderList("US")).toEqual([]);
		expect(paymentRouter.getAvailableProviders()).toEqual([]);
		expect(providerSelector.getPaymentButtonText("stripe", "US")).toBe(
			"Request enterprise invoice",
		);
	});

	it("offers Stripe and only Stripe when self-service is explicitly enabled", async () => {
		vi.resetModules();
		vi.stubEnv("VITE_AIDR_COMMERCIAL_MODE", "self-service");
		const selectors = await import("../billing/provider-selector");
		const router = await import("../billing/payment-router");

		const providers = selectors.buildProviderList("US");
		expect(providers).toHaveLength(1);
		expect(providers[0]?.id).toBe("stripe");
		expect(providers[0]?.name).toContain("Stripe");
		expect(JSON.stringify(providers)).not.toMatch(/lemon/i);

		expect(router.getAvailableProviders().map((provider) => provider.id)).toEqual(["stripe"]);
		expect(router.getRegionConfig().primary).toBe("stripe");
		expect(selectors.getPaymentButtonText("stripe", "US")).toBe("Subscribe with Stripe");
	});
});

describe("billing module exports", () => {
	it("exposes no client-side webhook signature verifier", () => {
		const exports = Object.keys(billingModule);
		expect(exports).not.toContain("verifyWebhookSignature");
		expect(exports).toContain("createCheckout");
	});

	it("uses tenant-bound server checkout and keeps secret-only actions closed", async () => {
		vi.resetModules();
		vi.stubEnv("VITE_AIDR_COMMERCIAL_MODE", "self-service");
		const client = await import("../billing/stripe-client");
		const { supabase } = await import("../lib/supabase");
		const invoke = supabase.functions.invoke as ReturnType<typeof vi.fn>;
		invoke.mockResolvedValue({
			data: {
				ok: true,
				checkout_id: "cs_1",
				checkout_url: "https://checkout.stripe.com/c/pay/cs_1",
			},
			error: null,
		});

		await expect(client.createCheckout("user", "a@b.invalid", 1, "monthly")).rejects.toThrow(
			/valid tenant.*server-side checkout/i,
		);
		await expect(
			client.createCheckout(
				"user",
				"a@b.invalid",
				1,
				"monthly",
				undefined,
				"11111111-1111-4111-8111-111111111111",
				"request_1234567890",
			),
		).resolves.toEqual({
			checkoutUrl: "https://checkout.stripe.com/c/pay/cs_1",
			checkoutId: "cs_1",
		});
		expect(invoke).toHaveBeenCalledWith("billing-checkout", {
			body: {
				tenant_id: "11111111-1111-4111-8111-111111111111",
				seats: 1,
				plan: "monthly",
				request_id: "request_1234567890",
			},
		});
		await expect(client.cancelSubscription("sub_1")).rejects.toThrow(/server-side/i);
		await expect(client.getUserSubscriptions("a@b.invalid")).rejects.toThrow(/server-side/i);
		await expect(client.createCustomerPortal("cus_1")).rejects.toThrow(/server-side/i);
	});

	it("keeps self-service checkout disabled by default", async () => {
		vi.resetModules();
		const client = await import("../billing/stripe-client");

		await expect(client.createCheckout("user", "a@b.invalid", 1, "monthly")).rejects.toThrow(
			/disabled for the direct-GA release/i,
		);
	});
});

describe("lemon squeezy removal", () => {
	it("deleted the unverified lemon-webhook Edge Function", () => {
		const lemonDir = resolve(
			REPO_ROOT,
			"packages",
			"dashboard",
			"supabase",
			"functions",
			"lemon-webhook",
		);
		expect(existsSync(lemonDir)).toBe(false);
	});

	it("deleted the lemon billing client", () => {
		const lemonClient = resolve(
			REPO_ROOT,
			"packages",
			"dashboard",
			"src",
			"billing",
			"lemon-client.ts",
		);
		expect(existsSync(lemonClient)).toBe(false);
	});
});
