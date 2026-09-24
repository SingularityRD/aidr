import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

const migration = readFileSync(
	new URL("../../migrations/20260923000022_billing_channel_intent_guard.sql", import.meta.url),
	"utf8",
);
const resubscriptionMigration = readFileSync(
	new URL("../../migrations/20260924000006_billing_resubscription_after_provider_close.sql", import.meta.url),
	"utf8",
);
const checkoutReplayMigration = readFileSync(
	new URL("../../migrations/20260924000011_billing_checkout_exact_replay.sql", import.meta.url),
	"utf8",
);
const claim = migration.split("create or replace function public.claim_billing_checkout_intent(")[1]?.split("\n$$;")[0] ?? "";
const invoiceGuard = migration.split("create or replace function app.prevent_invoice_provider_billing_overlap()")[1]?.split("\n$$;")[0] ?? "";
const providerGuard = migration.split("create or replace function app.prevent_subscription_provider_overlap()")[1]?.split("\n$$;")[0] ?? "";

describe("exclusive tenant billing channel", () => {
	it("rejects a pre-existing paid-invoice/checkout-intent overlap at migration time", () => {
		expect(migration).toMatch(/enterprise_invoice_approvals a\s+join public\.billing_checkout_intents i on i\.tenant_id = a\.tenant_id/);
		expect(migration).toContain("existing_billing_channel_conflict");
	});

	it("serializes both channel decisions on the same tenant lock", () => {
		const lock = "pg_advisory_xact_lock(hashtextextended(p_tenant_id::text, 2617))";
		expect(claim).toContain(lock);
		expect(invoiceGuard).toContain("pg_advisory_xact_lock(hashtextextended(new.tenant_id::text, 2617))");
		expect(claim.indexOf(lock)).toBeLessThan(claim.indexOf("select * into v_intent"));
	});

	it("blocks an invoice while any provider checkout remains payable or paid", () => {
		expect(invoiceGuard).toMatch(/public\.billing_checkout_intents\s+where tenant_id = new\.tenant_id/);
		expect(invoiceGuard).toContain("billing_channel_conflict");
	});

	it("blocks provider checkout after invoice payment or another checkout intent", () => {
		expect(claim).toMatch(/public\.enterprise_invoice_approvals\s+where tenant_id = p_tenant_id and status = 'paid'/);
		expect(claim).toMatch(/public\.billing_checkout_intents\s+where tenant_id = p_tenant_id and request_id <> p_request_id/);
		expect(claim).toMatch(/public\.subscriptions\s+where tenant_id = p_tenant_id and extra_agents > 0/);
		expect(claim).toContain("billing_channel_conflict");
	});

	it("requires the old online provider allocation to be closed before switching providers", () => {
		expect(migration).toContain("existing_billing_provider_conflict");
		expect(migration).toContain("subscriptions_provider_overlap_guard");
		expect(providerGuard).toContain("s.provider <> new.provider");
		expect(providerGuard).toContain("s.id is distinct from new.id");
		expect(providerGuard).toContain("old.provider <> new.provider");
		expect(providerGuard).toContain("s.extra_agents > 0");
		expect(providerGuard).toContain("billing_provider_conflict");
	});

	it("preserves same-key replay and never silently expires a payable intent", () => {
		expect(claim).toContain("v_intent.request_hash <> p_request_hash");
		expect(claim).toContain("v_existing := found;");
		expect(claim).toContain("if v_existing then");
		expect(migration).not.toMatch(/delete\s+from\s+public\.billing_checkout_intents/i);
		expect(migration).not.toMatch(/expires_at\s*<=\s*now\(\)/i);
	});

	it("reopens the channel only after a signed, provider-backed terminal transition", () => {
		const resubscriptionClaim = resubscriptionMigration
			.split("create or replace function public.claim_billing_checkout_intent(")[1]
			?.split("\n$$;")[0] ?? "";
		expect(resubscriptionMigration).toContain("create or replace function public.close_billing_checkout_intent(");
		expect(resubscriptionMigration).toContain("v_subscription.provider_event_id is distinct from p_provider_event_id");
		expect(resubscriptionMigration).toContain("v_subscription.extra_agents <> 0");
		expect(resubscriptionMigration).toContain("v_intent.status <> 'checkout_created'");
		expect(resubscriptionMigration).toContain("billing_provider_payments where settlement_id = p_settlement_id");
		expect(resubscriptionClaim).toContain("status <> 'closed'");
		expect(resubscriptionMigration).toContain("status <> 'closed'");
		expect(resubscriptionMigration).not.toMatch(/delete\s+from\s+public\.billing_checkout_intents/i);
		expect(resubscriptionMigration).not.toMatch(/expires_at\s*<=\s*now\(\)/i);
	});

	it("returns an exact paid-intent replay before checking active channel conflicts", () => {
		const replayClaim = checkoutReplayMigration
			.split("create or replace function public.claim_billing_checkout_intent(")[1]
			?.split("\n$$;")[0] ?? "";
		const replay = replayClaim.indexOf("if v_existing then");
		const conflictGuard = replayClaim.indexOf("if exists (");
		expect(replay).toBeGreaterThanOrEqual(0);
		expect(conflictGuard).toBeGreaterThan(replay);
		expect(replayClaim).toContain("v_intent.status");
		expect(replayClaim).toContain("billing_channel_conflict");
	});
});
