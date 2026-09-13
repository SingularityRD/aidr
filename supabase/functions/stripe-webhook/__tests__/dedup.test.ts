import { describe, expect, it } from "vitest";
import {
	claimStripeEvent,
	releaseStripeEvent,
	STRIPE_WEBHOOK_PROVIDER,
	WebhookDedupUnavailableError,
	type WebhookEventRecorder,
} from "../dedup.ts";

/** In-memory stand-in for public.billing_webhook_events (event_id is the key). */
function createMemoryRecorder(): WebhookEventRecorder & { rows: Map<string, unknown> } {
	const rows = new Map<string, unknown>();
	return {
		rows,
		async record(provider: string, eventId: string, payload: unknown) {
			if (provider !== STRIPE_WEBHOOK_PROVIDER) throw new Error("unexpected provider");
			if (rows.has(eventId)) return false;
			rows.set(eventId, payload);
			return true;
		},
		async release(eventId: string) {
			rows.delete(eventId);
		},
	};
}

describe("stripe webhook event deduplication", () => {
	it("claims a new event id and deduplicates a replayed delivery", async () => {
		const recorder = createMemoryRecorder();
		const payload = { id: "evt_replay_1", type: "invoice.paid" };

		const first = await claimStripeEvent(recorder, "evt_replay_1", payload);
		const replay = await claimStripeEvent(recorder, "evt_replay_1", payload);

		expect(first.claimed).toBe(true);
		expect(replay.claimed).toBe(false);
		expect(recorder.rows.size).toBe(1);
	});

	it("deduplicates a replay even when the body is resent byte-identical", async () => {
		const recorder = createMemoryRecorder();
		const body = JSON.stringify({ id: "evt_replay_2", type: "customer.subscription.deleted" });

		await claimStripeEvent(recorder, "evt_replay_2", JSON.parse(body));
		const replay = await claimStripeEvent(recorder, "evt_replay_2", JSON.parse(body));

		expect(replay.claimed).toBe(false);
	});

	it("claims distinct event ids independently", async () => {
		const recorder = createMemoryRecorder();

		expect((await claimStripeEvent(recorder, "evt_a", {})).claimed).toBe(true);
		expect((await claimStripeEvent(recorder, "evt_b", {})).claimed).toBe(true);
	});

	it("releases a claim so a provider retry is processed", async () => {
		const recorder = createMemoryRecorder();

		await claimStripeEvent(recorder, "evt_retry", {});
		expect((await claimStripeEvent(recorder, "evt_retry", {})).claimed).toBe(false);

		await releaseStripeEvent(recorder, "evt_retry");

		expect((await claimStripeEvent(recorder, "evt_retry", {})).claimed).toBe(true);
	});

	it("never throws from a failed release", async () => {
		const recorder: WebhookEventRecorder = {
			async record() {
				return true;
			},
			async release() {
				throw new Error("database unavailable");
			},
		};

		await expect(releaseStripeEvent(recorder, "evt_x")).resolves.toBeUndefined();
	});

	it("fails closed when the dedup store is unavailable", async () => {
		const recorder: WebhookEventRecorder = {
			async record() {
				throw new WebhookDedupUnavailableError();
			},
			async release() {},
		};

		await expect(claimStripeEvent(recorder, "evt_x", {})).rejects.toBeInstanceOf(
			WebhookDedupUnavailableError,
		);
	});
});
