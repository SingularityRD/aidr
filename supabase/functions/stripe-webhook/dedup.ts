// Event-id deduplication for the Stripe webhook (pure, injectable).
//
// Stripe retries deliveries, and an attacker who captures a valid request can
// replay it. Both cases are handled by claiming the event id in
// public.billing_webhook_events (via the SECURITY DEFINER RPC
// `record_billing_webhook_event`, which is the same concurrency boundary the
// Paddle handler uses) BEFORE any state is written.
//
// The recorder is injected so the claim/release semantics are unit-testable
// without Deno or a database.

export const STRIPE_WEBHOOK_PROVIDER = "stripe";

/**
 * Raised when the dedup store cannot be reached. The handler maps it to a 5xx
 * and refuses to write anything, because processing without a dedup guarantee
 * would let a replay apply twice.
 */
export class WebhookDedupUnavailableError extends Error {
	constructor() {
		super("webhook_dedup_unavailable");
		this.name = "WebhookDedupUnavailableError";
	}
}

export interface WebhookEventRecorder {
	/**
	 * Insert-if-absent. Must resolve `true` exactly once per event id, and
	 * `false` for every later delivery of that same id.
	 */
	record(provider: string, eventId: string, payload: unknown): Promise<boolean>;
	/** Release a failed claim so the provider's retry can be processed. */
	release(eventId: string): Promise<void>;
}

export interface DedupClaim {
	/** True when this delivery is the first one seen for the event id. */
	claimed: boolean;
}

/**
 * Claim a Stripe event id.
 *
 * A claim is taken before any write; callers must treat `claimed === false` as
 * "already processed" and return success without touching state.
 */
export async function claimStripeEvent(
	recorder: WebhookEventRecorder,
	eventId: string,
	payload: unknown,
): Promise<DedupClaim> {
	const claimed = await recorder.record(STRIPE_WEBHOOK_PROVIDER, eventId, payload);
	return { claimed: claimed === true };
}

/**
 * Release a claim after a processing failure.
 *
 * Every write performed by the handler after the claim is an idempotent upsert,
 * so letting Stripe retry is safe; keeping the claim would drop the event
 * permanently.
 */
export async function releaseStripeEvent(
	recorder: WebhookEventRecorder,
	eventId: string,
): Promise<void> {
	try {
		await recorder.release(eventId);
	} catch {
		// A failed release must never mask the original processing error.
	}
}
