/**
 * Shared error for a detection leg that could not run.
 *
 * ## Why this type exists
 *
 * The reputation clients used to answer a failed request with an empty result
 * array. That made "the endpoint returned 401 because no API key is provisioned"
 * byte-for-byte identical to "the endpoint answered and found nothing", so every
 * consumer reported a clean result it had no basis for. The plugin scanner was
 * the worst case: it constructed the clients with no API key at all, swallowed
 * the 401 in `catch { /* Fail open *\/ }`, and reported scanned plugins as clean.
 *
 * An unavailable leg is a degradation, not a verdict. Detection internals are
 * still allowed to degrade - callers may catch this and continue - but the
 * failure now carries enough information to be reported honestly instead of
 * being silently rounded down to "clean".
 *
 * AMSI joins the vocabulary for the same reason. It used to live outside this
 * abstraction entirely: every failure path in `clients/amsi.ts` returned null,
 * so "a Windows host with no working AMSI backend" and "AMSI scanned the
 * content and found nothing" produced byte-for-byte identical verdicts.
 *
 * A host that does not support AMSI at all (neither native Windows nor WSL) is
 * NOT an unavailable leg - the leg does not exist there - and must stay silent.
 */

export type DetectionLeg = "url_reputation" | "file_reputation" | "amsi";

export class DetectionLegUnavailableError extends Error {
	readonly leg: DetectionLeg;
	/** HTTP status when the endpoint answered with an error. */
	readonly status?: number;
	/** Operator-readable reason. */
	readonly reason: string;
	/**
	 * Results from the batches that DID succeed.
	 *
	 * A multi-batch check can partially fail. Returning the successful batches and
	 * throwing away the fact that others failed would report "1 of 75 hashes
	 * checked, 1 malicious" as if the whole set had been covered. The results are
	 * carried here so a caller can keep the real detections while still recording
	 * that coverage was incomplete - the detections are evidence, the missing
	 * batches are a gap, and both must survive.
	 */
	readonly partialResults: unknown[];
	/** How many artifacts went unchecked because of this failure. */
	readonly uncheckedCount: number;

	constructor(
		leg: DetectionLeg,
		reason: string,
		status?: number,
		partialResults: unknown[] = [],
		uncheckedCount = 0,
	) {
		super(`Detection leg "${leg}" did not run: ${reason}`);
		this.name = "DetectionLegUnavailableError";
		this.leg = leg;
		this.reason = reason;
		this.status = status;
		this.partialResults = partialResults;
		this.uncheckedCount = uncheckedCount;
	}
}

/**
 * Describe an HTTP failure in operator terms. A 401/403 is called out
 * explicitly because that is the shape an unprovisioned or mistyped API key
 * produces, and it is the single most likely cause of a silently dead leg.
 */
export function describeHttpFailure(status: number): string {
	if (status === 401 || status === 403) {
		return `endpoint rejected the request as unauthenticated (HTTP ${status}); check the configured API key`;
	}
	if (status === 404) {
		return `endpoint not found (HTTP 404); the reputation service may not be deployed`;
	}
	if (status >= 500) {
		return `endpoint error (HTTP ${status})`;
	}
	return `unexpected HTTP ${status}`;
}
