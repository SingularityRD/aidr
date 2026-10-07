// Per-isolate cache for the entitlement-signer healthcheck.
//
// /enroll and /ingest refuse service while a configured Ed25519 signer cannot
// sign. Importing the PKCS#8 key and signing a probe on every request lets an
// unauthenticated caller buy that work for free, so the result is cached per
// isolate. A failure is cached too (briefly), so the function still fails
// closed, and every real entitlement is still signed (and checked) on its own.

const HEALTHY_TTL_MS = 60_000;
const UNHEALTHY_TTL_MS = 5_000;

type Entry = { identity: string; healthy: boolean; until: number };
let cached: Entry | null = null;

/**
 * `identity` names the signer configuration (key id + key material); a change
 * invalidates the cache. `probe` must return true only after a real signature.
 */
export async function signerHealthy(
	identity: string,
	probe: () => Promise<boolean>,
	now: () => number = Date.now,
): Promise<boolean> {
	const current = cached;
	if (current && current.identity === identity && now() < current.until) return current.healthy;
	let healthy = false;
	try {
		healthy = (await probe()) === true;
	} catch {
		healthy = false;
	}
	cached = { identity, healthy, until: now() + (healthy ? HEALTHY_TTL_MS : UNHEALTHY_TTL_MS) };
	return healthy;
}

/** Test seam: forget the cached result. */
export function resetSignerHealthCache(): void {
	cached = null;
}
