// Bounded overlap rotation for hash-only bearer secrets (API keys and
// enrollment tokens).
//
// A rotation replaces the stored hash and keeps the retired hash in
// `previous_hash`/`previous_hash_expires_at` so a caller that is mid-request
// with the old secret is not cut off. The window mirrors the SCIM token
// overlap (`20260912000012_scim_directory.sql`): it is time bounded, and it can
// never be longer than the retired secret's own remaining validity, so a
// rotation never extends a credential's life.

export const ROTATION_OVERLAP_DEFAULT_HOURS = 24;
export const ROTATION_OVERLAP_MAX_HOURS = 24 * 7;

/** Clamp an operator-supplied overlap into the reviewed 1 hour .. 7 day range. */
export function boundedOverlapHours(value: unknown): number {
	const hours = typeof value === "number" ? value : Number(value);
	if (!Number.isFinite(hours)) return ROTATION_OVERLAP_DEFAULT_HOURS;
	return Math.max(1, Math.min(ROTATION_OVERLAP_MAX_HOURS, Math.floor(hours)));
}

export interface RotationPlan {
	/** When the stored hash was replaced. */
	rotatedAt: string;
	/**
	 * The retired hash's deadline, or null when the retired secret was already
	 * expired, in which case there is nothing to overlap.
	 */
	previousHashExpiresAt: string | null;
}

/**
 * Bound the retired secret's window.
 *
 * `previousExpiresAtIso` is the retired secret's own expiry (an enrollment
 * token), or null when it does not expire on its own (an API key).
 */
export function rotationPlan(
	nowMs: number,
	overlapHours: number,
	previousExpiresAtIso: string | null,
): RotationPlan {
	const rotatedAt = new Date(nowMs).toISOString();
	const requested = nowMs + boundedOverlapHours(overlapHours) * 60 * 60 * 1000;
	// A null expiry means the retired secret has no lifetime of its own (an API
	// key). An unparseable expiry is treated as already expired: fail closed
	// instead of inventing a window.
	let ownExpiry = Number.POSITIVE_INFINITY;
	if (previousExpiresAtIso !== null) {
		const parsed = Date.parse(previousExpiresAtIso);
		ownExpiry = Number.isFinite(parsed) ? parsed : nowMs;
	}
	const deadline = Math.min(requested, ownExpiry);
	if (!(deadline > nowMs)) return { rotatedAt, previousHashExpiresAt: null };
	return { rotatedAt, previousHashExpiresAt: new Date(deadline).toISOString() };
}

export interface StoredRotationRow {
	previous_hash?: unknown;
	previous_hash_expires_at?: unknown;
}

/**
 * True only while a retired secret is still inside its recorded window. The
 * presented hash must be the recorded predecessor: a hash that was never
 * recorded (or was already superseded) is refused. Accepts a raw database
 * value so callers can pass a query result without narrowing it first.
 */
export function retiredSecretActive(row: unknown, presentedHash: string, nowMs: number): boolean {
	if (!row || typeof row !== "object" || Array.isArray(row)) return false;
	const recorded = row as StoredRotationRow;
	if (typeof recorded.previous_hash !== "string" || recorded.previous_hash !== presentedHash) {
		return false;
	}
	const expiresAt =
		typeof recorded.previous_hash_expires_at === "string"
			? Date.parse(recorded.previous_hash_expires_at)
			: Number.NaN;
	return Number.isFinite(expiresAt) && expiresAt > nowMs;
}
