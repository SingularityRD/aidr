// A stored reputation row is evidence only while its source timestamp is fresh.
// Match the signed offline feed's default 24-hour maximum age.
const MAX_REPUTATION_AGE_MS = 24 * 60 * 60 * 1000;

export function isFreshReputationRow(createdAt: unknown, nowMs = Date.now()): boolean {
	if (typeof createdAt !== "string") return false;
	const ageMs = nowMs - Date.parse(createdAt);
	return Number.isFinite(ageMs) && ageMs >= 0 && ageMs <= MAX_REPUTATION_AGE_MS;
}

export function reputationFreshUntil(createdAt: unknown): string | null {
	if (typeof createdAt !== "string") return null;
	const createdAtMs = Date.parse(createdAt);
	if (!Number.isFinite(createdAtMs)) return null;
	return new Date(createdAtMs + MAX_REPUTATION_AGE_MS).toISOString();
}
