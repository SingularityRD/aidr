export const DEFAULT_PACK_URL_TTL_SECONDS = 600;
export const MIN_PACK_URL_TTL_SECONDS = 60;
export const MAX_PACK_URL_TTL_SECONDS = 3_600;
export const MAX_PACKS_PER_MANIFEST = 50;

/** Keep storage credentials short-lived even when deployment configuration is wrong. */
export function packUrlTtlSeconds(raw: string | undefined): number {
	const parsed = Number(raw);
	if (!Number.isFinite(parsed)) return DEFAULT_PACK_URL_TTL_SECONDS;
	return Math.min(MAX_PACK_URL_TTL_SECONDS, Math.max(MIN_PACK_URL_TTL_SECONDS, Math.floor(parsed)));
}

/** Cap a storage URL by pack lifetime, leaving five seconds for signing latency. */
export function packSigningTtlSeconds(expiresAt: unknown, configuredTtl: number, now = Date.now()): number | null {
	if (expiresAt === null) return configuredTtl;
	if (typeof expiresAt !== "string") return null;
	const remaining = Math.floor((Date.parse(expiresAt) - now) / 1_000) - 5;
	return Number.isFinite(remaining) && remaining >= 1 ? Math.min(configuredTtl, remaining) : null;
}

/** Validate the database result shape and put a hard ceiling on signing work. */
export function boundedPackCandidates(value: unknown): unknown[] | null {
	if (value === null) return [];
	if (!Array.isArray(value)) return null;
	return value.slice(0, MAX_PACKS_PER_MANIFEST);
}
