// API key hygiene rules for /v1/api-keys (CP-8): type prefixes, bounded
// labels and key lifetimes. Kept free of Deno/npm imports so the rules can be
// unit-tested and reused by the handler harnesses.

export type ApiKeyType = "tenant" | "ingest:browser_guard";

// Same bounds as the api_keys_label_check constraint.
export const MAX_LABEL_LENGTH = 100;
// Upper bound for a requested or default key lifetime.
export const MAX_KEY_TTL_DAYS = 730;
export const DEFAULT_KEY_TTL_DAYS = 365;
export const DEFAULT_TTL_ENV = "AIDR_APIKEY_DEFAULT_TTL_DAYS";
const DAY_MS = 86_400_000;

/** Prefix per key type, so operators and secret scanners classify a key correctly. */
export function apiKeyPrefix(scope: ApiKeyType): string {
	return scope === "tenant" ? "aidr_live_" : "aidr_ingest_";
}

/** Validate a label: `{ ok: false }` when invalid; undefined/null/blank means "no label". */
export function parseLabel(value: unknown): { ok: true; value: string | null } | { ok: false } {
	if (value === undefined || value === null) return { ok: true, value: null };
	if (typeof value !== "string") return { ok: false };
	const label = value.trim();
	if (label === "") return { ok: true, value: null };
	// deno-lint-ignore no-control-regex
	if ([...label].length > MAX_LABEL_LENGTH || /[\u0000-\u001f\u007f-\u009f]/.test(label)) return { ok: false };
	return { ok: true, value: label };
}

/** Configured default lifetime in days; null when the setting is malformed. */
export function defaultKeyTtlDays(raw: string | undefined | null): number | null {
	if (raw === undefined || raw === null) return DEFAULT_KEY_TTL_DAYS;
	if (!/^\d{1,4}$/.test(raw.trim())) return null;
	const days = Number(raw.trim());
	return days >= 1 && days <= MAX_KEY_TTL_DAYS ? days : null;
}

/**
 * Resolve the requested expiry. Omitted -> default lifetime; explicit null ->
 * non-expiring; an integer 1..730 -> that many days. Anything else is refused.
 */
export function resolveExpiry(
	body: Record<string, unknown>,
	defaultDays: number,
	now = Date.now(),
): { ok: true; expiresAt: string | null } | { ok: false } {
	if (!("expires_in_days" in body)) return { ok: true, expiresAt: new Date(now + defaultDays * DAY_MS).toISOString() };
	const days = body.expires_in_days;
	if (days === null) return { ok: true, expiresAt: null };
	if (typeof days !== "number" || !Number.isSafeInteger(days) || days < 1 || days > MAX_KEY_TTL_DAYS) return { ok: false };
	return { ok: true, expiresAt: new Date(now + days * DAY_MS).toISOString() };
}
