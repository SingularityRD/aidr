// Fleet enrollment key contract (C3), shared by `fleet-keys` (issue/list/revoke)
// and `enroll` (exchange). Schema and RPCs:
// supabase/migrations/20261014000210_fleet_enrollment_keys.sql.
//
// A fleet key is a multi-use, team-scoped, seat-capped, expiring and revocable
// secret an administrator distributes through machine policy
// (`enrollment_key` in HKLM\SOFTWARE\Policies\Singularity AIDR or
// /etc/singularity-aidr/managed.json). `/v1/enroll` accepts it wherever it
// accepts a single-use `aidr_enroll_` code.

const FLEET_KEY_PREFIX = "aidr_fleet_";
/** 32 random bytes, base64url without padding. */
const FLEET_KEY_PATTERN = /^aidr_fleet_[A-Za-z0-9_-]{43}$/;

const FLEET_KEY_MAX_SEAT_CAP = 100_000;
const FLEET_KEY_MAX_TTL_DAYS = 365;
const FLEET_KEY_DEFAULT_TTL_DAYS = 90;
const MAX_LABEL_LENGTH = 100;

/** Default per-key exchange budget: a 500+ machine rollout finishes in minutes. */
const FLEET_ENROLL_DEFAULT_RL_PER_MIN = 600;

/** Routes a bearer value to the fleet path by prefix; the database decides validity. */
export function isFleetKeyBearer(token: string): boolean {
	return token.startsWith(FLEET_KEY_PREFIX);
}

export function isWellFormedFleetKey(token: string): boolean {
	return FLEET_KEY_PATTERN.test(token);
}

function base64Url(bytes: Uint8Array): string {
	let bin = "";
	for (const b of bytes) bin += String.fromCharCode(b);
	return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

export function randomFleetKey(): string {
	const raw = new Uint8Array(32);
	crypto.getRandomValues(raw);
	return `${FLEET_KEY_PREFIX}${base64Url(raw)}`;
}

/** Last four characters, stored so an administrator can tell keys apart. */
export function fleetKeyHint(key: string): string {
	return key.slice(-4);
}

/**
 * Operator-configured per-key exchange budget. A malformed or out-of-range
 * value is a configuration error (the caller answers 503), never "unlimited".
 */
export function fleetEnrollRateLimit(raw: string | undefined): number | null {
	if (raw === undefined || raw.trim() === "") return FLEET_ENROLL_DEFAULT_RL_PER_MIN;
	if (!/^[1-9]\d{0,5}$/.test(raw.trim())) return null;
	const value = Number(raw.trim());
	return value <= 100_000 ? value : null;
}

export type FleetKeyCreate = { label: string | null; seatCap: number; ttlDays: number };

/** Validates a create request; returns an error code for a 400 answer. */
export function validateFleetKeyCreate(
	body: Record<string, unknown>,
): { ok: true; value: FleetKeyCreate } | { ok: false; error: string } {
	let label: string | null = null;
	if (body.label !== undefined && body.label !== null) {
		if (typeof body.label !== "string") return { ok: false, error: "invalid_label" };
		const trimmed = body.label.trim();
		if ([...trimmed].length > MAX_LABEL_LENGTH || /[\u0000-\u001f\u007f-\u009f]/.test(trimmed)) {
			return { ok: false, error: "invalid_label" };
		}
		label = trimmed || null;
	}
	const seatCap = body.seat_cap;
	if (typeof seatCap !== "number" || !Number.isSafeInteger(seatCap) || seatCap < 1
		|| seatCap > FLEET_KEY_MAX_SEAT_CAP) {
		return { ok: false, error: "invalid_seat_cap" };
	}
	const ttlRaw = body.ttl_days ?? FLEET_KEY_DEFAULT_TTL_DAYS;
	if (typeof ttlRaw !== "number" || !Number.isSafeInteger(ttlRaw) || ttlRaw < 1
		|| ttlRaw > FLEET_KEY_MAX_TTL_DAYS) {
		return { ok: false, error: "invalid_ttl_days" };
	}
	return { ok: true, value: { label, seatCap, ttlDays: ttlRaw } };
}
