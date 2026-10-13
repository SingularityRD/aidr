// Bounded parsing of the signed revocation feed's timing settings (CP-7).
//
// AIDR_REVOCATION_TTL_HOURS sets how long a signed list stays acceptable to a
// runtime; AIDR_REVOCATION_EPOCH is the monotonic revocation epoch. A typo used
// to produce an already-expired list (NaN -> 0 h), a list valid for years, or a
// silent epoch roll-back to 1. Like ingest/enroll (AIDR-011), a malformed or
// out-of-range value is now a configuration error that names the variable, and
// the feed refuses to sign anything until it is fixed.

import { ConfigurationError, type EnvReader } from "../_shared/config.ts";

export const REVOCATION_TTL_ENV = "AIDR_REVOCATION_TTL_HOURS";
export const REVOCATION_EPOCH_ENV = "AIDR_REVOCATION_EPOCH";
const DEFAULT_REVOCATION_TTL_HOURS = 24;
const MIN_REVOCATION_TTL_HOURS = 1;
/** One week: a signed list older than this must not omit a newer revocation. */
export const MAX_REVOCATION_TTL_HOURS = 168;
const DEFAULT_REVOCATION_EPOCH = 1;
/** Postgres integer range; runtimes compare the epoch as an integer. */
export const MAX_REVOCATION_EPOCH = 2_147_483_647;

export type RevocationTiming =
	| { ok: true; ttlHours: number; epoch: number }
	| { ok: false; error: ConfigurationError };

function boundedInteger(raw: string | undefined | null, fallback: number, min: number, max: number): number | null {
	if (raw === undefined || raw === null) return fallback;
	const text = raw.trim();
	if (!/^\d{1,10}$/.test(text)) return null;
	const value = Number(text);
	return Number.isSafeInteger(value) && value >= min && value <= max ? value : null;
}

export function revocationTiming(env: EnvReader): RevocationTiming {
	const ttlHours = boundedInteger(
		env(REVOCATION_TTL_ENV),
		DEFAULT_REVOCATION_TTL_HOURS,
		MIN_REVOCATION_TTL_HOURS,
		MAX_REVOCATION_TTL_HOURS,
	);
	const epoch = boundedInteger(env(REVOCATION_EPOCH_ENV), DEFAULT_REVOCATION_EPOCH, 1, MAX_REVOCATION_EPOCH);
	const invalid = [
		...(ttlHours === null ? [REVOCATION_TTL_ENV] : []),
		...(epoch === null ? [REVOCATION_EPOCH_ENV] : []),
	];
	if (invalid.length > 0 || ttlHours === null || epoch === null) {
		return { ok: false, error: new ConfigurationError({ invalid }) };
	}
	return { ok: true, ttlHours, epoch };
}
