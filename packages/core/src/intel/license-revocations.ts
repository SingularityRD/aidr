/**
 * Vendor-signed list of revoked licenses (`aidr-license-revocations-v1`).
 *
 * A revoked license receives no NEW update packs: `acceptPack` refuses a pack
 * for a license whose `license_id` is listed. It never removes or disables a
 * pack that is already installed, and it never affects detection; installed
 * rules keep enforcing (the same rule as for an expired license).
 *
 * Envelope and trust are the license ones (`../license/verify.ts`): the
 * signature covers `aidr-license-revocations-v1\n` + canonicalJson(payload) and
 * is made by a key from the `aidr-license-public-keys-v1` registry. The distinct
 * format prefix keeps a license or customer-packet signature from ever verifying
 * as a revocation list. Unknown, missing and malformed fields are refused, and
 * every failure throws (fail closed): a list that does not verify revokes
 * nothing and must not be read as "nothing is revoked" either, so callers refuse
 * the import instead of ignoring it.
 *
 * `sequence` orders lists: a caller holding a list keeps the one with the
 * higher sequence, so an older list cannot un-revoke a license.
 */
import {
	checkEnvelope,
	checkKeyWindow,
	isoTimestamp,
	isPlainObject,
	LicenseVerificationError,
	type LicenseVerifyOptions,
	nowMs,
	resolveRegistry,
	verifySignedEnvelope,
} from "../license/verify.js";

export const LICENSE_REVOCATIONS_FORMAT = "aidr-license-revocations-v1";

const LICENSE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PAYLOAD_KEYS = ["issued_at", "license_ids", "sequence"] as const;
/** Bounded by the 64 KiB signed-document limit shared with licenses. */
const MAX_REVOKED_LICENSES = 1000;

export interface LicenseRevocationsPayload {
	issued_at: string;
	sequence: number;
	license_ids: string[];
}

export interface VerifiedLicenseRevocations {
	keyId: string;
	issuedAt: string;
	sequence: number;
	licenseIds: ReadonlySet<string>;
}

function invalid(message: string): never {
	throw new LicenseVerificationError("invalid_payload", message);
}

function validatePayload(payload: unknown): LicenseRevocationsPayload & { issuedAtMs: number } {
	if (!isPlainObject(payload)) invalid("revocation list payload must be an object");
	const keys = Object.keys(payload).sort();
	const unknown = keys.filter((key) => !(PAYLOAD_KEYS as readonly string[]).includes(key));
	const missing = PAYLOAD_KEYS.filter((key) => !keys.includes(key));
	if (unknown.length)
		invalid(`revocation list payload has unknown field(s): ${unknown.join(", ")}`);
	if (missing.length) invalid(`revocation list payload is missing: ${missing.join(", ")}`);
	const p = payload as Record<string, unknown>;
	const issuedAtMs = isoTimestamp(p.issued_at, "issued_at", "invalid_payload");
	if (!Number.isSafeInteger(p.sequence) || (p.sequence as number) < 1)
		invalid("sequence must be a positive integer");
	const ids = p.license_ids;
	if (
		!Array.isArray(ids) ||
		ids.length > MAX_REVOKED_LICENSES ||
		ids.some((id) => typeof id !== "string" || !LICENSE_ID.test(id)) ||
		new Set(ids).size !== ids.length
	)
		invalid(
			`license_ids must be at most ${MAX_REVOKED_LICENSES} unique license ids of [A-Za-z0-9._-]`,
		);
	return {
		issued_at: p.issued_at as string,
		sequence: p.sequence as number,
		license_ids: ids as string[],
		issuedAtMs,
	};
}

/**
 * Verify an `aidr-license-revocations-v1` document against the license
 * public-key registry (default: the registry embedded at build time). Throws
 * `LicenseVerificationError` for anything that is not an authentic list.
 */
export function verifyLicenseRevocations(
	document: unknown,
	options: LicenseVerifyOptions = {},
): VerifiedLicenseRevocations {
	const now = nowMs(options.now);
	const envelope = checkEnvelope(document, LICENSE_REVOCATIONS_FORMAT, "revocation list");
	const registry = resolveRegistry(options.registry);
	const key = verifySignedEnvelope(
		envelope,
		LICENSE_REVOCATIONS_FORMAT,
		"revocation list",
		registry,
	);
	const payload = validatePayload(envelope.payload);
	checkKeyWindow(key, payload.issuedAtMs, now, "revocation list");
	return Object.freeze({
		keyId: envelope.keyId,
		issuedAt: payload.issued_at,
		sequence: payload.sequence,
		licenseIds: new Set(payload.license_ids),
	});
}
