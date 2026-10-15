/**
 * License-bound acceptance of NEW update packs.
 *
 * Called before a pack version is activated or imported, never when an already
 * active pack is loaded: installed packs keep enforcing whatever the license
 * state (only revocation of a signing key removes one, in loader.ts).
 *
 * Only signed times are compared, never the local clock: a pack is within the
 * license term when its signed `issued_at` is at or before the license's
 * `expires_at + grace_days`. Rolling the endpoint clock back therefore does not
 * admit a pack issued after the term, and a slow-to-arrive pack issued during
 * the term is still accepted after it.
 *
 * A license listed in a verified `aidr-license-revocations-v1` list
 * (./license-revocations.ts) receives no new packs at all. Revocation, like the
 * term, only gates what is accepted next; it never removes an installed pack.
 */
import {
	type LicenseDocument,
	type LicensePayload,
	licenseTermEndMs,
	type VerifiedLicense,
} from "../customer-license/verify.js";
import type { VerifiedLicenseRevocations } from "./license-revocations.js";
import type { IntelPackManifest } from "./schema.js";

export type PackRefusalCode =
	| "pack_audience_mismatch"
	| "license_term_ended"
	| "pack_audience_requires_license"
	| "license_revoked";

export type PackAcceptance =
	| { accepted: true }
	| { accepted: false; code: PackRefusalCode; message: string };

type PackTerms = Pick<IntelPackManifest, "pack_id" | "version" | "issued_at" | "audience">;

export interface AcceptPackOptions {
	/** A verified revocation list (`verifyLicenseRevocations`); null or absent revokes nothing. */
	revocations?: VerifiedLicenseRevocations | null;
}

/**
 * Decide whether a signed pack manifest may be activated under `license`
 * (a verified license, its document or its payload), or with no license.
 */
export function acceptPack(
	manifest: PackTerms,
	license: VerifiedLicense | LicenseDocument | LicensePayload | null,
	options: AcceptPackOptions = {},
): PackAcceptance {
	const label = `pack ${manifest.pack_id}@${manifest.version}`;
	const audience = manifest.audience?.customer_ids;
	if (license === null) {
		if (audience !== undefined) {
			return {
				accepted: false,
				code: "pack_audience_requires_license",
				message: `${label} is issued for specific customers; install your license to accept it`,
			};
		}
		return { accepted: true };
	}
	const payload: LicensePayload = "payload" in license ? license.payload : license;
	if (options.revocations?.licenseIds.has(payload.license_id)) {
		return {
			accepted: false,
			code: "license_revoked",
			message: `${label} is refused: license ${payload.license_id} is revoked (revocation list #${options.revocations.sequence}, ${options.revocations.issuedAt}). Installed rules keep enforcing.`,
		};
	}
	if (
		audience !== undefined &&
		(payload.customer_id === undefined || !audience.includes(payload.customer_id))
	) {
		return {
			accepted: false,
			code: "pack_audience_mismatch",
			message: `${label} is not issued for this customer (${payload.customer_id ?? "no customer id in the license"})`,
		};
	}
	const issuedAt = Date.parse(manifest.issued_at);
	const termEnd = licenseTermEndMs(payload);
	// An unreadable time cannot be shown to fall inside the term: refuse.
	if (!Number.isFinite(issuedAt) || !Number.isFinite(termEnd) || issuedAt > termEnd) {
		return {
			accepted: false,
			code: "license_term_ended",
			message: `${label} was issued at ${manifest.issued_at}, after the license's update term ended (${Number.isFinite(termEnd) ? new Date(termEnd).toISOString() : "unknown"}); renew the license to receive it. Installed rules keep enforcing.`,
		};
	}
	return { accepted: true };
}
