import { describe, expect, it } from "vitest";

import { acceptPack } from "../intel/acceptance.js";
import {
	LICENSE_REVOCATIONS_FORMAT,
	verifyLicenseRevocations,
} from "../intel/license-revocations.js";
import { IntelPackManifestSchema } from "../intel/schema.js";
import { LicenseVerificationError, verifyLicense } from "../license/verify.js";
import {
	devKey,
	licensePayload,
	registry,
	registryEntry,
	signDocument,
	signLicense,
} from "./license-fixtures.js";

const key = devKey("aidr-license-dev-1");
const other = devKey("aidr-license-dev-2");
const trusted = registry([registryEntry(key)]);
const inTerm = Date.parse("2027-03-01T00:00:00Z");
const license = signLicense(licensePayload(), key);
const verified = verifyLicense(license, { registry: trusted, now: inTerm });

const listPayload = (overrides: Record<string, unknown> = {}) => ({
	issued_at: "2027-02-01T00:00:00Z",
	sequence: 3,
	license_ids: ["LIC-2026-0001", "LIC-2026-0099"],
	...overrides,
});
const signList = (payload: unknown, signer = key, keyId = signer.keyId) =>
	signDocument(LICENSE_REVOCATIONS_FORMAT, payload, signer, keyId);

function codeOf(run: () => unknown): string | undefined {
	try {
		run();
	} catch (error) {
		expect(error).toBeInstanceOf(LicenseVerificationError);
		return (error as LicenseVerificationError).code;
	}
	return undefined;
}

const manifest = IntelPackManifestSchema.parse({
	pack_id: "aidr-intel",
	version: "2027.0201.1",
	issued_at: "2027-02-02T00:00:00Z",
	key_id: "k1",
});

describe("verifyLicenseRevocations", () => {
	it("verifies a signed list and returns its revoked license ids", () => {
		const list = verifyLicenseRevocations(signList(listPayload()), {
			registry: trusted,
			now: inTerm,
		});
		expect(list.sequence).toBe(3);
		expect(list.issuedAt).toBe("2027-02-01T00:00:00Z");
		expect([...list.licenseIds]).toEqual(["LIC-2026-0001", "LIC-2026-0099"]);
	});

	it("fails closed on tampering, foreign keys, other document kinds and bad fields", () => {
		const document = signList(listPayload());
		const tampered = {
			...document,
			payload: { ...(document.payload as Record<string, unknown>), license_ids: [] },
		};
		expect(codeOf(() => verifyLicenseRevocations(tampered, { registry: trusted }))).toBe(
			"bad_signature",
		);
		// Signed by a key outside the registry, whether it claims a trusted key id or not.
		expect(
			codeOf(() =>
				verifyLicenseRevocations(signList(listPayload(), other, key.keyId), { registry: trusted }),
			),
		).toBe("bad_signature");
		expect(
			codeOf(() => verifyLicenseRevocations(signList(listPayload(), other), { registry: trusted })),
		).toBe("unknown_key");
		// A license signature must never verify as a revocation list.
		expect(
			codeOf(() =>
				verifyLicenseRevocations(
					{ ...license, format: LICENSE_REVOCATIONS_FORMAT },
					{ registry: trusted },
				),
			),
		).toBe("bad_signature");
		// The embedded (shipped, empty) registry verifies nothing.
		expect(codeOf(() => verifyLicenseRevocations(document))).toBe("no_trusted_keys");
		for (const bad of [
			listPayload({ sequence: 0 }),
			listPayload({ license_ids: ["LIC-1", "LIC-1"] }),
			listPayload({ license_ids: ["../escape"] }),
			listPayload({ issued_at: "yesterday" }),
			{ ...listPayload(), extra: true },
			{ issued_at: "2027-02-01T00:00:00Z", license_ids: [] },
		]) {
			expect(codeOf(() => verifyLicenseRevocations(signList(bad), { registry: trusted }))).toBe(
				"invalid_payload",
			);
		}
	});
});

describe("acceptPack with a revocation list", () => {
	const revoked = verifyLicenseRevocations(signList(listPayload()), { registry: trusted });
	const notListed = verifyLicenseRevocations(
		signList(listPayload({ license_ids: ["LIC-2026-0099"] })),
		{ registry: trusted },
	);

	it("refuses new packs for a revoked license, even within its term", () => {
		expect(acceptPack(manifest, verified)).toEqual({ accepted: true });
		const refused = acceptPack(manifest, verified, { revocations: revoked });
		expect(refused).toMatchObject({ accepted: false, code: "license_revoked" });
		if (!refused.accepted) expect(refused.message).toMatch(/Installed rules keep enforcing/);
		expect(acceptPack(manifest, verified.payload, { revocations: revoked })).toMatchObject({
			code: "license_revoked",
		});
	});

	it("leaves other licenses and unlicensed generic packs alone", () => {
		expect(acceptPack(manifest, verified, { revocations: notListed })).toEqual({
			accepted: true,
		});
		expect(acceptPack(manifest, verified, { revocations: null })).toEqual({ accepted: true });
		expect(acceptPack(manifest, null, { revocations: revoked })).toEqual({ accepted: true });
	});
});
