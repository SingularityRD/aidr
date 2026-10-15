// The Edge license verifier (_shared/license.ts, WebCrypto) must agree with the
// operator CLI verifier (scripts/license-verify.mjs, node:crypto) on every
// vector: same lifecycle state for an authentic license, same refusal code for
// anything else, and the canonical digest over the same canonical JSON.
// DEV test keys only: generated in memory for every run.

import { createHash, generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
// @ts-expect-error JavaScript module without type declarations
import { publicKeyEntry, signLicense } from "../../../scripts/license-issue.mjs";
// @ts-expect-error JavaScript module without type declarations
import * as nodeVerifier from "../../../scripts/license-verify.mjs";
import {
	LicenseError,
	licenseCanonicalJson,
	licenseRegistryFromEnv,
	parseLicenseRegistry,
	verifyLicenseDocument,
} from "../_shared/license.ts";

const DAY = 24 * 60 * 60 * 1000;
const devKey = generateKeyPairSync("ed25519").privateKey;
const otherKey = generateKeyPairSync("ed25519").privateKey;
const retiredKey = generateKeyPairSync("ed25519").privateKey;

function payload(overrides: Record<string, unknown> = {}) {
	return {
		license_id: "LIC-2026-0001",
		customer: "Example Customer AG",
		customer_id: "example-ag",
		plan_id: "enterprise",
		seats: 250,
		features: ["managed_policy", "premium_intel"],
		deployment: "onprem",
		issued_at: "2026-09-01T00:00:00Z",
		not_before: "2026-09-01T00:00:00Z",
		expires_at: "2027-09-01T00:00:00Z",
		grace_days: 14,
		...overrides,
	};
}

const registryDocument = {
	format: "aidr-license-public-keys-v1",
	schema_version: 1,
	keys: [
		publicKeyEntry(devKey, { keyId: "dev-1", notBefore: "2026-01-01T00:00:00Z" }),
		publicKeyEntry(otherKey, { keyId: "revoked-1", notBefore: "2026-01-01T00:00:00Z", status: "revoked" }),
		publicKeyEntry(retiredKey, {
			keyId: "retired-1",
			notBefore: "2025-01-01T00:00:00Z",
			status: "retired",
			retiredAt: "2026-06-01T00:00:00Z",
		}),
	],
};

const signed = (terms: Record<string, unknown>, keyId = "dev-1", key = devKey) =>
	signLicense(payload(terms), { privateKey: key, keyId });

type Outcome = { status: string } | { code: string };

async function edgeOutcome(document: unknown, now: number): Promise<Outcome> {
	const registry = await parseLicenseRegistry(registryDocument);
	try {
		return { status: (await verifyLicenseDocument(document, registry, now)).status };
	} catch (error) {
		if (error instanceof LicenseError) return { code: error.code };
		throw error;
	}
}

function nodeOutcome(document: unknown, now: number): Outcome {
	const registry = nodeVerifier.parsePublicKeyRegistry(registryDocument);
	try {
		return { status: nodeVerifier.verifyLicense(document, { publicKeys: registry, now }).status };
	} catch (error) {
		if (error instanceof nodeVerifier.LicenseError) return { code: (error as { code: string }).code };
		throw error;
	}
}

const inTerm = Date.parse("2027-03-01T00:00:00Z");
const valid = signed({});

const vectors: Array<[string, unknown, number]> = [
	["valid", valid, inTerm],
	["grace", valid, Date.parse("2027-09-05T00:00:00Z")],
	["expired", valid, Date.parse("2027-10-01T00:00:00Z")],
	["not yet valid", signed({ not_before: "2026-12-01T00:00:00Z" }), Date.parse("2026-10-01T00:00:00Z")],
	["tampered seats", { ...valid, payload: { ...valid.payload, seats: 5000 } }, inTerm],
	["tampered expiry", { ...valid, payload: { ...valid.payload, expires_at: "2030-01-01T00:00:00Z" } }, inTerm],
	["unknown key", { ...valid, key_id: "nobody-1" }, inTerm],
	["revoked key", signed({}, "revoked-1", otherKey), inTerm],
	["signed by another key", signed({}, "dev-1", otherKey), inTerm],
	["retired key, issued before retirement", signed({ issued_at: "2026-05-01T00:00:00Z", not_before: "2026-05-01T00:00:00Z" }, "retired-1", retiredKey), inTerm],
	["retired key, issued after retirement", signed({}, "retired-1", retiredKey), inTerm],
	["retired key past acceptance", signed({ issued_at: "2026-05-01T00:00:00Z", not_before: "2026-05-01T00:00:00Z" }, "retired-1", retiredKey), Date.parse("2032-01-01T00:00:00Z")],
	["extra document field", { ...valid, note: "x" }, inTerm],
	["wrong format", { ...valid, format: "aidr-license-v2" }, inTerm],
	["short signature", { ...valid, sig: "AAAA" }, inTerm],
	["not an object", "license", inTerm],
	[
		"no customer id (older license)",
		signLicense(Object.fromEntries(Object.entries(payload()).filter(([key]) => key !== "customer_id")), {
			privateKey: devKey,
			keyId: "dev-1",
		}),
		inTerm,
	],
];

describe("license verifier parity (Edge vs operator CLI)", () => {
	it.each(vectors)("%s", async (_name, document, now) => {
		const clean = JSON.parse(JSON.stringify(document));
		expect(await edgeOutcome(clean, now)).toEqual(nodeOutcome(clean, now));
	});

	it("refuses an air-gapped license on a non-enterprise plan in both verifiers", async () => {
		// The issuer refuses to sign it, so sign the raw message directly.
		const { sign } = await import("node:crypto");
		const terms = payload({ deployment: "airgap", plan_id: "team" });
		const sig = sign(null, nodeVerifier.licenseSigningMessage(terms), devKey).toString("base64");
		const document = { format: "aidr-license-v1", key_id: "dev-1", payload: terms, sig };
		expect(await edgeOutcome(document, inTerm)).toEqual({ code: "plan_feature_required" });
		expect(nodeOutcome(document, inTerm)).toEqual({ code: "plan_feature_required" });
	});

	it("digests the canonical JSON of the whole document, independent of formatting", async () => {
		const registry = await parseLicenseRegistry(registryDocument);
		const reformatted = JSON.parse(JSON.stringify(valid, null, 4));
		reformatted.payload = Object.fromEntries(Object.entries(reformatted.payload).reverse());
		const verified = await verifyLicenseDocument(reformatted, registry, inTerm);
		const expected = createHash("sha256").update(nodeVerifier.canonicalJson(valid)).digest("hex");
		expect(verified.canonical_sha256).toBe(expected);
		expect(licenseCanonicalJson(reformatted)).toBe(nodeVerifier.canonicalJson(valid));
		expect(verified.grace_ends_at).toBe("2027-09-15T00:00:00.000Z");
	});

	it("reads the registry from AIDR_LICENSE_PUBLIC_KEYS_B64 and fails closed without it", async () => {
		expect(await licenseRegistryFromEnv(undefined)).toBeNull();
		expect(await licenseRegistryFromEnv("   ")).toBeNull();
		await expect(licenseRegistryFromEnv("not base64!")).rejects.toMatchObject({ code: "invalid_public_keys" });
		const b64 = Buffer.from(JSON.stringify(registryDocument)).toString("base64");
		const registry = await licenseRegistryFromEnv(b64);
		expect(registry?.size).toBe(3);
		const empty = await licenseRegistryFromEnv(
			Buffer.from(JSON.stringify({ ...registryDocument, keys: [] })).toString("base64"),
		);
		await expect(verifyLicenseDocument(valid, empty as never, inTerm)).rejects.toMatchObject({ code: "no_trusted_keys" });
	});

	it("the shipped registry parses in both verifiers", async () => {
		const { readFileSync } = await import("node:fs");
		const shipped = JSON.parse(readFileSync(nodeVerifier.DEFAULT_PUBLIC_KEYS_PATH, "utf8"));
		expect((await parseLicenseRegistry(shipped)).size).toBe(nodeVerifier.parsePublicKeyRegistry(shipped).size);
	});

	it("keeps the day arithmetic of the grace end", async () => {
		const registry = await parseLicenseRegistry(registryDocument);
		const license = signed({ grace_days: 0 });
		const atExpiry = Date.parse("2027-09-01T00:00:00Z");
		await expect(verifyLicenseDocument(license, registry, atExpiry - 1)).resolves.toMatchObject({ status: "valid", days_remaining: 1 });
		await expect(verifyLicenseDocument(license, registry, atExpiry)).resolves.toMatchObject({ status: "expired" });
		expect(DAY).toBe(86_400_000);
	});
});
