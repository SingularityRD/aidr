/**
 * Signed license / customer-packet fixtures generated in-test.
 *
 * DEV test keys only: generated in memory for every run, never written to the
 * shipped registry. The signing rules mirror scripts/license-issue.mjs and
 * scripts/customer-packet-issue.mjs (format line + canonical JSON of the payload).
 */
import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";

import { licenseCanonicalJson } from "../customer-license/verify.js";

export const DAY = 24 * 60 * 60 * 1000;

export interface DevKey {
	keyId: string;
	privateKey: KeyObject;
	publicPem: string;
}

export function devKey(keyId: string): DevKey {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return {
		keyId,
		privateKey,
		publicPem: publicKey.export({ type: "spki", format: "pem" }).toString(),
	};
}

export function registryEntry(key: DevKey, overrides: Record<string, unknown> = {}) {
	return {
		key_id: key.keyId,
		algorithm: "ed25519",
		public_key_pem: key.publicPem,
		not_before: "2026-01-01T00:00:00Z",
		not_after: null,
		status: "active",
		...overrides,
	};
}

export function registry(entries: unknown[]) {
	return { format: "aidr-license-public-keys-v1", schema_version: 1, keys: entries };
}

export function licensePayload(overrides: Record<string, unknown> = {}) {
	return {
		license_id: "LIC-2026-0001",
		customer: "Example Customer AG",
		customer_id: "example-co",
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

export function signDocument(format: string, payload: unknown, key: DevKey, keyId = key.keyId) {
	const message = Buffer.from(`${format}\n${licenseCanonicalJson(payload)}`, "utf8");
	return {
		format,
		key_id: keyId,
		payload,
		sig: sign(null, message, key.privateKey).toString("base64"),
	};
}

export function signLicense(payload: unknown, key: DevKey) {
	return signDocument("aidr-license-v1", payload, key);
}

export function packetPayload(license: unknown, overrides: Record<string, unknown> = {}) {
	return {
		customer_id: "example-co",
		packet_id: "PKT-example-co-1",
		issued_at: "2026-09-02T00:00:00Z",
		license,
		control_plane_url: "https://aidr.example-co.test/console",
		sensitivity: "balanced",
		display_name: "Example Customer",
		...overrides,
	};
}

export function signPacket(payload: unknown, key: DevKey) {
	return signDocument("aidr-customer-packet-v1", payload, key);
}
