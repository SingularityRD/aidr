/**
 * Test-only signing of `aidr-license-v1` licenses and `aidr-customer-packet-v1`
 * packets with a throwaway Ed25519 key generated per test run (never a real
 * vendor key). The signing rules mirror scripts/license-issue.mjs.
 */
import { generateKeyPairSync, type KeyObject, sign } from "node:crypto";

const DAY_MS = 24 * 60 * 60 * 1000;

function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value !== null && typeof value === "object") {
		const record = value as Record<string, unknown>;
		return `{${Object.keys(record)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${canonical(record[key])}`)
			.join(",")}}`;
	}
	return JSON.stringify(value);
}

export interface SigningKey {
	keyId: string;
	privateKey: KeyObject;
	registryEntry: Record<string, unknown>;
}

export function signingKey(keyId = "test-key-1", extra: Record<string, unknown> = {}): SigningKey {
	const { privateKey, publicKey } = generateKeyPairSync("ed25519");
	return {
		keyId,
		privateKey,
		registryEntry: {
			key_id: keyId,
			algorithm: "ed25519",
			public_key_pem: publicKey.export({ type: "spki", format: "pem" }).toString(),
			not_before: "2020-01-01T00:00:00Z",
			not_after: null,
			status: "active",
			...extra,
		},
	};
}

export function registryOf(...keys: SigningKey[]): Record<string, unknown> {
	return {
		format: "aidr-license-public-keys-v1",
		schema_version: 1,
		keys: keys.map((key) => key.registryEntry),
	};
}

export function signDocument(format: string, data: unknown, key: SigningKey) {
	// As it would arrive from a file: an `undefined` override drops the field.
	const payload = JSON.parse(JSON.stringify(data)) as Record<string, unknown>;
	const signature = sign(
		null,
		Buffer.from(`${format}\n${canonical(payload)}`, "utf8"),
		key.privateKey,
	);
	return { format, key_id: key.keyId, payload, sig: signature.toString("base64") };
}

const iso = (ms: number) => new Date(ms).toISOString().replace(/\.\d{3}Z$/u, "Z");

/** A license that ends `days` after `now` and started at least a year before that. */
export function licensePayload(
	now: number,
	days: number,
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	const start = Math.min(now - 30 * DAY_MS, now + (days - 365) * DAY_MS);
	return {
		license_id: "LIC-BILGEM-2026",
		customer: "TÜBİTAK BİLGEM",
		customer_id: "bilgem",
		plan_id: "enterprise",
		seats: 250,
		features: [],
		deployment: "onprem",
		issued_at: iso(start),
		not_before: iso(start),
		expires_at: iso(now + days * DAY_MS),
		grace_days: 30,
		...overrides,
	};
}

function packetPayload(
	license: unknown,
	now: number,
	overrides: Record<string, unknown> = {},
): Record<string, unknown> {
	return {
		customer_id: "bilgem",
		packet_id: "PKT-BILGEM-1",
		issued_at: iso(now - DAY_MS),
		license,
		control_plane_url: "https://aidr.bilgem.example.tr",
		sensitivity: "paranoid",
		display_name: "TÜBİTAK BİLGEM",
		...overrides,
	};
}

/** A signed packet whose license runs `days` beyond `now` (negative: already ended). */
export function signedPacket(
	key: SigningKey,
	now: number,
	days = 365,
	packetOverrides: Record<string, unknown> = {},
	licenseOverrides: Record<string, unknown> = {},
) {
	const license = signDocument("aidr-license-v1", licensePayload(now, days, licenseOverrides), key);
	return signDocument("aidr-customer-packet-v1", packetPayload(license, now, packetOverrides), key);
}
