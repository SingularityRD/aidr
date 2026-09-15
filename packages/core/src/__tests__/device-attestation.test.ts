import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
	createDeviceAttestation,
	deviceAttestationMatches,
	deviceAttestationPayload,
	hashDeviceKey,
	parseDeviceAttestation,
} from "../device-attestation.js";

const installationId = "installation-test-001";
const apiKey = "enrollment-secret";

describe("device enrollment attestation", () => {
	it("binds an installation identifier to the hash of the bearer key", () => {
		const attestation = createDeviceAttestation(installationId, apiKey);
		expect(attestation).toEqual({
			schemaVersion: 1,
			installationId,
			keyHash: createHash("sha256").update(apiKey).digest("hex"),
		});
		expect(deviceAttestationPayload(attestation)).toEqual({
			schema_version: 1,
			installation_id: installationId,
			key_hash: hashDeviceKey(apiKey),
		});
	});

	it("rejects malformed or ambiguous payloads", () => {
		for (const value of [
			undefined,
			{ schema_version: 1, installation_id: installationId, key_hash: "A".repeat(64) },
			{ schema_version: 2, installation_id: installationId, key_hash: hashDeviceKey(apiKey) },
			{ schema_version: 1, installation_id: "line\nbreak", key_hash: hashDeviceKey(apiKey) },
			{ schema_version: 1, installation_id: installationId, key_hash: hashDeviceKey(apiKey), extra: true },
		]) {
			expect(parseDeviceAttestation(value)).toMatchObject({ ok: false });
		}
	});

	it("compares both binding components", () => {
		const expected = createDeviceAttestation(installationId, apiKey);
		expect(deviceAttestationMatches(expected, expected)).toBe(true);
		expect(
			deviceAttestationMatches(expected, createDeviceAttestation("other-installation", apiKey)),
		).toBe(false);
		expect(deviceAttestationMatches(expected, createDeviceAttestation(installationId, "other-key"))).toBe(false);
	});
});
