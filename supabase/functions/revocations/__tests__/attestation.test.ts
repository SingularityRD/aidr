import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { deviceAttestationError } from "../attestation.ts";

const installationId = "installation-test-001";
const keyHash = createHash("sha256").update("enrollment-secret").digest("hex");
const context = { installationId, keyHash };

function attestation(overrides: Record<string, unknown> = {}) {
	return {
		schema_version: 1,
		installation_id: installationId,
		key_hash: keyHash,
		...overrides,
	};
}

describe("revocation device enrollment binding", () => {
	it("accepts the exact installation and bearer-key hash pairing", () => {
		expect(deviceAttestationError(attestation(), context)).toBeNull();
	});

	it("fails closed for missing, extra, malformed, and mismatched bindings", () => {
		for (const value of [
			undefined,
			attestation({ extra: "ignored" }),
			attestation({ schema_version: 2 }),
			attestation({ installation_id: "other-installation" }),
			attestation({ key_hash: "A".repeat(64) }),
			attestation({ key_hash: "not-a-hash" }),
			attestation({ installation_id: "line\nbreak" }),
		]) {
			expect(deviceAttestationError(value, context)).not.toBeNull();
		}
	});

	it("distinguishes installation and key mismatches without exposing the bearer", () => {
		expect(deviceAttestationError(attestation({ installation_id: "wrong" }), context)).toBe(
			"device_installation_mismatch",
		);
		expect(deviceAttestationError(attestation({ key_hash: "b".repeat(64) }), context)).toBe(
			"device_key_mismatch",
		);
	});
});
