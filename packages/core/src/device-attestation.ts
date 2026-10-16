import { createHash } from "node:crypto";

/**
 * Enrollment binding presented by the installed response worker.
 *
 * This is an enrollment/device binding, not hardware or OS attestation. The
 * control plane can verify that the bearer key and installation identifier are
 * the pair registered for one agent; it cannot infer host integrity from this
 * value.
 */
export interface DeviceAttestation {
	schemaVersion: 1;
	installationId: string;
	keyHash: string;
}

export type DeviceAttestationError =
	| "invalid_installation_id"
	| "invalid_key_hash"
	| "invalid_device_attestation";

const KEY_HASH = /^[a-f0-9]{64}$/;
const INSTALLATION_ID_MAX = 128;

export function hashDeviceKey(apiKey: string): string {
	return createHash("sha256").update(apiKey.trim(), "utf8").digest("hex");
}

function validInstallationId(value: unknown): value is string {
	return (
		typeof value === "string" &&
		value.trim().length > 0 &&
		value.trim().length <= INSTALLATION_ID_MAX &&
		!/[\u0000-\u001f\u007f\r\n]/.test(value)
	);
}

function validKeyHash(value: unknown): value is string {
	return typeof value === "string" && KEY_HASH.test(value);
}

/** Validate an attestation without accepting extra or ambiguous fields. */
export function parseDeviceAttestation(
	value: unknown,
): { ok: true; attestation: DeviceAttestation } | { ok: false; error: DeviceAttestationError } {
	if (!value || typeof value !== "object" || Array.isArray(value)) {
		return { ok: false, error: "invalid_device_attestation" };
	}
	const candidate = value as Record<string, unknown>;
	if (candidate.schema_version !== 1) {
		return { ok: false, error: "invalid_device_attestation" };
	}
	if (!validInstallationId(candidate.installation_id)) {
		return { ok: false, error: "invalid_installation_id" };
	}
	if (!validKeyHash(candidate.key_hash)) {
		return { ok: false, error: "invalid_key_hash" };
	}
	if (
		Object.keys(candidate).some(
			(key) => !["schema_version", "installation_id", "key_hash"].includes(key),
		)
	) {
		return { ok: false, error: "invalid_device_attestation" };
	}
	return {
		ok: true,
		attestation: {
			schemaVersion: 1,
			installationId: candidate.installation_id.trim(),
			keyHash: candidate.key_hash,
		},
	};
}

export function createDeviceAttestation(installationId: string, apiKey: string): DeviceAttestation {
	if (!validInstallationId(installationId)) throw new Error("invalid_installation_id");
	const keyHash = hashDeviceKey(apiKey);
	if (!apiKey.trim() || !KEY_HASH.test(keyHash)) throw new Error("invalid_key_hash");
	return {
		schemaVersion: 1,
		installationId: installationId.trim(),
		keyHash,
	};
}

export function deviceAttestationPayload(attestation: DeviceAttestation): {
	schema_version: 1;
	installation_id: string;
	key_hash: string;
} {
	return {
		schema_version: 1,
		installation_id: attestation.installationId,
		key_hash: attestation.keyHash,
	};
}

export function deviceAttestationMatches(
	actual: DeviceAttestation,
	expected: DeviceAttestation,
): boolean {
	return (
		actual.schemaVersion === 1 &&
		expected.schemaVersion === 1 &&
		actual.installationId === expected.installationId &&
		actual.keyHash === expected.keyHash
	);
}
