export interface DeviceAttestationContext {
	installationId: string;
	keyHash: string;
}

const DEVICE_KEY_HASH = /^[a-f0-9]{64}$/;
const ALLOWED_KEYS = new Set(["schema_version", "installation_id", "key_hash"]);

/**
 * Validate the enrollment binding carried by an agent command request.
 * This proves only that the request names the enrolled installation and bearer
 * key hash; it is not an OS, hardware, or provider containment attestation.
 */
export function deviceAttestationError(
	value: unknown,
	context: DeviceAttestationContext,
): string | null {
	if (!value || typeof value !== "object" || Array.isArray(value)) return "device_attestation_required";
	const candidate = value as Record<string, unknown>;
	if (
		candidate.schema_version !== 1 ||
		Object.keys(candidate).some((key) => !ALLOWED_KEYS.has(key))
	) {
		return "invalid_device_attestation";
	}
	if (
		typeof candidate.installation_id !== "string" ||
		candidate.installation_id.trim().length === 0 ||
		candidate.installation_id.trim().length > 128 ||
		/[\u0000-\u001f\u007f\r\n]/.test(candidate.installation_id)
	) {
		return "invalid_device_attestation";
	}
	if (typeof candidate.key_hash !== "string" || !DEVICE_KEY_HASH.test(candidate.key_hash)) {
		return "invalid_device_attestation";
	}
	if (candidate.installation_id.trim() !== context.installationId) return "device_installation_mismatch";
	if (candidate.key_hash !== context.keyHash) return "device_key_mismatch";
	return null;
}
