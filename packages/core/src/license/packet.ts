/**
 * Endpoint-side verifier for vendor-signed `aidr-customer-packet-v1` documents.
 *
 * A customer packet is what makes a generic, signed installer a customer's
 * installer: the customer id (also a leak-trace mark), the customer's license,
 * and optional setup defaults (control-plane URL, sensitivity, display name, and the
 * public keys of the customer's own deployment). It never carries a secret.
 *
 * The signature covers `aidr-customer-packet-v1\n` + canonicalJson(payload) and is
 * made by a key from the same registry as licenses; the different prefix keeps a
 * license signature from ever verifying as a packet and vice versa. The embedded
 * license is verified against the same registry and must carry the same
 * customer_id. A packet has no expiry of its own: a packet whose license has
 * expired still verifies so setup can install detection; callers read
 * `licenseState` to decide about updates and managed features.
 */
import { createPublicKey } from "node:crypto";
import {
	CUSTOMER_ID_PATTERN,
	checkEnvelope,
	checkKeyWindow,
	isoTimestamp,
	isPlainObject,
	type LicenseState,
	LicenseVerificationError,
	type LicenseVerifyOptions,
	nowMs,
	resolveRegistry,
	type VerifiedLicense,
	verifyLicense,
	verifySignedEnvelope,
} from "./verify.js";

export const CUSTOMER_PACKET_FORMAT = "aidr-customer-packet-v1";

const PACKET_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const REQUIRED_KEYS = ["customer_id", "issued_at", "license", "packet_id"] as const;
const OPTIONAL_KEYS = [
	"control_plane_url",
	"display_name",
	"licensing_public_keys_pem",
	"sensitivity",
] as const;
const MAX_LICENSING_KEYS = 8;
const SENSITIVITIES = ["paranoid", "balanced", "relaxed"] as const;
const MAX_URL_LENGTH = 2048;

export type CustomerPacketSensitivity = (typeof SENSITIVITIES)[number];

export interface CustomerPacketPayload {
	customer_id: string;
	packet_id: string;
	issued_at: string;
	license: unknown;
	control_plane_url?: string;
	sensitivity?: CustomerPacketSensitivity;
	display_name?: string;
	licensing_public_keys_pem?: string[];
}

export interface VerifiedCustomerPacket {
	document: {
		format: typeof CUSTOMER_PACKET_FORMAT;
		key_id: string;
		payload: CustomerPacketPayload;
		sig: string;
	};
	keyId: string;
	customerId: string;
	packetId: string;
	issuedAt: string;
	controlPlaneUrl?: string;
	sensitivity?: CustomerPacketSensitivity;
	displayName?: string;
	/** Ed25519 public keys of the customer's deployment (entitlements, runtime policy). */
	licensingPublicKeysPem?: string[];
	license: VerifiedLicense;
	/** The embedded license's state; an expired license does not fail the packet. */
	licenseState: LicenseState;
}

function invalid(message: string): never {
	throw new LicenseVerificationError("invalid_payload", message);
}

function checkControlPlaneUrl(value: unknown): string {
	if (typeof value !== "string" || value.length < 1 || value.length > MAX_URL_LENGTH)
		invalid(`control_plane_url must be 1..${MAX_URL_LENGTH} characters`);
	let url: URL;
	try {
		url = new URL(value as string);
	} catch {
		return invalid("control_plane_url must be an absolute URL");
	}
	if (/[\s\x00-\x1f\x7f]/u.test(value as string))
		invalid("control_plane_url must not contain whitespace or control characters");
	if (url.protocol !== "https:" || !url.hostname) invalid("control_plane_url must be an https URL");
	if (url.username || url.password) invalid("control_plane_url must not carry credentials");
	if ((value as string).includes("#")) invalid("control_plane_url must not carry a fragment");
	return value as string;
}

function checkDisplayName(value: unknown): string {
	if (
		typeof value !== "string" ||
		[...value].length < 1 ||
		[...value].length > 60 ||
		value.trim() !== value ||
		/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value)
	)
		invalid("display_name must be 1..60 printable characters without surrounding whitespace");
	return value as string;
}

function checkLicensingPublicKeys(value: unknown): string[] {
	const fail = () =>
		invalid(
			`licensing_public_keys_pem must be 1..${MAX_LICENSING_KEYS} Ed25519 public keys in PEM (SPKI)`,
		);
	if (!Array.isArray(value) || value.length < 1 || value.length > MAX_LICENSING_KEYS) fail();
	for (const pem of value as unknown[]) {
		if (
			typeof pem !== "string" ||
			pem.length > 1024 ||
			!pem.trim().startsWith("-----BEGIN PUBLIC KEY-----")
		)
			fail();
		let type: string | undefined;
		try {
			type = createPublicKey(pem as string).asymmetricKeyType;
		} catch {
			fail();
		}
		if (type !== "ed25519") fail();
	}
	return value as string[];
}

function validatePacketPayload(payload: unknown): CustomerPacketPayload {
	if (!isPlainObject(payload)) invalid("customer packet payload must be an object");
	const p = payload as Record<string, unknown>;
	const keys = Object.keys(p).sort();
	const allowed: readonly string[] = [...REQUIRED_KEYS, ...OPTIONAL_KEYS];
	const unknown = keys.filter((key) => !allowed.includes(key));
	const missing = REQUIRED_KEYS.filter((key) => !keys.includes(key));
	if (unknown.length)
		invalid(`customer packet payload has unknown field(s): ${unknown.join(", ")}`);
	if (missing.length) invalid(`customer packet payload is missing: ${missing.join(", ")}`);
	if (typeof p.customer_id !== "string" || !CUSTOMER_ID_PATTERN.test(p.customer_id))
		invalid("customer_id must be 2..32 characters of [a-z0-9-] starting with a letter or digit");
	if (typeof p.packet_id !== "string" || !PACKET_ID.test(p.packet_id))
		invalid("packet_id must be 1..128 characters of [A-Za-z0-9._-]");
	isoTimestamp(p.issued_at, "issued_at", "invalid_payload");
	if (!isPlainObject(p.license)) invalid("license must be an aidr-license-v1 document");
	if (p.control_plane_url !== undefined) checkControlPlaneUrl(p.control_plane_url);
	if (
		p.sensitivity !== undefined &&
		!SENSITIVITIES.includes(p.sensitivity as CustomerPacketSensitivity)
	)
		invalid(`sensitivity must be one of ${SENSITIVITIES.join(", ")}`);
	if (p.display_name !== undefined) checkDisplayName(p.display_name);
	if (p.licensing_public_keys_pem !== undefined)
		checkLicensingPublicKeys(p.licensing_public_keys_pem);
	return p as unknown as CustomerPacketPayload;
}

/**
 * Verify an `aidr-customer-packet-v1` document and the license inside it.
 * Throws `LicenseVerificationError` for anything that is not an authentic packet
 * for an authentic license of the same customer.
 */
export function verifyCustomerPacket(
	document: unknown,
	options: LicenseVerifyOptions = {},
): VerifiedCustomerPacket {
	const now = nowMs(options.now);
	const envelope = checkEnvelope(document, CUSTOMER_PACKET_FORMAT, "customer packet");
	const registry = resolveRegistry(options.registry);
	const key = verifySignedEnvelope(envelope, CUSTOMER_PACKET_FORMAT, "customer packet", registry);
	const payload = validatePacketPayload(envelope.payload);
	checkKeyWindow(key, Date.parse(payload.issued_at), now, "customer packet");

	let license: VerifiedLicense;
	try {
		license = verifyLicense(payload.license, { registry, now });
	} catch (error) {
		const reason =
			error instanceof LicenseVerificationError
				? `${error.code}: ${error.message}`
				: "verification failed";
		throw new LicenseVerificationError(
			"invalid_license",
			`the license inside the customer packet does not verify (${reason})`,
		);
	}
	if (license.payload.customer_id === undefined) {
		throw new LicenseVerificationError(
			"customer_mismatch",
			"the license inside the customer packet does not name a customer_id",
		);
	}
	if (license.payload.customer_id !== payload.customer_id) {
		throw new LicenseVerificationError(
			"customer_mismatch",
			`the customer packet is for ${payload.customer_id} but its license is for ${license.payload.customer_id}`,
		);
	}
	const doc = document as VerifiedCustomerPacket["document"];
	return {
		document: doc,
		keyId: doc.key_id,
		customerId: payload.customer_id,
		packetId: payload.packet_id,
		issuedAt: payload.issued_at,
		...(payload.control_plane_url === undefined
			? {}
			: { controlPlaneUrl: payload.control_plane_url }),
		...(payload.sensitivity === undefined ? {} : { sensitivity: payload.sensitivity }),
		...(payload.display_name === undefined ? {} : { displayName: payload.display_name }),
		...(payload.licensing_public_keys_pem === undefined
			? {}
			: { licensingPublicKeysPem: [...payload.licensing_public_keys_pem] }),
		license,
		licenseState: license.state,
	};
}
