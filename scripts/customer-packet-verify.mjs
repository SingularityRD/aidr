#!/usr/bin/env node
/**
 * Vendor-signed customer packet verification (library + CLI).
 *
 * Every customer gets the same signed product; a per-customer installer adds an
 * `aidr-customer-packet-v1` document that says who the build is for:
 *
 *   { "format": "aidr-customer-packet-v1", "key_id": "...", "payload": { ... }, "sig": "<base64 Ed25519>" }
 *
 * The signature covers `aidr-customer-packet-v1\n` followed by the canonical JSON
 * of the payload (the license's canonicalJson). The format line is the domain
 * separator: a license signature never verifies as a packet and vice versa, even
 * though both are signed by keys from the same `aidr-license-public-keys-v1`
 * registry under the same validity/status/retired rules.
 *
 * Payload (unknown keys refused, never any secret such as an enrollment code):
 *   customer_id        required, ^[a-z0-9][a-z0-9-]{1,31}$, equal to license.payload.customer_id
 *   packet_id          required, ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$
 *   issued_at          required, ISO-8601 UTC
 *   license            required, a full aidr-license-v1 document verified against the
 *                      same registry and carrying customer_id
 *   control_plane_url  optional, absolute https: URL, no credentials, no fragment, <= 2048 chars
 *   sensitivity        optional, paranoid | balanced | relaxed
 *   display_name       optional, 1..60 printable characters, no surrounding whitespace
 *   licensing_public_keys_pem
 *                      optional, 1..8 Ed25519 SPKI public keys (PEM) of the customer's own
 *                      deployment (deployment-prepare.mjs writes them to
 *                      endpoint-policy/licensing-public-keys.pem); `aidr setup` trusts them for
 *                      signed entitlements and runtime policy. Public keys only, never a secret.
 *
 * A packet has no expiry of its own. A packet whose embedded license is expired
 * still verifies, because local detection must install and keep enforcing
 * regardless of license state; the result reports the license state
 * (`active` | `grace` | `expired` | `not_yet_valid`) for callers that gate
 * managed features or update acceptance on it. Anything that is not an authentic
 * packet (malformed, empty registry, unknown/revoked key, bad signature, bad
 * embedded license, customer mismatch) is refused: verification fails closed.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { parseArgs } from "node:util";
import {
	assertSigningKeyUsable,
	BASE64,
	CUSTOMER_ID,
	canonicalJson,
	DEFAULT_PUBLIC_KEYS_PATH,
	isPlainObject,
	KEY_ID,
	LicenseError,
	loadPublicKeyRegistry,
	MAX_DOCUMENT_BYTES,
	requireRegularFile,
	timestamp,
	verifyLicense,
} from "./license-verify.mjs";

export const CUSTOMER_PACKET_FORMAT = "aidr-customer-packet-v1";
export const SENSITIVITIES = ["paranoid", "balanced", "relaxed"];
export const MAX_CONTROL_PLANE_URL_LENGTH = 2048;
export const MAX_DISPLAY_NAME_LENGTH = 60;
const PACKET_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const REQUIRED_KEYS = ["customer_id", "issued_at", "license", "packet_id"];
const OPTIONAL_KEYS = ["control_plane_url", "display_name", "licensing_public_keys_pem", "sensitivity"];
const MAX_LICENSING_KEYS = 8;
/** The license verifier says `valid`; the packet contract names that state `active`. */
const LICENSE_STATE = { valid: "active", grace: "grace", expired: "expired", not_yet_valid: "not_yet_valid" };

export class CustomerPacketError extends LicenseError {
	constructor(code, message) {
		super(code, message);
		this.name = "CustomerPacketError";
	}
}

function refuse(code, message) {
	return new CustomerPacketError(code, message);
}

/** The exact bytes an `aidr-customer-packet-v1` signature covers. */
export function customerPacketSigningMessage(payload) {
	return Buffer.from(`${CUSTOMER_PACKET_FORMAT}\n${canonicalJson(payload)}`, "utf8");
}

function validateControlPlaneUrl(value) {
	const fail = () =>
		refuse("invalid_payload", `control_plane_url must be an absolute https: URL without credentials or fragment, at most ${MAX_CONTROL_PLANE_URL_LENGTH} characters`);
	if (typeof value !== "string" || value.length > MAX_CONTROL_PLANE_URL_LENGTH || /[\s\x00-\x1f\x7f#]/u.test(value)) throw fail();
	let url;
	try {
		url = new URL(value);
	} catch {
		throw fail();
	}
	if (url.protocol !== "https:" || !url.hostname || url.username || url.password || url.hash) throw fail();
}

function validateDisplayName(value) {
	const length = typeof value === "string" ? [...value].length : 0;
	if (typeof value !== "string" || length < 1 || length > MAX_DISPLAY_NAME_LENGTH || value.trim() !== value || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(value)) {
		throw refuse("invalid_payload", `display_name must be 1..${MAX_DISPLAY_NAME_LENGTH} printable characters without surrounding whitespace`);
	}
}

function validateLicensingPublicKeys(value) {
	const fail = () => refuse("invalid_payload", `licensing_public_keys_pem must be 1..${MAX_LICENSING_KEYS} Ed25519 public keys in PEM (SPKI)`);
	if (!Array.isArray(value) || value.length < 1 || value.length > MAX_LICENSING_KEYS) throw fail();
	for (const pem of value) {
		if (typeof pem !== "string" || pem.length > 1024 || !pem.trim().startsWith("-----BEGIN PUBLIC KEY-----")) throw fail();
		let key;
		try {
			key = createPublicKey(pem);
		} catch {
			throw fail();
		}
		if (key.asymmetricKeyType !== "ed25519") throw fail();
	}
}

/**
 * Validate the packet's own signed terms (not the embedded license, which is
 * verified separately). Unknown fields are refused.
 */
export function validateCustomerPacketPayload(payload) {
	if (!isPlainObject(payload)) throw refuse("invalid_payload", "customer packet payload must be an object");
	const keys = Object.keys(payload);
	const unknown = keys.filter((key) => !REQUIRED_KEYS.includes(key) && !OPTIONAL_KEYS.includes(key)).sort();
	const missing = REQUIRED_KEYS.filter((key) => !keys.includes(key));
	if (unknown.length) throw refuse("invalid_payload", `customer packet payload has unknown field(s): ${unknown.join(", ")}`);
	if (missing.length) throw refuse("invalid_payload", `customer packet payload is missing: ${missing.join(", ")}`);
	if (typeof payload.customer_id !== "string" || !CUSTOMER_ID.test(payload.customer_id)) {
		throw refuse("invalid_payload", "customer_id must be 2..32 characters of [a-z0-9-], starting with a letter or digit");
	}
	if (typeof payload.packet_id !== "string" || !PACKET_ID.test(payload.packet_id)) {
		throw refuse("invalid_payload", "packet_id must be 1..128 characters of [A-Za-z0-9._-]");
	}
	let issuedAt;
	try {
		issuedAt = timestamp(payload.issued_at, "issued_at");
	} catch (error) {
		throw refuse("invalid_payload", error.message);
	}
	if (!isPlainObject(payload.license)) throw refuse("invalid_payload", "license must be an aidr-license-v1 document object");
	if (payload.control_plane_url !== undefined) validateControlPlaneUrl(payload.control_plane_url);
	if (payload.sensitivity !== undefined && !SENSITIVITIES.includes(payload.sensitivity)) {
		throw refuse("invalid_payload", `sensitivity must be one of ${SENSITIVITIES.join(", ")}`);
	}
	if (payload.display_name !== undefined) validateDisplayName(payload.display_name);
	if (payload.licensing_public_keys_pem !== undefined) validateLicensingPublicKeys(payload.licensing_public_keys_pem);
	return { issuedAt };
}

/**
 * Verify an `aidr-customer-packet-v1` document against a parsed public-key
 * registry (the same one licenses use).
 *
 * Throws `CustomerPacketError` for anything that is not an authentic packet. An
 * authentic packet returns its terms plus the embedded license's verification
 * result and state; an expired license does not make the packet fail.
 *
 * @returns {{ customer_id: string, packet_id: string, issued_at: string,
 *   control_plane_url?: string, sensitivity?: string, display_name?: string,
 *   key_id: string, key_status: string, license_state: "active"|"grace"|"expired"|"not_yet_valid",
 *   license: object, license_document: object, local_detection: "enforced" }}
 */
export function verifyCustomerPacket(document, { publicKeys, now = Date.now(), expectedCustomerId } = {}) {
	if (!(publicKeys instanceof Map)) throw refuse("invalid_public_keys", "a parsed license public-key registry is required");
	if (!isPlainObject(document)) throw refuse("invalid_document", "customer packet must be a JSON object");
	let serialized;
	try {
		serialized = JSON.stringify(document);
	} catch {
		throw refuse("invalid_document", "customer packet must be JSON data");
	}
	if (Buffer.byteLength(serialized, "utf8") > MAX_DOCUMENT_BYTES) throw refuse("invalid_document", `customer packet is larger than ${MAX_DOCUMENT_BYTES} bytes`);
	const extra = Object.keys(document).filter((key) => !["format", "key_id", "payload", "sig"].includes(key));
	if (extra.length) throw refuse("invalid_document", `customer packet has unknown field(s): ${extra.join(", ")}`);
	if (document.format !== CUSTOMER_PACKET_FORMAT) throw refuse("invalid_document", `customer packet format must be ${CUSTOMER_PACKET_FORMAT}`);
	if (typeof document.key_id !== "string" || !KEY_ID.test(document.key_id)) throw refuse("invalid_document", "customer packet key_id is missing or malformed");
	if (typeof document.sig !== "string" || !BASE64.test(document.sig)) throw refuse("invalid_document", "customer packet sig must be base64");
	const signature = Buffer.from(document.sig, "base64");
	if (signature.length !== 64) throw refuse("invalid_document", "customer packet sig must be a 64-byte Ed25519 signature");

	if (publicKeys.size === 0) {
		throw refuse(
			"no_trusted_keys",
			"no license public keys are configured; install the vendor-published deploy/onprem/license-public-keys.json (see docs/operations/licensing.md)",
		);
	}
	const key = publicKeys.get(document.key_id);
	if (!key) throw refuse("unknown_key", `customer packet was signed by key ${document.key_id}, which is not in the trusted license public-key registry`);
	if (key.status === "revoked") throw refuse("revoked_key", `customer packet signing key ${document.key_id} is revoked`);

	let message;
	try {
		message = customerPacketSigningMessage(document.payload);
	} catch (error) {
		throw refuse("invalid_document", error.message);
	}
	if (!verify(null, message, key.publicKey, signature)) {
		throw refuse("bad_signature", "customer packet signature does not verify; the file was altered or signed by a different key");
	}
	// Only a signature-verified payload is interpreted.
	const { payload } = document;
	const { issuedAt } = validateCustomerPacketPayload(payload);
	try {
		assertSigningKeyUsable(key, { issuedAt, now, subject: "customer packet" });
	} catch (error) {
		throw refuse(error.code, error.message);
	}

	let license;
	try {
		license = verifyLicense(payload.license, { publicKeys, now });
	} catch (error) {
		const reason = error instanceof LicenseError ? `${error.code}: ${error.message}` : "verification failed";
		throw refuse("invalid_license", `the license inside the customer packet does not verify (${reason})`);
	}
	if (license.payload.customer_id === undefined) {
		throw refuse("customer_mismatch", `license ${license.payload.license_id} carries no customer_id; reissue it with --customer-id ${payload.customer_id}`);
	}
	if (license.payload.customer_id !== payload.customer_id) {
		throw refuse("customer_mismatch", `customer packet is for ${payload.customer_id} but its license is for ${license.payload.customer_id}`);
	}
	if (expectedCustomerId !== undefined && payload.customer_id !== expectedCustomerId) {
		throw refuse("customer_mismatch", `customer packet is for ${payload.customer_id}, not ${expectedCustomerId}`);
	}
	return {
		customer_id: payload.customer_id,
		packet_id: payload.packet_id,
		issued_at: payload.issued_at,
		...(payload.control_plane_url === undefined ? {} : { control_plane_url: payload.control_plane_url }),
		...(payload.sensitivity === undefined ? {} : { sensitivity: payload.sensitivity }),
		...(payload.display_name === undefined ? {} : { display_name: payload.display_name }),
		...(payload.licensing_public_keys_pem === undefined ? {} : { licensing_public_keys_pem: payload.licensing_public_keys_pem }),
		key_id: document.key_id,
		key_status: key.status,
		license_state: LICENSE_STATE[license.status],
		license,
		license_document: payload.license,
		local_detection: "enforced",
	};
}

export function readCustomerPacketFile(path) {
	const absolute = resolve(path);
	try {
		requireRegularFile(absolute, "customer packet file");
	} catch (error) {
		throw refuse(error.code, error.message);
	}
	const bytes = readFileSync(absolute);
	let document;
	try {
		document = JSON.parse(bytes.toString("utf8"));
	} catch {
		throw refuse("invalid_document", `customer packet file ${absolute} is not JSON`);
	}
	return { document, sha256: createHash("sha256").update(bytes).digest("hex") };
}

/** Read and verify a customer packet file against a registry file in one step. */
export function verifyCustomerPacketFile(packetPath, { publicKeysPath = DEFAULT_PUBLIC_KEYS_PATH, now = Date.now(), expectedCustomerId } = {}) {
	const { document, sha256 } = readCustomerPacketFile(packetPath);
	const result = verifyCustomerPacket(document, { publicKeys: loadPublicKeyRegistry(publicKeysPath), now, expectedCustomerId });
	return { ...result, document_sha256: sha256 };
}

/** The non-secret summary the CLI prints (also what installers/CI log). */
export function summarizeCustomerPacket(result) {
	const terms = result.license.payload;
	return {
		verified: true,
		customer_id: result.customer_id,
		packet_id: result.packet_id,
		issued_at: result.issued_at,
		...(result.display_name === undefined ? {} : { display_name: result.display_name }),
		...(result.control_plane_url === undefined ? {} : { control_plane_url: result.control_plane_url }),
		...(result.sensitivity === undefined ? {} : { sensitivity: result.sensitivity }),
		...(result.licensing_public_keys_pem === undefined ? {} : { licensing_public_keys: result.licensing_public_keys_pem.length }),
		key_id: result.key_id,
		key_status: result.key_status,
		license_id: terms.license_id,
		license_state: result.license_state,
		license_expires_at: terms.expires_at,
		updates_until: result.license.grace_ends_at,
		local_detection: result.local_detection,
		...(result.document_sha256 === undefined ? {} : { document_sha256: result.document_sha256 }),
	};
}

const USAGE =
	"Usage: node scripts/customer-packet-verify.mjs --packet-file <customer-packet.json> [--public-keys <license-public-keys.json>] [--expect-customer-id <id>] [--now <ISO timestamp>]\n" +
	"Exit 0: the packet is authentic (whatever the license state, which is printed); exit 1: refused.";

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	try {
		const { values } = parseArgs({
			strict: true,
			options: {
				help: { type: "boolean", short: "h" },
				"packet-file": { type: "string" },
				"public-keys": { type: "string" },
				"expect-customer-id": { type: "string" },
				now: { type: "string" },
			},
		});
		if (values.help) {
			console.log(USAGE);
			process.exit(0);
		}
		if (!values["packet-file"]) throw refuse("usage", USAGE);
		const now = values.now === undefined ? Date.now() : Date.parse(values.now);
		if (!Number.isFinite(now)) throw refuse("usage", "--now must be an ISO timestamp");
		const result = verifyCustomerPacketFile(values["packet-file"], {
			publicKeysPath: values["public-keys"] ?? DEFAULT_PUBLIC_KEYS_PATH,
			now,
			expectedCustomerId: values["expect-customer-id"],
		});
		console.log(JSON.stringify(summarizeCustomerPacket(result), null, 2));
		if (result.license_state === "grace") {
			console.error(`WARNING: license ${result.license.payload.license_id} expired at ${result.license.payload.expires_at}; updates and managed features stop at ${result.license.grace_ends_at}. Local detection is not affected.`);
		} else if (result.license_state === "expired") {
			console.error(`WARNING: license ${result.license.payload.license_id} is past its grace period; new update packs are refused. Installed detection keeps enforcing.`);
		} else if (result.license_state === "not_yet_valid") {
			console.error(`WARNING: license ${result.license.payload.license_id} is not valid before ${result.license.payload.not_before}.`);
		}
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "customer packet verification failed"}`);
		process.exitCode = 1;
	}
}
