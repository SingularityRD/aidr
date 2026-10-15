// Server-side verification of vendor-signed `aidr-license-v1` documents.
//
// Edge Functions cannot import scripts/, so this is the WebCrypto port of
// scripts/license-verify.mjs (the operator CLI and the bootstrap use that one).
// supabase/functions/__tests__/license-verify-parity.test.ts runs both
// verifiers over the same signed vectors so a drift fails a test, not a
// customer import.
//
// Trust comes only from the deployment's public-key registry
// (`aidr-license-public-keys-v1`), supplied to the Edge runtime as
// AIDR_LICENSE_PUBLIC_KEYS_B64 (base64 of deploy/onprem/license-public-keys.json,
// written by scripts/deployment-prepare.mjs). No registry, an empty registry,
// an unknown/revoked key, a malformed document or a bad signature is refused:
// verification fails closed. Every time comparison uses the verifier's clock.

import type { EnvReader } from "./config.ts";

const LICENSE_FORMAT = "aidr-license-v1";
const PUBLIC_KEYS_FORMAT = "aidr-license-public-keys-v1";
const MAX_GRACE_DAYS = 90;
const MAX_LICENSE_TERM_DAYS = 1830;
const RETIRED_KEY_ACCEPTANCE_DAYS = MAX_LICENSE_TERM_DAYS + MAX_GRACE_DAYS;
export const MAX_LICENSE_DOCUMENT_BYTES = 64 * 1024;
const DAY_MS = 24 * 60 * 60 * 1000;
const LICENSE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CUSTOMER_ID = /^[a-z0-9][a-z0-9-]{1,31}$/;
const PLAN_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const FEATURE = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const PAYLOAD_KEYS = [
	"customer",
	"deployment",
	"expires_at",
	"features",
	"grace_days",
	"issued_at",
	"license_id",
	"not_before",
	"plan_id",
	"seats",
];
const OPTIONAL_PAYLOAD_KEYS = ["customer_id"];
const DEPLOYMENTS = ["onprem", "airgap"];
const PLAN_IDS = ["free", "team", "business", "enterprise"];
const AIRGAP_PLAN_IDS = ["enterprise"];

export type LicenseErrorCode =
	| "invalid_document"
	| "invalid_payload"
	| "plan_feature_required"
	| "invalid_public_keys"
	| "no_trusted_keys"
	| "unknown_key"
	| "revoked_key"
	| "bad_signature"
	| "key_window"
	| "retired_key_expired";

export class LicenseError extends Error {
	constructor(readonly code: LicenseErrorCode, message: string) {
		super(message);
		this.name = "LicenseError";
	}
}

interface LicensePayload {
	license_id: string;
	customer: string;
	customer_id?: string;
	plan_id: string;
	seats: number;
	features: string[];
	deployment: "onprem" | "airgap";
	issued_at: string;
	not_before: string;
	expires_at: string;
	grace_days: number;
}

type LicenseStatus = "valid" | "grace" | "expired" | "not_yet_valid";

export interface VerifiedLicense {
	status: LicenseStatus;
	payload: LicensePayload;
	key_id: string;
	key_status: "active" | "retired";
	grace_ends_at: string;
	days_remaining: number;
	/** SHA-256 (hex) of the canonical JSON of the whole document. */
	canonical_sha256: string;
}

interface RegistryKey {
	keyId: string;
	publicKey: CryptoKey;
	status: "active" | "retired" | "revoked";
	notBefore: number;
	notAfter: number | null;
	retiredAt: number | null;
}

export type LicenseRegistry = Map<string, RegistryKey>;

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Deterministic JSON identical to scripts/license-verify.mjs `canonicalJson`. */
export function licenseCanonicalJson(value: unknown): string {
	if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new LicenseError("invalid_payload", "license values must be finite");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(licenseCanonicalJson).join(",")}]`;
	if (isPlainObject(value)) {
		return `{${Object.keys(value)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${licenseCanonicalJson(value[key])}`)
			.join(",")}}`;
	}
	throw new LicenseError("invalid_payload", "license values must be JSON data");
}

function timestamp(value: unknown, field: string): number {
	if (typeof value !== "string" || !ISO_UTC.test(value) || !Number.isFinite(Date.parse(value))) {
		throw new LicenseError("invalid_payload", `${field} must be an ISO-8601 UTC timestamp`);
	}
	return Date.parse(value);
}

function base64ToBytes(value: string): Uint8Array<ArrayBuffer> {
	const binary = atob(value);
	const bytes = new Uint8Array(binary.length);
	for (let i = 0; i < binary.length; i += 1) bytes[i] = binary.charCodeAt(i);
	return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
	return Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

async function sha256Hex(text: string): Promise<string> {
	return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}

async function importEd25519Pem(pem: unknown, keyId: string): Promise<CryptoKey> {
	const match = typeof pem === "string"
		? /^-----BEGIN PUBLIC KEY-----\s*([A-Za-z0-9+/=\s]+?)\s*-----END PUBLIC KEY-----\s*$/.exec(pem)
		: null;
	if (!match) throw new LicenseError("invalid_public_keys", `license public key ${keyId} is not a PEM public key`);
	try {
		const der = base64ToBytes(match[1].replace(/\s+/g, ""));
		return await crypto.subtle.importKey("spki", der, { name: "Ed25519" }, false, ["verify"]);
	} catch {
		throw new LicenseError("invalid_public_keys", `license public key ${keyId} is not an Ed25519 key`);
	}
}

/** Parse an `aidr-license-public-keys-v1` registry. An empty registry verifies nothing. */
export async function parseLicenseRegistry(registry: unknown): Promise<LicenseRegistry> {
	if (!isPlainObject(registry) || registry.format !== PUBLIC_KEYS_FORMAT || registry.schema_version !== 1) {
		throw new LicenseError("invalid_public_keys", `license public-key registry must declare format ${PUBLIC_KEYS_FORMAT} and schema_version 1`);
	}
	if (!Array.isArray(registry.keys)) throw new LicenseError("invalid_public_keys", "license public-key registry must contain a keys array");
	const keys: LicenseRegistry = new Map();
	for (const entry of registry.keys) {
		if (!isPlainObject(entry) || typeof entry.key_id !== "string" || !KEY_ID.test(entry.key_id)) {
			throw new LicenseError("invalid_public_keys", "every license public key needs a key_id of [A-Za-z0-9._-]");
		}
		const keyId = entry.key_id;
		if (keys.has(keyId)) throw new LicenseError("invalid_public_keys", `duplicate license public key ${keyId}`);
		if (entry.algorithm !== "ed25519") throw new LicenseError("invalid_public_keys", `license public key ${keyId} must be ed25519`);
		if (entry.status !== "active" && entry.status !== "retired" && entry.status !== "revoked") {
			throw new LicenseError("invalid_public_keys", `license public key ${keyId} status must be active, retired or revoked`);
		}
		const publicKey = await importEd25519Pem(entry.public_key_pem, keyId);
		let notBefore: number;
		let notAfter: number | null;
		let retiredAt: number | null = null;
		try {
			notBefore = timestamp(entry.not_before, `${keyId}.not_before`);
			notAfter = entry.not_after === null || entry.not_after === undefined ? null : timestamp(entry.not_after, `${keyId}.not_after`);
			if (entry.status === "retired") retiredAt = timestamp(entry.retired_at, `${keyId}.retired_at`);
		} catch (error) {
			throw new LicenseError("invalid_public_keys", (error as Error).message);
		}
		if (notAfter !== null && notAfter <= notBefore) {
			throw new LicenseError("invalid_public_keys", `license public key ${keyId} not_after must be after not_before`);
		}
		if (entry.status === "retired") {
			if (retiredAt === null || retiredAt < notBefore || (notAfter !== null && retiredAt > notAfter)) {
				throw new LicenseError("invalid_public_keys", `license public key ${keyId} retired_at must fall within its window`);
			}
		} else if (entry.retired_at !== undefined && entry.retired_at !== null) {
			throw new LicenseError("invalid_public_keys", `license public key ${keyId} has retired_at but status ${entry.status}`);
		}
		keys.set(keyId, { keyId, publicKey, status: entry.status, notBefore, notAfter, retiredAt });
	}
	return keys;
}

/** Registry from AIDR_LICENSE_PUBLIC_KEYS_B64; null when the variable is unset. */
export async function licenseRegistryFromEnv(raw: string | undefined | null): Promise<LicenseRegistry | null> {
	const value = (raw ?? "").trim();
	if (!value) return null;
	let parsed: unknown;
	try {
		if (!BASE64.test(value) || value.length > MAX_LICENSE_DOCUMENT_BYTES * 2) throw new Error("not base64");
		parsed = JSON.parse(new TextDecoder().decode(base64ToBytes(value)));
	} catch {
		throw new LicenseError("invalid_public_keys", "AIDR_LICENSE_PUBLIC_KEYS_B64 is not a base64 JSON registry");
	}
	return await parseLicenseRegistry(parsed);
}

function validatePayload(payload: unknown): { issuedAt: number; notBefore: number; expiresAt: number } {
	if (!isPlainObject(payload)) throw new LicenseError("invalid_payload", "license payload must be an object");
	const keys = Object.keys(payload).sort();
	const unknown = keys.filter((key) => !PAYLOAD_KEYS.includes(key) && !OPTIONAL_PAYLOAD_KEYS.includes(key));
	const missing = PAYLOAD_KEYS.filter((key) => !keys.includes(key));
	if (unknown.length) throw new LicenseError("invalid_payload", `license payload has unknown field(s): ${unknown.join(", ")}`);
	if (missing.length) throw new LicenseError("invalid_payload", `license payload is missing: ${missing.join(", ")}`);
	if (typeof payload.license_id !== "string" || !LICENSE_ID.test(payload.license_id)) {
		throw new LicenseError("invalid_payload", "license_id is malformed");
	}
	const customer = payload.customer;
	if (typeof customer !== "string" || customer.trim() !== customer || customer.length < 1 || customer.length > 120
		|| /[\x00-\x1f\x7f]/.test(customer)) {
		throw new LicenseError("invalid_payload", "customer is malformed");
	}
	if (payload.customer_id !== undefined && (typeof payload.customer_id !== "string" || !CUSTOMER_ID.test(payload.customer_id))) {
		throw new LicenseError("invalid_payload", "customer_id is malformed");
	}
	if (typeof payload.plan_id !== "string" || !PLAN_ID.test(payload.plan_id) || !PLAN_IDS.includes(payload.plan_id)) {
		throw new LicenseError("invalid_payload", "plan_id must be a catalog plan");
	}
	if (!Number.isInteger(payload.seats) || (payload.seats as number) < 1 || (payload.seats as number) > 100000) {
		throw new LicenseError("invalid_payload", "seats must be an integer between 1 and 100000");
	}
	const features = payload.features;
	if (!Array.isArray(features) || features.length > 64
		|| features.some((feature) => typeof feature !== "string" || !FEATURE.test(feature))
		|| new Set(features).size !== features.length) {
		throw new LicenseError("invalid_payload", "features are malformed");
	}
	if (typeof payload.deployment !== "string" || !DEPLOYMENTS.includes(payload.deployment)) {
		throw new LicenseError("invalid_payload", "deployment must be onprem or airgap");
	}
	if (payload.deployment === "airgap" && !AIRGAP_PLAN_IDS.includes(payload.plan_id)) {
		throw new LicenseError("plan_feature_required", "air-gapped deployment requires the enterprise plan");
	}
	if (!Number.isInteger(payload.grace_days) || (payload.grace_days as number) < 0 || (payload.grace_days as number) > MAX_GRACE_DAYS) {
		throw new LicenseError("invalid_payload", `grace_days must be an integer between 0 and ${MAX_GRACE_DAYS}`);
	}
	const issuedAt = timestamp(payload.issued_at, "issued_at");
	const notBefore = timestamp(payload.not_before, "not_before");
	const expiresAt = timestamp(payload.expires_at, "expires_at");
	if (expiresAt <= notBefore) throw new LicenseError("invalid_payload", "expires_at must be after not_before");
	if (expiresAt <= issuedAt) throw new LicenseError("invalid_payload", "expires_at must be after issued_at");
	if (expiresAt - issuedAt > MAX_LICENSE_TERM_DAYS * DAY_MS) {
		throw new LicenseError("invalid_payload", `expires_at must be at most ${MAX_LICENSE_TERM_DAYS} days after issued_at`);
	}
	return { issuedAt, notBefore, expiresAt };
}

/**
 * Verify a license document against a parsed registry. Throws LicenseError for
 * anything that is not an authentic license; an authentic license returns its
 * lifecycle state and the caller decides what that state permits.
 */
export async function verifyLicenseDocument(
	document: unknown,
	publicKeys: LicenseRegistry,
	now: number,
): Promise<VerifiedLicense> {
	if (!isPlainObject(document)) throw new LicenseError("invalid_document", "license document must be a JSON object");
	const extra = Object.keys(document).filter((key) => !["format", "key_id", "payload", "sig"].includes(key));
	if (extra.length) throw new LicenseError("invalid_document", `license document has unknown field(s): ${extra.join(", ")}`);
	if (document.format !== LICENSE_FORMAT) throw new LicenseError("invalid_document", `license format must be ${LICENSE_FORMAT}`);
	if (typeof document.key_id !== "string" || !KEY_ID.test(document.key_id)) throw new LicenseError("invalid_document", "license key_id is malformed");
	if (typeof document.sig !== "string" || !BASE64.test(document.sig)) throw new LicenseError("invalid_document", "license sig must be base64");
	let signature: Uint8Array<ArrayBuffer>;
	try {
		signature = base64ToBytes(document.sig);
	} catch {
		throw new LicenseError("invalid_document", "license sig must be base64");
	}
	if (signature.length !== 64) throw new LicenseError("invalid_document", "license sig must be a 64-byte Ed25519 signature");
	if (publicKeys.size === 0) throw new LicenseError("no_trusted_keys", "no license public keys are configured");
	const key = publicKeys.get(document.key_id);
	if (!key) throw new LicenseError("unknown_key", `license was signed by key ${document.key_id}, which is not trusted`);
	if (key.status === "revoked") throw new LicenseError("revoked_key", `license signing key ${document.key_id} is revoked`);

	let message: Uint8Array<ArrayBuffer>;
	try {
		message = new TextEncoder().encode(`${LICENSE_FORMAT}\n${licenseCanonicalJson(document.payload)}`);
	} catch (error) {
		throw new LicenseError("invalid_document", (error as Error).message);
	}
	const valid = await crypto.subtle.verify("Ed25519", key.publicKey, signature, message);
	if (!valid) throw new LicenseError("bad_signature", "license signature does not verify");
	// Only a signature-verified payload is interpreted.
	const { issuedAt, notBefore, expiresAt } = validatePayload(document.payload);
	if (issuedAt < key.notBefore || (key.notAfter !== null && issuedAt > key.notAfter)) {
		throw new LicenseError("key_window", "license issued_at is outside the signing key's validity window");
	}
	if (key.status === "retired" && key.retiredAt !== null) {
		if (issuedAt > key.retiredAt) throw new LicenseError("key_window", "license claims issuance after its signing key was retired");
		if (now >= key.retiredAt + RETIRED_KEY_ACCEPTANCE_DAYS * DAY_MS) {
			throw new LicenseError("retired_key_expired", "the license signing key was retired too long ago");
		}
	}
	const payload = document.payload as unknown as LicensePayload;
	const graceEndsAt = expiresAt + payload.grace_days * DAY_MS;
	let status: LicenseStatus;
	if (now < notBefore) status = "not_yet_valid";
	else if (now < expiresAt) status = "valid";
	else if (now < graceEndsAt) status = "grace";
	else status = "expired";
	return {
		status,
		payload,
		key_id: document.key_id,
		key_status: key.status,
		grace_ends_at: new Date(graceEndsAt).toISOString(),
		days_remaining: Math.max(0, Math.ceil(((status === "grace" ? graceEndsAt : expiresAt) - now) / DAY_MS)),
		canonical_sha256: await sha256Hex(licenseCanonicalJson(document)),
	};
}

export type LicenseCheck =
	| { ok: true; verified: VerifiedLicense }
	| { ok: false; status: number; error: string; reason?: string };

/**
 * Verify a document for a control-plane action against the deployment's trust
 * registry (AIDR_LICENSE_PUBLIC_KEYS_B64) and optional customer binding
 * (AIDR_LICENSE_CUSTOMER_ID). license-admin (submit) and operator-admin
 * (apply) both use it, so both steps share one trust root, clock and set of
 * refusals. A license past its grace period is always refused; a license that
 * is not yet valid may be staged but not applied.
 */
export async function checkLicenseDocument(
	document: unknown,
	env: EnvReader,
	now: number,
	purpose: "submit" | "apply",
): Promise<LicenseCheck> {
	let registry;
	try {
		registry = await licenseRegistryFromEnv(env("AIDR_LICENSE_PUBLIC_KEYS_B64"));
	} catch {
		return { ok: false, status: 503, error: "license_registry_invalid" };
	}
	if (!registry) return { ok: false, status: 503, error: "license_registry_unavailable" };
	let verified: VerifiedLicense;
	try {
		verified = await verifyLicenseDocument(document, registry, now);
	} catch (error) {
		if (error instanceof LicenseError) {
			if (error.code === "no_trusted_keys") return { ok: false, status: 503, error: "license_registry_empty" };
			return { ok: false, status: 422, error: "license_rejected", reason: error.code };
		}
		return { ok: false, status: 503, error: "license_verification_unavailable" };
	}
	const boundCustomer = (env("AIDR_LICENSE_CUSTOMER_ID") ?? "").trim();
	if (boundCustomer && verified.payload.customer_id !== boundCustomer) {
		return { ok: false, status: 422, error: "license_rejected", reason: "customer_mismatch" };
	}
	if (verified.status === "expired") return { ok: false, status: 422, error: "license_rejected", reason: "expired" };
	if (purpose === "apply" && verified.status === "not_yet_valid") {
		return { ok: false, status: 422, error: "license_rejected", reason: "not_yet_valid" };
	}
	return { ok: true, verified };
}

export function licenseSummary(verified: VerifiedLicense) {
	const { payload } = verified;
	return {
		status: verified.status,
		license_id: payload.license_id,
		customer: payload.customer,
		customer_id: payload.customer_id ?? null,
		plan_id: payload.plan_id,
		seats: payload.seats,
		deployment: payload.deployment,
		not_before: payload.not_before,
		expires_at: payload.expires_at,
		grace_ends_at: verified.grace_ends_at,
		days_remaining: verified.days_remaining,
		key_id: verified.key_id,
		canonical_sha256: verified.canonical_sha256,
	};
}
