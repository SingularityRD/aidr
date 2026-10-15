/**
 * Endpoint-side verifier for vendor-signed `aidr-license-v1` documents.
 *
 * This is the TypeScript port of `scripts/license-verify.mjs` (the vendor/operator
 * tool); `license-parity.test.ts` signs fixtures in-test and asserts both accept
 * and refuse the same documents. The rules are the same: the signature covers
 * `aidr-license-v1\n` + canonicalJson(payload), trust comes only from an
 * `aidr-license-public-keys-v1` registry, unknown payload fields are refused and
 * every failure throws (fail closed). The only addition is the optional
 * `customer_id`, the customer's install/leak-trace id.
 *
 * The registry is injectable; by default the copy embedded at build time from
 * `deploy/onprem/license-public-keys.json` is used, so the release integrity
 * signature covers the trust root an endpoint verifies against.
 *
 * License state never stops detection: it gates accepting new update packs
 * (`intel/acceptance.ts`) and managed control-plane features only.
 */
import { createPublicKey, type KeyObject, verify } from "node:crypto";

import { EMBEDDED_LICENSE_PUBLIC_KEYS } from "../generated/license-public-keys.js";

export const LICENSE_FORMAT = "aidr-license-v1";
export const LICENSE_PUBLIC_KEYS_FORMAT = "aidr-license-public-keys-v1";
export const LICENSE_MAX_DOCUMENT_BYTES = 64 * 1024;
const LICENSE_MAX_GRACE_DAYS = 90;
/** Longest term (issued_at .. expires_at) any license may carry: five years. */
const LICENSE_MAX_TERM_DAYS = 1830;
/** How long after `retired_at` a retired key can still verify anything. */
const RETIRED_KEY_ACCEPTANCE_DAYS = LICENSE_MAX_TERM_DAYS + LICENSE_MAX_GRACE_DAYS;
export const CUSTOMER_ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,31}$/;

const DAY_MS = 24 * 60 * 60 * 1000;
const LICENSE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const PLAN_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const FEATURE = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const REQUIRED_PAYLOAD_KEYS = [
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
] as const;
const OPTIONAL_PAYLOAD_KEYS = ["customer_id"] as const;
const DEPLOYMENTS = ["onprem", "airgap"];
const PLAN_IDS = ["free", "team", "business", "enterprise"];
const AIRGAP_PLAN_IDS = ["enterprise"];

export type LicenseErrorCode =
	| "invalid_document"
	| "invalid_payload"
	| "invalid_public_keys"
	| "no_trusted_keys"
	| "unknown_key"
	| "revoked_key"
	| "bad_signature"
	| "key_window"
	| "retired_key_expired"
	| "plan_feature_required"
	| "customer_mismatch"
	| "invalid_license"
	| "unreadable";

export class LicenseVerificationError extends Error {
	readonly code: LicenseErrorCode;
	constructor(code: LicenseErrorCode, message: string) {
		super(message);
		this.name = "LicenseVerificationError";
		this.code = code;
	}
}

export interface LicensePayload {
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

export interface LicenseDocument {
	format: typeof LICENSE_FORMAT;
	key_id: string;
	payload: LicensePayload;
	sig: string;
}

/** `active` until expires_at, then `grace` for grace_days, then `expired`. */
export type LicenseState = "active" | "grace" | "expired" | "not_yet_valid";

interface RegistryKey {
	keyId: string;
	publicKey: KeyObject;
	status: "active" | "retired" | "revoked";
	notBefore: number;
	notAfter: number | null;
	retiredAt: number | null;
}

/** A parsed `aidr-license-public-keys-v1` registry. Construct with `parseLicensePublicKeyRegistry`. */
export interface LicenseKeyRegistry {
	readonly keys: ReadonlyMap<string, RegistryKey>;
}

export interface LicenseVerifyOptions {
	/** Parsed registry or raw registry JSON. Default: the registry embedded at build time. */
	registry?: LicenseKeyRegistry | unknown;
	/** Verifier clock, epoch ms or Date. Default: now. */
	now?: number | Date;
}

export interface VerifiedLicense {
	document: LicenseDocument;
	payload: LicensePayload;
	keyId: string;
	keyStatus: "active" | "retired";
	keyRetiredAt?: string;
	state: LicenseState;
	/** expires_at + grace_days: the last instant a new update pack may have been issued. */
	updatesUntil: string;
}

export function isPlainObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Deterministic JSON: sorted object keys, no whitespace. Only JSON data types. */
export function licenseCanonicalJson(value: unknown): string {
	if (value === null || typeof value === "boolean" || typeof value === "string")
		return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isFinite(value))
			throw new LicenseVerificationError("invalid_payload", "license values must be finite");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(licenseCanonicalJson).join(",")}]`;
	if (isPlainObject(value)) {
		return `{${Object.keys(value)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${licenseCanonicalJson(value[key])}`)
			.join(",")}}`;
	}
	throw new LicenseVerificationError("invalid_payload", "license values must be JSON data");
}

/** The exact bytes a `<format>` signature covers: `<format>\n` + canonical payload. */
function signingMessage(format: string, payload: unknown): Buffer {
	return Buffer.from(`${format}\n${licenseCanonicalJson(payload)}`, "utf8");
}

export function isoTimestamp(value: unknown, field: string, code: LicenseErrorCode): number {
	if (typeof value !== "string" || !ISO_UTC.test(value) || !Number.isFinite(Date.parse(value))) {
		throw new LicenseVerificationError(
			code,
			`${field} must be an ISO-8601 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)`,
		);
	}
	return Date.parse(value);
}

/** Unknown, missing and malformed signed fields are refused, never ignored. */
function validateLicensePayload(payload: unknown): {
	issuedAt: number;
	notBefore: number;
	expiresAt: number;
} {
	const fail = (message: string): never => {
		throw new LicenseVerificationError("invalid_payload", message);
	};
	if (!isPlainObject(payload)) return fail("license payload must be an object");
	const keys = Object.keys(payload).sort();
	const allowed: readonly string[] = [...REQUIRED_PAYLOAD_KEYS, ...OPTIONAL_PAYLOAD_KEYS];
	const unknown = keys.filter((key) => !allowed.includes(key));
	const missing = REQUIRED_PAYLOAD_KEYS.filter((key) => !keys.includes(key));
	if (unknown.length) fail(`license payload has unknown field(s): ${unknown.join(", ")}`);
	if (missing.length) fail(`license payload is missing: ${missing.join(", ")}`);
	const p = payload as Record<string, unknown>;
	if (typeof p.license_id !== "string" || !LICENSE_ID.test(p.license_id))
		fail("license_id must be 1..128 characters of [A-Za-z0-9._-]");
	if (
		typeof p.customer !== "string" ||
		p.customer.trim() !== p.customer ||
		p.customer.length < 1 ||
		p.customer.length > 120 ||
		/[\x00-\x1f\x7f]/.test(p.customer)
	)
		fail("customer must be 1..120 printable characters without surrounding whitespace");
	if (
		p.customer_id !== undefined &&
		(typeof p.customer_id !== "string" || !CUSTOMER_ID_PATTERN.test(p.customer_id))
	)
		fail("customer_id must be 2..32 characters of [a-z0-9-] starting with a letter or digit");
	if (typeof p.plan_id !== "string" || !PLAN_ID.test(p.plan_id))
		fail("plan_id must be 1..64 characters of [a-z0-9._-]");
	if (!PLAN_IDS.includes(p.plan_id as string))
		fail(`plan_id must be a catalog plan: ${PLAN_IDS.join(", ")}`);
	if (!Number.isInteger(p.seats) || (p.seats as number) < 1 || (p.seats as number) > 100000)
		fail("seats must be an integer between 1 and 100000");
	if (
		!Array.isArray(p.features) ||
		p.features.length > 64 ||
		p.features.some((feature) => typeof feature !== "string" || !FEATURE.test(feature)) ||
		new Set(p.features).size !== p.features.length
	)
		fail("features must be at most 64 unique identifiers of [a-z0-9._:-]");
	if (!DEPLOYMENTS.includes(p.deployment as string))
		fail(`deployment must be one of ${DEPLOYMENTS.join(", ")}`);
	if (p.deployment === "airgap" && !AIRGAP_PLAN_IDS.includes(p.plan_id as string)) {
		throw new LicenseVerificationError(
			"plan_feature_required",
			`air-gapped deployment requires the ${AIRGAP_PLAN_IDS.join("/")} plan`,
		);
	}
	if (
		!Number.isInteger(p.grace_days) ||
		(p.grace_days as number) < 0 ||
		(p.grace_days as number) > LICENSE_MAX_GRACE_DAYS
	)
		fail(`grace_days must be an integer between 0 and ${LICENSE_MAX_GRACE_DAYS}`);
	const issuedAt = isoTimestamp(p.issued_at, "issued_at", "invalid_payload");
	const notBefore = isoTimestamp(p.not_before, "not_before", "invalid_payload");
	const expiresAt = isoTimestamp(p.expires_at, "expires_at", "invalid_payload");
	if (expiresAt <= notBefore) fail("expires_at must be after not_before");
	if (expiresAt <= issuedAt) fail("expires_at must be after issued_at");
	if (expiresAt - issuedAt > LICENSE_MAX_TERM_DAYS * DAY_MS)
		fail(`expires_at must be at most ${LICENSE_MAX_TERM_DAYS} days after issued_at`);
	return { issuedAt, notBefore, expiresAt };
}

const REGISTRY_BRAND = new WeakSet<object>();

/**
 * Parse and structurally validate a public-key registry. An empty `keys` array is
 * a valid registry that verifies nothing (fail closed).
 */
export function parseLicensePublicKeyRegistry(registry: unknown): LicenseKeyRegistry {
	const fail = (message: string): never => {
		throw new LicenseVerificationError("invalid_public_keys", message);
	};
	if (
		!isPlainObject(registry) ||
		registry.format !== LICENSE_PUBLIC_KEYS_FORMAT ||
		registry.schema_version !== 1
	)
		fail(
			`license public-key registry must declare format ${LICENSE_PUBLIC_KEYS_FORMAT} and schema_version 1`,
		);
	const entries = (registry as Record<string, unknown>).keys;
	if (!Array.isArray(entries)) fail("license public-key registry must contain a keys array");
	const keys = new Map<string, RegistryKey>();
	for (const entry of entries as unknown[]) {
		if (!isPlainObject(entry) || typeof entry.key_id !== "string" || !KEY_ID.test(entry.key_id))
			fail("every license public key needs a key_id of [A-Za-z0-9._-]");
		const e = entry as Record<string, unknown>;
		const keyId = e.key_id as string;
		if (keys.has(keyId)) fail(`duplicate license public key ${keyId}`);
		if (e.algorithm !== "ed25519") fail(`license public key ${keyId} must be ed25519`);
		if (e.status !== "active" && e.status !== "retired" && e.status !== "revoked")
			fail(`license public key ${keyId} status must be active, retired or revoked`);
		let publicKey: KeyObject | undefined;
		try {
			publicKey = createPublicKey(String(e.public_key_pem ?? ""));
		} catch {
			fail(`license public key ${keyId} is not a PEM public key`);
		}
		if (publicKey?.asymmetricKeyType !== "ed25519")
			fail(`license public key ${keyId} is not an Ed25519 key`);
		const notBefore = isoTimestamp(e.not_before, `${keyId}.not_before`, "invalid_public_keys");
		const notAfter =
			e.not_after === null || e.not_after === undefined
				? null
				: isoTimestamp(e.not_after, `${keyId}.not_after`, "invalid_public_keys");
		if (notAfter !== null && notAfter <= notBefore)
			fail(`license public key ${keyId} not_after must be after not_before`);
		let retiredAt: number | null = null;
		if (e.status === "retired") {
			retiredAt = isoTimestamp(e.retired_at, `${keyId}.retired_at`, "invalid_public_keys");
			if (retiredAt < notBefore || (notAfter !== null && retiredAt > notAfter))
				fail(
					`license public key ${keyId} retired_at must fall within its not_before..not_after window`,
				);
		} else if (e.retired_at !== undefined && e.retired_at !== null) {
			fail(`license public key ${keyId} has retired_at but status ${String(e.status)}`);
		}
		keys.set(keyId, {
			keyId,
			publicKey: publicKey as KeyObject,
			status: e.status as RegistryKey["status"],
			notBefore,
			notAfter,
			retiredAt,
		});
	}
	const parsed: LicenseKeyRegistry = Object.freeze({ keys });
	REGISTRY_BRAND.add(parsed);
	return parsed;
}

let embeddedRegistry: LicenseKeyRegistry | null = null;

/** The registry embedded at build time from deploy/onprem/license-public-keys.json. */
export function defaultLicenseKeyRegistry(): LicenseKeyRegistry {
	embeddedRegistry ??= parseLicensePublicKeyRegistry(EMBEDDED_LICENSE_PUBLIC_KEYS);
	return embeddedRegistry;
}

export function resolveRegistry(registry: unknown): LicenseKeyRegistry {
	if (registry === undefined) return defaultLicenseKeyRegistry();
	if (registry !== null && typeof registry === "object" && REGISTRY_BRAND.has(registry))
		return registry as LicenseKeyRegistry;
	return parseLicensePublicKeyRegistry(registry);
}

export function nowMs(now: number | Date | undefined): number {
	const value = now === undefined ? Date.now() : now instanceof Date ? now.getTime() : now;
	if (!Number.isFinite(value))
		throw new LicenseVerificationError("invalid_document", "the verifier clock is not a time");
	return value;
}

/** Envelope checks shared by licenses and customer packets. */
export function checkEnvelope(
	document: unknown,
	format: string,
	label: string,
): { keyId: string; signature: Buffer; payload: unknown } {
	const fail = (message: string): never => {
		throw new LicenseVerificationError("invalid_document", message);
	};
	if (!isPlainObject(document)) return fail(`${label} document must be a JSON object`);
	const extra = Object.keys(document).filter(
		(key) => !["format", "key_id", "payload", "sig"].includes(key),
	);
	if (extra.length) fail(`${label} document has unknown field(s): ${extra.join(", ")}`);
	if (document.format !== format) fail(`${label} format must be ${format}`);
	if (typeof document.key_id !== "string" || !KEY_ID.test(document.key_id))
		fail(`${label} key_id is missing or malformed`);
	if (typeof document.sig !== "string" || !BASE64.test(document.sig))
		fail(`${label} sig must be base64`);
	const signature = Buffer.from(document.sig as string, "base64");
	if (signature.length !== 64) fail(`${label} sig must be a 64-byte Ed25519 signature`);
	let size: number;
	try {
		size = Buffer.byteLength(JSON.stringify(document), "utf8");
	} catch {
		return fail(`${label} document is not JSON data`);
	}
	if (size > LICENSE_MAX_DOCUMENT_BYTES)
		fail(`${label} document is larger than ${LICENSE_MAX_DOCUMENT_BYTES} bytes`);
	return { keyId: document.key_id as string, signature, payload: document.payload };
}

/** Registry lookup + signature check, then the signing key's validity rules for `issuedAt`. */
export function verifySignedEnvelope(
	envelope: { keyId: string; signature: Buffer; payload: unknown },
	format: string,
	label: string,
	registry: LicenseKeyRegistry,
): RegistryKey {
	if (registry.keys.size === 0) {
		throw new LicenseVerificationError(
			"no_trusted_keys",
			"no license public keys are configured; install the vendor-published license-public-keys.json (see docs/operations/licensing.md)",
		);
	}
	const key = registry.keys.get(envelope.keyId);
	if (!key)
		throw new LicenseVerificationError(
			"unknown_key",
			`${label} was signed by key ${envelope.keyId}, which is not in the trusted license public-key registry`,
		);
	if (key.status === "revoked")
		throw new LicenseVerificationError(
			"revoked_key",
			`${label} signing key ${envelope.keyId} is revoked`,
		);
	let message: Buffer;
	try {
		message = signingMessage(format, envelope.payload);
	} catch (error) {
		throw new LicenseVerificationError("invalid_document", (error as Error).message);
	}
	if (!verify(null, message, key.publicKey, envelope.signature)) {
		throw new LicenseVerificationError(
			"bad_signature",
			`${label} signature does not verify; the file was altered or signed by a different key`,
		);
	}
	return key;
}

/** issued_at must fall inside the signing key's window; a retired key is time-bounded by the verifier clock. */
export function checkKeyWindow(
	key: RegistryKey,
	issuedAt: number,
	now: number,
	label: string,
): void {
	if (issuedAt < key.notBefore || (key.notAfter !== null && issuedAt > key.notAfter)) {
		throw new LicenseVerificationError(
			"key_window",
			`${label} issued_at is outside the validity window of signing key ${key.keyId}`,
		);
	}
	if (key.status === "retired" && key.retiredAt !== null) {
		if (issuedAt > key.retiredAt) {
			throw new LicenseVerificationError(
				"key_window",
				`${label} claims issuance after signing key ${key.keyId} was retired`,
			);
		}
		const acceptUntil = key.retiredAt + RETIRED_KEY_ACCEPTANCE_DAYS * DAY_MS;
		if (now >= acceptUntil) {
			throw new LicenseVerificationError(
				"retired_key_expired",
				`signing key ${key.keyId} was retired at ${new Date(key.retiredAt).toISOString()}; it verifies nothing after ${new Date(acceptUntil).toISOString()}`,
			);
		}
	}
}

type LicenseLike = LicenseDocument | LicensePayload | VerifiedLicense;

function payloadOf(license: LicenseLike): LicensePayload {
	return "payload" in license && isPlainObject(license.payload)
		? (license.payload as LicensePayload)
		: (license as LicensePayload);
}

/** expires_at + grace_days in epoch ms (NaN when the payload is not a license). */
export function licenseTermEndMs(license: LicenseLike): number {
	const payload = payloadOf(license);
	const expiresAt = Date.parse(payload.expires_at);
	return Number.isInteger(payload.grace_days) && Number.isFinite(expiresAt)
		? expiresAt + payload.grace_days * DAY_MS
		: Number.NaN;
}

/**
 * Lifecycle state of an (already verified) license at `now`. Pure date math on
 * the signed terms; it never verifies anything and never affects detection.
 */
export function licenseState(license: LicenseLike, now: number | Date = Date.now()): LicenseState {
	const payload = payloadOf(license);
	const at = nowMs(now);
	const notBefore = Date.parse(payload.not_before);
	const expiresAt = Date.parse(payload.expires_at);
	const termEnd = licenseTermEndMs(payload);
	if (!(at >= notBefore)) return "not_yet_valid";
	if (at < expiresAt) return "active";
	if (at < termEnd) return "grace";
	return "expired";
}

/**
 * Verify an `aidr-license-v1` document. Throws `LicenseVerificationError` for
 * anything that is not an authentic license; an authentic license is returned
 * with its lifecycle state whatever that state is.
 */
export function verifyLicense(
	document: unknown,
	options: LicenseVerifyOptions = {},
): VerifiedLicense {
	const now = nowMs(options.now);
	const envelope = checkEnvelope(document, LICENSE_FORMAT, "license");
	const registry = resolveRegistry(options.registry);
	const key = verifySignedEnvelope(envelope, LICENSE_FORMAT, "license", registry);
	// Only a signature-verified payload is interpreted.
	const { issuedAt } = validateLicensePayload(envelope.payload);
	checkKeyWindow(key, issuedAt, now, "license");
	const doc = document as LicenseDocument;
	return {
		document: doc,
		payload: doc.payload,
		keyId: doc.key_id,
		keyStatus: key.status === "retired" ? "retired" : "active",
		...(key.retiredAt === null ? {} : { keyRetiredAt: new Date(key.retiredAt).toISOString() }),
		state: licenseState(doc.payload, now),
		updatesUntil: new Date(licenseTermEndMs(doc.payload)).toISOString(),
	};
}
