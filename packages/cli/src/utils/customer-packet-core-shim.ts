/**
 * TEMPORARY stand-in for the core license API (packages/core/src/license/, WS2).
 * Delete this file at merge and import `verifyCustomerPacket` / `licenseState`
 * from `@singularityrd/aidr-core` in utils/customer-packet.ts instead; the
 * exported signatures below are the contract ones.
 *
 * It is a faithful, fail-closed port of scripts/license-verify.mjs plus the
 * `aidr-customer-packet-v1` rules of the shared contract: an empty registry,
 * an unknown/revoked key, a bad signature or a malformed document throws. With
 * no `registry` injected it trusts NO key (core embeds the vendor registry at
 * build time; this shim deliberately does not), so every packet is refused.
 */
import { createPublicKey, type KeyObject, verify } from "node:crypto";

const LICENSE_FORMAT = "aidr-license-v1";
const PACKET_FORMAT = "aidr-customer-packet-v1";
const PUBLIC_KEYS_FORMAT = "aidr-license-public-keys-v1";
const DAY_MS = 24 * 60 * 60 * 1000;
const MAX_GRACE_DAYS = 90;
const MAX_LICENSE_TERM_DAYS = 1830;
const RETIRED_KEY_ACCEPTANCE_DAYS = MAX_LICENSE_TERM_DAYS + MAX_GRACE_DAYS;
const MAX_DOCUMENT_BYTES = 64 * 1024;
const ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const CUSTOMER_ID = /^[a-z0-9][a-z0-9-]{1,31}$/;
const PLAN_IDS = ["free", "team", "business", "enterprise"];
const FEATURE = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
const LICENSE_KEYS = [
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
const PACKET_REQUIRED = ["customer_id", "issued_at", "license", "packet_id"];
const PACKET_OPTIONAL = ["control_plane_url", "display_name", "sensitivity"];

export interface LicenseDocument {
	format: typeof LICENSE_FORMAT;
	key_id: string;
	payload: {
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
	};
	sig: string;
}

export interface VerifiedCustomerPacket {
	customerId: string;
	packetId: string;
	displayName?: string;
	controlPlaneUrl?: string;
	sensitivity?: "paranoid" | "balanced" | "relaxed";
	license: LicenseDocument;
}

export type LicenseLifecycle = "active" | "grace" | "expired" | "not_yet_valid";

class CustomerPacketError extends Error {
	constructor(
		readonly code: string,
		message: string,
	) {
		super(message);
		this.name = "CustomerPacketError";
	}
}

interface TrustedKey {
	publicKey: KeyObject;
	status: "active" | "retired" | "revoked";
	notBefore: number;
	notAfter: number | null;
	retiredAt: number | null;
}

const isObject = (value: unknown): value is Record<string, unknown> =>
	value !== null && typeof value === "object" && !Array.isArray(value);

/** Throw a {@link CustomerPacketError} unless `ok`. */
function ensure(ok: boolean, code: string, message: string): void {
	if (!ok) throw new CustomerPacketError(code, message);
}

const matches = (value: unknown, pattern: RegExp): value is string =>
	typeof value === "string" && pattern.test(value);

const intIn = (value: unknown, min: number, max: number): boolean =>
	Number.isInteger(value) && (value as number) >= min && (value as number) <= max;

/** 1..max characters, no surrounding whitespace, no control characters. */
function printable(value: unknown, max: number, controls: RegExp): boolean {
	if (typeof value !== "string" || value.length < 1 || value.length > max) return false;
	return value.trim() === value && !controls.test(value);
}

/** Every required key present and nothing outside `required` + `optional`. */
function exactKeys(record: Record<string, unknown>, required: string[], optional: string[] = []) {
	const keys = Object.keys(record);
	const allowed = [...required, ...optional];
	return keys.every((key) => allowed.includes(key)) && required.every((key) => keys.includes(key));
}

function canonicalJson(value: unknown): string {
	if (value === null || typeof value === "boolean" || typeof value === "string")
		return JSON.stringify(value);
	if (typeof value === "number") {
		ensure(Number.isFinite(value), "invalid_document", "values must be finite");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	ensure(isObject(value), "invalid_document", "values must be JSON data");
	const record = value as Record<string, unknown>;
	return `{${Object.keys(record)
		.sort()
		.map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
		.join(",")}}`;
}

function time(value: unknown, field: string): number {
	const parsed = matches(value, ISO_UTC) ? Date.parse(value) : Number.NaN;
	ensure(Number.isFinite(parsed), "invalid_payload", `${field} must be an ISO-8601 UTC timestamp`);
	return parsed;
}

const optionalTime = (value: unknown, field: string): number | null =>
	value === null || value === undefined ? null : time(value, field);

function parsePublicKey(pem: unknown, keyId: string): KeyObject {
	let publicKey: KeyObject | null = null;
	try {
		publicKey = createPublicKey(String(pem ?? ""));
	} catch {
		publicKey = null;
	}
	ensure(
		publicKey?.asymmetricKeyType === "ed25519",
		"invalid_public_keys",
		`registry key ${keyId} is not an Ed25519 PEM public key`,
	);
	return publicKey as KeyObject;
}

function parseKeyEntry(entry: unknown, seen: Map<string, TrustedKey>): [string, TrustedKey] {
	const item = (isObject(entry) ? entry : {}) as Record<string, unknown>;
	ensure(matches(item.key_id, ID), "invalid_public_keys", "a registry key has no valid key_id");
	const keyId = item.key_id as string;
	ensure(
		!seen.has(keyId) && item.algorithm === "ed25519",
		"invalid_public_keys",
		`registry key ${keyId} is duplicate or not ed25519`,
	);
	ensure(
		["active", "retired", "revoked"].includes(item.status as string),
		"invalid_public_keys",
		`registry key ${keyId} has an unknown status`,
	);
	const publicKey = parsePublicKey(item.public_key_pem, keyId);
	const notBefore = time(item.not_before, `${keyId}.not_before`);
	const notAfter = optionalTime(item.not_after, `${keyId}.not_after`);
	ensure(
		notAfter === null || notAfter > notBefore,
		"invalid_public_keys",
		`registry key ${keyId} has an empty validity window`,
	);
	const retired = item.status === "retired";
	const retiredAt = retired ? time(item.retired_at, `${keyId}.retired_at`) : null;
	ensure(
		retired || optionalTime(item.retired_at, `${keyId}.retired_at`) === null,
		"invalid_public_keys",
		`registry key ${keyId} has retired_at but is not retired`,
	);
	ensure(
		retiredAt === null || (retiredAt >= notBefore && (notAfter === null || retiredAt <= notAfter)),
		"invalid_public_keys",
		`registry key ${keyId} retired_at is outside its window`,
	);
	const status = item.status as TrustedKey["status"];
	return [keyId, { publicKey, status, notBefore, notAfter, retiredAt }];
}

function parseRegistry(registry: unknown): Map<string, TrustedKey> {
	const keys = new Map<string, TrustedKey>();
	if (registry === undefined) return keys;
	const document = (isObject(registry) ? registry : {}) as Record<string, unknown>;
	ensure(
		document.format === PUBLIC_KEYS_FORMAT &&
			document.schema_version === 1 &&
			Array.isArray(document.keys),
		"invalid_public_keys",
		"the license public-key registry is malformed",
	);
	for (const entry of document.keys as unknown[]) keys.set(...parseKeyEntry(entry, keys));
	return keys;
}

/** The envelope shape; returns the signature bytes. */
function envelopeSignature(document: Record<string, unknown>, format: string, label: string) {
	ensure(
		exactKeys(document, [], ["format", "key_id", "payload", "sig"]),
		"invalid_document",
		`${label} has unknown fields`,
	);
	ensure(document.format === format, "invalid_document", `${label} format must be ${format}`);
	ensure(matches(document.key_id, ID), "invalid_document", `${label} key_id is malformed`);
	ensure(matches(document.sig, BASE64), "invalid_document", `${label} sig must be base64`);
	const signature = Buffer.from(document.sig as string, "base64");
	ensure(signature.length === 64, "invalid_document", `${label} sig must be 64 bytes`);
	return signature;
}

/** issued_at is signer-chosen: the key's window and retirement bound it. */
function checkKeyWindow(key: TrustedKey, issuedAt: number, now: number, label: string): void {
	ensure(
		issuedAt >= key.notBefore && (key.notAfter === null || issuedAt <= key.notAfter),
		"key_window",
		`${label} issued_at is outside the signing key's validity window`,
	);
	if (key.retiredAt === null) return;
	ensure(issuedAt <= key.retiredAt, "key_window", `${label} claims issuance after retirement`);
	ensure(
		now < key.retiredAt + RETIRED_KEY_ACCEPTANCE_DAYS * DAY_MS,
		"retired_key_expired",
		`${label} signing key was retired too long ago`,
	);
}

/** Envelope + signature + signing-key window checks shared by both formats. */
function verifyEnvelope(
	document: unknown,
	format: string,
	keys: Map<string, TrustedKey>,
	now: number,
	label: string,
): Record<string, unknown> {
	ensure(isObject(document), "invalid_document", `${label} must be a JSON object`);
	const envelope = document as Record<string, unknown>;
	const signature = envelopeSignature(envelope, format, label);
	ensure(keys.size > 0, "no_trusted_keys", "no license public keys are configured");
	const key = keys.get(envelope.key_id as string);
	ensure(key !== undefined, "unknown_key", `${label} was signed by an untrusted key`);
	const trusted = key as TrustedKey;
	ensure(trusted.status !== "revoked", "revoked_key", `${label} signing key is revoked`);
	// The format line is the domain separator: a license never verifies as a packet.
	const message = Buffer.from(`${format}\n${canonicalJson(envelope.payload)}`, "utf8");
	ensure(
		verify(null, message, trusted.publicKey, signature),
		"bad_signature",
		`${label} signature does not verify`,
	);
	ensure(isObject(envelope.payload), "invalid_payload", `${label} payload must be an object`);
	const payload = envelope.payload as Record<string, unknown>;
	checkKeyWindow(trusted, time(payload.issued_at, `${label} issued_at`), now, label);
	return payload;
}

function validateLicenseIdentity(payload: Record<string, unknown>): void {
	ensure(
		exactKeys(payload, LICENSE_KEYS, ["customer_id"]),
		"invalid_payload",
		"license payload has unknown or missing fields",
	);
	ensure(matches(payload.license_id, ID), "invalid_payload", "license_id is malformed");
	ensure(
		printable(payload.customer, 120, /[\x00-\x1f\x7f]/),
		"invalid_payload",
		"customer is malformed",
	);
	ensure(
		payload.customer_id === undefined || matches(payload.customer_id, CUSTOMER_ID),
		"invalid_payload",
		"customer_id is malformed",
	);
	ensure(PLAN_IDS.includes(payload.plan_id as string), "invalid_payload", "plan_id is unknown");
	ensure(intIn(payload.seats, 1, 100000), "invalid_payload", "seats is out of range");
	const features = payload.features;
	ensure(
		Array.isArray(features) &&
			features.length <= 64 &&
			features.every((feature) => matches(feature, FEATURE)) &&
			new Set(features).size === features.length,
		"invalid_payload",
		"features are malformed",
	);
}

function validateLicenseTerms(payload: Record<string, unknown>): void {
	ensure(
		payload.deployment === "onprem" || payload.deployment === "airgap",
		"invalid_payload",
		"deployment is unknown",
	);
	ensure(
		payload.deployment !== "airgap" || payload.plan_id === "enterprise",
		"plan_feature_required",
		"air-gapped deployment requires the enterprise plan",
	);
	ensure(
		intIn(payload.grace_days, 0, MAX_GRACE_DAYS),
		"invalid_payload",
		"grace_days is out of range",
	);
	const issuedAt = time(payload.issued_at, "issued_at");
	const notBefore = time(payload.not_before, "not_before");
	const expiresAt = time(payload.expires_at, "expires_at");
	ensure(
		expiresAt > notBefore && expiresAt > issuedAt,
		"invalid_payload",
		"expires_at must be after not_before and issued_at",
	);
	ensure(
		expiresAt - issuedAt <= MAX_LICENSE_TERM_DAYS * DAY_MS,
		"invalid_payload",
		"the license term is too long",
	);
}

function validControlPlaneUrl(value: unknown): boolean {
	if (typeof value !== "string" || value.length > 2048 || value.includes("#")) return false;
	try {
		const url = new URL(value);
		return url.protocol === "https:" && !url.username && !url.password;
	} catch {
		return false;
	}
}

function validatePacketPayload(payload: Record<string, unknown>): void {
	ensure(
		exactKeys(payload, PACKET_REQUIRED, PACKET_OPTIONAL),
		"invalid_payload",
		"customer packet payload has unknown or missing fields",
	);
	ensure(matches(payload.customer_id, CUSTOMER_ID), "invalid_payload", "customer_id is malformed");
	ensure(matches(payload.packet_id, ID), "invalid_payload", "packet_id is malformed");
	ensure(
		payload.control_plane_url === undefined || validControlPlaneUrl(payload.control_plane_url),
		"invalid_payload",
		"control_plane_url must be an https address without credentials",
	);
	ensure(
		payload.sensitivity === undefined ||
			["paranoid", "balanced", "relaxed"].includes(payload.sensitivity as string),
		"invalid_payload",
		"sensitivity is unknown",
	);
	ensure(
		payload.display_name === undefined ||
			printable(payload.display_name, 60, /[\x00-\x1f\x7f-\x9f]/),
		"invalid_payload",
		"display_name is malformed",
	);
}

function documentSize(doc: unknown): number {
	try {
		return Buffer.byteLength(JSON.stringify(doc) ?? "", "utf8");
	} catch {
		return Number.POSITIVE_INFINITY;
	}
}

const toMs = (now: Date | number | undefined) =>
	now === undefined ? Date.now() : typeof now === "number" ? now : now.getTime();

/**
 * Verify an `aidr-customer-packet-v1` document and its embedded license.
 * Throws {@link CustomerPacketError} for anything not authentic. An expired
 * embedded license still verifies: read {@link licenseState} separately.
 */
export function verifyCustomerPacket(
	doc: unknown,
	options: { registry?: unknown; now?: Date | number } = {},
): VerifiedCustomerPacket {
	const now = toMs(options.now);
	const keys = parseRegistry(options.registry);
	ensure(
		documentSize(doc) <= MAX_DOCUMENT_BYTES,
		"invalid_document",
		"customer packet is larger than 64 KiB",
	);
	const payload = verifyEnvelope(doc, PACKET_FORMAT, keys, now, "customer packet");
	validatePacketPayload(payload);
	const license = verifyEnvelope(payload.license, LICENSE_FORMAT, keys, now, "license");
	validateLicenseIdentity(license);
	validateLicenseTerms(license);
	ensure(
		license.customer_id === payload.customer_id,
		"customer_mismatch",
		"the embedded license belongs to a different customer",
	);
	const optional = <T>(key: string, value: unknown) =>
		value === undefined ? {} : ({ [key]: value } as T);
	return {
		customerId: payload.customer_id as string,
		packetId: payload.packet_id as string,
		...optional<{ displayName: string }>("displayName", payload.display_name),
		...optional<{ controlPlaneUrl: string }>("controlPlaneUrl", payload.control_plane_url),
		...optional<Pick<VerifiedCustomerPacket, "sensitivity">>("sensitivity", payload.sensitivity),
		license: payload.license as LicenseDocument,
	};
}

/** Lifecycle of an (already verified) license; `updatesUntil` is expires_at + grace_days. */
export function licenseState(
	license: LicenseDocument,
	now: Date | number = Date.now(),
): { state: LicenseLifecycle; updatesUntil: Date } {
	const at = toMs(now);
	const expiresAt = Date.parse(license.payload.expires_at);
	const updatesUntil = expiresAt + license.payload.grace_days * DAY_MS;
	let state: LicenseLifecycle = "expired";
	if (at < Date.parse(license.payload.not_before)) state = "not_yet_valid";
	else if (at < expiresAt) state = "active";
	else if (at < updatesUntil) state = "grace";
	return { state, updatesUntil: new Date(updatesUntil) };
}
