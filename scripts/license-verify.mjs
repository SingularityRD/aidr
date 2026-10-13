#!/usr/bin/env node
/**
 * Vendor-signed on-prem / air-gapped license verification (library + CLI).
 *
 * An `aidr-license-v1` document is
 *
 *   { "format": "aidr-license-v1", "key_id": "...", "payload": { ... }, "sig": "<base64 Ed25519>" }
 *
 * The signature covers `aidr-license-v1\n` followed by the canonical JSON of the
 * payload (object keys sorted, no insignificant whitespace), so reformatting the
 * file does not break verification while any change to a signed term does.
 *
 * Trust comes only from a public-key registry (`deploy/onprem/license-public-keys.json`
 * by default). The license names the `key_id` that signed it; the registry maps
 * that id to an Ed25519 public key with a validity window and a status, which is
 * how signing keys are rotated. An empty registry, an unknown or revoked key, a
 * malformed document or a bad signature is refused: verification fails closed.
 *
 * Clock semantics: every time comparison uses the verifier's clock (`now`, the
 * host clock or `--now`), never a time the signer chose. `issued_at` is chosen
 * by whoever holds a signing key, so it only proves anything while that key is
 * uncompromised. A `retired` key therefore carries a `retired_at` and verifies a
 * license only while (a) the license claims `issued_at <= retired_at` and (b) the
 * verifier's clock is before `retired_at` plus the longest possible license life
 * (MAX_LICENSE_TERM_DAYS + MAX_GRACE_DAYS). Because every license is also capped
 * at MAX_LICENSE_TERM_DAYS from its `issued_at`, a leaked retired key cannot mint
 * a license that outlives that bound by back-dating `issued_at`.
 *
 * Optional `customer_id` (`^[a-z0-9][a-z0-9-]{1,31}$`) names the customer a
 * per-customer build is made for. It binds a license to a customer packet
 * (scripts/customer-packet-verify.mjs) and to update packs addressed to that
 * customer, and doubles as a leak-trace mark. Licenses without it stay valid.
 *
 * Enforcement is operator-side: the operator controls the host, its clock, the
 * registry file and the database, and the database does not re-verify the
 * signature. See docs/operations/licensing.md ("What the license can and cannot
 * enforce").
 *
 * Expiry is a managed-feature boundary, never a detection boundary. After
 * `expires_at` a license enters `grace` for `grace_days`; after that it is
 * `expired`, which degrades managed control-plane features (seat admission,
 * enrollment, managed policy/pack delivery). Local detection on every endpoint
 * keeps enforcing regardless of the license state — see docs/operations/licensing.md.
 */
import { createHash, createPublicKey, verify } from "node:crypto";
import { lstatSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

export const LICENSE_FORMAT = "aidr-license-v1";
export const PUBLIC_KEYS_FORMAT = "aidr-license-public-keys-v1";
export const DEFAULT_PUBLIC_KEYS_PATH = resolve(
	dirname(fileURLToPath(import.meta.url)),
	"../deploy/onprem/license-public-keys.json",
);
const DAY_MS = 24 * 60 * 60 * 1000;
export const MAX_DOCUMENT_BYTES = 64 * 1024;
const LICENSE_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
export const KEY_ID = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
/** Customer id carried by a license, a customer packet and an update-pack audience. */
export const CUSTOMER_ID = /^[a-z0-9][a-z0-9-]{1,31}$/;
const PLAN_ID = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const FEATURE = /^[a-z0-9][a-z0-9._:-]{0,63}$/;
export const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,3})?Z$/;
export const BASE64 = /^[A-Za-z0-9+/]+={0,2}$/;
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
/** Signed terms a license may carry but need not (older licenses lack them). */
const OPTIONAL_PAYLOAD_KEYS = ["customer_id"];
export const DEPLOYMENTS = ["onprem", "airgap"];
/** Catalog editions (public.plans, 20260925000010_plan_catalog.sql). */
export const PLAN_IDS = ["free", "team", "business", "enterprise"];
/**
 * Air-gapped deployment is the catalog feature `air_gapped_deployment`, which
 * only the Enterprise edition includes (supabase/functions/_shared/plan-entitlements.ts).
 */
export const AIRGAP_PLAN_IDS = ["enterprise"];
export const MAX_GRACE_DAYS = 90;
/** Longest term (issued_at .. expires_at) any license may carry: five years. */
export const MAX_LICENSE_TERM_DAYS = 1830;
/** How long after `retired_at` a retired key can still verify anything. */
export const RETIRED_KEY_ACCEPTANCE_DAYS = MAX_LICENSE_TERM_DAYS + MAX_GRACE_DAYS;

export class LicenseError extends Error {
	constructor(code, message) {
		super(message);
		this.name = "LicenseError";
		this.code = code;
	}
}

export function isPlainObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Deterministic JSON: sorted object keys, no whitespace. Only JSON data types. */
export function canonicalJson(value) {
	if (value === null || typeof value === "boolean" || typeof value === "string") return JSON.stringify(value);
	if (typeof value === "number") {
		if (!Number.isFinite(value)) throw new LicenseError("invalid_payload", "license values must be finite");
		return JSON.stringify(value);
	}
	if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
	if (isPlainObject(value)) {
		return `{${Object.keys(value)
			.sort()
			.map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
			.join(",")}}`;
	}
	throw new LicenseError("invalid_payload", "license values must be JSON data");
}

/** The exact bytes an `aidr-license-v1` signature covers. */
export function licenseSigningMessage(payload) {
	return Buffer.from(`${LICENSE_FORMAT}\n${canonicalJson(payload)}`, "utf8");
}

export function timestamp(value, field) {
	if (typeof value !== "string" || !ISO_UTC.test(value) || !Number.isFinite(Date.parse(value))) {
		throw new LicenseError("invalid_payload", `${field} must be an ISO-8601 UTC timestamp (YYYY-MM-DDTHH:MM:SSZ)`);
	}
	return Date.parse(value);
}

/**
 * Validate the signed terms. Unknown fields are refused: a signed field that this
 * verifier does not understand must not be silently ignored.
 */
export function validateLicensePayload(payload) {
	if (!isPlainObject(payload)) throw new LicenseError("invalid_payload", "license payload must be an object");
	const keys = Object.keys(payload).sort();
	const unknown = keys.filter((key) => !PAYLOAD_KEYS.includes(key) && !OPTIONAL_PAYLOAD_KEYS.includes(key));
	const missing = PAYLOAD_KEYS.filter((key) => !keys.includes(key));
	if (unknown.length) throw new LicenseError("invalid_payload", `license payload has unknown field(s): ${unknown.join(", ")}`);
	if (missing.length) throw new LicenseError("invalid_payload", `license payload is missing: ${missing.join(", ")}`);
	if (typeof payload.license_id !== "string" || !LICENSE_ID.test(payload.license_id)) {
		throw new LicenseError("invalid_payload", "license_id must be 1..128 characters of [A-Za-z0-9._-]");
	}
	if (
		typeof payload.customer !== "string" ||
		payload.customer.trim() !== payload.customer ||
		payload.customer.length < 1 ||
		payload.customer.length > 120 ||
		/[\x00-\x1f\x7f]/.test(payload.customer)
	) {
		throw new LicenseError("invalid_payload", "customer must be 1..120 printable characters without surrounding whitespace");
	}
	if (payload.customer_id !== undefined && (typeof payload.customer_id !== "string" || !CUSTOMER_ID.test(payload.customer_id))) {
		throw new LicenseError("invalid_payload", "customer_id must be 2..32 characters of [a-z0-9-], starting with a letter or digit");
	}
	if (typeof payload.plan_id !== "string" || !PLAN_ID.test(payload.plan_id)) {
		throw new LicenseError("invalid_payload", "plan_id must be 1..64 characters of [a-z0-9._-]");
	}
	if (!PLAN_IDS.includes(payload.plan_id)) {
		throw new LicenseError("invalid_payload", `plan_id must be a catalog plan: ${PLAN_IDS.join(", ")}`);
	}
	if (!Number.isInteger(payload.seats) || payload.seats < 1 || payload.seats > 100000) {
		throw new LicenseError("invalid_payload", "seats must be an integer between 1 and 100000");
	}
	if (
		!Array.isArray(payload.features) ||
		payload.features.length > 64 ||
		payload.features.some((feature) => typeof feature !== "string" || !FEATURE.test(feature)) ||
		new Set(payload.features).size !== payload.features.length
	) {
		throw new LicenseError("invalid_payload", "features must be at most 64 unique identifiers of [a-z0-9._:-]");
	}
	if (!DEPLOYMENTS.includes(payload.deployment)) {
		throw new LicenseError("invalid_payload", `deployment must be one of ${DEPLOYMENTS.join(", ")}`);
	}
	if (payload.deployment === "airgap" && !AIRGAP_PLAN_IDS.includes(payload.plan_id)) {
		throw new LicenseError(
			"plan_feature_required",
			`air-gapped deployment (air_gapped_deployment) requires the ${AIRGAP_PLAN_IDS.join("/")} plan; plan_id ${payload.plan_id} may only be licensed for onprem`,
		);
	}
	if (!Number.isInteger(payload.grace_days) || payload.grace_days < 0 || payload.grace_days > MAX_GRACE_DAYS) {
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
 * Parse and structurally validate a public-key registry. Entries are
 * `{ key_id, algorithm: "ed25519", public_key_pem, not_before, not_after|null, status }`,
 * plus `retired_at` (required for, and only allowed on, a `retired` key).
 * An empty `keys` array is a valid file but verifies nothing (fail closed).
 */
export function parsePublicKeyRegistry(registry) {
	if (!isPlainObject(registry) || registry.format !== PUBLIC_KEYS_FORMAT || registry.schema_version !== 1) {
		throw new LicenseError("invalid_public_keys", `license public-key registry must declare format ${PUBLIC_KEYS_FORMAT} and schema_version 1`);
	}
	if (!Array.isArray(registry.keys)) throw new LicenseError("invalid_public_keys", "license public-key registry must contain a keys array");
	const keys = new Map();
	for (const entry of registry.keys) {
		if (!isPlainObject(entry) || typeof entry.key_id !== "string" || !KEY_ID.test(entry.key_id)) {
			throw new LicenseError("invalid_public_keys", "every license public key needs a key_id of [A-Za-z0-9._-]");
		}
		if (keys.has(entry.key_id)) throw new LicenseError("invalid_public_keys", `duplicate license public key ${entry.key_id}`);
		if (entry.algorithm !== "ed25519") throw new LicenseError("invalid_public_keys", `license public key ${entry.key_id} must be ed25519`);
		if (!["active", "retired", "revoked"].includes(entry.status)) {
			throw new LicenseError("invalid_public_keys", `license public key ${entry.key_id} status must be active, retired or revoked`);
		}
		let publicKey;
		try {
			publicKey = createPublicKey(String(entry.public_key_pem ?? ""));
		} catch {
			throw new LicenseError("invalid_public_keys", `license public key ${entry.key_id} is not a PEM public key`);
		}
		if (publicKey.asymmetricKeyType !== "ed25519") {
			throw new LicenseError("invalid_public_keys", `license public key ${entry.key_id} is not an Ed25519 key`);
		}
		const notBefore = timestamp(entry.not_before, `${entry.key_id}.not_before`);
		const notAfter = entry.not_after === null || entry.not_after === undefined ? null : timestamp(entry.not_after, `${entry.key_id}.not_after`);
		if (notAfter !== null && notAfter <= notBefore) {
			throw new LicenseError("invalid_public_keys", `license public key ${entry.key_id} not_after must be after not_before`);
		}
		let retiredAt = null;
		if (entry.status === "retired") {
			retiredAt = timestamp(entry.retired_at, `${entry.key_id}.retired_at`);
			if (retiredAt < notBefore || (notAfter !== null && retiredAt > notAfter)) {
				throw new LicenseError("invalid_public_keys", `license public key ${entry.key_id} retired_at must fall within its not_before..not_after window`);
			}
		} else if (entry.retired_at !== undefined && entry.retired_at !== null) {
			throw new LicenseError("invalid_public_keys", `license public key ${entry.key_id} has retired_at but status ${entry.status}`);
		}
		keys.set(entry.key_id, { keyId: entry.key_id, publicKey, status: entry.status, notBefore, notAfter, retiredAt });
	}
	return keys;
}

export function requireRegularFile(path, label) {
	let stats;
	try {
		stats = lstatSync(path);
	} catch {
		throw new LicenseError("unreadable", `${label} ${path} does not exist or is not accessible`);
	}
	if (stats.isSymbolicLink() || !stats.isFile()) throw new LicenseError("unreadable", `${label} must be a regular, non-symlink file`);
	if (stats.size > MAX_DOCUMENT_BYTES) throw new LicenseError("unreadable", `${label} is larger than ${MAX_DOCUMENT_BYTES} bytes`);
}

function readJsonFile(path, label) {
	try {
		requireRegularFile(path, label);
		return JSON.parse(readFileSync(path, "utf8"));
	} catch (error) {
		if (error instanceof LicenseError) throw error;
		throw new LicenseError("unreadable", `${label} ${path} is not readable JSON`);
	}
}

export function loadPublicKeyRegistry(path = DEFAULT_PUBLIC_KEYS_PATH) {
	return parsePublicKeyRegistry(readJsonFile(resolve(path), "license public-key registry"));
}

export function readLicenseFile(path) {
	const absolute = resolve(path);
	requireRegularFile(absolute, "license file");
	const bytes = readFileSync(absolute);
	let document;
	try {
		document = JSON.parse(bytes.toString("utf8"));
	} catch {
		throw new LicenseError("invalid_document", `license file ${absolute} is not JSON`);
	}
	return { document, sha256: createHash("sha256").update(bytes).digest("hex") };
}

/**
 * Check that a registry key may have signed a document claiming `issuedAt`:
 * the claim must fall in the key's validity window, a retired key must not claim
 * issuance after `retired_at`, and the verifier's clock (`now`) ends a retired
 * key's acceptance. Shared by the license and the customer-packet verifiers.
 */
export function assertSigningKeyUsable(key, { issuedAt, now, subject }) {
	if (issuedAt < key.notBefore || (key.notAfter !== null && issuedAt > key.notAfter)) {
		throw new LicenseError("key_window", `${subject} issued_at is outside the validity window of signing key ${key.keyId}`);
	}
	if (key.status === "retired") {
		// issued_at is signer-chosen; retirement bounds it, and the verifier's own
		// clock bounds how long anything signed by the retired key is honoured.
		if (issuedAt > key.retiredAt) {
			throw new LicenseError("key_window", `${subject} claims issuance after signing key ${key.keyId} was retired`);
		}
		if (now >= key.retiredAt + RETIRED_KEY_ACCEPTANCE_DAYS * DAY_MS) {
			throw new LicenseError(
				"retired_key_expired",
				`signing key ${key.keyId} was retired at ${new Date(key.retiredAt).toISOString()}; it verifies nothing after ${new Date(key.retiredAt + RETIRED_KEY_ACCEPTANCE_DAYS * DAY_MS).toISOString()}`,
			);
		}
	}
}

/**
 * Verify an `aidr-license-v1` document.
 *
 * Throws `LicenseError` for anything that is not an authentic license (malformed
 * document, no trusted keys, unknown/revoked key, bad signature). An authentic
 * license returns its lifecycle state; the caller decides what an expired or
 * not-yet-valid license means for the action it is about to take.
 *
 * @returns {{ status: "valid"|"grace"|"expired"|"not_yet_valid", payload: object,
 *   key_id: string, grace_ends_at: string, managed_features: "enabled"|"degraded",
 *   local_detection: "enforced", days_remaining: number }}
 */
export function verifyLicense(document, { publicKeys, now = Date.now() } = {}) {
	if (!(publicKeys instanceof Map)) throw new LicenseError("invalid_public_keys", "a parsed license public-key registry is required");
	if (!isPlainObject(document)) throw new LicenseError("invalid_document", "license document must be a JSON object");
	const extra = Object.keys(document).filter((key) => !["format", "key_id", "payload", "sig"].includes(key));
	if (extra.length) throw new LicenseError("invalid_document", `license document has unknown field(s): ${extra.join(", ")}`);
	if (document.format !== LICENSE_FORMAT) throw new LicenseError("invalid_document", `license format must be ${LICENSE_FORMAT}`);
	if (typeof document.key_id !== "string" || !KEY_ID.test(document.key_id)) throw new LicenseError("invalid_document", "license key_id is missing or malformed");
	if (typeof document.sig !== "string" || !BASE64.test(document.sig)) throw new LicenseError("invalid_document", "license sig must be base64");
	const signature = Buffer.from(document.sig, "base64");
	if (signature.length !== 64) throw new LicenseError("invalid_document", "license sig must be a 64-byte Ed25519 signature");

	if (publicKeys.size === 0) {
		throw new LicenseError(
			"no_trusted_keys",
			"no license public keys are configured; install the vendor-published deploy/onprem/license-public-keys.json (see docs/operations/licensing.md)",
		);
	}
	const key = publicKeys.get(document.key_id);
	if (!key) throw new LicenseError("unknown_key", `license was signed by key ${document.key_id}, which is not in the trusted license public-key registry`);
	if (key.status === "revoked") throw new LicenseError("revoked_key", `license signing key ${document.key_id} is revoked`);

	let message;
	try {
		message = licenseSigningMessage(document.payload);
	} catch (error) {
		throw new LicenseError("invalid_document", error.message);
	}
	if (!verify(null, message, key.publicKey, signature)) {
		throw new LicenseError("bad_signature", "license signature does not verify; the file was altered or signed by a different key");
	}
	// Only a signature-verified payload is interpreted.
	const { issuedAt, notBefore, expiresAt } = validateLicensePayload(document.payload);
	assertSigningKeyUsable(key, { issuedAt, now, subject: "license" });

	const graceEndsAt = expiresAt + document.payload.grace_days * DAY_MS;
	let status;
	if (now < notBefore) status = "not_yet_valid";
	else if (now < expiresAt) status = "valid";
	else if (now < graceEndsAt) status = "grace";
	else status = "expired";
	return {
		status,
		payload: document.payload,
		key_id: document.key_id,
		key_status: key.status,
		...(key.retiredAt === null ? {} : { key_retired_at: new Date(key.retiredAt).toISOString() }),
		grace_ends_at: new Date(graceEndsAt).toISOString(),
		managed_features: status === "valid" || status === "grace" ? "enabled" : "degraded",
		local_detection: "enforced",
		days_remaining: Math.max(0, Math.ceil(((status === "grace" ? graceEndsAt : expiresAt) - now) / DAY_MS)),
	};
}

/** Read and verify a license file against a registry file in one step. */
export function verifyLicenseFile(licensePath, { publicKeysPath = DEFAULT_PUBLIC_KEYS_PATH, now = Date.now() } = {}) {
	const { document, sha256 } = readLicenseFile(licensePath);
	const result = verifyLicense(document, { publicKeys: loadPublicKeyRegistry(publicKeysPath), now });
	return { ...result, document_sha256: sha256 };
}

const EXIT = { valid: 0, grace: 2, expired: 3, not_yet_valid: 4 };
const USAGE = "Usage: node scripts/license-verify.mjs --license-file <license.json> [--public-keys <license-public-keys.json>] [--now <ISO timestamp>]";

function parseCli(argv) {
	const values = {};
	for (let i = 0; i < argv.length; i += 1) {
		const name = argv[i];
		if (name === "--help" || name === "-h") return { help: true };
		if (!["--license-file", "--public-keys", "--now"].includes(name) || argv[i + 1] === undefined || argv[i + 1].startsWith("--")) {
			throw new LicenseError("usage", USAGE);
		}
		if (values[name] !== undefined) throw new LicenseError("usage", `Duplicate argument ${name}`);
		values[name] = argv[++i];
	}
	if (!values["--license-file"]) throw new LicenseError("usage", USAGE);
	return values;
}

const invoked = process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href;
if (invoked) {
	try {
		const args = parseCli(process.argv.slice(2));
		if (args.help) {
			console.log(USAGE);
			process.exit(0);
		}
		const now = args["--now"] === undefined ? Date.now() : Date.parse(args["--now"]);
		if (!Number.isFinite(now)) throw new LicenseError("usage", "--now must be an ISO timestamp");
		const result = verifyLicenseFile(args["--license-file"], {
			publicKeysPath: args["--public-keys"] ?? DEFAULT_PUBLIC_KEYS_PATH,
			now,
		});
		const { payload } = result;
		console.log(JSON.stringify({
			status: result.status,
			license_id: payload.license_id,
			customer: payload.customer,
			...(payload.customer_id === undefined ? {} : { customer_id: payload.customer_id }),
			plan_id: payload.plan_id,
			seats: payload.seats,
			features: payload.features,
			deployment: payload.deployment,
			not_before: payload.not_before,
			expires_at: payload.expires_at,
			grace_ends_at: result.grace_ends_at,
			days_remaining: result.days_remaining,
			key_id: result.key_id,
			key_status: result.key_status,
			...(result.key_retired_at ? { key_retired_at: result.key_retired_at } : {}),
			managed_features: result.managed_features,
			local_detection: result.local_detection,
			document_sha256: result.document_sha256,
		}, null, 2));
		if (result.status === "grace") {
			console.error(`WARNING: license ${payload.license_id} expired at ${payload.expires_at}; managed features stop at ${result.grace_ends_at}. Local detection is not affected.`);
		} else if (result.status === "expired") {
			console.error(`WARNING: license ${payload.license_id} is past its grace period; managed features are degraded. Local detection keeps enforcing.`);
		} else if (result.status === "not_yet_valid") {
			console.error(`WARNING: license ${payload.license_id} is not valid before ${payload.not_before}.`);
		}
		process.exitCode = EXIT[result.status];
	} catch (error) {
		console.error(`ERROR: ${error instanceof Error ? error.message : "license verification failed"}`);
		process.exitCode = 1;
	}
}
