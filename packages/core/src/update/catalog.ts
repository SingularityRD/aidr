/**
 * Endpoint-side verification of the signed installer catalog that
 * scripts/publish-installers.mjs publishes to the download portal
 * (docs/installation/download-portal.md, "Storage contract"):
 *
 *   latest.json / latest.json.sig                signed pointer to the current catalog
 *   <version>/manifest.json / manifest.json.sig  signed catalog (files, sizes, SHA-256)
 *
 * Both are signed over their exact bytes with the release signature envelope
 * `{ schema_version: 1, algorithm: "Ed25519", key_id, signature_b64 }` and the
 * dedicated installer-catalog key. The rules mirror the portal's own verifier
 * (supabase/functions/_shared/installer-catalog.ts), but the endpoint verifies
 * independently with the key its installer pinned: nothing the server says
 * about the catalog is trusted, and a document that does not verify is never
 * parsed for content.
 */
import { createHash, createPublicKey, type KeyObject, verify } from "node:crypto";

export const INSTALLER_PLATFORMS = [
	"windows-x64",
	"windows-arm64",
	"linux-x64",
	"linux-arm64",
] as const;
export type InstallerPlatform = (typeof INSTALLER_PLATFORMS)[number];

export interface InstallerCatalogFile {
	platform: InstallerPlatform;
	os: "windows" | "linux";
	arch: string;
	file: string;
	path: string;
	size: number;
	sha256: string;
	minimum_os: string;
	format: string;
}

export interface InstallerCatalog {
	version: string;
	published_at: string;
	release_notes_url: string | null;
	release_sequence: number;
	files: InstallerCatalogFile[];
}

/** One signed document: its exact bytes and the detached signature envelope. */
export interface SignedDocument {
	document: Uint8Array;
	signature: Uint8Array;
}

type CatalogVerificationError =
	| "no_trusted_key"
	| "signature_invalid"
	| "pointer_invalid"
	| "digest_mismatch"
	| "catalog_invalid";

export type CatalogVerification =
	| { ok: true; catalog: InstallerCatalog }
	| { ok: false; error: CatalogVerificationError };

const PRODUCT_ID = "singularity-aidr";
const VERSION = /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,64})?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/;
/** Same bounds as the portal: a larger document is refused before parsing. */
export const MAX_POINTER_BYTES = 16 * 1024;
export const MAX_CATALOG_BYTES = 256 * 1024;
export const MAX_SIGNATURE_BYTES = 4 * 1024;
/** DER prefix of an Ed25519 SubjectPublicKeyInfo; followed by the 32 raw key bytes. */
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function record(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value)
		? (value as Record<string, unknown>)
		: null;
}

function parseJson(bytes: Uint8Array): Record<string, unknown> | null {
	try {
		return record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
	} catch {
		return null;
	}
}

function sha256Hex(bytes: Uint8Array): string {
	return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Parse one installer-catalog public key: a PEM public key, or base64 of the
 * SPKI DER or of the raw 32-byte key (the format of the portal's
 * AIDR_INSTALLER_MANIFEST_PUBLIC_KEY_B64). Anything else, a private key or a
 * non-Ed25519 key is null.
 */
export function parseCatalogPublicKey(text: string): KeyObject | null {
	const value = text.trim();
	if (!value || /BEGIN [A-Z ]*PRIVATE KEY/u.test(value)) return null;
	try {
		let key: KeyObject;
		if (value.includes("-----BEGIN")) {
			key = createPublicKey(value);
		} else {
			if (!/^[A-Za-z0-9+/]+={0,2}$/u.test(value)) return null;
			const raw = Buffer.from(value, "base64");
			const der = raw.length === 32 ? Buffer.concat([ED25519_SPKI_PREFIX, raw]) : raw;
			key = createPublicKey({ key: der, format: "der", type: "spki" });
		}
		return key.asymmetricKeyType === "ed25519" ? key : null;
	} catch {
		return null;
	}
}

/** Verify a detached release-format Ed25519 envelope over the exact bytes with any trusted key. */
function verifySignedDocument(signed: SignedDocument, keys: readonly KeyObject[]): boolean {
	if (signed.signature.length > MAX_SIGNATURE_BYTES) return false;
	const envelope = parseJson(signed.signature);
	if (
		!envelope ||
		envelope.schema_version !== 1 ||
		envelope.algorithm !== "Ed25519" ||
		typeof envelope.key_id !== "string" ||
		typeof envelope.signature_b64 !== "string" ||
		!/^[A-Za-z0-9+/]+={0,2}$/u.test(envelope.signature_b64)
	) {
		return false;
	}
	const signature = Buffer.from(envelope.signature_b64, "base64");
	if (signature.length !== 64) return false;
	return keys.some((key) => {
		try {
			return verify(null, signed.document, key, signature);
		} catch {
			return false;
		}
	});
}

function parsePointer(value: Record<string, unknown> | null) {
	if (
		!value ||
		value.schema_version !== 1 ||
		value.type !== "aidr-installer-latest" ||
		value.product_id !== PRODUCT_ID ||
		typeof value.version !== "string" ||
		!VERSION.test(value.version) ||
		value.manifest_path !== `${value.version}/manifest.json` ||
		typeof value.manifest_sha256 !== "string" ||
		!SHA256.test(value.manifest_sha256) ||
		!Number.isSafeInteger(value.release_sequence)
	)
		return null;
	return { version: value.version, manifestSha256: value.manifest_sha256 };
}

/**
 * A pointer whose signature verifies, reduced to where its catalog is. Used to
 * locate the catalog in a mirror before verifyPublishedCatalog checks the pair.
 */
export function readVerifiedPointer(
	pointer: SignedDocument,
	keys: readonly KeyObject[],
): { version: string; manifestPath: string } | null {
	if (pointer.document.length > MAX_POINTER_BYTES || !verifySignedDocument(pointer, keys))
		return null;
	const parsed = parsePointer(parseJson(pointer.document));
	return parsed
		? { version: parsed.version, manifestPath: `${parsed.version}/manifest.json` }
		: null;
}

function parseFile(value: unknown, version: string): InstallerCatalogFile | null {
	const entry = record(value);
	if (!entry) return null;
	const platform = entry.platform;
	if (
		typeof platform !== "string" ||
		!(INSTALLER_PLATFORMS as readonly string[]).includes(platform)
	)
		return null;
	const [os, arch] = platform.split("-");
	if (
		entry.os !== os ||
		entry.arch !== arch ||
		typeof entry.file !== "string" ||
		!FILE_NAME.test(entry.file) ||
		entry.path !== `${version}/${platform}/${entry.file}` ||
		!Number.isSafeInteger(entry.size) ||
		(entry.size as number) < 1 ||
		typeof entry.sha256 !== "string" ||
		!SHA256.test(entry.sha256) ||
		typeof entry.minimum_os !== "string" ||
		entry.minimum_os.length < 1 ||
		entry.minimum_os.length > 120 ||
		typeof entry.format !== "string" ||
		!/^[a-z0-9.]{1,16}$/.test(entry.format)
	)
		return null;
	return {
		platform: platform as InstallerPlatform,
		os: os as InstallerCatalogFile["os"],
		arch: arch as string,
		file: entry.file,
		path: entry.path as string,
		size: entry.size as number,
		sha256: entry.sha256,
		minimum_os: entry.minimum_os,
		format: entry.format,
	};
}

function httpsOrNull(value: unknown): string | null | undefined {
	if (value === null || value === undefined) return null;
	if (typeof value !== "string" || value.length > 2048) return undefined;
	try {
		const url = new URL(value);
		return url.protocol === "https:" && !url.username && !url.password ? url.toString() : undefined;
	} catch {
		return undefined;
	}
}

/** Strictly parse a verified catalog; `version` pins it to the pointer when there is one. */
function parseCatalog(
	value: Record<string, unknown> | null,
	version?: string,
): InstallerCatalog | null {
	if (
		!value ||
		value.schema_version !== 1 ||
		value.type !== "aidr-installer-catalog" ||
		value.product_id !== PRODUCT_ID ||
		typeof value.version !== "string" ||
		!VERSION.test(value.version) ||
		(version !== undefined && value.version !== version) ||
		typeof value.published_at !== "string" ||
		!Number.isFinite(Date.parse(value.published_at))
	)
		return null;
	const notes = httpsOrNull(value.release_notes_url);
	const release = record(value.release);
	if (notes === undefined || !release || !Number.isSafeInteger(release.release_sequence))
		return null;
	if (
		!Array.isArray(value.files) ||
		value.files.length < 1 ||
		value.files.length > INSTALLER_PLATFORMS.length
	)
		return null;
	const files: InstallerCatalogFile[] = [];
	for (const candidate of value.files) {
		const file = parseFile(candidate, value.version);
		if (!file || files.some((existing) => existing.platform === file.platform)) return null;
		files.push(file);
	}
	return {
		version: value.version,
		published_at: value.published_at,
		release_notes_url: notes,
		release_sequence: release.release_sequence as number,
		files,
	};
}

/**
 * Verify the portal pair: the pointer's signature, the catalog's SHA-256 against
 * the pointer, the catalog's signature, then the catalog's content.
 */
export function verifyPublishedCatalog(
	input: { pointer: SignedDocument; catalog: SignedDocument },
	keys: readonly KeyObject[],
): CatalogVerification {
	if (keys.length === 0) return { ok: false, error: "no_trusted_key" };
	if (
		input.pointer.document.length > MAX_POINTER_BYTES ||
		!verifySignedDocument(input.pointer, keys)
	) {
		return { ok: false, error: "signature_invalid" };
	}
	const pointer = parsePointer(parseJson(input.pointer.document));
	if (!pointer) return { ok: false, error: "pointer_invalid" };
	if (
		input.catalog.document.length > MAX_CATALOG_BYTES ||
		sha256Hex(input.catalog.document) !== pointer.manifestSha256
	) {
		return { ok: false, error: "digest_mismatch" };
	}
	if (!verifySignedDocument(input.catalog, keys)) return { ok: false, error: "signature_invalid" };
	const catalog = parseCatalog(parseJson(input.catalog.document), pointer.version);
	return catalog ? { ok: true, catalog } : { ok: false, error: "catalog_invalid" };
}

/** Verify a catalog on its own (an installer the administrator provides with its manifest.json). */
export function verifyCatalogDocument(
	catalog: SignedDocument,
	keys: readonly KeyObject[],
): CatalogVerification {
	if (keys.length === 0) return { ok: false, error: "no_trusted_key" };
	if (catalog.document.length > MAX_CATALOG_BYTES || !verifySignedDocument(catalog, keys)) {
		return { ok: false, error: "signature_invalid" };
	}
	const parsed = parseCatalog(parseJson(catalog.document));
	return parsed ? { ok: true, catalog: parsed } : { ok: false, error: "catalog_invalid" };
}
