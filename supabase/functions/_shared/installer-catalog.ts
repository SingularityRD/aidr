// Installer download portal: the storage contract written by
// scripts/publish-installers.mjs and read by the `installer-download` function.
//
// Bucket layout (private; service role only):
//
//   latest.json / latest.json.sig                 signed pointer { version, release_sequence, manifest_path, manifest_sha256 }
//   <version>/manifest.json / manifest.json.sig   signed installer catalog (files, sizes, SHA-256, minimum OS, release notes URL)
//   <version>/<platform>/<file>                   installer bytes (one file per platform AND format)
//   <version>/SHA256SUMS, <version>/release/*     checksum list and the signed release manifest it came from
//
// Both JSON documents are signed over their exact bytes with the release signature
// envelope of scripts/release-signing-lib.mjs ({ schema_version: 1, algorithm:
// "Ed25519", key_id, signature_b64 }). Nothing here trusts a document before its
// signature verifies, the pointer's digest matches the catalog bytes and every
// file entry matches the layout; any failure withholds the whole catalog.

import { fromBase64, spkiFor, verifyEd25519 } from "./release-version.ts";

// Windows and Linux only (no macOS installer is offered yet). The list is data:
// adding a platform here, in scripts/publish-installers.mjs PLATFORMS and in the
// record_installer_download check is all a new platform needs.
export const INSTALLER_PLATFORMS = ["windows-x64", "windows-arm64", "linux-x64", "linux-arm64"] as const;
type InstallerPlatform = (typeof INSTALLER_PLATFORMS)[number];

// The formats a platform is published in (scripts/publish-installers.mjs FORMATS
// mirrors it). A catalog may carry one file per platform and format.
const INSTALLER_FORMATS = { windows: ["msi"], linux: ["deb", "rpm", "tar.gz"] } as const;
// Served when a download request names no format (the request shape from before
// formats existed): the format that installs on every distribution of that OS.
const DEFAULT_FORMAT = { windows: "msi", linux: "tar.gz" } as const;
const FORMAT = /^[a-z0-9.]{1,16}$/;
// Catalog schema 1: at most one file per platform. Schema 2 (multi-format): one
// file per platform AND format, and every file name ends in `.<format>`. Both verify
// with the same signature envelope; the publisher writes 1 whenever every platform
// has a single file, so endpoints that only read schema 1 keep updating.
const MAX_FORMATS_PER_PLATFORM = 8;

type InstallerFile = {
	platform: InstallerPlatform;
	os: "windows" | "linux";
	arch: string;
	file: string;
	path: string;
	size: number;
	sha256: string;
	minimum_os: string;
	format: string;
};

export type InstallerCatalog = {
	schema_version: 1 | 2;
	version: string;
	published_at: string;
	release_notes_url: string | null;
	release: { tag: string; git_sha: string; release_sequence: number };
	files: InstallerFile[];
};

/**
 * The exact signed bytes a verified catalog came from. The device update path
 * (installer-update) hands them to the endpoint, which verifies the same
 * signatures again with the key the installer pinned; it never trusts this
 * function's parse.
 */
type SignedCatalogDocuments = {
	pointer: Uint8Array<ArrayBuffer>;
	pointerSignature: Uint8Array;
	catalog: Uint8Array<ArrayBuffer>;
	catalogSignature: Uint8Array;
};

export type CatalogResult =
	| { ok: true; catalog: InstallerCatalog; documents: SignedCatalogDocuments }
	| { ok: false; status: 404 | 503; error: "installers_unpublished" | "catalog_unavailable" | "catalog_integrity_failed" };

/** `null` = the object does not exist; a throw or `"error"` = storage is unavailable. */
export type ObjectReader = (path: string, maxBytes: number) => Promise<Uint8Array<ArrayBuffer> | null | "error">;

const PRODUCT_ID = "singularity-aidr";
const VERSION = /^\d{1,6}\.\d{1,6}\.\d{1,6}(?:-[0-9A-Za-z.-]{1,64})?$/;
const SHA256 = /^[0-9a-f]{64}$/;
const FILE_NAME = /^[A-Za-z0-9][A-Za-z0-9._+-]{0,199}$/;
const MAX_POINTER_BYTES = 16 * 1024;
const MAX_CATALOG_BYTES = 256 * 1024;
const MAX_SIGNATURE_BYTES = 4 * 1024;

function record(value: unknown): Record<string, unknown> | null {
	return value && typeof value === "object" && !Array.isArray(value) ? (value as Record<string, unknown>) : null;
}

function parseJson(bytes: Uint8Array): Record<string, unknown> | null {
	try {
		return record(JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes)));
	} catch {
		return null;
	}
}

async function sha256Hex(bytes: Uint8Array<ArrayBuffer>): Promise<string> {
	const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
	return Array.from(digest, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

/** The catalog public key (SPKI DER or raw 32 bytes, base64), or null when unusable. */
export function installerPublicKey(publicKeyB64: string): Uint8Array<ArrayBuffer> | null {
	const raw = fromBase64(publicKeyB64);
	return raw ? spkiFor(raw) : null;
}

/** Verify a detached release-format Ed25519 envelope over the exact object bytes. */
async function verifySignedObject(
	bytes: Uint8Array<ArrayBuffer>,
	signatureBytes: Uint8Array,
	spki: Uint8Array<ArrayBuffer>,
): Promise<boolean> {
	const envelope = parseJson(signatureBytes);
	if (!envelope || envelope.schema_version !== 1 || envelope.algorithm !== "Ed25519" || typeof envelope.key_id !== "string") {
		return false;
	}
	const signature = typeof envelope.signature_b64 === "string" ? fromBase64(envelope.signature_b64) : null;
	if (!signature || signature.length !== 64) return false;
	return verifyEd25519(spki, signature, bytes);
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
	) return null;
	return { version: value.version, manifestPath: value.manifest_path, manifestSha256: value.manifest_sha256 };
}

function parseFile(value: unknown, version: string): InstallerFile | null {
	const entry = record(value);
	if (!entry) return null;
	const platform = entry.platform;
	if (typeof platform !== "string" || !(INSTALLER_PLATFORMS as readonly string[]).includes(platform)) return null;
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
		!FORMAT.test(entry.format)
	) return null;
	return {
		platform: platform as InstallerPlatform,
		os: os as InstallerFile["os"],
		arch,
		file: entry.file,
		path: entry.path as string,
		size: entry.size as number,
		sha256: entry.sha256,
		minimum_os: entry.minimum_os,
		format: entry.format,
	};
}

function httpsOrNull(value: unknown): string | null | undefined {
	if (value === null) return null;
	if (typeof value !== "string" || value.length > 2048) return undefined;
	try {
		const url = new URL(value);
		return url.protocol === "https:" && !url.username && !url.password ? url.toString() : undefined;
	} catch {
		return undefined;
	}
}

/** Strictly parse a verified catalog for `version`; anything unexpected is null. */
function parseInstallerCatalog(value: Record<string, unknown> | null, version: string): InstallerCatalog | null {
	if (!value || value.type !== "aidr-installer-catalog" || value.product_id !== PRODUCT_ID) return null;
	const schema = value.schema_version;
	if (schema !== 1 && schema !== 2) return null;
	if (value.version !== version || typeof value.published_at !== "string" || !Number.isFinite(Date.parse(value.published_at))) return null;
	const notes = httpsOrNull(value.release_notes_url);
	const release = record(value.release);
	if (
		notes === undefined ||
		!release ||
		typeof release.tag !== "string" ||
		release.tag.length > 256 ||
		typeof release.git_sha !== "string" ||
		!/^[0-9a-f]{40,64}$/i.test(release.git_sha) ||
		!Number.isSafeInteger(release.release_sequence)
	) return null;
	const maxFiles = INSTALLER_PLATFORMS.length * (schema === 1 ? 1 : MAX_FORMATS_PER_PLATFORM);
	if (!Array.isArray(value.files) || value.files.length < 1 || value.files.length > maxFiles) return null;
	const files: InstallerFile[] = [];
	for (const candidate of value.files) {
		const file = parseFile(candidate, version);
		if (!file) return null;
		if (schema === 2 && !file.file.toLowerCase().endsWith(`.${file.format}`)) return null;
		const duplicate = files.some(
			(existing) => existing.platform === file.platform && (schema === 1 || existing.format === file.format),
		);
		if (duplicate) return null;
		files.push(file);
	}
	return {
		schema_version: schema,
		version,
		published_at: value.published_at,
		release_notes_url: notes,
		release: { tag: release.tag, git_sha: release.git_sha, release_sequence: release.release_sequence as number },
		files,
	};
}

/** A download request's `format`: absent, or a well-formed format name (checked against the catalog later). */
export function requestedFormat(value: unknown): string | null | undefined {
	if (value === undefined) return null;
	return typeof value === "string" && FORMAT.test(value) ? value : undefined;
}

/**
 * The catalog file for `platform` in `format`. Without a format: the platform's only
 * file, else its default format (DEFAULT_FORMAT), else the first in INSTALLER_FORMATS
 * order, else the first one listed.
 */
export function selectInstallerFile(
	catalog: InstallerCatalog,
	platform: string,
	format: string | null,
): InstallerFile | undefined {
	const candidates = catalog.files.filter((entry) => entry.platform === platform);
	if (format) return candidates.find((entry) => entry.format === format);
	if (candidates.length <= 1) return candidates[0];
	const os = candidates[0].os;
	for (const preferred of [DEFAULT_FORMAT[os], ...INSTALLER_FORMATS[os]]) {
		const match = candidates.find((entry) => entry.format === preferred);
		if (match) return match;
	}
	return candidates[0];
}

/**
 * Read latest.json, follow it to the versioned catalog and verify both signatures and
 * the pointer digest. Storage errors are 503, a missing pointer is 404 (nothing
 * published yet), and any integrity failure is 503 with no partial data.
 */
export async function loadVerifiedCatalog(read: ObjectReader, spki: Uint8Array<ArrayBuffer>): Promise<CatalogResult> {
	const unavailable = { ok: false, status: 503, error: "catalog_unavailable" } as const;
	const integrity = { ok: false, status: 503, error: "catalog_integrity_failed" } as const;
	try {
		const [pointerBytes, pointerSig] = await Promise.all([
			read("latest.json", MAX_POINTER_BYTES),
			read("latest.json.sig", MAX_SIGNATURE_BYTES),
		]);
		if (pointerBytes === "error" || pointerSig === "error") return unavailable;
		if (pointerBytes === null) return { ok: false, status: 404, error: "installers_unpublished" };
		if (pointerSig === null || !(await verifySignedObject(pointerBytes, pointerSig, spki))) return integrity;
		const pointer = parsePointer(parseJson(pointerBytes));
		if (!pointer) return integrity;

		const [catalogBytes, catalogSig] = await Promise.all([
			read(pointer.manifestPath, MAX_CATALOG_BYTES),
			read(`${pointer.manifestPath}.sig`, MAX_SIGNATURE_BYTES),
		]);
		if (catalogBytes === "error" || catalogSig === "error") return unavailable;
		if (catalogBytes === null || catalogSig === null) return integrity;
		if ((await sha256Hex(catalogBytes)) !== pointer.manifestSha256) return integrity;
		if (!(await verifySignedObject(catalogBytes, catalogSig, spki))) return integrity;
		const catalog = parseInstallerCatalog(parseJson(catalogBytes), pointer.version);
		if (!catalog) return integrity;
		return {
			ok: true,
			catalog,
			documents: { pointer: pointerBytes, pointerSignature: pointerSig, catalog: catalogBytes, catalogSignature: catalogSig },
		};
	} catch {
		return unavailable;
	}
}

/** Signed-URL lifetime: default 300 s, clamped to 30..900 s. */
export function installerUrlTtlSeconds(raw: string | undefined | null): number {
	const value = (raw ?? "").trim();
	const ttl = value === "" ? 300 : /^\d{1,6}$/.test(value) ? Number(value) : Number.NaN;
	return Number.isSafeInteger(ttl) ? Math.min(900, Math.max(30, ttl)) : 300;
}

/**
 * Accept only a Storage signed-object URL for this bucket on the internal Supabase
 * origin, and rebase it onto the public API origin (a self-hosted SUPABASE_URL may be
 * an internal service name the browser cannot reach).
 */
export function publicInstallerUrl(
	signedUrl: unknown,
	supabaseUrl: string,
	publicOrigin: string,
	bucket: string,
): string | null {
	if (typeof signedUrl !== "string" || !signedUrl) return null;
	try {
		const base = new URL(supabaseUrl);
		const target = new URL(signedUrl, base);
		const prefix = `/storage/v1/object/sign/${encodeURIComponent(bucket)}/`;
		if (target.origin !== base.origin || !target.pathname.startsWith(prefix) || !target.searchParams.has("token")) return null;
		return new URL(`${target.pathname}${target.search}`, publicOrigin).toString();
	} catch {
		return null;
	}
}
