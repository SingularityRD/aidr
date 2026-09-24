/**
 * AIG threat-data synchronisation.
 *
 * The sync client deliberately treats the three generated indices as one
 * immutable bundle.  A manifest is downloaded and verified before any
 * pointer is promoted, so a partial/corrupt update can never become active.
 */

import { createHash, createPublicKey, createVerify, randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { lstat, mkdir, mkdtemp, open, readdir, rename, rm, rmdir, unlink } from "node:fs/promises";
import { hostname } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolvePath } from "./config.js";
import {
	atomicWriteJson,
	getFileContent,
	getFileContentRaw,
	getFileContentSync,
} from "./file-utils.js";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

const GENERATED_DIR_REL = join("src", "generated");
const AIG_INDEX_FILES = [
	"aig-cve-index.json",
	"aig-fingerprints.json",
	"aig-mcp-categories.json",
] as const;
const MANIFEST_FILE = "aig-data-manifest.json";
const ACTIVE_POINTER = "active.json";
const STAGED_POINTER = "staged.json";
const RELEASES_DIR = "releases";
const BUNDLE_ID_RE = /^[a-f0-9]{64}$/;
const SHA256_RE = /^[a-f0-9]{64}$/;
const RELEASE_ID_RE = /^[a-f0-9]{64}-[a-f0-9]{64}$/;
const MAX_MANIFEST_BYTES = 1024 * 1024;
const MAX_ARTIFACT_BYTES = 32 * 1024 * 1024;
const PROMOTION_LOCK = ".promotion.lock";
const PROMOTION_LOCK_STALE_MS = 60_000;
const PROMOTION_LOCK_WAIT_MS = 30_000;
const PROMOTION_LOCK_POLL_MS = 10;
const PROCESS_STARTED_AT_MS = Math.max(0, Math.trunc(Date.now() - process.uptime() * 1000));

/**
 * Index schema generations this runtime can consume.
 *
 * The fingerprint index was bumped to v3 when it gained executable detection
 * blocks; accepting only v2 made a legitimately promoted bundle look invalid.
 * Unknown generations still fail closed.
 */
const SUPPORTED_INDEX_SCHEMAS: ReadonlyArray<{ schema: string; version: number }> = [
	{ schema: "aig-cve-index/v2", version: 2 },
	{ schema: "aig-fingerprint-index/v2", version: 2 },
	{ schema: "aig-fingerprint-index/v3", version: 3 },
	{ schema: "aig-mcp-categories/v2", version: 2 },
];

export interface AigSyncConfig {
	enabled: boolean;
	mode: "local" | "http";
	generated_dir: string;
	remote_url: string;
	poll_interval_seconds: number;
	http_timeout_seconds: number;
	cache_dir: string;
	/** Require a cryptographically signed manifest before promotion. */
	require_signed?: boolean;
	/** PEM RSA public key used to verify manifest signatures. */
	public_key?: string;
	/** Path to a PEM RSA public key used when public_key is not set. */
	public_key_path?: string;
	/** Manifest signer key ID approved by release policy. */
	trusted_key_id?: string;
	/** SHA-256 of the trusted public key's DER-encoded SPKI. */
	trusted_public_key_sha256?: string;
	/** Explicit test/development escape hatch for HTTP on a loopback host. */
	allow_insecure_loopback?: boolean;
}

export interface SyncStatus {
	lastCheck: string | null;
	lastUpdate: string | null;
	cveCount: number;
	mcpCategoryCount: number;
	fingerprintCount: number;
	updateAvailable: boolean;
	mode: "local" | "http";
	currentHash: string;
	lastError: string | null;
	manifestValid: boolean;
	signaturePresent: boolean;
	bundleId: string | null;
	activeDir: string;
}

interface IndexMeta {
	schema?: string;
	version?: number;
	generated?: string;
	cves?: unknown[];
	fingerprints?: unknown[];
	categories?: unknown[];
	[key: string]: unknown;
}

interface DataManifest {
	schema: string;
	generated: string;
	release_sequence?: number;
	source?: { repository?: string; commit?: string; tree_sha256?: string };
	bundle_id: string;
	artifacts: Record<string, { sha256: string; bytes: number }>;
	counts?: { cves?: number; fingerprints?: number; mcp_categories?: number };
	signature?: { algorithm: string; key_id: string; value: string } | null;
}

export interface AigBundleValidation {
	valid: boolean;
	signaturePresent: boolean;
	bundleId: string | null;
	error: string | null;
}

function moduleDirectory(): string {
	try {
		if (typeof import.meta.dirname === "string") return import.meta.dirname;
	} catch {
		// import.meta.dirname is unavailable on older Node versions.
	}
	try {
		if (typeof import.meta.url === "string") return dirname(fileURLToPath(import.meta.url));
	} catch {
		// CommonJS bundles replace import.meta with an empty object.
	}
	return process.cwd();
}

const PACKAGE_ROOT = join(moduleDirectory(), "..");

function defaultGeneratedDir(): string {
	return join(PACKAGE_ROOT, GENERATED_DIR_REL);
}

function defaultCacheDir(): string {
	return resolvePath("~/.singularity-aidr/cache/aig-sync");
}

const DEFAULT_AIG_SYNC_CONFIG: AigSyncConfig = {
	enabled: true,
	mode: "local",
	generated_dir: defaultGeneratedDir(),
	remote_url: "",
	poll_interval_seconds: 3600,
	http_timeout_seconds: 30,
	cache_dir: defaultCacheDir(),
	require_signed: process.env.AIG_REQUIRE_SIGNED === "true",
	public_key: process.env.AIG_SIGNING_PUBLIC_KEY || "",
	public_key_path: process.env.AIG_SIGNING_PUBLIC_KEY_PATH || "",
	trusted_key_id: process.env.AIG_TRUSTED_SIGNING_KEY_ID || "",
	trusted_public_key_sha256: process.env.AIG_TRUSTED_SIGNING_PUBLIC_KEY_SHA256 || "",
	allow_insecure_loopback: process.env.AIG_ALLOW_INSECURE_LOOPBACK === "true",
};

function resolveConfig(config?: Partial<AigSyncConfig>): AigSyncConfig {
	const resolved = { ...DEFAULT_AIG_SYNC_CONFIG, ...config };
	// Remote data is never allowed to weaken the trust boundary, even when a
	// caller accidentally carries over a permissive local-mode configuration.
	if (resolved.mode === "http") resolved.require_signed = true;
	return resolved;
}

function isManifest(value: unknown): value is DataManifest {
	if (!value || typeof value !== "object") return false;
	const candidate = value as Partial<DataManifest>;
	if (candidate.schema !== "aig-data-manifest/v1") return false;
	if (typeof candidate.generated !== "string" || !Number.isFinite(Date.parse(candidate.generated)))
		return false;
	if (
		candidate.release_sequence !== undefined &&
		(!Number.isSafeInteger(candidate.release_sequence) || candidate.release_sequence < 1)
	)
		return false;
	if (typeof candidate.bundle_id !== "string" || !BUNDLE_ID_RE.test(candidate.bundle_id))
		return false;
	if (!candidate.artifacts || typeof candidate.artifacts !== "object") return false;
	for (const file of AIG_INDEX_FILES) {
		const artifact = candidate.artifacts[file];
		if (!artifact || typeof artifact !== "object") return false;
		if (
			!SHA256_RE.test(artifact.sha256) ||
			!Number.isInteger(artifact.bytes) ||
			artifact.bytes <= 0 ||
			artifact.bytes > MAX_ARTIFACT_BYTES
		)
			return false;
	}
	const expectedBundleId = createHash("sha256")
		.update(
			canonicalJson(
				Object.fromEntries(AIG_INDEX_FILES.map((file) => [file, candidate.artifacts?.[file]])),
			),
		)
		.digest("hex");
	if (candidate.bundle_id !== expectedBundleId) return false;
	if (candidate.signature !== undefined && candidate.signature !== null) {
		if (typeof candidate.signature !== "object") return false;
		if (
			candidate.signature.algorithm !== "RSA-SHA256" ||
			typeof candidate.signature.key_id !== "string" ||
			typeof candidate.signature.value !== "string"
		)
			return false;
	}
	return true;
}

function manifestPayload(manifest: DataManifest): Record<string, unknown> {
	const { signature: _signature, ...payload } = manifest;
	return payload;
}

function canonicalJson(value: unknown): string {
	return JSON.stringify(value);
}

function verifyManifestSignature(manifest: DataManifest, publicKey: string): boolean {
	if (!manifest.signature || !publicKey) return false;
	try {
		const key = createPublicKey(publicKey);
		if (key.asymmetricKeyType !== "rsa") return false;
		const verifier = createVerify("RSA-SHA256");
		verifier.update(canonicalJson(manifestPayload(manifest)));
		verifier.end();
		return verifier.verify(key, manifest.signature.value, "base64");
	} catch {
		return false;
	}
}

function publicKeyFingerprint(publicKey: string): string | null {
	try {
		const key = createPublicKey(publicKey);
		if (key.asymmetricKeyType !== "rsa") return null;
		const spki = key.export({ type: "spki", format: "der" });
		return createHash("sha256").update(spki).digest("hex");
	} catch {
		return null;
	}
}

async function resolvePublicKey(
	config: Pick<AigSyncConfig, "public_key" | "public_key_path">,
): Promise<string> {
	if (config.public_key?.trim()) return config.public_key;
	if (!config.public_key_path?.trim()) return "";
	try {
		return await getFileContent(config.public_key_path);
	} catch {
		return "";
	}
}

async function validateManifestTrust(
	manifest: DataManifest,
	config: Pick<
		AigSyncConfig,
		| "require_signed"
		| "public_key"
		| "public_key_path"
		| "trusted_key_id"
		| "trusted_public_key_sha256"
	>,
): Promise<string | null> {
	if (config.require_signed && !manifest.signature) return "signed manifest required";
	if (!manifest.signature) return null;

	const trustedKeyId = config.trusted_key_id?.trim() ?? "";
	const trustedFingerprint = config.trusted_public_key_sha256?.trim().toLowerCase() ?? "";
	if (!manifest.signature.key_id.trim() || manifest.signature.key_id === "unspecified") {
		return "manifest signature key ID is invalid";
	}
	if (config.require_signed && (!trustedKeyId || !SHA256_RE.test(trustedFingerprint))) {
		return "trusted signing policy is incomplete";
	}
	if (trustedKeyId && manifest.signature.key_id !== trustedKeyId)
		return "manifest signer is not trusted";
	if (trustedFingerprint && !SHA256_RE.test(trustedFingerprint))
		return "trusted public-key fingerprint is invalid";

	const publicKey = await resolvePublicKey(config);
	if (!publicKey)
		return config.require_signed
			? "manifest signature cannot be verified without a public key"
			: null;
	const fingerprint = publicKeyFingerprint(publicKey);
	if (!fingerprint) return "manifest public key is invalid";
	if (trustedFingerprint && fingerprint !== trustedFingerprint)
		return "manifest public key is not trusted";
	if (!verifyManifestSignature(manifest, publicKey))
		return "manifest signature verification failed";
	return null;
}

async function sha256File(path: string): Promise<{ sha256: string; bytes: number } | null> {
	try {
		const bytes = await getFileContentRaw(path);
		return { sha256: createHash("sha256").update(bytes).digest("hex"), bytes: bytes.byteLength };
	} catch {
		return null;
	}
}

async function readManifest(dir: string): Promise<DataManifest | null> {
	try {
		const parsed: unknown = JSON.parse(await getFileContent(join(dir, MANIFEST_FILE)));
		return isManifest(parsed) ? parsed : null;
	} catch {
		return null;
	}
}

/** Verify all index hashes and (when configured) the manifest signature. */
export async function validateAigDataBundle(
	dir: string,
	config: Pick<
		AigSyncConfig,
		| "require_signed"
		| "public_key"
		| "public_key_path"
		| "trusted_key_id"
		| "trusted_public_key_sha256"
	> = DEFAULT_AIG_SYNC_CONFIG,
): Promise<AigBundleValidation> {
	const manifest = await readManifest(dir);
	if (!manifest)
		return {
			valid: false,
			signaturePresent: false,
			bundleId: null,
			error: "manifest missing or malformed",
		};
	const signaturePresent = Boolean(manifest.signature);
	const trustError = await validateManifestTrust(manifest, config);
	if (trustError) {
		return { valid: false, signaturePresent, bundleId: manifest.bundle_id, error: trustError };
	}

	for (const file of AIG_INDEX_FILES) {
		const expected = manifest.artifacts[file];
		if (!expected)
			return {
				valid: false,
				signaturePresent: Boolean(manifest.signature),
				bundleId: manifest.bundle_id,
				error: `manifest artifact missing: ${file}`,
			};
		const actual = await sha256File(join(dir, file));
		if (!actual || actual.sha256 !== expected.sha256 || actual.bytes !== expected.bytes) {
			return {
				valid: false,
				signaturePresent: Boolean(manifest.signature),
				bundleId: manifest.bundle_id,
				error: `artifact hash/size mismatch: ${file}`,
			};
		}
		try {
			const index = JSON.parse(await getFileContent(join(dir, file))) as IndexMeta;
			// Accept every supported index schema generation. The fingerprint index
			// moved to v3 when it started carrying executable detection blocks
			// (probes, matchers, version extractors); the CVE and MCP indexes remain
			// at v2. Rejecting v3 here would make a valid promoted bundle look
			// tampered, and the check runs before the signature test, so it also
			// masked the "signed manifest required" error.
			const schemaVersion = Number(index.version);
			if (
				typeof index.schema !== "string" ||
				!SUPPORTED_INDEX_SCHEMAS.some(
					(entry) => entry.schema === index.schema && entry.version === schemaVersion,
				)
			) {
				return {
					valid: false,
					signaturePresent: Boolean(manifest.signature),
					bundleId: manifest.bundle_id,
					error: `unsupported index schema: ${file}`,
				};
			}
		} catch {
			return {
				valid: false,
				signaturePresent: Boolean(manifest.signature),
				bundleId: manifest.bundle_id,
				error: `invalid JSON: ${file}`,
			};
		}
	}

	return { valid: true, signaturePresent, bundleId: manifest.bundle_id, error: null };
}

async function quickHash(filePath: string): Promise<string> {
	const hash = await sha256File(filePath);
	return hash?.sha256 ?? "";
}

async function readIndex(filePath: string): Promise<IndexMeta | null> {
	try {
		const raw = await getFileContent(filePath);
		const parsed: unknown = JSON.parse(raw);
		return parsed && typeof parsed === "object" ? (parsed as IndexMeta) : null;
	} catch {
		return null;
	}
}

interface BundlePointer {
	bundle_id?: string;
	manifest_sha256?: string;
	release_id?: string;
}

function readPointer(cacheDir: string, pointer: string): BundlePointer | null {
	try {
		const parsed: unknown = JSON.parse(getFileContentSync(join(cacheDir, pointer), "utf8"));
		return parsed && typeof parsed === "object" ? (parsed as BundlePointer) : null;
	} catch {
		return null;
	}
}

function pointerReleaseDir(cacheDir: string, pointer: BundlePointer): string | null {
	if (!pointer.bundle_id || !BUNDLE_ID_RE.test(pointer.bundle_id)) return null;
	if (pointer.release_id !== undefined) {
		if (
			!RELEASE_ID_RE.test(pointer.release_id) ||
			pointer.release_id !== `${pointer.bundle_id}-${pointer.manifest_sha256}`
		)
			return null;
	}
	const releaseName = pointer.release_id ?? pointer.bundle_id;
	return join(cacheDir, RELEASES_DIR, releaseName);
}

function resolveGeneratedDir(config: AigSyncConfig): string {
	if (config.mode !== "http") return config.generated_dir;
	const active = readPointer(config.cache_dir, ACTIVE_POINTER);
	if (active) {
		const releaseDir = pointerReleaseDir(config.cache_dir, active);
		if (!releaseDir) return config.cache_dir;
		if (existsSync(releaseDir)) return releaseDir;
	}
	// Backwards-compatible cache layout for pre-manifest installations.
	return config.cache_dir;
}

function countEntries(data: IndexMeta | null, key: "cves" | "fingerprints" | "categories"): number {
	return Array.isArray(data?.[key]) ? (data[key]?.length ?? 0) : 0;
}

function initTimeout(seconds: number): [AbortController, NodeJS.Timeout] {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), Math.max(1, seconds) * 1000);
	return [controller, timer];
}

interface RemoteUrls {
	manifest: URL;
	artifacts: Record<(typeof AIG_INDEX_FILES)[number], URL>;
}

function isLoopbackHost(hostname: string): boolean {
	return (
		hostname === "localhost" ||
		hostname === "127.0.0.1" ||
		hostname === "[::1]" ||
		hostname === "::1"
	);
}

function resolveRemoteUrls(remoteUrl: string, allowInsecureLoopback = false): RemoteUrls {
	const configured = new URL(remoteUrl);
	if (configured.username || configured.password || configured.search || configured.hash) {
		throw new Error("remote AIG URL must not contain credentials, query parameters, or a fragment");
	}
	if (
		configured.protocol !== "https:" &&
		!(
			configured.protocol === "http:" &&
			allowInsecureLoopback &&
			isLoopbackHost(configured.hostname)
		)
	) {
		throw new Error(
			"remote AIG URL must use HTTPS (loopback HTTP requires allow_insecure_loopback)",
		);
	}

	const manifest = configured.pathname.endsWith(`/${MANIFEST_FILE}`)
		? configured
		: new URL(`${configured.pathname.replace(/\/+$/, "")}/${MANIFEST_FILE}`, configured);
	const base = new URL(".", manifest);
	const artifacts = Object.fromEntries(
		AIG_INDEX_FILES.map((file) => [file, new URL(file, base)]),
	) as RemoteUrls["artifacts"];
	for (const url of Object.values(artifacts)) {
		if (url.origin !== manifest.origin)
			throw new Error("remote AIG artifacts must use the manifest origin");
	}
	return { manifest, artifacts };
}

async function fetchBytes(url: URL, timeoutSeconds: number, maxBytes: number): Promise<Buffer> {
	const [controller, timer] = initTimeout(timeoutSeconds);
	try {
		const resp = await fetch(url, {
			signal: controller.signal,
			headers: { accept: "application/json" },
			redirect: "manual",
		});
		if (resp.status >= 300 && resp.status < 400)
			throw new Error(`redirect refused for ${url.origin}`);
		if (!resp.ok) throw new Error(`HTTP ${resp.status} from ${url.origin}`);
		if (resp.redirected) throw new Error(`redirect refused for ${url.origin}`);
		if (resp.url && new URL(resp.url).origin !== url.origin)
			throw new Error("remote AIG response changed origin");

		const lengthHeader = resp.headers.get("content-length");
		if (lengthHeader !== null) {
			if (!/^\d+$/.test(lengthHeader))
				throw new Error("invalid Content-Length from remote AIG server");
			if (Number(lengthHeader) > maxBytes)
				throw new Error(`remote AIG response exceeds ${maxBytes} bytes`);
		}
		if (!resp.body) throw new Error("remote AIG response body is missing");

		const reader = resp.body.getReader();
		const chunks: Buffer[] = [];
		let received = 0;
		for (;;) {
			const { done, value } = await reader.read();
			if (done) break;
			received += value.byteLength;
			if (received > maxBytes) {
				await reader.cancel().catch(() => undefined);
				throw new Error(`remote AIG response exceeds ${maxBytes} bytes`);
			}
			chunks.push(Buffer.from(value));
		}
		return Buffer.concat(chunks, received);
	} finally {
		clearTimeout(timer);
	}
}

function rollbackError(current: DataManifest | null, candidate: DataManifest): string | null {
	if (!current) return null;
	if (candidate.release_sequence !== undefined) {
		if (current.release_sequence === undefined) return null;
		if (candidate.release_sequence < current.release_sequence)
			return `refusing AIG release-sequence rollback from ${current.release_sequence} to ${candidate.release_sequence}`;
		if (
			candidate.release_sequence === current.release_sequence &&
			current.bundle_id !== candidate.bundle_id
		)
			return `refusing conflicting AIG bundle at release sequence ${candidate.release_sequence}`;
		return null;
	}
	if (current.release_sequence !== undefined)
		return "refusing unsequenced AIG manifest after release-sequence migration";
	if (current.bundle_id === candidate.bundle_id) return null;
	if (Date.parse(candidate.generated) <= Date.parse(current.generated)) {
		return `refusing AIG rollback from ${current.generated} to ${candidate.generated}`;
	}
	return null;
}

async function checkRemoteForUpdate(
	cfg: AigSyncConfig,
	genDir: string,
	status: SyncStatus,
	logger: Logger,
): Promise<void> {
	try {
		const urls = resolveRemoteUrls(cfg.remote_url, cfg.allow_insecure_loopback);
		const remoteBytes = await fetchBytes(
			urls.manifest,
			cfg.http_timeout_seconds,
			MAX_MANIFEST_BYTES,
		);
		const remote = parseJsonBytes(remoteBytes);
		if (!isManifest(remote)) throw new Error("remote AIG manifest missing or malformed");
		const trustError = await validateManifestTrust(remote, cfg);
		if (trustError) throw new Error(trustError);
		const localManifest = await readManifest(genDir);
		const rollback = rollbackError(localManifest, remote);
		if (rollback) throw new Error(rollback);
		status.updateAvailable =
			!status.manifestValid || !localManifest || localManifest.bundle_id !== remote.bundle_id;
	} catch (err) {
		status.updateAvailable = false;
		status.lastError = err instanceof Error ? err.message : String(err);
		logger.warn("AIG sync HTTP check failed", { error: status.lastError });
	}
}

async function checkLocalForUpdate(
	genDir: string,
	status: SyncStatus,
	cfg: AigSyncConfig,
): Promise<void> {
	const validation = await validateAigDataBundle(genDir, cfg);
	status.updateAvailable = !validation.valid;
	if (!validation.valid) status.lastError = validation.error;
}

export async function getSyncStatus(
	config?: Partial<AigSyncConfig>,
	logger: Logger = nullLogger,
): Promise<SyncStatus> {
	const cfg = resolveConfig(config);
	const genDir = resolveGeneratedDir(cfg);
	logger.debug("Reading AIG sync status", { generatedDir: genDir, mode: cfg.mode });

	const cveIndex = await readIndex(join(genDir, "aig-cve-index.json"));
	const fpIndex = await readIndex(join(genDir, "aig-fingerprints.json"));
	const mcpIndex = await readIndex(join(genDir, "aig-mcp-categories.json"));
	const validation = await validateAigDataBundle(genDir, cfg);
	const manifest = await readManifest(genDir);

	return {
		lastCheck: null,
		lastUpdate: null,
		cveCount: countEntries(cveIndex, "cves"),
		mcpCategoryCount: countEntries(mcpIndex, "categories"),
		fingerprintCount: countEntries(fpIndex, "fingerprints"),
		updateAvailable: false,
		mode: cfg.mode,
		currentHash: await quickHash(join(genDir, "aig-cve-index.json")),
		lastError: validation.valid ? null : validation.error,
		manifestValid: validation.valid,
		signaturePresent: validation.signaturePresent,
		bundleId: manifest?.bundle_id ?? validation.bundleId,
		activeDir: genDir,
	};
}

export async function checkForUpdates(
	config?: Partial<AigSyncConfig>,
	logger: Logger = nullLogger,
): Promise<SyncStatus> {
	const cfg = resolveConfig(config);
	const genDir = resolveGeneratedDir(cfg);
	const status = await getSyncStatus(config, logger);
	status.lastCheck = new Date().toISOString();

	if (cfg.mode === "http" && cfg.remote_url)
		await checkRemoteForUpdate(cfg, genDir, status, logger);
	else await checkLocalForUpdate(genDir, status, cfg);
	return status;
}

function parseJsonBytes(bytes: Buffer): unknown | null {
	try {
		return JSON.parse(bytes.toString("utf8"));
	} catch {
		return null;
	}
}

interface PromotionLockOwner {
	v: 1;
	token: string;
	pid: number;
	host: string;
	process_started_at_ms: number;
}

function errorCode(error: unknown): string | undefined {
	return (error as NodeJS.ErrnoException | undefined)?.code;
}

function isPromotionLockOwner(value: unknown): value is PromotionLockOwner {
	if (!value || typeof value !== "object" || Array.isArray(value)) return false;
	const owner = value as Partial<PromotionLockOwner>;
	return (
		owner.v === 1 &&
		typeof owner.token === "string" &&
		owner.token.length > 0 &&
		Number.isSafeInteger(owner.pid) &&
		(owner.pid ?? 0) > 0 &&
		typeof owner.host === "string" &&
		owner.host.length > 0 &&
		Number.isSafeInteger(owner.process_started_at_ms) &&
		(owner.process_started_at_ms ?? -1) >= 0
	);
}

function promotionOwnerAlive(owner: PromotionLockOwner): boolean | null {
	if (owner.pid === process.pid) return owner.process_started_at_ms === PROCESS_STARTED_AT_MS;
	try {
		process.kill(owner.pid, 0);
		return true;
	} catch (error) {
		if (errorCode(error) === "ESRCH") return false;
		if (errorCode(error) === "EPERM") return true;
		return null;
	}
}

async function writeSyncedExclusive(path: string, bytes: string | Buffer): Promise<void> {
	const handle = await open(path, "wx", 0o600);
	try {
		await handle.writeFile(bytes);
		await handle.sync();
	} finally {
		await handle.close();
	}
}

async function syncDirectory(path: string): Promise<void> {
	if (process.platform === "win32") return;
	const handle = await open(path, "r");
	try {
		await handle.sync();
	} finally {
		await handle.close();
	}
}

function promotionOwnerFile(token: string): string {
	return `owner.${token}.json`;
}

async function removePromotionLock(lockPath: string, token: string): Promise<boolean> {
	try {
		await unlink(join(lockPath, promotionOwnerFile(token)));
	} catch (error) {
		if (errorCode(error) === "ENOENT") return false;
		throw error;
	}
	try {
		await rmdir(lockPath);
		return true;
	} catch (error) {
		if (["ENOENT", "ENOTEMPTY", "EEXIST"].includes(errorCode(error) ?? "")) return false;
		throw error;
	}
}

async function recoverPromotionLock(lockPath: string): Promise<boolean> {
	let lockStat;
	try {
		lockStat = await lstat(lockPath);
	} catch (error) {
		if (errorCode(error) === "ENOENT") return true;
		throw error;
	}
	if (
		!lockStat.isDirectory() ||
		lockStat.isSymbolicLink() ||
		Date.now() - lockStat.mtimeMs <= PROMOTION_LOCK_STALE_MS
	) {
		return false;
	}

	const names = await readdir(lockPath);
	if (names.length === 0) {
		try {
			await rmdir(lockPath);
			return true;
		} catch (error) {
			if (["ENOENT", "ENOTEMPTY", "EEXIST"].includes(errorCode(error) ?? "")) return false;
			throw error;
		}
	}
	const marker =
		names.length === 1 && /^owner\.[^.]+\.json$/.test(names[0] ?? "") ? names[0] : undefined;
	if (!marker) return false;

	let owner: PromotionLockOwner | null = null;
	try {
		const parsed: unknown = JSON.parse(await getFileContent(join(lockPath, marker)));
		if (isPromotionLockOwner(parsed) && marker === promotionOwnerFile(parsed.token)) owner = parsed;
	} catch {
		// An aged partial owner publication is abandoned.
	}
	if (owner?.host === hostname() && promotionOwnerAlive(owner) !== false) return false;
	return removePromotionLock(lockPath, owner?.token ?? marker.slice(6, -5));
}

async function withPromotionLock<T>(cacheDir: string, work: () => Promise<T>): Promise<T> {
	await mkdir(cacheDir, { recursive: true, mode: 0o700 });
	const lockPath = join(cacheDir, PROMOTION_LOCK);
	const token = randomUUID();
	const marker = promotionOwnerFile(token);
	const temporary = join(cacheDir, `.promotion-owner.${token}.tmp`);
	const until = Date.now() + PROMOTION_LOCK_WAIT_MS;
	for (;;) {
		try {
			await mkdir(lockPath, { mode: 0o700 });
			try {
				await writeSyncedExclusive(
					temporary,
					`${JSON.stringify({
						v: 1,
						token,
						pid: process.pid,
						host: hostname(),
						process_started_at_ms: PROCESS_STARTED_AT_MS,
					} satisfies PromotionLockOwner)}\n`,
				);
				await rename(temporary, join(lockPath, marker));
			} catch (error) {
				await unlink(temporary).catch(() => undefined);
				await rmdir(lockPath).catch(() => undefined);
				throw error;
			}
			break;
		} catch (error) {
			if (errorCode(error) !== "EEXIST") throw error;
			if (await recoverPromotionLock(lockPath)) continue;
			if (Date.now() >= until) throw new Error("aig_promotion_lock_unavailable");
			await new Promise((resolve) => setTimeout(resolve, PROMOTION_LOCK_POLL_MS));
		}
	}
	try {
		return await work();
	} finally {
		await unlink(temporary).catch(() => undefined);
		await removePromotionLock(lockPath, token).catch(() => undefined);
	}
}

async function downloadHttpMode(cfg: AigSyncConfig, logger: Logger): Promise<boolean> {
	const urls = resolveRemoteUrls(cfg.remote_url, cfg.allow_insecure_loopback);
	const remoteManifestBytes = await fetchBytes(
		urls.manifest,
		cfg.http_timeout_seconds,
		MAX_MANIFEST_BYTES,
	);
	const remoteManifest = parseJsonBytes(remoteManifestBytes);
	if (!isManifest(remoteManifest)) {
		logger.error("Failed to fetch a valid remote AIG manifest", { url: urls.manifest.toString() });
		return false;
	}
	const trustError = await validateManifestTrust(remoteManifest, cfg);
	if (trustError) {
		logger.error("Refusing untrusted remote AIG manifest", { error: trustError });
		return false;
	}
	const rollback = rollbackError(await readManifest(resolveGeneratedDir(cfg)), remoteManifest);
	if (rollback) {
		logger.error("Refusing remote AIG rollback", { error: rollback });
		return false;
	}
	const manifestHash = createHash("sha256").update(remoteManifestBytes).digest("hex");

	await mkdir(cfg.cache_dir, { recursive: true });
	const stagingDir = await mkdtemp(join(cfg.cache_dir, ".staging-"));
	const releaseId = `${remoteManifest.bundle_id}-${manifestHash}`;
	const releasesDir = join(cfg.cache_dir, RELEASES_DIR);
	const releaseDir = join(releasesDir, releaseId);
	try {
		for (const file of AIG_INDEX_FILES) {
			logger.debug("Fetching AIG artifact", { file });
			const expected = remoteManifest.artifacts[file];
			if (!expected) throw new Error(`manifest artifact missing: ${file}`);
			const bytes = await fetchBytes(
				urls.artifacts[file],
				cfg.http_timeout_seconds,
				expected.bytes,
			);
			if (bytes.byteLength !== expected.bytes) throw new Error(`artifact size mismatch: ${file}`);
			const parsed = parseJsonBytes(bytes);
			if (!parsed || typeof parsed !== "object") throw new Error(`invalid JSON in ${file}`);
			await writeSyncedExclusive(join(stagingDir, file), bytes);
		}
		await writeSyncedExclusive(join(stagingDir, MANIFEST_FILE), remoteManifestBytes);
		await syncDirectory(stagingDir);
		const validation = await validateAigDataBundle(stagingDir, cfg);
		if (!validation.valid || validation.bundleId !== remoteManifest.bundle_id)
			throw new Error(validation.error ?? "bundle validation failed");

		await mkdir(releasesDir, { recursive: true });
		await syncDirectory(cfg.cache_dir);
		try {
			await rename(stagingDir, releaseDir);
		} catch {
			const existing = await validateAigDataBundle(releaseDir, cfg);
			const reusable =
				existing.valid &&
				existing.bundleId === remoteManifest.bundle_id &&
				(await quickHash(join(releaseDir, MANIFEST_FILE))) === manifestHash;
			if (reusable) {
				await rm(stagingDir, { recursive: true, force: true });
			} else {
				await rm(releaseDir, { recursive: true, force: true });
				await rename(stagingDir, releaseDir);
			}
		}
		await syncDirectory(releasesDir);
		await atomicWriteJson(join(cfg.cache_dir, STAGED_POINTER), {
			bundle_id: remoteManifest.bundle_id,
			manifest_sha256: manifestHash,
			release_id: releaseId,
		});
		return true;
	} catch (err) {
		logger.error("Failed to stage remote AIG update", {
			error: err instanceof Error ? err.message : String(err),
		});
		await rm(stagingDir, { recursive: true, force: true }).catch(() => undefined);
		return false;
	}
}

async function downloadLocalMode(
	genDir: string,
	logger: Logger,
	cfg: AigSyncConfig,
): Promise<boolean> {
	const validation = await validateAigDataBundle(genDir, cfg);
	if (!validation.valid) {
		logger.warn("Generated AIG bundle is not valid", { error: validation.error });
		return false;
	}
	return true;
}

export async function downloadUpdate(
	config?: Partial<AigSyncConfig>,
	logger: Logger = nullLogger,
): Promise<boolean> {
	const cfg = resolveConfig(config);
	const genDir = resolveGeneratedDir(cfg);
	logger.info("Downloading AIG threat update", { mode: cfg.mode, generatedDir: genDir });
	try {
		if (cfg.mode === "http" && cfg.remote_url) return await downloadHttpMode(cfg, logger);
		return await downloadLocalMode(genDir, logger, cfg);
	} catch (err) {
		logger.error("AIG download update failed", {
			error: err instanceof Error ? err.message : String(err),
		});
		return false;
	}
}

export async function applyUpdate(
	config?: Partial<AigSyncConfig>,
	logger: Logger = nullLogger,
): Promise<boolean> {
	const cfg = resolveConfig(config);
	if (cfg.mode !== "http") {
		const validation = await validateAigDataBundle(cfg.generated_dir, cfg);
		if (!validation.valid) {
			logger.warn("Generated AIG bundle is invalid; refusing to apply", {
				error: validation.error,
			});
			return false;
		}
		process.env.AIG_GENERATED_DIR = cfg.generated_dir;
		return true;
	}

	const staged = readPointer(cfg.cache_dir, STAGED_POINTER);
	if (!staged?.bundle_id || !BUNDLE_ID_RE.test(staged.bundle_id)) {
		logger.warn("No staged AIG bundle available");
		return false;
	}
	const releaseDir = pointerReleaseDir(cfg.cache_dir, staged);
	if (!releaseDir) {
		logger.error("Refusing invalid staged AIG pointer");
		return false;
	}
	return withPromotionLock(cfg.cache_dir, async () => {
		const stagedManifest = await readManifest(releaseDir);
		if (
			!staged.manifest_sha256 ||
			!SHA256_RE.test(staged.manifest_sha256) ||
			(await quickHash(join(releaseDir, MANIFEST_FILE))) !== staged.manifest_sha256
		) {
			logger.error("Refusing staged AIG manifest hash mismatch");
			return false;
		}
		const validation = await validateAigDataBundle(releaseDir, cfg);
		if (!stagedManifest || !validation.valid || validation.bundleId !== staged.bundle_id) {
			logger.error("Refusing to activate invalid AIG bundle", { error: validation.error });
			return false;
		}
		const rollback = rollbackError(await readManifest(resolveGeneratedDir(cfg)), stagedManifest);
		if (rollback) {
			logger.error("Refusing to activate AIG rollback", { error: rollback });
			return false;
		}
		await atomicWriteJson(join(cfg.cache_dir, ACTIVE_POINTER), {
			bundle_id: staged.bundle_id,
			manifest_sha256: staged.manifest_sha256,
			...(staged.release_id ? { release_id: staged.release_id } : {}),
			activated_at: new Date().toISOString(),
		});
		process.env.AIG_GENERATED_DIR = releaseDir;
		logger.info("AIG update activated", { bundleId: staged.bundle_id });
		return true;
	});
}

export async function fullSyncCycle(
	config?: Partial<AigSyncConfig>,
	logger: Logger = nullLogger,
): Promise<boolean> {
	logger.info("Starting AIG full sync cycle");
	const status = await checkForUpdates(config, logger);
	if (!status.updateAvailable) {
		logger.debug("AIG indices are up-to-date, skipping download");
		return status.manifestValid;
	}
	if (!(await downloadUpdate(config, logger))) {
		logger.error("AIG download failed during full sync cycle");
		return false;
	}
	if (!(await applyUpdate(config, logger))) {
		logger.error("AIG apply failed during full sync cycle");
		return false;
	}
	logger.info("AIG full sync cycle completed successfully");
	return true;
}
