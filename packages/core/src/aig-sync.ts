/**
 * AIG threat-data synchronisation.
 *
 * The sync client deliberately treats the three generated indices as one
 * immutable bundle.  A manifest is downloaded and verified before any
 * pointer is promoted, so a partial/corrupt update can never become active.
 */

import { existsSync } from "node:fs";
import { mkdir, rename, rm } from "node:fs/promises";
import { createHash, createVerify } from "node:crypto";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent, getFileContentRaw, getFileContentSync } from "./file-utils.js";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

const GENERATED_DIR_REL = join("src", "generated");
export const AIG_INDEX_FILES = ["aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json"] as const;
const MANIFEST_FILE = "aig-data-manifest.json";
const ACTIVE_POINTER = "active.json";
const STAGED_POINTER = "staged.json";
const RELEASES_DIR = "releases";
const BUNDLE_ID_RE = /^[a-f0-9]{64}$/;

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

export interface DataManifest {
	schema: string;
	generated: string;
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

export const DEFAULT_AIG_SYNC_CONFIG: AigSyncConfig = {
	enabled: true,
	mode: "local",
	generated_dir: defaultGeneratedDir(),
	remote_url: "",
	poll_interval_seconds: 3600,
	http_timeout_seconds: 30,
	cache_dir: defaultCacheDir(),
	require_signed: process.env.AIG_REQUIRE_SIGNED === "true",
	public_key: process.env.AIG_SIGNING_PUBLIC_KEY || "",
};

function isManifest(value: unknown): value is DataManifest {
	if (!value || typeof value !== "object") return false;
	const candidate = value as Partial<DataManifest>;
	if (typeof candidate.schema !== "string" || !candidate.schema.startsWith("aig-data-manifest/")) return false;
	if (typeof candidate.generated !== "string" || !candidate.generated) return false;
	if (typeof candidate.bundle_id !== "string" || !BUNDLE_ID_RE.test(candidate.bundle_id)) return false;
	if (!candidate.artifacts || typeof candidate.artifacts !== "object") return false;
	for (const file of AIG_INDEX_FILES) {
		const artifact = candidate.artifacts[file];
		if (!artifact || typeof artifact !== "object") return false;
		if (!/^[a-f0-9]{64}$/.test(artifact.sha256) || !Number.isInteger(artifact.bytes) || artifact.bytes < 0) return false;
	}
	if (candidate.signature !== undefined && candidate.signature !== null) {
		if (typeof candidate.signature !== "object") return false;
		if (candidate.signature.algorithm !== "RSA-SHA256" || typeof candidate.signature.value !== "string") return false;
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
		const verifier = createVerify("RSA-SHA256");
		verifier.update(canonicalJson(manifestPayload(manifest)));
		verifier.end();
		return verifier.verify(publicKey, manifest.signature.value, "base64");
	} catch {
		return false;
	}
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
	config: Pick<AigSyncConfig, "require_signed" | "public_key"> = DEFAULT_AIG_SYNC_CONFIG,
): Promise<AigBundleValidation> {
	const manifest = await readManifest(dir);
	if (!manifest) return { valid: false, signaturePresent: false, bundleId: null, error: "manifest missing or malformed" };

	for (const file of AIG_INDEX_FILES) {
		const expected = manifest.artifacts[file];
		if (!expected) return { valid: false, signaturePresent: Boolean(manifest.signature), bundleId: manifest.bundle_id, error: `manifest artifact missing: ${file}` };
		const actual = await sha256File(join(dir, file));
		if (!actual || actual.sha256 !== expected.sha256 || actual.bytes !== expected.bytes) {
			return { valid: false, signaturePresent: Boolean(manifest.signature), bundleId: manifest.bundle_id, error: `artifact hash/size mismatch: ${file}` };
		}
		try {
			const index = JSON.parse(await getFileContent(join(dir, file))) as IndexMeta;
			if (index.version !== 2 || typeof index.schema !== "string" || !index.schema.endsWith("/v2")) {
				return { valid: false, signaturePresent: Boolean(manifest.signature), bundleId: manifest.bundle_id, error: `unsupported index schema: ${file}` };
			}
		} catch {
			return { valid: false, signaturePresent: Boolean(manifest.signature), bundleId: manifest.bundle_id, error: `invalid JSON: ${file}` };
		}
	}

	const signaturePresent = Boolean(manifest.signature);
	if (config.require_signed && !signaturePresent) {
		return { valid: false, signaturePresent: false, bundleId: manifest.bundle_id, error: "signed manifest required" };
	}
	if (signaturePresent && config.public_key && !verifyManifestSignature(manifest, config.public_key)) {
		return { valid: false, signaturePresent: true, bundleId: manifest.bundle_id, error: "manifest signature verification failed" };
	}
	if (config.require_signed && (!config.public_key || !verifyManifestSignature(manifest, config.public_key))) {
		return { valid: false, signaturePresent: true, bundleId: manifest.bundle_id, error: "manifest signature could not be verified" };
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

function readPointer(cacheDir: string, pointer: string): { bundle_id?: string; manifest_sha256?: string } | null {
	try {
		const parsed: unknown = JSON.parse(getFileContentSync(join(cacheDir, pointer), "utf8"));
		return parsed && typeof parsed === "object" ? (parsed as { bundle_id?: string; manifest_sha256?: string }) : null;
	} catch {
		return null;
	}
}

function resolveGeneratedDir(config: AigSyncConfig): string {
	if (config.mode !== "http") return config.generated_dir;
	const active = readPointer(config.cache_dir, ACTIVE_POINTER);
	if (active?.bundle_id && BUNDLE_ID_RE.test(active.bundle_id)) {
		const releaseDir = join(config.cache_dir, RELEASES_DIR, active.bundle_id);
		if (existsSync(releaseDir)) return releaseDir;
	}
	// Backwards-compatible cache layout for pre-manifest installations.
	return config.cache_dir;
}

function countEntries(data: IndexMeta | null, key: "cves" | "fingerprints" | "categories"): number {
	return Array.isArray(data?.[key]) ? data[key]?.length ?? 0 : 0;
}

function initTimeout(seconds: number): [AbortController, NodeJS.Timeout] {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), Math.max(1, seconds) * 1000);
	return [controller, timer];
}

function manifestUrl(remoteUrl: string): string {
	const trimmed = remoteUrl.replace(/\/+$/, "");
	return trimmed.endsWith(`/${MANIFEST_FILE}`) ? trimmed : `${trimmed}/${MANIFEST_FILE}`;
}

async function fetchJson(url: string, timeoutSeconds: number): Promise<unknown | null> {
	const [controller, timer] = initTimeout(timeoutSeconds);
	try {
		const resp = await fetch(url, { signal: controller.signal, headers: { accept: "application/json" } });
		if (!resp.ok) return null;
		return await resp.json();
	} catch {
		return null;
	} finally {
		clearTimeout(timer);
	}
}

async function checkRemoteForUpdate(
	cfg: AigSyncConfig,
	genDir: string,
	status: SyncStatus,
	logger: Logger,
): Promise<void> {
	const remote = await fetchJson(manifestUrl(cfg.remote_url), cfg.http_timeout_seconds);
	if (!isManifest(remote)) {
		status.lastError = "Remote AIG manifest missing or malformed";
		logger.warn("AIG sync HTTP check failed", { error: status.lastError });
		return;
	}
	const localManifest = await readManifest(genDir);
	status.updateAvailable = !localManifest || localManifest.bundle_id !== remote.bundle_id;
	if (status.updateAvailable && localManifest?.generated && remote.generated <= localManifest.generated) {
		// A changed bundle with an older timestamp is still treated as an update;
		// never allow timestamps to mask a rollback or emergency correction.
		status.updateAvailable = true;
	}
}

async function checkLocalForUpdate(genDir: string, status: SyncStatus, cfg: AigSyncConfig): Promise<void> {
	const validation = await validateAigDataBundle(genDir, cfg);
	status.updateAvailable = !validation.valid;
	if (!validation.valid) status.lastError = validation.error;
}

export async function getSyncStatus(
	config?: Partial<AigSyncConfig>,
	logger: Logger = nullLogger,
): Promise<SyncStatus> {
	const cfg: AigSyncConfig = { ...DEFAULT_AIG_SYNC_CONFIG, ...config };
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
	const cfg: AigSyncConfig = { ...DEFAULT_AIG_SYNC_CONFIG, ...config };
	const genDir = resolveGeneratedDir(cfg);
	const status = await getSyncStatus(config, logger);
	status.lastCheck = new Date().toISOString();

	if (cfg.mode === "http" && cfg.remote_url) await checkRemoteForUpdate(cfg, genDir, status, logger);
	else await checkLocalForUpdate(genDir, status, cfg);
	return status;
}

async function fetchBytes(url: string, timeoutSeconds: number): Promise<Buffer | null> {
	const [controller, timer] = initTimeout(timeoutSeconds);
	try {
		const resp = await fetch(url, { signal: controller.signal, headers: { accept: "application/json" } });
		if (!resp.ok) return null;
		return Buffer.from(await resp.arrayBuffer());
	} catch {
		return null;
	} finally {
		clearTimeout(timer);
	}
}

function parseJsonBytes(bytes: Buffer): unknown | null {
	try {
		return JSON.parse(bytes.toString("utf8"));
	} catch {
		return null;
	}
}

async function downloadHttpMode(cfg: AigSyncConfig, logger: Logger): Promise<boolean> {
	const baseUrl = cfg.remote_url.replace(/\/+$/, "").replace(new RegExp(`/${MANIFEST_FILE}$`), "");
	const remoteManifestBytes = await fetchBytes(`${baseUrl}/${MANIFEST_FILE}`, cfg.http_timeout_seconds);
	const remoteManifest = remoteManifestBytes ? parseJsonBytes(remoteManifestBytes) : null;
	if (!isManifest(remoteManifest)) {
		logger.error("Failed to fetch a valid remote AIG manifest", { url: `${baseUrl}/${MANIFEST_FILE}` });
		return false;
	}

	const stagingDir = join(cfg.cache_dir, `.staging-${process.pid}-${Date.now()}`);
	const releaseDir = join(cfg.cache_dir, RELEASES_DIR, remoteManifest.bundle_id);
	try {
		await mkdir(stagingDir, { recursive: true });
		for (const file of AIG_INDEX_FILES) {
			const url = `${baseUrl}/${file}`;
			logger.debug("Fetching AIG artifact", { file });
			const bytes = await fetchBytes(url, cfg.http_timeout_seconds);
			if (!bytes) throw new Error(`failed to fetch ${file}`);
			const parsed = parseJsonBytes(bytes);
			if (!parsed || typeof parsed !== "object") throw new Error(`invalid JSON in ${file}`);
			await atomicWriteJson(join(stagingDir, file), parsed);
		}
		await atomicWriteJson(join(stagingDir, MANIFEST_FILE), remoteManifest);
		const validation = await validateAigDataBundle(stagingDir, cfg);
		if (!validation.valid || validation.bundleId !== remoteManifest.bundle_id) throw new Error(validation.error ?? "bundle validation failed");

		await mkdir(join(cfg.cache_dir, RELEASES_DIR), { recursive: true });
		if (existsSync(releaseDir)) await rm(releaseDir, { recursive: true, force: true });
		await rename(stagingDir, releaseDir);
		const manifestHash = createHash("sha256").update(remoteManifestBytes ?? "").digest("hex");
		await atomicWriteJson(join(cfg.cache_dir, STAGED_POINTER), { bundle_id: remoteManifest.bundle_id, manifest_sha256: manifestHash });
		return true;
	} catch (err) {
		logger.error("Failed to stage remote AIG update", { error: err instanceof Error ? err.message : String(err) });
		await rm(stagingDir, { recursive: true, force: true }).catch(() => undefined);
		return false;
	}
}

async function downloadLocalMode(genDir: string, logger: Logger, cfg: AigSyncConfig): Promise<boolean> {
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
	const cfg: AigSyncConfig = { ...DEFAULT_AIG_SYNC_CONFIG, ...config };
	const genDir = resolveGeneratedDir(cfg);
	logger.info("Downloading AIG threat update", { mode: cfg.mode, generatedDir: genDir });
	try {
		if (cfg.mode === "http" && cfg.remote_url) return await downloadHttpMode(cfg, logger);
		return await downloadLocalMode(genDir, logger, cfg);
	} catch (err) {
		logger.error("AIG download update failed", { error: err instanceof Error ? err.message : String(err) });
		return false;
	}
}

export async function applyUpdate(
	config?: Partial<AigSyncConfig>,
	logger: Logger = nullLogger,
): Promise<boolean> {
	const cfg: AigSyncConfig = { ...DEFAULT_AIG_SYNC_CONFIG, ...config };
	if (cfg.mode !== "http") {
		const validation = await validateAigDataBundle(cfg.generated_dir, cfg);
		if (!validation.valid) {
			logger.warn("Generated AIG bundle is invalid; refusing to apply", { error: validation.error });
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
	const releaseDir = join(cfg.cache_dir, RELEASES_DIR, staged.bundle_id);
	const validation = await validateAigDataBundle(releaseDir, cfg);
	if (!validation.valid || validation.bundleId !== staged.bundle_id) {
		logger.error("Refusing to activate invalid AIG bundle", { error: validation.error });
		return false;
	}
	await atomicWriteJson(join(cfg.cache_dir, ACTIVE_POINTER), {
		bundle_id: staged.bundle_id,
		manifest_sha256: staged.manifest_sha256,
		activated_at: new Date().toISOString(),
	});
	process.env.AIG_GENERATED_DIR = releaseDir;
	logger.info("AIG update activated", { bundleId: staged.bundle_id });
	return true;
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
