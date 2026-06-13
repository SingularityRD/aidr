/**
 * AIG Threat Sync Client
 *
 * Edge-side client that checks for and applies threat intel updates.
 * Can be called at session start or on a timer.
 *
 * Supports two modes:
 *   - local  : reads compiled indices directly from the filesystem (development / self-hosted)
 *   - http   : fetches compiled indices from a remote endpoint (SaaS / managed deployment)
 *
 * Both modes are configured via AIDR's config.json under the `intel` or `aig_sync` key.
 */

import { existsSync } from "node:fs";
import { mkdir } from "node:fs/promises";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

const GENERATED_DIR_REL = join("src", "generated");

const GENERATED_FILES = ["aig-cve-index.json", "aig-fingerprints.json", "aig-mcp-categories.json"];

export interface AigSyncConfig {
	enabled: boolean;
	mode: "local" | "http";
	generated_dir: string;
	remote_url: string;
	poll_interval_seconds: number;
	http_timeout_seconds: number;
	cache_dir: string;
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
}

interface IndexMeta {
	version: number;
	generated: string;
	cves: unknown[];
	fingerprints: unknown[];
	categories: unknown[];
	[key: string]: unknown;
}

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

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
};

async function quickHash(filePath: string): Promise<string> {
	try {
		const content = await getFileContent(filePath);
		const len = content.length;
		const prefix = content.slice(0, 256);
		const suffix = content.slice(-256);
		const hashInput = `${len}:${prefix}:${suffix}`;
		const { createHash } = await import("node:crypto");
		return createHash("sha256").update(hashInput).digest("hex").slice(0, 12);
	} catch {
		return "";
	}
}

async function readIndex(filePath: string): Promise<Record<string, unknown> | null> {
	try {
		const raw = await getFileContent(filePath);
		return JSON.parse(raw) as Record<string, unknown>;
	} catch {
		return null;
	}
}

function resolveGeneratedDir(config: AigSyncConfig): string {
	if (config.mode === "http") {
		return config.cache_dir;
	}
	return config.generated_dir;
}

function countEntries(data: Record<string, unknown> | null, key: string): number {
	return Array.isArray(data?.[key]) ? (data[key] as unknown[]).length : 0;
}

function initTimeout(seconds: number): [AbortController, NodeJS.Timeout] {
	const controller = new AbortController();
	const timer = setTimeout(() => controller.abort(), seconds * 1000);
	return [controller, timer];
}

async function checkRemoteForUpdate(
	cfg: AigSyncConfig,
	genDir: string,
	status: SyncStatus,
	logger: Logger,
): Promise<void> {
	const [controller, timeout] = initTimeout(cfg.http_timeout_seconds);
	try {
		const resp = await fetch(cfg.remote_url, { signal: controller.signal });
		clearTimeout(timeout);

		if (!resp.ok) {
			status.lastError = `HTTP ${resp.status}: ${resp.statusText}`;
			logger.warn("AIG sync HTTP check failed", { status: resp.status });
			return;
		}

		const remoteMeta = (await resp.json()) as IndexMeta | null;
		if (!remoteMeta) {
			status.lastError = "Empty response from remote";
			return;
		}

		const localIndex = await readIndex(join(genDir, "aig-cve-index.json"));
		const localVersion = (localIndex?.version as number) ?? 0;
		const remoteVersion = remoteMeta.version ?? 0;

		status.updateAvailable = remoteVersion > localVersion;
		if (!status.updateAvailable && remoteMeta.generated && localIndex?.generated) {
			status.updateAvailable = remoteMeta.generated > (localIndex.generated as string);
		}
	} catch (err) {
		clearTimeout(timeout);
		status.lastError = err instanceof Error ? err.message : String(err);
		logger.warn("AIG sync HTTP check error", { error: status.lastError });
	}
}

async function checkLocalForUpdate(genDir: string, status: SyncStatus): Promise<void> {
	for (const file of GENERATED_FILES) {
		if (!existsSync(join(genDir, file))) {
			status.updateAvailable = true;
			return;
		}
	}
	status.updateAvailable = false;
}

async function fetchIndexFile(
	url: string,
	timeoutSeconds: number,
): Promise<Record<string, unknown> | null> {
	const [controller, timer] = initTimeout(timeoutSeconds);
	try {
		const resp = await fetch(url, { signal: controller.signal });
		clearTimeout(timer);
		if (!resp.ok) return null;
		const data = (await resp.json()) as Record<string, unknown>;
		if (!data || typeof data !== "object") return null;
		return data;
	} catch {
		clearTimeout(timer);
		return null;
	}
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

	const cveCount = countEntries(cveIndex, "cves");
	const fingerprintCount = countEntries(fpIndex, "fingerprints");
	const mcpCategoryCount = countEntries(mcpIndex, "categories");

	const cveHash = await quickHash(join(genDir, "aig-cve-index.json"));

	return {
		lastCheck: null,
		lastUpdate: null,
		cveCount,
		mcpCategoryCount,
		fingerprintCount,
		updateAvailable: false,
		mode: cfg.mode,
		currentHash: cveHash,
		lastError: null,
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

	if (cfg.mode === "http" && cfg.remote_url) {
		await checkRemoteForUpdate(cfg, genDir, status, logger);
	} else {
		await checkLocalForUpdate(genDir, status);
	}

	return status;
}

async function downloadHttpMode(cfg: AigSyncConfig, logger: Logger): Promise<boolean> {
	const baseUrl = cfg.remote_url.replace(/\/+$/, "");

	for (const file of GENERATED_FILES) {
		const url = `${baseUrl}/${file}`;
		logger.debug("Fetching", { url });

		const data = await fetchIndexFile(url, cfg.http_timeout_seconds);
		if (!data) {
			logger.error("Failed to fetch remote index", { url });
			return false;
		}

		const destDir = join(cfg.cache_dir);
		await mkdir(destDir, { recursive: true });
		await atomicWriteJson(join(destDir, file), data);
	}
	return true;
}

async function downloadLocalMode(genDir: string, logger: Logger): Promise<boolean> {
	for (const file of GENERATED_FILES) {
		const fp = join(genDir, file);
		if (!existsSync(fp)) {
			logger.warn("Generated index missing", { file: fp });
			return false;
		}
		const data = await readIndex(fp);
		if (!data) {
			logger.warn("Generated index is corrupt or empty", { file: fp });
			return false;
		}
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
		if (cfg.mode === "http" && cfg.remote_url) {
			return await downloadHttpMode(cfg, logger);
		}
		return await downloadLocalMode(genDir, logger);
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
	const cfg: AigSyncConfig = { ...DEFAULT_AIG_SYNC_CONFIG, ...config };
	const genDir = resolveGeneratedDir(cfg);

	logger.info("Applying AIG threat update", { mode: cfg.mode });

	if (cfg.mode === "http") {
		const cacheDir = cfg.cache_dir;
		for (const file of GENERATED_FILES) {
			if (!existsSync(join(cacheDir, file))) {
				logger.error("Cannot apply update: cached file missing", { file });
				return false;
			}
		}
		logger.info("AIG update applied from cache", { cacheDir });
	} else {
		for (const file of GENERATED_FILES) {
			if (!existsSync(join(genDir, file))) {
				logger.warn("Generated index missing, cannot apply update", { file });
				return false;
			}
		}
	}

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
		return true;
	}

	const downloaded = await downloadUpdate(config, logger);
	if (!downloaded) {
		logger.error("AIG download failed during full sync cycle");
		return false;
	}

	const applied = await applyUpdate(config, logger);
	if (!applied) {
		logger.error("AIG apply failed during full sync cycle");
		return false;
	}

	logger.info("AIG full sync cycle completed successfully");
	return true;
}
