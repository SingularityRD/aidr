/**
 * Configuration loader for Singularity AIDR.
 * Loads settings from ~/.singularity-aidr/config.json with full defaults fallback.
 */

import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { isCommercialBuild } from "./build-flavor.js";
import { getFileContent } from "./file-utils.js";
import type { Config, Logger } from "./types.js";
import { ConfigSchema, nullLogger } from "./types.js";

export const AIDR_DIR = "~/.singularity-aidr";

function resolvedAidrDir(): string {
	return resolvePath(AIDR_DIR);
}

function defaultConfigPath(): string {
	return join(resolvedAidrDir(), "config.json");
}

function defaultCachePath(): string {
	return join(resolvedAidrDir(), "cache.json");
}

function defaultAllowlistPath(): string {
	return join(resolvedAidrDir(), "allowlist.json");
}

function defaultAuditPath(): string {
	return join(resolvedAidrDir(), "audit.jsonl");
}

function defaultResponseAuditPath(): string {
	return join(resolvedAidrDir(), "response-audit.jsonl");
}

type StateFileField = "cache" | "allowlist" | "logging" | "response.audit";

/** Expand ~ to the user's home directory. */
export function resolvePath(pathStr: string): string {
	if (pathStr.startsWith("~/") || pathStr === "~") {
		const envHome = process.env.HOME?.trim();
		const home = envHome && envHome.length > 0 ? envHome : homedir();
		return join(home, pathStr.slice(1));
	}
	return pathStr;
}

function isWithinDirectory(baseDir: string, targetPath: string): boolean {
	const rel = relative(baseDir, targetPath);
	if (rel === "") return true;
	if (isAbsolute(rel)) return false;
	return rel !== ".." && !rel.startsWith(`..${sep}`);
}

function normalizeStateFilePath(
	configuredPath: string,
	fallbackPath: string,
	field: StateFileField,
	logger: Logger,
): string {
	const aidrDir = resolvedAidrDir();
	const trimmed = configuredPath.trim();
	if (trimmed === "") {
		logger.warn(`Config ${field}.path is empty; using default`, {
			configuredPath,
			defaultPath: fallbackPath,
		});
		return fallbackPath;
	}

	const expanded = resolvePath(trimmed);
	const resolved = isAbsolute(expanded) ? resolve(expanded) : resolve(aidrDir, expanded);
	if (isWithinDirectory(aidrDir, resolved)) {
		if (resolved === aidrDir) {
			logger.warn(`Config ${field}.path must point to a file; using default`, {
				configuredPath,
				defaultPath: fallbackPath,
			});
			return fallbackPath;
		}
		return resolved;
	}

	logger.warn(`Config ${field}.path escapes ${aidrDir}; using default`, {
		configuredPath,
		defaultPath: fallbackPath,
	});
	return fallbackPath;
}

function sanitizeConfigPaths(config: Config, logger: Logger): Config {
	const cachePath = defaultCachePath();
	const allowlistPath = defaultAllowlistPath();
	const auditPath = defaultAuditPath();
	const responseAuditPath = defaultResponseAuditPath();
	let next: Config = {
		...config,
		cache: {
			...config.cache,
			path: normalizeStateFilePath(config.cache.path, cachePath, "cache", logger),
		},
		allowlist: {
			...config.allowlist,
			path: normalizeStateFilePath(config.allowlist.path, allowlistPath, "allowlist", logger),
		},
		logging: {
			...config.logging,
			path: normalizeStateFilePath(config.logging.path, auditPath, "logging", logger),
		},
		// The signed response chain is security evidence: like the other state
		// files it must not be redirectable outside the AIDR state directory.
		//
		// `response.audit` can be genuinely absent (a nested Zod default is not
		// applied when a sibling key such as `response.actions` is present), so the
		// configured path is read defensively and falls back to the default location.
		response: {
			...config.response,
			audit: {
				...(config.response?.audit ?? {}),
				path: normalizeStateFilePath(
					config.response?.audit?.path ?? responseAuditPath,
					responseAuditPath,
					"response.audit",
					logger,
				),
			},
		},
	};

	// Commercial builds are managed-only and should not accept local-mode configs.
	if (isCommercialBuild()) {
		if (next.mode !== "managed") {
			logger.warn("Commercial build: forcing mode=managed (local mode is disabled).", {
				configuredMode: next.mode,
			});
			next = { ...next, mode: "managed" };
		}
		if (!next.licensing.require_signed_entitlements) {
			next = {
				...next,
				licensing: { ...next.licensing, require_signed_entitlements: true },
			};
		}
	}

	return next;
}

function safeConfigForInvalidFile(logger: Logger): Config {
	// A present but malformed/unreadable config must not silently disable a
	// centrally required policy by falling back to ordinary local defaults.
	return sanitizeConfigPaths(
		ConfigSchema.parse({ control_plane: { remote_policy_required: true } }),
		logger,
	);
}

function isMissingFileError(error: unknown): boolean {
	return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

export async function loadConfig(
	configPath?: string,
	logger: Logger = nullLogger,
): Promise<Config> {
	const path = configPath ?? defaultConfigPath();

	let raw: string;
	try {
		raw = await getFileContent(path);
	} catch (error) {
		if (isMissingFileError(error)) {
			// Missing file is a deliberate fresh-install state: use local defaults.
			return sanitizeConfigPaths(ConfigSchema.parse({}), logger);
		}
		logger.warn(`Failed to read config from ${path}; requiring central policy`, { error: String(error) });
		return safeConfigForInvalidFile(logger);
	}

	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch (e) {
		logger.warn(`Failed to parse config from ${path}; requiring central policy`, { error: String(e) });
		return safeConfigForInvalidFile(logger);
	}

	if (typeof data !== "object" || data === null || Array.isArray(data)) {
		logger.warn(`Config file ${path} does not contain a JSON object; requiring central policy`);
		return safeConfigForInvalidFile(logger);
	}

	try {
		return sanitizeConfigPaths(ConfigSchema.parse(data), logger);
	} catch (e) {
		logger.warn(`Config validation failed; requiring central policy`, { error: String(e) });
		return safeConfigForInvalidFile(logger);
	}
}
