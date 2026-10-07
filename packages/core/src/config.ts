/**
 * Configuration loader for Singularity AIDR.
 * Loads settings from ~/.singularity-aidr/config.json with full defaults fallback.
 */

import { homedir } from "node:os";
import { isAbsolute, join, relative, resolve, sep } from "node:path";
import { isCommercialBuild } from "./build-flavor.js";
import {
	assertSecureControlPlaneEndpoint,
	DEFAULT_CONTROL_PLANE_ENDPOINT,
} from "./clients/control-plane-url.js";
import { getFileContent } from "./file-utils.js";
import { resolveSecretStore, type SecretStore } from "./secret-store.js";
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

type StateFileField = "cache" | "allowlist" | "logging" | "response.audit" | "response.quarantine";

function defaultQuarantineDir(): string {
	return join(resolvedAidrDir(), "quarantine");
}

/**
 * Whether the verdict log is hash-chained and signed.
 *
 * An explicit `audit.signed_chain` wins in a local build. Unset, managed mode
 * turns it on (an enrolled install is the one whose evidence is used) and local
 * mode leaves it off. A commercial build is managed-only and forces it on, the
 * same way it forces integrity verification on.
 */
export function resolveAuditSignedChain(
	config: Pick<Config, "mode"> & { audit?: Partial<Config["audit"]> },
): boolean {
	if (isCommercialBuild()) return true;
	return config.audit?.signed_chain ?? config.mode === "managed";
}

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
			// The vault holds hostile files and is protected by the self-defense
			// rules only inside the AIDR state directory, so it cannot be moved out.
			...(config.response?.quarantine
				? {
						quarantine: {
							...config.response.quarantine,
							dir: normalizeStateFilePath(
								config.response.quarantine.dir,
								defaultQuarantineDir(),
								"response.quarantine",
								logger,
							),
						},
					}
				: {}),
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
		if (!next.integrity.enabled || !next.integrity.verify_on_start) {
			next = {
				...next,
				integrity: { ...next.integrity, enabled: true, verify_on_start: true },
			};
		}
	}

	// Managed mode is an explicit opt-in to the AIDR control plane; give it the
	// documented endpoint when none is configured. Local mode stays endpoint-less.
	if (next.mode === "managed" && !next.control_plane.endpoint.trim()) {
		next = {
			...next,
			control_plane: { ...next.control_plane, endpoint: DEFAULT_CONTROL_PLANE_ENDPOINT },
		};
	}

	next = {
		...next,
		logging: {
			...next.logging,
			signed_chain: resolveAuditSignedChain(next),
			chain_key_storage: next.audit?.key_storage ?? "os-vault",
			chain_epoch_hours: next.audit?.epoch_hours ?? 24,
		},
	};

	return next;
}

function parseRuntimeConfig(data: unknown): Config {
	const config = ConfigSchema.parse(data);
	assertSecureControlPlaneEndpoint(
		config.control_plane.endpoint,
		config.control_plane.allow_insecure_loopback,
	);
	return config;
}

function resolveCommercialAuth(
	data: Record<string, unknown>,
	injectedStore?: SecretStore,
): Record<string, unknown> {
	if (!isCommercialBuild()) return data;
	const auth = data.auth;
	if (!auth || typeof auth !== "object" || Array.isArray(auth)) return data;
	const documentAuth = { ...(auth as Record<string, unknown>) };
	for (const field of ["api_key", "enrollment_token"] as const) {
		const ref = documentAuth[`${field}_ref`];
		if (typeof documentAuth[field] === "string" && documentAuth[field].trim()) {
			throw new Error(
				"Managed auth contains a plaintext credential; migrate it with the CLI first.",
			);
		}
		if (!ref) continue;
		if (typeof ref !== "object" || Array.isArray(ref))
			throw new Error("Managed auth reference is invalid.");
		const { store: kind, id } = ref as Record<string, unknown>;
		if (typeof kind !== "string" || typeof id !== "string")
			throw new Error("Managed auth reference is invalid.");
		const store = injectedStore ?? resolveSecretStore({ selection: kind });
		if (store.location !== "os-vault" || store.kind !== kind)
			throw new Error("Managed auth requires a matching OS credential vault.");
		const secret = store.get(id);
		if (!secret) throw new Error("Managed auth credential is missing from its vault.");
		documentAuth[field] = secret;
	}
	return { ...data, auth: documentAuth };
}

const invalidRuntimeConfigs = new WeakSet<Config>();

/** A present but unreadable/invalid config is not the same as a fresh install. */
export function isInvalidConfig(config: Config): boolean {
	return invalidRuntimeConfigs.has(config);
}

function safeConfigForInvalidFile(logger: Logger): Config {
	// A present but malformed/unreadable config must not silently disable a
	// centrally required policy by falling back to ordinary local defaults.
	const config = sanitizeConfigPaths(
		parseRuntimeConfig({ control_plane: { remote_policy_required: true } }),
		logger,
	);
	invalidRuntimeConfigs.add(config);
	return config;
}

function isMissingFileError(error: unknown): boolean {
	return typeof error === "object" && error !== null && "code" in error && error.code === "ENOENT";
}

export async function loadConfig(
	configPath?: string,
	logger: Logger = nullLogger,
	secretStore?: SecretStore,
	source?: { raw: string | null },
): Promise<Config> {
	const path = configPath ?? defaultConfigPath();

	let raw: string;
	try {
		if (source?.raw === null) return sanitizeConfigPaths(parseRuntimeConfig({}), logger);
		raw = source ? (source.raw as string) : await getFileContent(path);
	} catch (error) {
		if (isMissingFileError(error)) {
			// Missing file is a deliberate fresh-install state: use local defaults.
			return sanitizeConfigPaths(parseRuntimeConfig({}), logger);
		}
		logger.warn(`Failed to read config from ${path}; requiring central policy`, {
			error: String(error),
		});
		return safeConfigForInvalidFile(logger);
	}

	let data: unknown;
	try {
		data = JSON.parse(raw);
	} catch (e) {
		logger.warn(`Failed to parse config from ${path}; requiring central policy`, {
			error: String(e),
		});
		return safeConfigForInvalidFile(logger);
	}

	if (typeof data !== "object" || data === null || Array.isArray(data)) {
		logger.warn(`Config file ${path} does not contain a JSON object; requiring central policy`);
		return safeConfigForInvalidFile(logger);
	}

	try {
		return sanitizeConfigPaths(
			parseRuntimeConfig(resolveCommercialAuth(data as Record<string, unknown>, secretStore)),
			logger,
		);
	} catch (e) {
		logger.warn(`Config validation failed; requiring central policy`, { error: String(e) });
		return safeConfigForInvalidFile(logger);
	}
}
