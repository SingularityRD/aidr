import { createHash } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { ControlPlaneClient } from "./clients/control-plane.js";
import { resolvePath } from "./config.js";
import type { Config, Logger } from "./types.js";
import { ConfigSchema, nullLogger } from "./types.js";

type RuntimePolicyMode = "allow" | "ask" | "deny";

type RuntimePolicyPayload = {
	command_default?: RuntimePolicyMode;
	file_default?: RuntimePolicyMode;
	url_default?: RuntimePolicyMode;
	package_default?: RuntimePolicyMode;
	output_default?: RuntimePolicyMode;
	mcp_unknown?: RuntimePolicyMode;
	mcp_risky?: RuntimePolicyMode;
	mcp_allow_servers?: unknown;
	mcp_require_approval_servers?: unknown;
	mcp_deny_servers?: unknown;
	mcp_allow_tools?: unknown;
	mcp_require_approval_tools?: unknown;
	mcp_deny_tools?: unknown;
};

type CachedPolicy = {
	key: string;
	expiresAt: number;
	body: Record<string, unknown>;
};

let cachedPolicy: CachedPolicy | null = null;

type PersistedRemotePolicyCache = {
	schema_version: 1;
	key_hash: string;
	endpoint: string;
	policy_version: string;
	cached_at: string;
	expires_at: string;
	body: Record<string, unknown>;
};

export type RemoteRuntimePolicyCacheSource =
	| "disabled"
	| "missing"
	| "valid"
	| "expired"
	| "mismatched"
	| "invalid";

export type RemoteRuntimePolicyCacheStatus = {
	enabled: boolean;
	path: string;
	source: RemoteRuntimePolicyCacheSource;
	usable: boolean;
	present: boolean;
	policyVersion?: string;
	cachedAt?: string;
	expiresAt?: string;
	ageSeconds?: number;
	ttlSeconds?: number;
	keyMatches?: boolean;
	message?: string;
};

function cacheKeyHash(endpoint: string, token: string): string {
	return createHash("sha256").update(`${endpoint}|${token}`).digest("hex");
}

function getRemotePolicyCachePath(config: Config): string {
	return resolvePath(config.control_plane.remote_policy_cache_path);
}

function getPolicyVersion(body: Record<string, unknown> | undefined): string {
	const version = body?.policy_version;
	return typeof version === "string" && version.trim() ? version.trim() : "unknown";
}

function isRecord(value: unknown): value is Record<string, unknown> {
	return !!value && typeof value === "object" && !Array.isArray(value);
}

function parsePersistedRemotePolicyCache(raw: string): PersistedRemotePolicyCache | null {
	const parsed = JSON.parse(raw) as Partial<PersistedRemotePolicyCache>;
	if (parsed.schema_version !== 1) return null;
	if (typeof parsed.key_hash !== "string" || !parsed.key_hash) return null;
	if (typeof parsed.endpoint !== "string" || !parsed.endpoint) return null;
	if (typeof parsed.policy_version !== "string") return null;
	if (typeof parsed.cached_at !== "string") return null;
	if (typeof parsed.expires_at !== "string") return null;
	if (!isRecord(parsed.body)) return null;
	return parsed as PersistedRemotePolicyCache;
}

function getPersistablePolicyBody(
	body: Record<string, unknown> | undefined,
): Record<string, unknown> {
	return {
		ok: body?.ok === true,
		policy_version: getPolicyVersion(body),
		...(typeof body?.cache_seconds === "number" && Number.isFinite(body.cache_seconds)
			? { cache_seconds: body.cache_seconds }
			: {}),
		...(getRuntimePolicy(body) ? { runtime_policy: getRuntimePolicy(body) } : {}),
	};
}

async function readPersistentPolicyCache(input: {
	config: Config;
	keyHash: string;
	now: number;
	logger: Logger;
}): Promise<Record<string, unknown> | null> {
	if (!input.config.control_plane.remote_policy_cache_enabled) return null;
	try {
		const raw = await readFile(getRemotePolicyCachePath(input.config), "utf-8");
		const parsed = parsePersistedRemotePolicyCache(raw);
		if (!parsed) return null;
		if (parsed.key_hash !== input.keyHash) return null;
		const expiresAt = Date.parse(parsed.expires_at);
		if (!Number.isFinite(expiresAt) || expiresAt <= input.now) return null;
		return parsed.body;
	} catch (error) {
		input.logger.debug("Remote runtime policy persistent cache miss", { error: String(error) });
		return null;
	}
}

async function writePersistentPolicyCache(input: {
	config: Config;
	keyHash: string;
	body: Record<string, unknown>;
	expiresAt: number;
	now: number;
	logger: Logger;
}): Promise<void> {
	if (!input.config.control_plane.remote_policy_cache_enabled) return;
	try {
		const cachePath = getRemotePolicyCachePath(input.config);
		await mkdir(dirname(cachePath), { recursive: true });
		const payload: PersistedRemotePolicyCache = {
			schema_version: 1,
			key_hash: input.keyHash,
			endpoint: input.config.control_plane.endpoint,
			policy_version: getPolicyVersion(input.body),
			cached_at: new Date(input.now).toISOString(),
			expires_at: new Date(input.expiresAt).toISOString(),
			body: getPersistablePolicyBody(input.body),
		};
		const tmpPath = `${cachePath}.${process.pid}.tmp`;
		await writeFile(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, "utf-8");
		await rename(tmpPath, cachePath);
	} catch (error) {
		input.logger.debug("Remote runtime policy persistent cache write failed", {
			error: String(error),
		});
	}
}

export async function inspectRemoteRuntimePolicyCache(
	config: Config,
	token = "",
	now = Date.now(),
): Promise<RemoteRuntimePolicyCacheStatus> {
	const path = getRemotePolicyCachePath(config);
	if (!config.control_plane.remote_policy_cache_enabled) {
		return { enabled: false, path, source: "disabled", usable: false, present: false };
	}

	try {
		const raw = await readFile(path, "utf-8");
		const parsed = parsePersistedRemotePolicyCache(raw);
		if (!parsed) {
			return { enabled: true, path, source: "invalid", usable: false, present: true };
		}

		const cachedAt = Date.parse(parsed.cached_at);
		const expiresAt = Date.parse(parsed.expires_at);
		if (!Number.isFinite(cachedAt) || !Number.isFinite(expiresAt)) {
			return { enabled: true, path, source: "invalid", usable: false, present: true };
		}

		const trimmedToken = token.trim();
		const keyMatches = trimmedToken
			? parsed.key_hash === cacheKeyHash(config.control_plane.endpoint, trimmedToken)
			: undefined;
		if (keyMatches === false) {
			return {
				enabled: true,
				path,
				source: "mismatched",
				usable: false,
				present: true,
				keyMatches,
				policyVersion: parsed.policy_version,
				cachedAt: parsed.cached_at,
				expiresAt: parsed.expires_at,
				message: "Cached policy belongs to a different endpoint or agent token.",
			};
		}

		const source = expiresAt > now ? "valid" : "expired";
		return {
			enabled: true,
			path,
			source,
			usable: source === "valid",
			present: true,
			policyVersion: parsed.policy_version,
			cachedAt: parsed.cached_at,
			expiresAt: parsed.expires_at,
			ageSeconds: Math.max(0, Math.floor((now - cachedAt) / 1000)),
			ttlSeconds: Math.max(0, Math.floor((expiresAt - now) / 1000)),
			keyMatches,
		};
	} catch (error) {
		return {
			enabled: true,
			path,
			source: "missing",
			usable: false,
			present: false,
			message: error instanceof Error ? error.message : String(error),
		};
	}
}

function modeToMcpAction(mode: unknown): "allow" | "block" | "require_approval" | null {
	if (mode === "allow") return "allow";
	if (mode === "ask") return "require_approval";
	if (mode === "deny") return "block";
	return null;
}

function modeToRuntimeAction(mode: unknown): "allow" | "block" | "require_approval" | null {
	return modeToMcpAction(mode);
}

function parseServerList(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	const seen = new Set<string>();
	const out: string[] = [];
	for (const item of value) {
		if (typeof item !== "string") continue;
		const server = item.trim().toLowerCase();
		if (!server || seen.has(server)) continue;
		if (!/^[a-z0-9][a-z0-9._-]{0,79}$/.test(server)) continue;
		seen.add(server);
		out.push(server);
	}
	return out;
}

function parsePolicyStringList(value: unknown): string[] {
	if (!Array.isArray(value)) return [];
	const seen = new Set<string>();
	const out: string[] = [];
	for (const item of value) {
		if (typeof item !== "string") continue;
		const entry = item.trim().toLowerCase();
		if (!entry || seen.has(entry)) continue;
		seen.add(entry);
		out.push(entry);
	}
	return out;
}

function getRuntimePolicy(body: Record<string, unknown> | undefined): RuntimePolicyPayload | null {
	const policy = body?.runtime_policy;
	if (!policy || typeof policy !== "object" || Array.isArray(policy)) return null;
	return policy as RuntimePolicyPayload;
}

export function applyRemoteRuntimePolicy(
	config: Config,
	body: Record<string, unknown> | undefined,
): Config {
	const policy = getRuntimePolicy(body);
	if (!policy) return config;

	const unknownAction = modeToMcpAction(policy.mcp_unknown);
	const riskyAction = modeToMcpAction(policy.mcp_risky);
	const commandAction = modeToRuntimeAction(policy.command_default);
	const fileAction = modeToRuntimeAction(policy.file_default);
	const urlAction = modeToRuntimeAction(policy.url_default);
	const packageAction = modeToRuntimeAction(policy.package_default);
	const outputAction = modeToRuntimeAction(policy.output_default);
	const allowServers = parseServerList(policy.mcp_allow_servers);
	const approvalServers = parseServerList(policy.mcp_require_approval_servers);
	const denyServers = parseServerList(policy.mcp_deny_servers);
	const allowTools = parsePolicyStringList(policy.mcp_allow_tools);
	const approvalTools = parsePolicyStringList(policy.mcp_require_approval_tools);
	const denyTools = parsePolicyStringList(policy.mcp_deny_tools);

	return ConfigSchema.parse({
		...config,
		policy: {
			...config.policy,
			enabled: true,
			runtime_defaults: {
				...config.policy.runtime_defaults,
				...(commandAction ? { command_action: commandAction } : {}),
				...(fileAction ? { file_action: fileAction } : {}),
				...(urlAction ? { url_action: urlAction } : {}),
				...(packageAction ? { package_action: packageAction } : {}),
				...(outputAction ? { output_action: outputAction } : {}),
			},
			mcp: {
				...config.policy.mcp,
				enabled: true,
				...(unknownAction ? { unknown_server_action: unknownAction } : {}),
				...(riskyAction ? { risky_server_action: riskyAction } : {}),
				allow_servers: allowServers,
				require_approval_servers: approvalServers,
				deny_servers: denyServers,
				allow_tools: allowTools,
				require_approval_tools: approvalTools,
				deny_tools: denyTools,
			},
		},
	});
}

export async function syncRemoteRuntimePolicy(
	config: Config,
	token: string,
	logger: Logger = nullLogger,
	now = Date.now(),
): Promise<Config> {
	if (!config.control_plane.enabled) return config;
	const trimmedToken = token.trim();
	if (!trimmedToken) return config;

	const cacheKey = `${config.control_plane.endpoint}|${trimmedToken}`;
	const keyHash = cacheKeyHash(config.control_plane.endpoint, trimmedToken);
	if (cachedPolicy && cachedPolicy.key === cacheKey && cachedPolicy.expiresAt > now) {
		return applyRemoteRuntimePolicy(config, cachedPolicy.body);
	}

	const persisted = await readPersistentPolicyCache({ config, keyHash, now, logger });
	if (persisted) {
		cachedPolicy = {
			key: cacheKey,
			expiresAt: now + 30_000,
			body: persisted,
		};
		return applyRemoteRuntimePolicy(config, persisted);
	}

	try {
		const client = new ControlPlaneClient(config.control_plane, trimmedToken, logger);
		const result = await client.fetchRuntimePolicy();
		if (!result.ok) return config;
		const body = result.body ?? {};
		const nextConfig = applyRemoteRuntimePolicy(config, body);
		const cacheSeconds =
			typeof result.body?.cache_seconds === "number" && Number.isFinite(result.body.cache_seconds)
				? Math.max(5, Math.min(300, result.body.cache_seconds))
				: 60;
		const expiresAt = now + cacheSeconds * 1000;
		cachedPolicy = {
			key: cacheKey,
			expiresAt,
			body,
		};
		await writePersistentPolicyCache({
			config,
			keyHash,
			body,
			expiresAt,
			now,
			logger,
		});
		return nextConfig;
	} catch (error) {
		logger.debug("Remote runtime policy sync failed", { error: String(error) });
		return config;
	}
}

export function clearRemoteRuntimePolicyCacheForTests(cachePath?: string): void {
	cachedPolicy = null;
	// Best-effort clear the default disk cache for test isolation
	const defaultCachePath = cachePath ?? join(homedir(), ".singularity-aidr", "remote-policy-cache");
	rm(defaultCachePath, { force: true }).catch(() => {});
}
