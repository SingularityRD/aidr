import { createHash } from "node:crypto";
import { mkdir, readFile, rename, rm, writeFile } from "node:fs/promises";
import { dirname } from "node:path";
import { ControlPlaneClient } from "./clients/control-plane.js";
import { resolvePath } from "./config.js";
import { loadRevocationBinding, loadRevocationsCache } from "./managed.js";
import {
	governanceUnboundBySignature,
	type PolicyHighWater,
	policyBodySequence,
	verifySignedPolicy,
} from "./policy-signature.js";
import type { Config, Logger } from "./types.js";
import { ConfigSchema, nullLogger } from "./types.js";

type RuntimePolicyMode = "allow" | "ask" | "deny";

type RuntimePolicyPayload = {
	command_default?: RuntimePolicyMode;
	file_default?: RuntimePolicyMode;
	url_default?: RuntimePolicyMode;
	package_default?: RuntimePolicyMode;
	output_default?: RuntimePolicyMode;
	mcp_default?: RuntimePolicyMode;
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
	policySha256: string;
	expiresAt: number;
	cachedAt: number;
	body: Record<string, unknown>;
	authorityRejected?: true;
};

let cachedPolicy: CachedPolicy | null = null;

class RemoteRuntimePolicyUnavailableError extends Error {
	constructor() {
		super(
			"Required central policy is unavailable or its offline grace has expired. Restore connectivity or contact the policy administrator.",
		);
	}
}

/** Opaque revision label: integer (Supabase) or an identifier such as `pol_20260506101000` (web control plane). */
const POLICY_VERSION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const MCP_ID = /^[A-Za-z0-9][A-Za-z0-9._:/_-]{0,255}$/;
const LEGACY_MCP_TOOL = /^[A-Za-z0-9][A-Za-z0-9_:/-]{0,255}\.[A-Za-z0-9][A-Za-z0-9_:/-]{0,255}$/;

function validMcpToolSelector(value: unknown): boolean {
	if (typeof value !== "string") return false;
	if (LEGACY_MCP_TOOL.test(value)) return true;
	if (value.length > 519 || !value.startsWith("[")) return false;
	try {
		const pair: unknown = JSON.parse(value);
		return (
			Array.isArray(pair) &&
			pair.length === 2 &&
			pair.every((part) => typeof part === "string" && MCP_ID.test(part)) &&
			JSON.stringify(pair) === value
		);
	} catch {
		return false;
	}
}

function validRequiredPolicy(body: Record<string, unknown>): boolean {
	const policy = getRuntimePolicy(body);
	if (!policy || !POLICY_VERSION_ID.test(String(body.policy_version))) return false;
	return validRuntimePolicy(body) && verifiedPolicySha256(body) !== null;
}

const GOVERNANCE_OVERLAY_MAX_ENTRIES = 500;

type GovernanceOverlay = {
	mcp_deny_servers: string[];
	mcp_require_approval_servers: string[];
};

function governanceServerList(value: unknown): string[] | null {
	return Array.isArray(value) &&
		value.length <= GOVERNANCE_OVERLAY_MAX_ENTRIES &&
		value.every((item) => typeof item === "string" && MCP_ID.test(item))
		? (value as string[])
		: null;
}

/**
 * The AI governance overlay the control plane sends next to `runtime_policy`
 * (docs/ai-governance.md): register bans/restrictions for this caller. Absent
 * means none. Present but malformed, or not matching `governance_sha256`,
 * makes the whole policy response unusable, exactly like a bad runtime
 * policy, because silently dropping it would relax enforcement.
 */
function getGovernanceOverlay(
	body: Record<string, unknown> | undefined,
): { ok: true; overlay: GovernanceOverlay | null } | { ok: false } {
	if (body?.governance === undefined && body?.governance_sha256 === undefined) {
		return { ok: true, overlay: null };
	}
	const raw = body?.governance;
	const digest = body?.governance_sha256;
	if (!isRecord(raw) || typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest))
		return { ok: false };
	if (
		!Object.keys(raw).every(
			(key) => key === "mcp_deny_servers" || key === "mcp_require_approval_servers",
		)
	) {
		return { ok: false };
	}
	const deny = governanceServerList(raw.mcp_deny_servers);
	const approval = governanceServerList(raw.mcp_require_approval_servers);
	if (!deny || !approval) return { ok: false };
	if (createHash("sha256").update(canonicalPolicy(raw)).digest("hex") !== digest)
		return { ok: false };
	return { ok: true, overlay: { mcp_deny_servers: deny, mcp_require_approval_servers: approval } };
}

/** Keep client parsing aligned with the Edge policy contract in required and optional modes. */
function validRuntimePolicy(body: Record<string, unknown> | undefined): boolean {
	const policy = getRuntimePolicy(body);
	if (!policy) return false;
	if (!getGovernanceOverlay(body).ok) return false;
	const modes = new Set([
		"command_default",
		"file_default",
		"url_default",
		"package_default",
		"output_default",
		"mcp_default",
		"mcp_unknown",
		"mcp_risky",
	]);
	const serverLists = new Set([
		"mcp_allow_servers",
		"mcp_require_approval_servers",
		"mcp_deny_servers",
	]);
	const toolLists = new Set(["mcp_allow_tools", "mcp_require_approval_tools", "mcp_deny_tools"]);
	const entries = Object.entries(policy);
	return (
		entries.length > 0 &&
		entries.every(([key, value]) => {
			if (modes.has(key))
				return typeof value === "string" && ["allow", "ask", "deny"].includes(value);
			if (serverLists.has(key))
				return (
					Array.isArray(value) &&
					value.length <= 200 &&
					value.every((item) => typeof item === "string" && MCP_ID.test(item))
				);
			if (toolLists.has(key))
				return Array.isArray(value) && value.length <= 200 && value.every(validMcpToolSelector);
			return false;
		})
	);
}

type PersistedRemotePolicyCache = {
	schema_version: 2;
	key_hash: string;
	endpoint: string;
	policy_version: string;
	policy_sha256: string;
	cached_at: string;
	expires_at: string;
	body: Record<string, unknown>;
	authority_rejected?: true;
};

type RemoteRuntimePolicyCacheSource =
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
	offlineGraceExpiresAt?: string;
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

function canonicalPolicy(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonicalPolicy).join(",")}]`;
	if (isRecord(value)) {
		return `{${Object.entries(value)
			.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
			.map(([key, item]) => `${JSON.stringify(key)}:${canonicalPolicy(item)}`)
			.join(",")}}`;
	}
	return JSON.stringify(value) ?? "null";
}

function verifiedPolicySha256(body: Record<string, unknown> | undefined): string | null {
	const policy = getRuntimePolicy(body);
	const digest = body?.policy_sha256;
	if (!policy || typeof digest !== "string" || !/^[a-f0-9]{64}$/.test(digest)) return null;
	return createHash("sha256").update(canonicalPolicy(policy)).digest("hex") === digest
		? digest
		: null;
}

/**
 * Trust anchors for signed policy. `keys` come from `control_plane.policy_public_keys_pem`,
 * falling back to `licensing.public_keys_pem`; with none configured verification is off and
 * only the digest (over TLS) protects the policy. Revoked key ids come from the same signed
 * revocation feed that revokes entitlement and intel-pack keys.
 */
type PolicyTrust = {
	keys: string[];
	revoked: ReadonlySet<string>;
	/** Verified tenant the signed envelope must name; undefined skips the binding. */
	expectedTenantId?: string | null;
};

async function loadPolicyTrust(config: Config): Promise<PolicyTrust> {
	const licensingKeys = config.licensing.public_keys_pem;
	const keys =
		(config.control_plane.policy_public_keys_pem?.length ?? 0) > 0
			? (config.control_plane.policy_public_keys_pem ?? [])
			: licensingKeys;
	const revoked = new Set<string>();
	if (keys.length > 0 && config.licensing.revocations_enabled && licensingKeys.length > 0) {
		const signed = await loadRevocationsCache(
			resolvePath(config.licensing.revocations_cache_path),
			licensingKeys,
			await loadRevocationBinding(licensingKeys),
		);
		for (const id of signed?.payload.revocations.key_ids ?? []) revoked.add(id);
	}
	return { keys, revoked };
}

/** True when the policy is acceptable under `trust` right now (always true when no keys are configured). */
function policyTrusted(
	body: Record<string, unknown> | undefined,
	trust: PolicyTrust,
	now: number,
	logger?: Logger,
	highWater?: PolicyHighWater | null,
): boolean {
	if (trust.keys.length === 0) return true;
	const result = verifySignedPolicy({
		body,
		publicKeysPem: trust.keys,
		revokedKeyIds: trust.revoked,
		now,
		highWater,
		...(trust.expectedTenantId !== undefined ? { expectedTenantId: trust.expectedTenantId } : {}),
	});
	if (!result.ok) {
		logger?.warn("Remote runtime policy signature rejected", { reason: result.reason });
	} else if (governanceUnboundBySignature(body)) {
		// A legacy signer does not bind the overlay. It can only add restrictions,
		// so it is still applied, but it is reported as unsigned rather than verified.
		logger?.warn("Remote runtime policy governance overlay is not bound by its signature");
	}
	return result.ok;
}

async function readPersistedHighWater(
	config: Config,
	keyHash: string,
): Promise<PolicyHighWater | null> {
	if (!config.control_plane.remote_policy_cache_enabled) return null;
	try {
		const parsed = parsePersistedRemotePolicyCache(
			await readFile(getRemotePolicyCachePath(config), "utf-8"),
		);
		if (!parsed || parsed.key_hash !== keyHash || parsed.endpoint !== config.control_plane.endpoint)
			return null;
		return policyBodySequence(parsed.body);
	} catch {
		return null;
	}
}

function parsePersistedRemotePolicyCache(raw: string): PersistedRemotePolicyCache | null {
	const parsed = JSON.parse(raw) as Partial<PersistedRemotePolicyCache>;
	if (parsed.schema_version !== 2) return null;
	if (typeof parsed.key_hash !== "string" || !parsed.key_hash) return null;
	if (typeof parsed.endpoint !== "string" || !parsed.endpoint) return null;
	if (typeof parsed.policy_version !== "string") return null;
	if (typeof parsed.policy_sha256 !== "string" || !/^[a-f0-9]{64}$/.test(parsed.policy_sha256))
		return null;
	if (typeof parsed.cached_at !== "string") return null;
	if (typeof parsed.expires_at !== "string") return null;
	if (!isRecord(parsed.body)) return null;
	if (parsed.authority_rejected !== undefined && parsed.authority_rejected !== true) return null;
	return parsed as PersistedRemotePolicyCache;
}

function getPersistablePolicyBody(
	body: Record<string, unknown> | undefined,
): Record<string, unknown> {
	return {
		ok: body?.ok === true,
		policy_version: getPolicyVersion(body),
		policy_sha256: body?.policy_sha256,
		...(typeof body?.cache_seconds === "number" && Number.isFinite(body.cache_seconds)
			? { cache_seconds: body.cache_seconds }
			: {}),
		...(getRuntimePolicy(body) ? { runtime_policy: getRuntimePolicy(body) } : {}),
		...(isRecord(body?.policy_signed) ? { policy_signed: body.policy_signed } : {}),
		...(body?.governance !== undefined
			? { governance: body.governance, governance_sha256: body.governance_sha256 }
			: {}),
	};
}

async function readPersistentPolicyCache(input: {
	config: Config;
	keyHash: string;
	now: number;
	logger: Logger;
	trust: PolicyTrust;
}): Promise<PersistedRemotePolicyCache | null> {
	if (!input.config.control_plane.remote_policy_cache_enabled) return null;
	try {
		const raw = await readFile(getRemotePolicyCachePath(input.config), "utf-8");
		const parsed = parsePersistedRemotePolicyCache(raw);
		if (!parsed || parsed.authority_rejected) return null;
		if (
			parsed.key_hash !== input.keyHash ||
			parsed.endpoint !== input.config.control_plane.endpoint
		)
			return null;
		if (
			parsed.policy_version !== getPolicyVersion(parsed.body) ||
			parsed.policy_sha256 !== parsed.body.policy_sha256 ||
			verifiedPolicySha256(parsed.body) !== parsed.policy_sha256
		)
			return null;
		const expiresAt = Date.parse(parsed.expires_at);
		const cachedAt = Date.parse(parsed.cached_at);
		if (
			!Number.isFinite(expiresAt) ||
			!Number.isFinite(cachedAt) ||
			cachedAt > input.now + 5000 ||
			expiresAt < cachedAt ||
			expiresAt > cachedAt + 300000
		)
			return null;
		if (
			!validRuntimePolicy(parsed.body) ||
			(input.config.control_plane.remote_policy_required && !validRequiredPolicy(parsed.body))
		)
			return null;
		if (!policyTrusted(parsed.body, input.trust, input.now, input.logger)) return null;
		return parsed;
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
	authorityRejected?: true;
}): Promise<void> {
	if (!input.config.control_plane.remote_policy_cache_enabled) return;
	try {
		const cachePath = getRemotePolicyCachePath(input.config);
		await mkdir(dirname(cachePath), { recursive: true });
		const payload: PersistedRemotePolicyCache = {
			schema_version: 2,
			key_hash: input.keyHash,
			endpoint: input.config.control_plane.endpoint,
			policy_version: getPolicyVersion(input.body),
			policy_sha256: String(input.body.policy_sha256),
			cached_at: new Date(input.now).toISOString(),
			expires_at: new Date(input.expiresAt).toISOString(),
			body: getPersistablePolicyBody(input.body),
			...(input.authorityRejected ? { authority_rejected: true } : {}),
		};
		const tmpPath = `${cachePath}.${process.pid}.tmp`;
		await writeFile(tmpPath, `${JSON.stringify(payload, null, 2)}\n`, {
			encoding: "utf-8",
			mode: 0o600,
		});
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
		const trust = await loadPolicyTrust(config);
		const raw = await readFile(path, "utf-8");
		const parsed = parsePersistedRemotePolicyCache(raw);
		if (parsed?.authority_rejected) {
			return {
				enabled: true,
				path,
				source: "invalid",
				usable: false,
				present: true,
				message:
					"The control plane rejected this cached authority; a fresh accepted policy is required.",
			};
		}
		if (
			!parsed ||
			parsed.endpoint !== config.control_plane.endpoint ||
			parsed.policy_version !== getPolicyVersion(parsed.body) ||
			parsed.policy_sha256 !== parsed.body.policy_sha256 ||
			verifiedPolicySha256(parsed.body) !== parsed.policy_sha256 ||
			!validRuntimePolicy(parsed.body) ||
			(config.control_plane.remote_policy_required && !validRequiredPolicy(parsed.body)) ||
			!policyTrusted(parsed.body, trust, now)
		) {
			return { enabled: true, path, source: "invalid", usable: false, present: true };
		}

		const cachedAt = Date.parse(parsed.cached_at);
		const expiresAt = Date.parse(parsed.expires_at);
		if (
			!Number.isFinite(cachedAt) ||
			!Number.isFinite(expiresAt) ||
			cachedAt > now + 5000 ||
			expiresAt < cachedAt ||
			expiresAt > cachedAt + 300000
		) {
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
		const offlineUntil =
			expiresAt + config.control_plane.remote_policy_offline_grace_seconds * 1000;
		const inOfflineGrace =
			config.control_plane.remote_policy_required &&
			keyMatches === true &&
			validRequiredPolicy(parsed.body) &&
			now < offlineUntil;
		return {
			enabled: true,
			path,
			source,
			usable:
				(source === "valid" &&
					(!config.control_plane.remote_policy_required || keyMatches === true)) ||
				inOfflineGrace,
			present: true,
			policyVersion: parsed.policy_version,
			cachedAt: parsed.cached_at,
			expiresAt: parsed.expires_at,
			ageSeconds: Math.max(0, Math.floor((now - cachedAt) / 1000)),
			ttlSeconds: Math.max(0, Math.floor((expiresAt - now) / 1000)),
			keyMatches,
			...(config.control_plane.remote_policy_required
				? { offlineGraceExpiresAt: new Date(offlineUntil).toISOString() }
				: {}),
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
		const server = item.trim();
		if (!server || seen.has(server)) continue;
		if (!MCP_ID.test(server)) continue;
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
		const entry = item.trim();
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
	if (!policy || !validRuntimePolicy(body)) return config;

	const unknownAction = modeToMcpAction(policy.mcp_unknown);
	const riskyAction = modeToMcpAction(policy.mcp_risky);
	const mcpDefaultAction = modeToMcpAction(policy.mcp_default);
	const commandAction = modeToRuntimeAction(policy.command_default);
	const fileAction = modeToRuntimeAction(policy.file_default);
	const urlAction = modeToRuntimeAction(policy.url_default);
	const packageAction = modeToRuntimeAction(policy.package_default);
	const outputAction = modeToRuntimeAction(policy.output_default);
	const governance = getGovernanceOverlay(body);
	if (!governance.ok) return config;
	const allowServers = parseServerList(policy.mcp_allow_servers);
	// Governance entries only add restrictions; deny takes precedence over
	// require-approval and allow in the MCP evaluation order.
	const approvalServers = parseServerList([
		...parseServerList(policy.mcp_require_approval_servers),
		...(governance.overlay?.mcp_require_approval_servers ?? []),
	]);
	const denyServers = parseServerList([
		...parseServerList(policy.mcp_deny_servers),
		...(governance.overlay?.mcp_deny_servers ?? []),
	]);
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
				...(mcpDefaultAction ? { default_action: mcpDefaultAction } : {}),
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
	options: {
		/**
		 * Tenant from this installation's verified entitlement. When set (or
		 * `null` for "unknown"), a signed policy must name exactly this tenant;
		 * a mismatch is rejected before it can apply or advance the high-water
		 * mark.
		 */
		expectedTenantId?: string | null;
	} = {},
): Promise<Config> {
	const trimmedToken = token.trim();
	if (!config.control_plane.enabled || !trimmedToken) {
		if (config.control_plane.remote_policy_required)
			throw new RemoteRuntimePolicyUnavailableError();
		return config;
	}

	const cacheKey = `${config.control_plane.endpoint}|${trimmedToken}`;
	const keyHash = cacheKeyHash(config.control_plane.endpoint, trimmedToken);
	const trust: PolicyTrust = {
		...(await loadPolicyTrust(config)),
		...(options.expectedTenantId !== undefined
			? { expectedTenantId: options.expectedTenantId }
			: {}),
	};
	if (
		cachedPolicy &&
		!cachedPolicy.authorityRejected &&
		cachedPolicy.key === cacheKey &&
		cachedPolicy.expiresAt > now &&
		cachedPolicy.cachedAt <= now + 5000
	) {
		if (
			cachedPolicy.policySha256 === cachedPolicy.body.policy_sha256 &&
			verifiedPolicySha256(cachedPolicy.body) === cachedPolicy.policySha256 &&
			validRuntimePolicy(cachedPolicy.body) &&
			policyTrusted(cachedPolicy.body, trust, now) &&
			(!config.control_plane.remote_policy_required || validRequiredPolicy(cachedPolicy.body))
		) {
			return applyRemoteRuntimePolicy(config, cachedPolicy.body);
		}
	}

	const persisted = await readPersistentPolicyCache({ config, keyHash, now, logger, trust });
	if (persisted && Date.parse(persisted.expires_at) > now) {
		cachedPolicy = {
			key: cacheKey,
			policySha256: persisted.policy_sha256,
			expiresAt: Date.parse(persisted.expires_at),
			cachedAt: Date.parse(persisted.cached_at),
			body: persisted.body,
		};
		return applyRemoteRuntimePolicy(config, persisted.body);
	}
	const stale = persisted
		? {
				key: cacheKey,
				body: persisted.body,
				expiresAt: Date.parse(persisted.expires_at),
				cachedAt: Date.parse(persisted.cached_at),
			}
		: cachedPolicy?.key === cacheKey && !cachedPolicy.authorityRejected
			? cachedPolicy
			: null;
	const unavailable = (allowStale: boolean): Config => {
		if (!config.control_plane.remote_policy_required) return config;
		if (
			allowStale &&
			stale &&
			validRequiredPolicy(stale.body) &&
			policyTrusted(stale.body, trust, now, logger) &&
			stale.cachedAt <= now + 5000 &&
			now < stale.expiresAt + config.control_plane.remote_policy_offline_grace_seconds * 1000
		) {
			logger.warn("Using last-known central policy within its fixed offline grace", {
				policyVersion: getPolicyVersion(stale.body),
			});
			return applyRemoteRuntimePolicy(config, stale.body);
		}
		throw new RemoteRuntimePolicyUnavailableError();
	};

	try {
		const client = new ControlPlaneClient(config.control_plane, trimmedToken, logger);
		const result = await client.fetchRuntimePolicy();
		if (!result.ok) {
			const retryable =
				result.status === undefined ||
				result.status === 408 ||
				result.status === 429 ||
				result.status >= 500;
			if (!retryable) {
				// An observed authority rejection also invalidates offline use on later
				// calls. Otherwise the next outage could resurrect the denied grant.
				// Retain the signed envelope's sequence while preventing offline use.
				// Deleting it would erase the rollback boundary after authentication recovers.
				if (cachedPolicy?.key === cacheKey) cachedPolicy.authorityRejected = true;
				if (config.control_plane.remote_policy_cache_enabled) {
					const previous = await readFile(getRemotePolicyCachePath(config), "utf-8")
						.then(parsePersistedRemotePolicyCache)
						.catch(() => null);
					if (
						previous?.key_hash === keyHash &&
						previous.endpoint === config.control_plane.endpoint
					) {
						await writePersistentPolicyCache({
							config,
							keyHash,
							body: previous.body,
							expiresAt: Date.parse(previous.expires_at),
							now: Date.parse(previous.cached_at),
							logger,
							authorityRejected: true,
						});
					}
				}
			}
			return unavailable(retryable);
		}
		const body = result.body ?? {};
		const policySha256 = verifiedPolicySha256(body);
		if (!policySha256) {
			logger.warn("Remote runtime policy digest is missing or does not match its contents");
			return unavailable(false);
		}
		if (!validRuntimePolicy(body)) {
			logger.warn("Remote runtime policy does not match the supported policy contract");
			return unavailable(false);
		}
		if (config.control_plane.remote_policy_required && !validRequiredPolicy(body))
			return unavailable(false);
		if (trust.keys.length > 0) {
			// Highest sequence this endpoint/token has already accepted (memory or disk): refuse rollback/replay.
			const known = [
				cachedPolicy?.key === cacheKey ? policyBodySequence(cachedPolicy.body) : null,
				await readPersistedHighWater(config, keyHash),
			].reduce<PolicyHighWater | null>(
				(best, item) => (item && (!best || item.sequence > best.sequence) ? item : best),
				null,
			);
			if (!policyTrusted(body, trust, now, logger, known)) return unavailable(false);
		}
		const nextConfig = applyRemoteRuntimePolicy(config, body);
		const cacheSeconds =
			typeof result.body?.cache_seconds === "number" && Number.isFinite(result.body.cache_seconds)
				? Math.max(5, Math.min(300, result.body.cache_seconds))
				: 60;
		const expiresAt = now + cacheSeconds * 1000;
		cachedPolicy = {
			key: cacheKey,
			policySha256,
			expiresAt,
			cachedAt: now,
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
		if (
			body.agent_bound === true &&
			Number.isSafeInteger(Number(body.policy_version)) &&
			Number(body.policy_version) > 0
		) {
			await client.acknowledgeRuntimePolicy(Number(body.policy_version), policySha256);
		}
		return nextConfig;
	} catch (error) {
		if (error instanceof RemoteRuntimePolicyUnavailableError) throw error;
		logger.debug("Remote runtime policy sync failed", { error: String(error) });
		return unavailable(true);
	}
}

export function clearRemoteRuntimePolicyCacheForTests(cachePath?: string): void {
	cachedPolicy = null;
	// Never touch a user's default runtime state from test cleanup. Tests that
	// create a disk cache must pass their dedicated temporary path explicitly.
	if (cachePath) rm(cachePath, { force: true }).catch(() => {});
}
