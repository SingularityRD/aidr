import { createHash, createPublicKey, timingSafeEqual } from "node:crypto";
import { isAbsolute, normalize, resolve } from "node:path";
import { DlpPolicySchema, validateAgentProfileDocument } from "@singularityrd/aidr-core";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const HEX = /^[0-9a-f]{64}$/;
const ENV = /^[A-Z][A-Z0-9_]{0,127}$/;
const HARD_MAX_BODY = 1024 * 1024;
export const MCP_PROTOCOL_VERSIONS = Object.freeze([
	"2025-03-26",
	"2025-06-18",
	"2025-11-25",
	"2026-07-28",
]);
const MCP_SERVER_METHODS = Object.freeze([
	"sampling/createMessage",
	"elicitation/create",
	"roots/list",
	"ping",
	"notifications/progress",
	"notifications/message",
	"notifications/tools/list_changed",
]);

const PROMPT_NAME = /^[\x21-\x7e](?:[\x20-\x7e]{0,126}[\x21-\x7e])?$/;
const MAX_CONTEXT_ENTRIES = 1024;

/**
 * A resource URI the gateway will compare literally: printable ASCII only,
 * an explicit scheme, and no dot segments, backslashes or percent-encoded
 * separators that a server could normalize into a different location.
 */
function safeResourceUri(uri) {
	if (
		typeof uri !== "string" ||
		uri.length === 0 ||
		uri.length > 2048 ||
		!/^[A-Za-z][A-Za-z0-9+.-]*:[\x21-\x7e]+$/.test(uri) ||
		/\\|%2e|%2f|%5c|%00/i.test(uri)
	)
		return false;
	return !uri.split(/[/?#]/).some((segment) => segment === "." || segment === "..");
}

/** Exact URI, or a literal prefix when the operator pattern ends in a single `*`. */
export function resourceUriAllowed(uri, patterns) {
	if (!safeResourceUri(uri) || !Array.isArray(patterns)) return false;
	return patterns.some((pattern) =>
		pattern.endsWith("*") ? uri.startsWith(pattern.slice(0, -1)) : uri === pattern,
	);
}

function validResourcePattern(pattern) {
	if (typeof pattern !== "string") return false;
	const literal = pattern.endsWith("*") ? pattern.slice(0, -1) : pattern;
	return !literal.includes("*") && safeResourceUri(literal);
}

function validateContextAllowlist(client, field, validEntry) {
	const value = client[field];
	if (value === undefined) return;
	if (!record(value)) throw new GatewayConfigError(`invalid ${field}`);
	for (const [serverId, entries] of Object.entries(value)) {
		if (
			!Object.hasOwn(client.allowedTools, serverId) ||
			!Array.isArray(entries) ||
			entries.length === 0 ||
			entries.length > MAX_CONTEXT_ENTRIES ||
			new Set(entries).size !== entries.length ||
			!entries.every(validEntry)
		)
			throw new GatewayConfigError(`invalid ${field}`);
	}
}

const DEFAULT_MAX_BINARY_BYTES = 256 * 1024;

/**
 * Binary MIME types whose leading bytes the gateway can verify. Only these may
 * be allowlisted: a type the gateway cannot sniff would let an upstream label
 * arbitrary bytes as an accepted format.
 */
const SNIFFABLE_BINARY_MIME_TYPES = Object.freeze([
	"image/png",
	"image/jpeg",
	"image/gif",
	"image/webp",
	"audio/wav",
	"audio/mpeg",
	"audio/ogg",
	"application/pdf",
]);
const DEFAULT_BINARY_MIME_TYPES = Object.freeze([
	"image/png",
	"image/jpeg",
	"image/gif",
	"image/webp",
]);

/** Server-initiated message categories an operator can set to "deny" or "ignore". */
const SERVER_INITIATED_CATEGORIES = Object.freeze([
	"sampling",
	"elicitation",
	"roots",
	"notifications",
]);
const SERVER_INITIATED_ACTIONS = new Set(["deny", "ignore"]);

/**
 * A configuration failure with a stable, secret-free reason code. Messages are
 * fixed literals, so the code can be printed by the operator CLIs.
 */
export class GatewayConfigError extends Error {
	constructor(message) {
		super(message);
		this.name = "GatewayConfigError";
		this.code = message
			.toLowerCase()
			.replace(/[^a-z0-9]+/g, "_")
			.replace(/^_|_$/g, "")
			.slice(0, 64);
	}
}

function record(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function freezeTree(value, seen = new WeakSet()) {
	if (value === null || typeof value !== "object" || seen.has(value)) return value;
	seen.add(value);
	for (const child of Object.values(value)) freezeTree(child, seen);
	return Object.freeze(value);
}

function validId(value) {
	return typeof value === "string" && ID.test(value);
}

function requireKeys(value, allowed, label) {
	if (!record(value) || Object.keys(value).some((key) => !allowed.includes(key))) {
		throw new GatewayConfigError(`invalid ${label}`);
	}
}

function validateClient(client, clientKeys, tokenHashes) {
	requireKeys(
		client,
		[
			"id",
			"tenantId",
			"tokenSha256",
			"allowedTools",
			"allowedServerMethods",
			"allowedResources",
			"allowedPrompts",
			"probeTokenEnv",
			"profile",
		],
		"client",
	);
	if (client.probeTokenEnv !== undefined && !ENV.test(client.probeTokenEnv))
		throw new GatewayConfigError("invalid probe token environment variable");
	if (client.profile !== undefined && !/^[a-z0-9][a-z0-9._-]{0,63}$/.test(client.profile))
		throw new GatewayConfigError("invalid client profile name");
	if (!validId(client.id) || !validId(client.tenantId) || !HEX.test(client.tokenSha256)) {
		throw new GatewayConfigError("invalid client identity or token hash");
	}
	if (!record(client.allowedTools) || Object.keys(client.allowedTools).length === 0) {
		throw new GatewayConfigError("client requires explicit allowedTools");
	}
	for (const [serverId, names] of Object.entries(client.allowedTools)) {
		if (
			!validId(serverId) ||
			!Array.isArray(names) ||
			names.length === 0 ||
			names.some((name) => !validId(name)) ||
			new Set(names).size !== names.length
		)
			throw new GatewayConfigError("invalid client tool allowlist");
	}
	if (client.allowedServerMethods !== undefined) {
		if (!record(client.allowedServerMethods))
			throw new GatewayConfigError("invalid server method allowlist");
		for (const [serverId, methods] of Object.entries(client.allowedServerMethods)) {
			if (
				!Object.hasOwn(client.allowedTools, serverId) ||
				!Array.isArray(methods) ||
				methods.length > MCP_SERVER_METHODS.length ||
				new Set(methods).size !== methods.length ||
				methods.some((method) => !MCP_SERVER_METHODS.includes(method))
			)
				throw new GatewayConfigError("invalid server method allowlist");
		}
	}
	validateContextAllowlist(client, "allowedResources", validResourcePattern);
	validateContextAllowlist(
		client,
		"allowedPrompts",
		(name) => typeof name === "string" && PROMPT_NAME.test(name),
	);
	const key = `${client.tenantId}\0${client.id}`;
	if (clientKeys.has(key) || tokenHashes.has(client.tokenSha256))
		throw new GatewayConfigError("duplicate client or token");
	clientKeys.add(key);
	tokenHashes.add(client.tokenSha256);
	return client;
}

function validateServer(server, serverKeys) {
	requireKeys(
		server,
		[
			"tenantId",
			"id",
			"url",
			"transport",
			"sessionMode",
			"signedManifest",
			"trustedSigners",
			"revokedKeyIds",
			"upstreamAuthEnv",
			"protocolVersions",
			"pinnedAddresses",
			"dlpPolicy",
		],
		"server",
	);
	if (
		!validId(server.tenantId) ||
		!validId(server.id) ||
		typeof server.url !== "string" ||
		!server.url.startsWith("https://") ||
		!["json", "sse"].includes(server.transport) ||
		!["stateless", "required"].includes(server.sessionMode) ||
		!record(server.signedManifest) ||
		!record(server.trustedSigners) ||
		Object.keys(server.trustedSigners).length === 0 ||
		(server.upstreamAuthEnv !== undefined && !ENV.test(server.upstreamAuthEnv)) ||
		(server.revokedKeyIds !== undefined &&
			(!Array.isArray(server.revokedKeyIds) || server.revokedKeyIds.some((id) => !validId(id))))
	)
		throw new GatewayConfigError("invalid server config");
	let url;
	try {
		url = new URL(server.url);
	} catch {
		throw new GatewayConfigError("invalid server URL");
	}
	if (url.username || url.password || url.hash || url.search)
		throw new GatewayConfigError("server URL must not contain credentials, query, or fragment");
	server.protocolVersions ??= MCP_PROTOCOL_VERSIONS.slice(0, 3);
	if (
		!Array.isArray(server.protocolVersions) ||
		server.protocolVersions.length === 0 ||
		server.protocolVersions.some((version) => !MCP_PROTOCOL_VERSIONS.includes(version))
	)
		throw new GatewayConfigError("invalid protocol versions");
	if (server.protocolVersions.includes("2026-07-28") && server.sessionMode !== "stateless")
		throw new GatewayConfigError("modern MCP requires stateless transport");
	if (
		server.pinnedAddresses !== undefined &&
		(!Array.isArray(server.pinnedAddresses) ||
			server.pinnedAddresses.length === 0 ||
			server.pinnedAddresses.length > 16 ||
			server.pinnedAddresses.some((address) => typeof address !== "string" || !address.trim()))
	)
		throw new GatewayConfigError("invalid pinned addresses");
	const key = `${server.tenantId}\0${server.id}`;
	if (serverKeys.has(key)) throw new GatewayConfigError("duplicate tenant server");
	serverKeys.add(key);
	if (server.dlpPolicy === undefined) return server;
	let dlpPolicy;
	try {
		dlpPolicy = DlpPolicySchema.parse(server.dlpPolicy);
	} catch {
		throw new GatewayConfigError("invalid server dlp policy");
	}
	// A DLP policy belongs to exactly one tenant. Binding it to another tenant's
	// server would evaluate that tenant's traffic against foreign rules.
	if (dlpPolicy.tenantId !== server.tenantId)
		throw new GatewayConfigError("server dlp policy tenant mismatch");
	return { ...server, dlpPolicy };
}

function validateDetection(input) {
	if (input === undefined) return {};
	requireKeys(input, ["threatsDir", "allowlistsDir", "agentConfigPath"], "detection config");
	const detection = {};
	for (const key of ["threatsDir", "allowlistsDir", "agentConfigPath"]) {
		if (input[key] === undefined) continue;
		if (typeof input[key] !== "string" || !isAbsolute(input[key]))
			throw new GatewayConfigError("detection paths must be absolute");
		detection[key] = resolve(input[key]);
	}
	return detection;
}

/**
 * Optional agent permission profiles for MCP clients. An invalid document or a
 * client naming a missing profile refuses startup: a profile is a restriction,
 * so the gateway never runs without one it was configured to enforce.
 */
function validateAgentProfiles(input, clients) {
	if (input === undefined) {
		if (clients.some((client) => client.profile !== undefined))
			throw new GatewayConfigError("client profile requires agentProfiles");
		return undefined;
	}
	const result = validateAgentProfileDocument(input);
	if (!result.ok) throw new GatewayConfigError("invalid agent profiles");
	const names = new Set(result.document.profiles.map((profile) => profile.name));
	if (clients.some((client) => client.profile !== undefined && !names.has(client.profile)))
		throw new GatewayConfigError("client profile is not defined in agentProfiles");
	return result.document;
}

/**
 * Shared admission pools: in-flight parent requests, server-initiated requests
 * awaiting a client reply, and MRTR continuations awaiting a retry.
 *
 * - `global`: hard cap across all tenants (`gateway_busy` once reached).
 * - `perTenant`: default per-tenant quota (`tenant_busy`); configurable through
 *   `tenantQuotas` but never above `global - reserved` or below `guaranteed`.
 * - `reserved`: the last slots of the global cap, admitted only to a tenant that
 *   holds fewer than `guaranteed` entries. However many tenants run at quota,
 *   they can fill at most `global - reserved`, so a quiet tenant is still served.
 */
export const GATEWAY_CAPACITY = freezeTree({
	activeRequests: { global: 64, reserved: 16, guaranteed: 2, perTenant: 16 },
	pendingReplies: { global: 256, reserved: 64, guaranteed: 8, perTenant: 64 },
	continuations: { global: 256, reserved: 64, guaranteed: 8, perTenant: 64 },
});

function validateTenantQuotas(input) {
	const pools = Object.keys(GATEWAY_CAPACITY);
	if (input !== undefined) requireKeys(input, pools, "tenant quotas");
	return Object.fromEntries(
		pools.map((pool) => {
			const limits = GATEWAY_CAPACITY[pool];
			const perTenant = input?.[pool] === undefined ? limits.perTenant : input[pool];
			if (
				!Number.isSafeInteger(perTenant) ||
				perTenant < limits.guaranteed ||
				perTenant > limits.global - limits.reserved
			)
				throw new GatewayConfigError(`invalid tenant quota for ${pool}`);
			return [pool, { ...limits, perTenant }];
		}),
	);
}

function validateBinaryOutput(input, maxBodyBytes) {
	if (input === undefined)
		return {
			maxDecodedBytes: Math.min(DEFAULT_MAX_BINARY_BYTES, maxBodyBytes),
			allowedMimeTypes: [...DEFAULT_BINARY_MIME_TYPES],
		};
	requireKeys(input, ["maxDecodedBytes", "allowedMimeTypes"], "binary output config");
	const maxDecodedBytes = input.maxDecodedBytes ?? Math.min(DEFAULT_MAX_BINARY_BYTES, maxBodyBytes);
	if (
		!Number.isSafeInteger(maxDecodedBytes) ||
		maxDecodedBytes < 0 ||
		maxDecodedBytes > maxBodyBytes
	)
		throw new GatewayConfigError("invalid binary output size limit");
	const allowedMimeTypes = input.allowedMimeTypes ?? [...DEFAULT_BINARY_MIME_TYPES];
	if (
		!Array.isArray(allowedMimeTypes) ||
		allowedMimeTypes.some((type) => !SNIFFABLE_BINARY_MIME_TYPES.includes(type)) ||
		new Set(allowedMimeTypes).size !== allowedMimeTypes.length
	)
		throw new GatewayConfigError("invalid binary output mime allowlist");
	return { maxDecodedBytes, allowedMimeTypes: [...allowedMimeTypes] };
}

/** Signed-manifest lifetime policy (`manifestPolicy`), in whole days. */
const MANIFEST_POLICY_DEFAULTS = Object.freeze({
	maxLifetimeDays: 7,
	expiryWarningDays: 2,
	maxLifetimeDaysCeiling: 90,
});

function validateManifestPolicy(input) {
	if (input !== undefined)
		requireKeys(input, ["maxLifetimeDays", "expiryWarningDays"], "manifest policy");
	const maxLifetimeDays = input?.maxLifetimeDays ?? MANIFEST_POLICY_DEFAULTS.maxLifetimeDays;
	if (
		!Number.isSafeInteger(maxLifetimeDays) ||
		maxLifetimeDays < 1 ||
		maxLifetimeDays > MANIFEST_POLICY_DEFAULTS.maxLifetimeDaysCeiling
	)
		throw new GatewayConfigError("invalid manifest max lifetime");
	const expiryWarningDays =
		input?.expiryWarningDays ??
		Math.min(MANIFEST_POLICY_DEFAULTS.expiryWarningDays, maxLifetimeDays);
	if (
		!Number.isSafeInteger(expiryWarningDays) ||
		expiryWarningDays < 0 ||
		expiryWarningDays > maxLifetimeDays
	)
		throw new GatewayConfigError("invalid manifest expiry warning window");
	return { maxLifetimeDays, expiryWarningDays };
}

const HOST = /^(?:[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?|\[[0-9a-f:.]{2,45}\]):[0-9]{1,5}$/;

/**
 * Extra `Host` header values (`host:port`, for example an operator reverse
 * proxy). The loopback names for the bound port are always accepted.
 */
function validateAllowedHosts(input) {
	if (input === undefined) return [];
	if (
		!Array.isArray(input) ||
		input.length > 64 ||
		input.some((host) => typeof host !== "string" || !HOST.test(host.toLowerCase()))
	)
		throw new GatewayConfigError("invalid allowedHosts");
	return [...new Set(input.map((host) => host.toLowerCase()))];
}

function validateServerInitiated(input) {
	const policy = Object.fromEntries(SERVER_INITIATED_CATEGORIES.map((key) => [key, "deny"]));
	if (input === undefined) return policy;
	requireKeys(input, SERVER_INITIATED_CATEGORIES, "server initiated policy");
	for (const [key, action] of Object.entries(input)) {
		if (!SERVER_INITIATED_ACTIONS.has(action))
			throw new GatewayConfigError("invalid server initiated policy");
		policy[key] = action;
	}
	return policy;
}

function validateScopes(clients, servers) {
	for (const client of clients) {
		for (const serverId of Object.keys(client.allowedTools)) {
			const server = servers.find(
				(item) => item.tenantId === client.tenantId && item.id === serverId,
			);
			if (!server)
				throw new GatewayConfigError(
					"client allowlist references another tenant or unknown server",
				);
			const signedNames = new Set(server.signedManifest.manifest?.tools?.map((tool) => tool.name));
			if (client.allowedTools[serverId].some((name) => !signedNames.has(name)))
				throw new GatewayConfigError("client allowlist references unsigned tool");
		}
	}
}

function validateStateDir(value) {
	if (typeof value !== "string" || !value.trim()) throw new GatewayConfigError("invalid stateDir");
	// A relative stateDir resolves against each process's working directory, so
	// the gateway and aidr-mcp-approve could silently use different stores.
	if (!isAbsolute(value)) throw new GatewayConfigError("stateDir must be absolute");
	return normalize(value);
}

const MAX_APPROVAL_KEYS = 16;

/**
 * Operator approval public keys (key id -> Ed25519 SPKI PEM). An approval in
 * the state directory is honoured only when one of these keys signed it, so a
 * gateway without them could never serve a tool: refuse the configuration.
 */
function validateApprovalKeys(value) {
	if (value === undefined) throw new GatewayConfigError("missing approvalKeys");
	if (!record(value)) throw new GatewayConfigError("invalid approvalKeys");
	const entries = Object.entries(value);
	if (entries.length === 0 || entries.length > MAX_APPROVAL_KEYS)
		throw new GatewayConfigError("invalid approvalKeys");
	const keys = {};
	for (const [keyId, pem] of entries) {
		if (!validId(keyId) || typeof pem !== "string")
			throw new GatewayConfigError("invalid approvalKeys");
		let publicKey;
		try {
			publicKey = createPublicKey(pem);
		} catch {
			throw new GatewayConfigError("invalid approval key");
		}
		if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519")
			throw new GatewayConfigError("invalid approval key");
		keys[keyId] = publicKey.export({ type: "spki", format: "pem" }).toString();
	}
	return keys;
}

export function validateGatewayConfig(input) {
	// The caller may retain or expose its input object. Validate and retain a
	// detached immutable snapshot so later mutations cannot widen tenant scope,
	// replace an upstream, or alter a trusted manifest after startup.
	input = structuredClone(input);
	requireKeys(
		input,
		[
			"stateDir",
			"approvalKeys",
			"port",
			"maxBodyBytes",
			"clients",
			"servers",
			"routingRequired",
			"detection",
			"binaryOutput",
			"serverInitiated",
			"agentProfiles",
			"tenantQuotas",
			"manifestPolicy",
			"allowedHosts",
			"stdioUpstreamCredentials",
		],
		"gateway config",
	);
	if (
		input.stdioUpstreamCredentials !== undefined &&
		!["warn", "refuse"].includes(input.stdioUpstreamCredentials)
	)
		throw new GatewayConfigError("invalid stdioUpstreamCredentials");
	if (input.routingRequired !== undefined && typeof input.routingRequired !== "boolean")
		throw new GatewayConfigError("invalid routing requirement");
	const stateDir = validateStateDir(input.stateDir);
	const approvalKeys = validateApprovalKeys(input.approvalKeys);
	const port = input.port ?? 7789;
	if (!Number.isSafeInteger(port) || port < 0 || port > 65535)
		throw new GatewayConfigError("invalid port");
	const maxBodyBytes = input.maxBodyBytes ?? 256 * 1024;
	if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > HARD_MAX_BODY)
		throw new GatewayConfigError("invalid maxBodyBytes");
	if (!Array.isArray(input.clients) || input.clients.length === 0 || input.clients.length > 10000)
		throw new GatewayConfigError("invalid clients");
	if (!Array.isArray(input.servers) || input.servers.length === 0 || input.servers.length > 1000)
		throw new GatewayConfigError("invalid servers");
	const clientKeys = new Set();
	const tokenHashes = new Set();
	const serverKeys = new Set();
	const clients = input.clients.map((client) => validateClient(client, clientKeys, tokenHashes));
	const servers = input.servers.map((server) => validateServer(server, serverKeys));
	if (
		input.routingRequired &&
		servers.some((server) => !server.upstreamAuthEnv || !server.pinnedAddresses)
	)
		throw new GatewayConfigError(
			"mandatory routing requires isolated upstream credentials and pinned addresses",
		);
	if (input.routingRequired && clients.some((client) => !client.probeTokenEnv))
		throw new GatewayConfigError("mandatory routing requires client credential negative probes");
	validateScopes(clients, servers);
	return freezeTree({
		stateDir,
		approvalKeys,
		port,
		maxBodyBytes,
		clients,
		servers,
		routingRequired: input.routingRequired === true,
		detection: validateDetection(input.detection),
		binaryOutput: validateBinaryOutput(input.binaryOutput, maxBodyBytes),
		serverInitiated: validateServerInitiated(input.serverInitiated),
		agentProfiles: validateAgentProfiles(input.agentProfiles, clients),
		tenantQuotas: validateTenantQuotas(input.tenantQuotas),
		manifestPolicy: validateManifestPolicy(input.manifestPolicy),
		allowedHosts: validateAllowedHosts(input.allowedHosts),
		stdioUpstreamCredentials: input.stdioUpstreamCredentials ?? "warn",
	});
}

export function authenticateBearer(header, clients) {
	if (typeof header !== "string" || !/^Bearer [A-Za-z0-9_-]{32,256}$/.test(header)) return null;
	const token = header.slice(7);
	const digest = createHash("sha256").update(token, "utf8").digest();
	let matched = null;
	for (const client of clients) {
		const expected = Buffer.from(client.tokenSha256, "hex");
		if (timingSafeEqual(digest, expected)) matched = client;
	}
	return matched;
}
