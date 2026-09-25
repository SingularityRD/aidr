import { createHash, timingSafeEqual } from "node:crypto";
import { isAbsolute, resolve } from "node:path";
import { DlpPolicySchema, validateAgentProfileDocument } from "@singularityrd/aidr-core";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const HEX = /^[0-9a-f]{64}$/;
const ENV = /^[A-Z][A-Z0-9_]{0,127}$/;
const HARD_MAX_BODY = 1024 * 1024;
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
	requireKeys(client, ["id", "tenantId", "tokenSha256", "allowedTools", "profile"], "client");
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

export function validateGatewayConfig(input) {
	// The caller may retain or expose its input object. Validate and retain a
	// detached immutable snapshot so later mutations cannot widen tenant scope,
	// replace an upstream, or alter a trusted manifest after startup.
	input = structuredClone(input);
	requireKeys(
		input,
		[
			"stateDir",
			"port",
			"maxBodyBytes",
			"clients",
			"servers",
			"detection",
			"binaryOutput",
			"serverInitiated",
			"agentProfiles",
		],
		"gateway config",
	);
	if (typeof input.stateDir !== "string" || !input.stateDir.trim())
		throw new GatewayConfigError("invalid stateDir");
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
	validateScopes(clients, servers);
	return freezeTree({
		stateDir: resolve(input.stateDir),
		port,
		maxBodyBytes,
		clients,
		servers,
		detection: validateDetection(input.detection),
		binaryOutput: validateBinaryOutput(input.binaryOutput, maxBodyBytes),
		serverInitiated: validateServerInitiated(input.serverInitiated),
		agentProfiles: validateAgentProfiles(input.agentProfiles, clients),
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
