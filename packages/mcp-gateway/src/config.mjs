import { createHash, timingSafeEqual } from "node:crypto";
import { resolve } from "node:path";

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
		throw new Error(`invalid ${label}`);
	}
}

function validateClient(client, clientKeys, tokenHashes) {
	requireKeys(
		client,
		["id", "tenantId", "tokenSha256", "allowedTools", "allowedServerMethods", "probeTokenEnv"],
		"client",
	);
	if (client.probeTokenEnv !== undefined && !ENV.test(client.probeTokenEnv))
		throw new Error("invalid probe token environment variable");
	if (!validId(client.id) || !validId(client.tenantId) || !HEX.test(client.tokenSha256)) {
		throw new Error("invalid client identity or token hash");
	}
	if (!record(client.allowedTools) || Object.keys(client.allowedTools).length === 0) {
		throw new Error("client requires explicit allowedTools");
	}
	for (const [serverId, names] of Object.entries(client.allowedTools)) {
		if (
			!validId(serverId) ||
			!Array.isArray(names) ||
			names.length === 0 ||
			names.some((name) => !validId(name)) ||
			new Set(names).size !== names.length
		)
			throw new Error("invalid client tool allowlist");
	}
	if (client.allowedServerMethods !== undefined) {
		if (!record(client.allowedServerMethods)) throw new Error("invalid server method allowlist");
		for (const [serverId, methods] of Object.entries(client.allowedServerMethods)) {
			if (
				!Object.hasOwn(client.allowedTools, serverId) ||
				!Array.isArray(methods) ||
				methods.length > MCP_SERVER_METHODS.length ||
				new Set(methods).size !== methods.length ||
				methods.some((method) => !MCP_SERVER_METHODS.includes(method))
			)
				throw new Error("invalid server method allowlist");
		}
	}
	const key = `${client.tenantId}\0${client.id}`;
	if (clientKeys.has(key) || tokenHashes.has(client.tokenSha256))
		throw new Error("duplicate client or token");
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
		throw new Error("invalid server config");
	let url;
	try {
		url = new URL(server.url);
	} catch {
		throw new Error("invalid server URL");
	}
	if (url.username || url.password || url.hash || url.search)
		throw new Error("server URL must not contain credentials, query, or fragment");
	server.protocolVersions ??= MCP_PROTOCOL_VERSIONS.slice(0, 3);
	if (
		!Array.isArray(server.protocolVersions) ||
		server.protocolVersions.length === 0 ||
		server.protocolVersions.some((version) => !MCP_PROTOCOL_VERSIONS.includes(version))
	)
		throw new Error("invalid protocol versions");
	if (server.protocolVersions.includes("2026-07-28") && server.sessionMode !== "stateless")
		throw new Error("modern MCP requires stateless transport");
	if (
		server.pinnedAddresses !== undefined &&
		(!Array.isArray(server.pinnedAddresses) ||
			server.pinnedAddresses.length === 0 ||
			server.pinnedAddresses.length > 16 ||
			server.pinnedAddresses.some((address) => typeof address !== "string" || !address.trim()))
	)
		throw new Error("invalid pinned addresses");
	const key = `${server.tenantId}\0${server.id}`;
	if (serverKeys.has(key)) throw new Error("duplicate tenant server");
	serverKeys.add(key);
	return server;
}

function validateScopes(clients, servers) {
	for (const client of clients) {
		for (const serverId of Object.keys(client.allowedTools)) {
			const server = servers.find(
				(item) => item.tenantId === client.tenantId && item.id === serverId,
			);
			if (!server) throw new Error("client allowlist references another tenant or unknown server");
			const signedNames = new Set(server.signedManifest.manifest?.tools?.map((tool) => tool.name));
			if (client.allowedTools[serverId].some((name) => !signedNames.has(name)))
				throw new Error("client allowlist references unsigned tool");
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
		["stateDir", "port", "maxBodyBytes", "clients", "servers", "routingRequired"],
		"gateway config",
	);
	if (input.routingRequired !== undefined && typeof input.routingRequired !== "boolean")
		throw new Error("invalid routing requirement");
	if (typeof input.stateDir !== "string" || !input.stateDir.trim())
		throw new Error("invalid stateDir");
	const port = input.port ?? 7789;
	if (!Number.isSafeInteger(port) || port < 0 || port > 65535) throw new Error("invalid port");
	const maxBodyBytes = input.maxBodyBytes ?? 256 * 1024;
	if (!Number.isSafeInteger(maxBodyBytes) || maxBodyBytes < 1024 || maxBodyBytes > HARD_MAX_BODY)
		throw new Error("invalid maxBodyBytes");
	if (!Array.isArray(input.clients) || input.clients.length === 0 || input.clients.length > 10000)
		throw new Error("invalid clients");
	if (!Array.isArray(input.servers) || input.servers.length === 0 || input.servers.length > 1000)
		throw new Error("invalid servers");
	const clientKeys = new Set();
	const tokenHashes = new Set();
	const serverKeys = new Set();
	const clients = input.clients.map((client) => validateClient(client, clientKeys, tokenHashes));
	const servers = input.servers.map((server) => validateServer(server, serverKeys));
	if (
		input.routingRequired &&
		servers.some((server) => !server.upstreamAuthEnv || !server.pinnedAddresses)
	)
		throw new Error(
			"mandatory routing requires isolated upstream credentials and pinned addresses",
		);
	if (input.routingRequired && clients.some((client) => !client.probeTokenEnv))
		throw new Error("mandatory routing requires client credential negative probes");
	validateScopes(clients, servers);
	return freezeTree({
		stateDir: resolve(input.stateDir),
		port,
		maxBodyBytes,
		clients,
		servers,
		routingRequired: input.routingRequired === true,
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
