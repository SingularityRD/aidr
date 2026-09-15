import { createHash } from "node:crypto";
import { createServer } from "node:http";
import { join } from "node:path";
import {
	approveQuarantinedMcpToolset,
	attestMcpToolManifest,
	FileMcpAttestationStore,
	McpToolDefinitionSchema,
	mcpToolsetHash,
} from "../../core/dist/mcp-attestation.js";
import { fetchMcpEndpoint, McpTransportError } from "../../core/dist/mcp-transport.js";
import { scanModelOutput } from "../../core/dist/output-scanner.js";
import { authenticateBearer, validateGatewayConfig } from "./config.mjs";
import {
	coverageDescriptor,
	McpGatewayRefusal,
	makeMcpGatewayCoverageEvent,
	refusalPayload,
} from "./coverage.mjs";

const ID = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const SESSION = /^[\x21-\x7e]{8,256}$/;
const MAX_ACTIVE_PER_TENANT = 16;
const MAX_SESSIONS = 10_000;
const SESSION_TTL_MS = 30 * 60 * 1000;
const UPSTREAM_TIMEOUT_MS = 15_000;
const textDecoder = new TextDecoder("utf-8", { fatal: true });

function upstreamHeaders(server, sessionId) {
	const auth = server.upstreamAuthEnv ? process.env[server.upstreamAuthEnv] : undefined;
	if (server.upstreamAuthEnv && (!auth || /[\r\n]/.test(auth)))
		throw new Error("upstream_auth_unavailable");
	return {
		"content-type": "application/json",
		accept: server.transport === "sse" ? "text/event-stream" : "application/json",
		...(auth ? { authorization: `Bearer ${auth}` } : {}),
		...(sessionId ? { "mcp-session-id": sessionId } : {}),
	};
}

function error(id, code, message, data) {
	return {
		jsonrpc: "2.0",
		id,
		error: { code, message, ...(data ? { data } : {}) },
	};
}

function rpcResponse(id, result) {
	return { jsonrpc: "2.0", id, result };
}

function jsonObject(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function safeJson(value) {
	const text = JSON.stringify(value);
	if (typeof text !== "string") throw new Error("invalid JSON");
	return text;
}

async function readBody(request, maxBytes) {
	const announced = request.headers["content-length"];
	if (announced !== undefined && (!/^\d+$/.test(announced) || Number(announced) > maxBytes)) {
		throw new Error("request_too_large");
	}
	const chunks = [];
	let bytes = 0;
	for await (const chunk of request) {
		bytes += chunk.byteLength;
		if (bytes > maxBytes) throw new Error("request_too_large");
		chunks.push(chunk);
	}
	return textDecoder.decode(Buffer.concat(chunks));
}

function parseRequest(text) {
	const rpc = JSON.parse(text);
	const notification = rpc?.method === "notifications/initialized";
	if (
		!jsonObject(rpc) ||
		rpc.jsonrpc !== "2.0" ||
		typeof rpc.method !== "string" ||
		!["initialize", "ping", "tools/list", "tools/call", "notifications/initialized"].includes(
			rpc.method,
		) ||
		(notification
			? Object.hasOwn(rpc, "id")
			: typeof rpc.id !== "string" && typeof rpc.id !== "number") ||
		(typeof rpc.id === "number" && !Number.isSafeInteger(rpc.id)) ||
		(rpc.params !== undefined && !jsonObject(rpc.params))
	) {
		throw new Error("invalid_rpc_request");
	}
	return rpc;
}

function parseSseEvent(event) {
	if (!event.trim()) return null;
	const data = [];
	let eventType = "message";
	for (const line of event.split("\n")) {
		if (!line || line.startsWith(":")) continue;
		if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
		else if (line.startsWith("event:")) eventType = line.slice(6).trim();
		else if (line.startsWith("id:") || line.startsWith("retry:")) continue;
		else throw new Error("invalid_sse_field");
	}
	if (data.length === 0) return null;
	if (eventType !== "message") throw new Error("unsupported_sse_event");
	return JSON.parse(data.join("\n"));
}

function serverInitiatedRefusal() {
	return new McpGatewayRefusal(
		"server_initiated_method",
		"MCP server-initiated methods are outside the gateway response coverage and were refused",
	);
}

function rejectServerInitiated(value) {
	if (jsonObject(value) && typeof value.method === "string") throw serverInitiatedRefusal();
	return value;
}

function parseSse(text) {
	let response = null;
	for (const event of text.replace(/\r\n/g, "\n").split(/\n\n+/)) {
		const parsed = rejectServerInitiated(parseSseEvent(event));
		if (parsed === null) continue;
		if (response !== null) throw new Error("multiple_sse_responses");
		response = parsed;
	}
	if (response === null) throw new Error("missing_sse_response");
	return response;
}

function parseUpstreamResponse(text, mode, expectedId) {
	const rpc = rejectServerInitiated(mode === "sse" ? parseSse(text) : JSON.parse(text));
	if (
		!jsonObject(rpc) ||
		rpc.jsonrpc !== "2.0" ||
		rpc.id !== expectedId ||
		"result" in rpc === "error" in rpc
	) {
		throw new Error("invalid_upstream_rpc");
	}
	if ("error" in rpc) throw new Error("upstream_rpc_error");
	return rpc.result;
}

function normalizeToolSet(result) {
	if (
		!jsonObject(result) ||
		!Array.isArray(result.tools) ||
		result.nextCursor !== undefined ||
		result.tools.length > 4096
	)
		throw new Error("invalid_tool_list");
	const tools = result.tools.map((tool) => {
		if (!jsonObject(tool)) throw new Error("invalid_tool_definition");
		return McpToolDefinitionSchema.parse({
			name: tool.name,
			description: tool.description,
			input_schema: tool.inputSchema,
			...(tool.outputSchema !== undefined ? { output_schema: tool.outputSchema } : {}),
			...(tool.annotations !== undefined ? { annotations: tool.annotations } : {}),
		});
	});
	return tools;
}

function collectStrings(value, depth = 0, nodes = { count: 0 }, output = []) {
	nodes.count += 1;
	if (nodes.count > 100_000 || depth > 32) throw new Error("output_uninspectable");
	if (typeof value === "string") output.push(value);
	else if (Array.isArray(value))
		for (const item of value) collectStrings(item, depth + 1, nodes, output);
	else if (jsonObject(value))
		for (const [key, item] of Object.entries(value)) {
			output.push(key);
			collectStrings(item, depth + 1, nodes, output);
		}
	return output;
}

function inspect(value, scanner, maxBytes) {
	const json = safeJson(value);
	if (Buffer.byteLength(json, "utf8") > maxBytes) throw new Error("output_oversize");
	const text = collectStrings(value)
		.join(" ")
		.normalize("NFKC")
		.replace(/[\u200B-\u200D\uFEFF]/g, "");
	if (Buffer.byteLength(text, "utf8") > maxBytes * 2) throw new Error("output_oversize");
	let findings;
	try {
		findings = scanner(`${json}\n${text}`);
	} catch {
		throw new Error("scanner_unavailable");
	}
	if (!Array.isArray(findings)) throw new Error("scanner_unavailable");
	if (findings.length > 0) throw new Error("output_blocked");
}

const BLOCK_REASONS = new Set([
	"manifest_quarantined",
	"manifest_rejected",
	"request_too_large",
	"invalid_content_type",
	"invalid_rpc_request",
	"invalid_session",
	"session_required",
	"unexpected_session",
	"invalid_upstream_session",
	"unexpected_upstream_session",
	"session_changed",
	"tool_not_allowed",
	"toolset_drift",
	"output_blocked",
	"output_oversize",
	"output_uninspectable",
	"scanner_unavailable",
	"unsupported_tool_output",
	"unsupported_structured_output",
	"unsupported_binary_output",
	"server_initiated_method",
	"invalid_tool_result",
	"invalid_initialize_result",
	"invalid_tool_list",
	"invalid_tool_definition",
	"invalid_upstream_rpc",
	"upstream_rpc_error",
	"invalid_sse_field",
	"unsupported_sse_event",
	"multiple_sse_responses",
	"missing_sse_response",
	"upstream_auth_unavailable",
	"notification_response_body",
	"invalid_notification_ack",
]);

function safeReason(cause) {
	if (cause instanceof McpGatewayRefusal && /^[a-z0-9_]{1,64}$/.test(cause.code)) return cause.code;
	if (cause instanceof McpTransportError && /^[a-z0-9_]{1,64}$/.test(cause.code)) return cause.code;
	if (cause instanceof Error && BLOCK_REASONS.has(cause.message)) return cause.message;
	return "gateway_unavailable";
}

const BINARY_OUTPUT_TYPES = new Set(["image", "audio"]);

function validateToolResult(result) {
	if (
		!jsonObject(result) ||
		!Array.isArray(result.content) ||
		result.content.length > 4096 ||
		(result.isError !== undefined && typeof result.isError !== "boolean")
	) {
		throw new McpGatewayRefusal(
			"invalid_tool_result",
			"MCP tool output has an invalid result envelope and was refused",
		);
	}
	for (const item of result.content) {
		if (!jsonObject(item)) {
			throw new McpGatewayRefusal(
				"unsupported_tool_output",
				"MCP tool output representation is unsupported and was refused",
			);
		}
		if (BINARY_OUTPUT_TYPES.has(item.type)) {
			throw new McpGatewayRefusal(
				"unsupported_binary_output",
				"MCP binary tool output is outside the gateway response coverage and was refused",
			);
		}
		if (item.type !== "text" || typeof item.text !== "string") {
			throw new McpGatewayRefusal(
				"unsupported_tool_output",
				"MCP tool output representation is unsupported and was refused",
			);
		}
	}
	if (result.structuredContent !== undefined && !jsonObject(result.structuredContent)) {
		throw new McpGatewayRefusal(
			"unsupported_structured_output",
			"MCP structured tool output is outside the gateway response coverage and was refused",
		);
	}
}

function clientInitializeResult(result) {
	if (
		!jsonObject(result) ||
		typeof result.protocolVersion !== "string" ||
		result.protocolVersion.length === 0 ||
		result.protocolVersion.length > 64 ||
		!jsonObject(result.serverInfo) ||
		typeof result.serverInfo.name !== "string" ||
		result.serverInfo.name.length === 0 ||
		result.serverInfo.name.length > 128 ||
		typeof result.serverInfo.version !== "string" ||
		result.serverInfo.version.length === 0 ||
		result.serverInfo.version.length > 128
	) {
		throw new Error("invalid_initialize_result");
	}
	return {
		protocolVersion: result.protocolVersion,
		capabilities: { tools: {} },
		serverInfo: { name: result.serverInfo.name, version: result.serverInfo.version },
	};
}

function send(response, status, body, extraHeaders = {}) {
	if (response.writableEnded || response.destroyed) return;
	response.writeHead(status, {
		"content-type": "application/json; charset=utf-8",
		"cache-control": "no-store",
		"x-content-type-options": "nosniff",
		...extraHeaders,
	});
	response.end(safeJson(body));
}

function sendRpcResult(response, result) {
	if (result.notification) {
		response.writeHead(202, {
			"cache-control": "no-store",
			"x-content-type-options": "nosniff",
		});
		response.end();
		return;
	}
	send(
		response,
		200,
		result.body,
		result.sessionHeader ? { "mcp-session-id": result.sessionHeader } : {},
	);
}

export function createMcpGateway(input, dependencies = {}) {
	const config = validateGatewayConfig(input);
	const stores = new Map();
	const sessions = new Map();
	const inflight = new Map();
	const scanner = dependencies.scanner ?? scanModelOutput;
	const lookup = dependencies.lookup;
	const pinnedFetch = dependencies.pinnedFetch;
	const now = dependencies.now ?? (() => new Date());
	const onEvent = dependencies.onEvent ?? (() => undefined);
	const directUpstreamCheck = dependencies.directUpstreamCheck ?? dependencies.checkDirectUpstream;
	let startupCheckPromise;

	async function emitEvent(event) {
		try {
			await onEvent(event);
		} catch {
			/* Coverage and audit sinks cannot weaken a refusal or startup result. */
		}
	}

	function storeFor(tenantId) {
		let store = stores.get(tenantId);
		if (!store) {
			store =
				dependencies.storeFactory?.(tenantId) ??
				new FileMcpAttestationStore(
					join(config.stateDir, createHash("sha256").update(tenantId).digest("hex")),
				);
			stores.set(tenantId, store);
		}
		return store;
	}

	async function audit(tenantId, serverId, clientId, decision, reason) {
		await emitEvent({ tenantId, serverId, clientId, decision, reason, at: now().toISOString() });
	}

	async function emitCoverageForRefusal(refusal, context) {
		const descriptor = coverageDescriptor(refusal.code);
		await emitEvent(
			makeMcpGatewayCoverageEvent({
				channel: "upstream_response",
				surface: refusal.surface ?? descriptor.surface,
				status: "refused",
				coverageStatus: refusal.coverageStatus ?? descriptor.coverageStatus,
				reasonCode: refusal.code,
				decision: "deny",
				enforcement: refusal.enforcement ?? descriptor.enforcement,
				at: now().toISOString(),
				tenantId: context.tenantId,
				serverId: context.serverId,
				clientId: context.clientId,
				requestMethod: context.requestMethod,
				outputType: refusal.outputType ?? descriptor.outputType,
				refusal: refusalPayload(refusal),
			}),
		);
	}

	function normalizeDirectUpstreamCheck(result) {
		if (
			result === "bypass" ||
			result?.status === "bypass" ||
			result?.directAccess === true ||
			result?.bypass === true
		)
			return "bypass";
		if (
			result === "routed" ||
			result?.status === "routed" ||
			result === false ||
			result?.bypass === false
		)
			return "routed";
		if (result === "unobservable" || result?.status === "unobservable" || result == null)
			return "unobservable";
		throw new Error("invalid_direct_upstream_check");
	}

	function startupReason(status) {
		return status === "bypass"
			? "direct_upstream_bypass_detected"
			: status === "routed"
				? "direct_upstream_bypass_not_observed"
				: "direct_upstream_bypass_unobservable";
	}

	async function observeDirectUpstream(server, gatewayAddress) {
		if (typeof directUpstreamCheck !== "function")
			return { status: "unobservable", reasonCode: "direct_upstream_bypass_unobservable" };
		try {
			const status = normalizeDirectUpstreamCheck(
				await directUpstreamCheck({
					tenantId: server.tenantId,
					serverId: server.id,
					upstreamUrl: server.url,
					gatewayAddress,
				}),
			);
			return { status, reasonCode: startupReason(status) };
		} catch {
			return { status: "unobservable", reasonCode: "direct_upstream_check_failed" };
		}
	}

	function startupBypassRefusal() {
		return new McpGatewayRefusal(
			"direct_upstream_bypass_detected",
			"Direct upstream access was observed for an MCP server; gateway startup was refused",
			{
				surface: "direct_upstream",
				coverageStatus: "limited",
				enforcement: "startup_refusal",
			},
		);
	}

	async function runStartupSelfCheck(gatewayAddress) {
		const results = [];
		for (const server of config.servers) {
			const observation = await observeDirectUpstream(server, gatewayAddress);
			const refusal = observation.status === "bypass" ? startupBypassRefusal() : null;
			await emitEvent(
				makeMcpGatewayCoverageEvent({
					channel: "startup",
					surface: "direct_upstream",
					status: refusal ? "refused" : observation.status,
					coverageStatus: observation.status === "routed" ? "observed" : "limited",
					reasonCode: observation.reasonCode,
					decision: refusal ? "deny" : "unknown",
					enforcement: refusal ? "startup_refusal" : "not_verified",
					at: now().toISOString(),
					tenantId: server.tenantId,
					serverId: server.id,
					refusal: refusal ? refusalPayload(refusal) : undefined,
				}),
			);
			results.push({
				tenantId: server.tenantId,
				serverId: server.id,
				status: observation.status,
				reasonCode: observation.reasonCode,
			});
			if (refusal) throw refusal;
		}
		return results;
	}

	async function attest(server) {
		const result = await attestMcpToolManifest({
			candidate: server.signedManifest,
			verifier: {
				trustedSigners: server.trustedSigners,
				revokedKeyIds: new Set(server.revokedKeyIds ?? []),
				expectedServerId: server.id,
				now: now(),
			},
			store: storeFor(server.tenantId),
		});
		if (result.status !== "accepted") throw new Error(`manifest_${result.status}`);
	}

	async function forward(server, rpc, sessionId, signal) {
		const response = await fetchMcpEndpoint(
			server.url,
			{
				method: "POST",
				headers: upstreamHeaders(server, sessionId),
				body: safeJson(rpc),
				signal,
			},
			{
				mode: server.transport,
				maxBodyBytes: config.maxBodyBytes,
				lookup,
				pinnedFetch,
				acceptNotificationResponse: rpc.method === "notifications/initialized",
			},
		);
		const sessionHeader = response.headers.get("mcp-session-id");
		if (rpc.method !== "initialize" && sessionHeader && sessionHeader !== sessionId) {
			throw new Error("session_changed");
		}
		if (rpc.method === "notifications/initialized") {
			if (response.status !== 202) throw new Error("invalid_notification_ack");
			return { result: undefined, sessionHeader };
		}
		const text = textDecoder.decode(new Uint8Array(await response.arrayBuffer()));
		return { result: parseUpstreamResponse(text, server.transport, rpc.id), sessionHeader };
	}

	async function verifiedTools(server, sessionId, signal) {
		const id = `aidr-list-${Date.now()}-${Math.random().toString(36).slice(2)}`;
		const { result } = await forward(
			server,
			{ jsonrpc: "2.0", id, method: "tools/list", params: {} },
			sessionId,
			signal,
		);
		const observed = normalizeToolSet(result);
		if (mcpToolsetHash(observed) !== mcpToolsetHash(server.signedManifest.manifest.tools)) {
			throw new Error("toolset_drift");
		}
		inspect(result, scanner, config.maxBodyBytes);
		return observed;
	}

	function boundSession(header, client, server) {
		if (server.sessionMode === "stateless") {
			if (header !== undefined) throw new Error("unexpected_session");
			return undefined;
		}
		if (typeof header !== "string" || !SESSION.test(header)) throw new Error("session_required");
		const session = sessions.get(header);
		if (session && session.expiresAt <= now().getTime()) sessions.delete(header);
		if (
			!session ||
			session.clientId !== client.id ||
			session.tenantId !== client.tenantId ||
			session.serverId !== server.id ||
			session.expiresAt <= now().getTime()
		)
			throw new Error("invalid_session");
		session.expiresAt = now().getTime() + SESSION_TTL_MS;
		return header;
	}

	function pruneExpiredSessions() {
		const current = now().getTime();
		for (const [id, session] of sessions) {
			if (session.expiresAt <= current) sessions.delete(id);
		}
	}

	async function initializeRpc(rpc, client, server, request, signal) {
		if (server.sessionMode === "stateless" && request.headers["mcp-session-id"] !== undefined)
			throw new Error("unexpected_session");
		const { result, sessionHeader } = await forward(server, rpc, undefined, signal);
		inspect(result, scanner, config.maxBodyBytes);
		const clientResult = clientInitializeResult(result);
		if (server.sessionMode === "required") {
			pruneExpiredSessions();
			if (
				!sessionHeader ||
				!SESSION.test(sessionHeader) ||
				sessions.has(sessionHeader) ||
				sessions.size >= MAX_SESSIONS
			)
				throw new Error("invalid_upstream_session");
			sessions.set(sessionHeader, {
				clientId: client.id,
				tenantId: client.tenantId,
				serverId: server.id,
				expiresAt: now().getTime() + SESSION_TTL_MS,
			});
		} else if (sessionHeader) throw new Error("unexpected_upstream_session");
		return { body: rpcResponse(rpc.id, clientResult), sessionHeader };
	}

	function listTools(rpc, observed, allowed) {
		const tools = observed
			.filter((tool) => allowed.has(tool.name))
			.map((tool) => ({
				name: tool.name,
				description: tool.description,
				inputSchema: tool.input_schema,
				...(tool.output_schema ? { outputSchema: tool.output_schema } : {}),
				...(tool.annotations ? { annotations: tool.annotations } : {}),
			}));
		return { body: rpcResponse(rpc.id, { tools }) };
	}

	async function callTool(rpc, server, observed, allowed, sessionId, signal) {
		if (
			!jsonObject(rpc.params) ||
			typeof rpc.params.name !== "string" ||
			!allowed.has(rpc.params.name) ||
			!observed.some((tool) => tool.name === rpc.params.name) ||
			(rpc.params.arguments !== undefined && !jsonObject(rpc.params.arguments))
		) {
			throw new Error("tool_not_allowed");
		}
		const upstream = await forward(
			server,
			{
				jsonrpc: "2.0",
				id: rpc.id,
				method: "tools/call",
				params: { name: rpc.params.name, arguments: rpc.params.arguments ?? {} },
			},
			sessionId,
			signal,
		);
		validateToolResult(upstream.result);
		inspect(upstream.result, scanner, config.maxBodyBytes);
		return { body: rpcResponse(rpc.id, upstream.result) };
	}

	async function processRpc(rpc, client, server, request, signal) {
		if (rpc.method === "initialize") return initializeRpc(rpc, client, server, request, signal);
		const sessionId = boundSession(request.headers["mcp-session-id"], client, server);
		if (rpc.method === "notifications/initialized") {
			await forward(server, rpc, sessionId, signal);
			return { notification: true };
		}
		if (rpc.method === "ping") return { body: rpcResponse(rpc.id, {}) };
		const observed = await verifiedTools(server, sessionId, signal);
		const allowed = new Set(client.allowedTools[server.id]);
		return rpc.method === "tools/list"
			? listTools(rpc, observed, allowed)
			: callTool(rpc, server, observed, allowed, sessionId, signal);
	}

	async function handleAuthorized(request, response, client, upstream, serverId) {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), UPSTREAM_TIMEOUT_MS);
		response.once("close", () => {
			if (!response.writableEnded) controller.abort();
		});
		let rpcId = null;
		let rpcMethod;
		try {
			if (!/^application\/json(?:\s*;|$)/i.test(request.headers["content-type"] ?? "")) {
				throw new Error("invalid_content_type");
			}
			const rpc = parseRequest(await readBody(request, config.maxBodyBytes));
			rpcId = rpc.id ?? null;
			rpcMethod = rpc.method;
			await attest(upstream);
			const result = await processRpc(rpc, client, upstream, request, controller.signal);
			await audit(client.tenantId, serverId, client.id, "allow", rpc.method);
			sendRpcResult(response, result);
		} catch (cause) {
			const reason = safeReason(cause);
			await audit(client.tenantId, serverId, client.id, "deny", reason);
			const refusal = cause instanceof McpGatewayRefusal ? cause : null;
			if (refusal) {
				await emitCoverageForRefusal(refusal, {
					tenantId: client.tenantId,
					serverId,
					clientId: client.id,
					requestMethod: rpcMethod,
				});
			}
			const status = reason === "request_too_large" ? 413 : rpcId === null ? 400 : 200;
			send(
				response,
				status,
				error(
					rpcId,
					-32001,
					`AIDR blocked MCP request: ${reason}`,
					refusal ? refusalPayload(refusal) : undefined,
				),
			);
		} finally {
			clearTimeout(timeout);
			inflight.set(client.tenantId, (inflight.get(client.tenantId) ?? 1) - 1);
		}
	}

	function resolveRoute(request, response) {
		const client = authenticateBearer(request.headers.authorization, config.clients);
		if (!client) {
			send(response, 401, { error: "unauthorized" });
			return null;
		}
		let serverId;
		try {
			serverId = decodeURIComponent(request.url.slice(5));
		} catch {
			send(response, 404, { error: "not_found" });
			return null;
		}
		if (!ID.test(serverId) || !Object.hasOwn(client.allowedTools, serverId)) {
			send(response, 403, { error: "forbidden" });
			return null;
		}
		const upstream = config.servers.find(
			(item) => item.tenantId === client.tenantId && item.id === serverId,
		);
		if (!upstream) {
			send(response, 403, { error: "forbidden" });
			return null;
		}
		return { client, serverId, upstream };
	}

	const server = createServer(async (request, response) => {
		if (request.method === "GET" && request.url === "/healthz") {
			send(response, 200, { status: "up" });
			return;
		}
		if (
			request.method !== "POST" ||
			!request.url?.startsWith("/mcp/") ||
			request.url.includes("?")
		) {
			send(response, 404, { error: "not_found" });
			return;
		}
		const route = resolveRoute(request, response);
		if (!route) return;
		const { client, serverId, upstream } = route;
		const current = inflight.get(client.tenantId) ?? 0;
		if (current >= MAX_ACTIVE_PER_TENANT) {
			send(response, 429, { error: "tenant_busy" });
			return;
		}
		inflight.set(client.tenantId, current + 1);
		await handleAuthorized(request, response, client, upstream, serverId);
	});
	server.maxConnections = 100;
	server.maxRequestsPerSocket = 100;
	server.headersTimeout = 10_000;
	server.requestTimeout = 15_000;
	server.keepAliveTimeout = 5_000;

	return {
		config,
		storeFor,
		close() {
			return new Promise((resolve) => server.close(resolve));
		},
		async approve({ tenantId, serverId, toolsetHash, approvedBy, reason }) {
			const target = config.servers.find(
				(item) => item.tenantId === tenantId && item.id === serverId,
			);
			if (!target) throw new Error("unknown tenant server");
			return approveQuarantinedMcpToolset({
				serverId,
				toolsetHash,
				approvedBy,
				reason,
				store: storeFor(tenantId),
				now: now(),
			});
		},
		startupSelfCheck(gatewayAddress = null) {
			if (!startupCheckPromise) startupCheckPromise = runStartupSelfCheck(gatewayAddress);
			return startupCheckPromise;
		},
		listen(port = config.port) {
			return new Promise((resolve, reject) => {
				server.once("error", reject);
				server.listen(port, "127.0.0.1", async () => {
					server.off("error", reject);
					const address = server.address();
					try {
						if (!startupCheckPromise) startupCheckPromise = runStartupSelfCheck(address);
						await startupCheckPromise;
						resolve(address);
					} catch (cause) {
						server.close(() => reject(cause));
					}
				});
			});
		},
	};
}
