import { once } from "node:events";
import { readMcpSseMessages } from "../../core/dist/mcp-transport.js";
import { authenticateBearer, MCP_PROTOCOL_VERSIONS } from "./config.mjs";

const ENV_NAME = /^[A-Z][A-Z0-9_]{0,127}$/;
const decoder = new TextDecoder("utf-8", { fatal: true });
// Requests that may wait on the gateway while correlated client replies keep flowing.
const CONCURRENT_METHODS = new Set([
	"tools/call",
	"tools/list",
	"server/discover",
	"ping",
	"resources/list",
	"resources/templates/list",
	"resources/read",
	"prompts/list",
	"prompts/get",
]);

function object(value) {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

function bridgeError(id, reason) {
	return {
		jsonrpc: "2.0",
		id,
		error: { code: -32001, message: `AIDR blocked MCP request: ${reason}` },
	};
}

async function writeLine(output, message, assertInstalledPrivacySupported) {
	await assertInstalledPrivacySupported?.();
	if (!output.write(`${JSON.stringify(message)}\n`)) await once(output, "drain");
}

async function readBoundedText(response, maxBytes) {
	const reader = response.body?.getReader();
	if (!reader) return "";
	const chunks = [];
	let bytes = 0;
	try {
		for (;;) {
			const item = await reader.read();
			if (item.done) break;
			bytes += item.value.byteLength;
			if (bytes > maxBytes) throw new Error("bridge_response_too_large");
			chunks.push(item.value);
		}
		return decoder.decode(Buffer.concat(chunks));
	} catch (cause) {
		await reader.cancel().catch(() => undefined);
		throw cause;
	}
}

export function validateStdioBinding(
	config,
	{ tenantId, clientId, serverId, tokenEnv },
	environment = process.env,
) {
	if (!ENV_NAME.test(tokenEnv ?? "")) throw new Error("invalid token environment variable");
	const token = environment[tokenEnv];
	const matched = authenticateBearer(
		typeof token === "string" ? `Bearer ${token}` : "",
		config.clients,
	);
	if (
		!matched ||
		matched.id !== clientId ||
		matched.tenantId !== tenantId ||
		!Object.hasOwn(matched.allowedTools, serverId) ||
		!config.servers.some((server) => server.id === serverId && server.tenantId === tenantId)
	) {
		throw new Error("stdio client binding rejected");
	}
	return token;
}

/**
 * The stdio bridge runs as the MCP client's (the agent's) own process, so its
 * configuration, environment and state are within the agent user's reach: it
 * is not a credential-isolation boundary. Every start says so on stderr. A
 * server with an upstream credential (`upstreamAuthEnv`) puts that credential
 * in the agent's environment; `stdioUpstreamCredentials: "refuse"` makes that
 * a startup refusal instead of a warning. Messages carry no secret values.
 */
export function assertStdioIsolationPolicy(config, { tenantId, serverId, stderr }) {
	stderr.write(
		"AIDR MCP stdio bridge warning: stdio mode runs as the agent's user; the agent can read this configuration and environment, so it is not a credential-isolation or approval boundary. Use the HTTP gateway as an operator-owned service for that guarantee.\n",
	);
	const server = config.servers.find((item) => item.tenantId === tenantId && item.id === serverId);
	if (!server?.upstreamAuthEnv) return;
	if (config.stdioUpstreamCredentials === "refuse")
		throw new Error("stdio upstream credential refused");
	stderr.write(
		"AIDR MCP stdio bridge warning: upstreamAuthEnv is set, so the upstream credential is in the agent's environment and the agent can call the upstream directly. Set stdioUpstreamCredentials to refuse to block this.\n",
	);
}

function parseFrame(line) {
	try {
		return { rpc: JSON.parse(decoder.decode(line)) };
	} catch {
		return {
			error: {
				jsonrpc: "2.0",
				id: null,
				error: { code: -32700, message: "Invalid JSON-RPC frame" },
			},
		};
	}
}

async function postToGateway(context, rpc) {
	const metadataVersion = rpc.params?._meta?.["io.modelcontextprotocol/protocolVersion"];
	if (metadataVersion !== undefined && !MCP_PROTOCOL_VERSIONS.includes(metadataVersion))
		throw new Error("invalid stdio protocol version");
	const protocolVersion = metadataVersion ?? context.protocolVersion;
	await context.assertInstalledPrivacySupported?.();
	return context.fetchImpl(context.route, {
		method: "POST",
		headers: {
			authorization: `Bearer ${context.token}`,
			"content-type": "application/json",
			accept: "application/json, text/event-stream",
			...(context.sessionId && protocolVersion !== "2026-07-28"
				? { "mcp-session-id": context.sessionId }
				: {}),
			...(protocolVersion ? { "mcp-protocol-version": protocolVersion } : {}),
		},
		body: JSON.stringify(rpc),
		signal: AbortSignal.any([AbortSignal.timeout(20_000), context.signal]),
	});
}

async function readGatewayReply(response, rpc, maxBytes, context) {
	if (response.status !== 200) throw new Error("stdio gateway unavailable");
	let reply;
	try {
		if (/^text\/event-stream(?:\s*;|$)/i.test(response.headers.get("content-type") ?? "")) {
			for await (const message of readMcpSseMessages(
				response,
				maxBytes * 2 + 2048,
				context.signal,
			)) {
				if (typeof message.method === "string") {
					if (Object.hasOwn(message, "id")) {
						if (context.pendingServerIds.size >= 256 || context.pendingServerIds.has(message.id))
							throw new Error("invalid gateway request id");
						context.pendingServerIds.add(message.id);
					}
					await writeLine(context.output, message, context.assertInstalledPrivacySupported);
				} else {
					reply = message;
					break;
				}
			}
		} else reply = JSON.parse(await readBoundedText(response, maxBytes * 2 + 2048));
	} catch {
		throw new Error("invalid stdio gateway response");
	}
	if (
		!object(reply) ||
		reply.jsonrpc !== "2.0" ||
		reply.id !== (rpc.id ?? null) ||
		Object.hasOwn(reply, "result") === Object.hasOwn(reply, "error")
	) {
		throw new Error("invalid stdio gateway response");
	}
	if (
		rpc.method === "initialize" &&
		Object.hasOwn(reply, "result") &&
		(!MCP_PROTOCOL_VERSIONS.includes(reply.result?.protocolVersion) ||
			reply.result.protocolVersion === "2026-07-28")
	)
		throw new Error("invalid stdio gateway response");
	return reply;
}

async function handleFrame(line, context) {
	if (line.length === 0) return;
	await context.assertInstalledPrivacySupported?.();
	const parsed = parseFrame(line);
	if (parsed.error)
		return writeLine(context.output, parsed.error, context.assertInstalledPrivacySupported);
	const rpc = parsed.rpc;
	if (!object(rpc))
		return writeLine(
			context.output,
			bridgeError(null, "invalid_rpc_request"),
			context.assertInstalledPrivacySupported,
		);
	const notification = !Object.hasOwn(rpc, "id");
	const serverResponse = !Object.hasOwn(rpc, "method");
	if (serverResponse && !context.pendingServerIds.delete(rpc.id))
		throw new Error("unexpected stdio response");
	if (notification && rpc.method !== "notifications/initialized")
		throw new Error("unsupported stdio notification");
	if (rpc.method === "initialize") {
		context.sessionId = undefined;
		context.protocolVersion = undefined;
	}
	const response = await postToGateway(context, rpc);
	if (notification || serverResponse) {
		if (response.status !== 202 || (await readBoundedText(response, context.maxBytes)) !== "")
			throw new Error("stdio notification rejected");
		return;
	}
	const reply = await readGatewayReply(response, rpc, context.maxBytes, context);
	if (rpc.method === "initialize" && Object.hasOwn(reply, "result")) {
		context.sessionId = response.headers.get("mcp-session-id") ?? undefined;
		context.protocolVersion = reply.result.protocolVersion;
	}
	await writeLine(context.output, reply, context.assertInstalledPrivacySupported);
}

async function consumeChunk(chunk, pending, maxBytes, onFrame) {
	const bytes = Buffer.from(chunk);
	let offset = 0;
	for (;;) {
		const end = bytes.indexOf(0x0a, offset);
		const next = end < 0 ? bytes.subarray(offset) : bytes.subarray(offset, end);
		if (pending.length + next.length > maxBytes) throw new Error("stdio frame too large");
		pending = Buffer.concat([pending, next]);
		if (end < 0) return pending;
		const line = pending.at(-1) === 0x0d ? pending.subarray(0, -1) : pending;
		pending = Buffer.alloc(0);
		await onFrame(line);
		offset = end + 1;
		if (offset === bytes.length) return pending;
	}
}

async function consumeFrames(input, maxBytes, onFrame) {
	let pending = Buffer.alloc(0);
	for await (const chunk of input) pending = await consumeChunk(chunk, pending, maxBytes, onFrame);
	if (pending.length !== 0) throw new Error("unterminated stdio frame");
}

/** Run one MCP stdio client over the gateway's inspected, authenticated loopback route. */
export async function runStdioBridge({
	gateway,
	tenantId,
	clientId,
	serverId,
	tokenEnv,
	input,
	output,
	environment = process.env,
	fetchImpl = fetch,
	assertInstalledPrivacySupported,
}) {
	const token = validateStdioBinding(
		gateway.config,
		{ tenantId, clientId, serverId, tokenEnv },
		environment,
	);
	const address = await gateway.listen(0);
	const controller = new AbortController();
	const context = {
		route: `http://127.0.0.1:${address.port}/mcp/${encodeURIComponent(serverId)}`,
		token,
		output,
		fetchImpl,
		maxBytes: gateway.config.maxBodyBytes,
		assertInstalledPrivacySupported,
		sessionId: undefined,
		pendingServerIds: new Set(),
		signal: controller.signal,
	};
	const tasks = new Set();
	let failure;
	try {
		await assertInstalledPrivacySupported?.();
		await consumeFrames(input, context.maxBytes, async (line) => {
			const frame = parseFrame(line).rpc;
			if (frame?.method === "initialize" && tasks.size)
				throw new Error("initialize during pending requests");
			if (CONCURRENT_METHODS.has(frame?.method)) {
				if (tasks.size >= 16) throw new Error("stdio requests exceeded");
				const task = handleFrame(line, context)
					.catch((cause) => {
						failure ??= cause;
						controller.abort(cause);
						input.destroy?.(cause);
					})
					.finally(() => tasks.delete(task));
				tasks.add(task);
			} else await handleFrame(line, context);
		});
		await Promise.all(tasks);
		if (failure) throw failure;
	} finally {
		controller.abort();
		await Promise.all(tasks);
		await gateway.close();
	}
}
