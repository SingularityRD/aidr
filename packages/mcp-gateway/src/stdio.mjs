import { once } from "node:events";
import { authenticateBearer } from "./config.mjs";

const ENV_NAME = /^[A-Z][A-Z0-9_]{0,127}$/;
const decoder = new TextDecoder("utf-8", { fatal: true });

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

async function writeLine(output, message) {
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
	return context.fetchImpl(context.route, {
		method: "POST",
		headers: {
			authorization: `Bearer ${context.token}`,
			"content-type": "application/json",
			accept: "application/json, text/event-stream",
			...(context.sessionId ? { "mcp-session-id": context.sessionId } : {}),
		},
		body: JSON.stringify(rpc),
		signal: AbortSignal.timeout(20_000),
	});
}

async function readGatewayReply(response, rpc, maxBytes) {
	if (response.status !== 200) throw new Error("stdio gateway unavailable");
	let reply;
	try {
		reply = JSON.parse(await readBoundedText(response, maxBytes * 2 + 2048));
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
	return reply;
}

async function handleFrame(line, context) {
	if (line.length === 0) return;
	const parsed = parseFrame(line);
	if (parsed.error) return writeLine(context.output, parsed.error);
	const rpc = parsed.rpc;
	if (!object(rpc)) return writeLine(context.output, bridgeError(null, "invalid_rpc_request"));
	const notification = !Object.hasOwn(rpc, "id");
	if (notification && rpc.method !== "notifications/initialized")
		throw new Error("unsupported stdio notification");
	if (rpc.method === "initialize") context.sessionId = undefined;
	const response = await postToGateway(context, rpc);
	if (notification) {
		if (response.status !== 202 || (await readBoundedText(response, context.maxBytes)) !== "")
			throw new Error("stdio notification rejected");
		return;
	}
	const reply = await readGatewayReply(response, rpc, context.maxBytes);
	if (rpc.method === "initialize" && Object.hasOwn(reply, "result"))
		context.sessionId = response.headers.get("mcp-session-id") ?? undefined;
	await writeLine(context.output, reply);
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
}) {
	const token = validateStdioBinding(
		gateway.config,
		{ tenantId, clientId, serverId, tokenEnv },
		environment,
	);
	const address = await gateway.listen(0);
	const context = {
		route: `http://127.0.0.1:${address.port}/mcp/${encodeURIComponent(serverId)}`,
		token,
		output,
		fetchImpl,
		maxBytes: gateway.config.maxBodyBytes,
		sessionId: undefined,
	};
	try {
		await consumeFrames(input, context.maxBytes, (line) => handleFrame(line, context));
	} finally {
		await gateway.close();
	}
}
