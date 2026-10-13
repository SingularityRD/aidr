import { createHash, generateKeyPairSync } from "node:crypto";
import { afterEach } from "node:test";
import {
	MemoryMcpAttestationStore,
	mcpToolsetHash,
	signMcpToolManifest,
} from "@singularityrd/aidr-core";
import { createMcpGateway } from "../../gateway.mjs";
import { TEST_APPROVAL_KEY, TEST_APPROVAL_KEYS, testStateDir } from "./approval-key.mjs";

const running = [];
afterEach(async () => {
	await Promise.all(running.splice(0).map((gateway) => gateway.close()));
});

/** What the fake upstream MCP server answers to one JSON-RPC request. */
function fakeRpcResult(rpc, tools, overrides) {
	if (rpc.method === "tools/list") {
		return {
			tools: tools.map((tool) => ({
				name: tool.name,
				description: tool.description,
				inputSchema: tool.input_schema,
				...(tool.output_schema !== undefined ? { outputSchema: tool.output_schema } : {}),
			})),
		};
	}
	if (rpc.method === "initialize") {
		return Object.hasOwn(overrides, "initializeResult")
			? overrides.initializeResult
			: {
					protocolVersion: "2025-03-26",
					capabilities: {},
					serverInfo: { name: "test", version: "1" },
				};
	}
	return (
		overrides.toolResult ?? {
			content: [{ type: "text", text: overrides.output ?? "Normal result" }],
		}
	);
}

/** The fake upstream's HTTP response (JSON or SSE), with a session id on initialize if asked. */
function fakeUpstreamResponse(rpc, result, overrides, nextSessionId) {
	const responseBody = JSON.stringify({ jsonrpc: "2.0", id: rpc.id, result });
	const sse = overrides.transport === "sse";
	const hasSessionHeader =
		(overrides.sessionMode === "required" || overrides.unexpectedSession) &&
		rpc.method === "initialize";
	return new Response(sse ? `event: message\ndata: ${responseBody}\n\n` : responseBody, {
		status: 200,
		headers: {
			"content-type": sse ? "text/event-stream" : "application/json",
			...(hasSessionHeader ? { "mcp-session-id": nextSessionId() } : {}),
		},
	});
}

export function fixture(overrides = {}) {
	const { privateKey, publicKey } = overrides.keyPair ?? generateKeyPairSync("ed25519");
	const tools = overrides.tools ?? [
		{ name: "search", description: "Search trusted corpus", input_schema: { type: "object" } },
	];
	const manifest = {
		schema_version: 1,
		server_id: "server-a",
		sequence: overrides.sequence ?? 1,
		issued_at: new Date(Date.now() - 60_000).toISOString(),
		expires_at: new Date(Date.now() + 60 * 60_000).toISOString(),
		tools,
	};
	const signedManifest =
		overrides.signedManifest ?? signMcpToolManifest({ manifest, keyId: "publisher", privateKey });
	if (overrides.invalidSignature) signedManifest.signature_b64 = "A".repeat(88);
	const tokenA = "a".repeat(48);
	const tokenB = "b".repeat(48);
	const clients = [
		{
			id: "client-a",
			tenantId: "tenant-a",
			tokenSha256: createHash("sha256").update(tokenA).digest("hex"),
			allowedTools: { "server-a": overrides.allowedTools ?? ["search"] },
		},
		{
			id: "client-b",
			tenantId: "tenant-b",
			tokenSha256: createHash("sha256").update(tokenB).digest("hex"),
			allowedTools: { "server-a": overrides.allowedTools ?? ["search"] },
		},
	];
	const servers = ["tenant-a", "tenant-b"].map((tenantId) => {
		const tenantOverrides = tenantId === "tenant-b" ? (overrides.tenantB ?? {}) : {};
		return {
			tenantId,
			id: "server-a",
			url: overrides.url ?? "https://mcp.example.test/mcp",
			transport: overrides.transport ?? "json",
			sessionMode: overrides.sessionMode ?? "stateless",
			...(overrides.upstreamAuthEnv ? { upstreamAuthEnv: overrides.upstreamAuthEnv } : {}),
			...(overrides.revokedKeyIds ? { revokedKeyIds: overrides.revokedKeyIds } : {}),
			...(overrides.dlpPolicy && tenantId === "tenant-a" ? { dlpPolicy: overrides.dlpPolicy } : {}),
			signedManifest: tenantOverrides.signedManifest ?? signedManifest,
			trustedSigners: tenantOverrides.trustedSigners ??
				overrides.trustedSigners ?? {
					publisher: publicKey.export({ type: "spki", format: "pem" }),
				},
		};
	});
	const stores = overrides.stores ?? new Map();
	const events = [];
	const terminatedSessions = [];
	let upstreamCalls = 0;
	let toolCalls = 0;
	let upstreamSessions = 0;
	const dependencies = {
		lookup: async () => overrides.addresses ?? ["8.8.8.8"],
		storeFactory: (tenantId) => {
			if (!stores.has(tenantId)) stores.set(tenantId, new MemoryMcpAttestationStore());
			return stores.get(tenantId);
		},
		scanner: overrides.scanner,
		onEvent: overrides.onEvent ?? ((event) => events.push(event)),
		directUpstreamCheck: overrides.directUpstreamCheck,
		...(overrides.evaluateToolCall ? { evaluateToolCall: overrides.evaluateToolCall } : {}),
		pinnedFetch: async (request) => {
			upstreamCalls += 1;
			if (overrides.pinnedFetch) return overrides.pinnedFetch(request);
			if (request.init.method === "DELETE") {
				terminatedSessions.push(new Headers(request.init.headers).get("mcp-session-id"));
				return new Response(null, { status: 204 });
			}
			const rpc = JSON.parse(request.init.body);
			await overrides.beforeUpstream?.(request, rpc);
			if (rpc.method === "notifications/initialized") return new Response(null, { status: 202 });
			if (rpc.method === "tools/call") toolCalls += 1;
			const nextSessionId = () =>
				overrides.uniqueSessions
					? `session-${String(++upstreamSessions).padStart(8, "0")}`
					: "session-12345678";
			return fakeUpstreamResponse(
				rpc,
				fakeRpcResult(rpc, tools, overrides),
				overrides,
				nextSessionId,
			);
		},
	};
	const gateway = createMcpGateway(
		{
			stateDir: testStateDir(),
			approvalKeys: TEST_APPROVAL_KEYS,
			port: 0,
			clients,
			servers,
			maxBodyBytes: overrides.maxBodyBytes ?? 4096,
			...(overrides.gatewayConfig ?? {}),
		},
		dependencies,
	);
	return {
		gateway,
		tools,
		tokenA,
		tokenB,
		clients,
		servers,
		signedManifest,
		get upstreamCalls() {
			return upstreamCalls;
		},
		get toolCalls() {
			return toolCalls;
		},
		get events() {
			return events;
		},
		get terminatedSessions() {
			return terminatedSessions;
		},
		async start() {
			const address = await gateway.listen(0);
			running.push(gateway);
			return `http://127.0.0.1:${address.port}`;
		},
		async approve(tenantId = "tenant-a", bindingSha256) {
			const reviewed =
				bindingSha256 ??
				(await gateway.storeFor(tenantId).read("server-a"))?.quarantine?.bindingSha256;
			if (!reviewed) throw new Error("missing reviewed MCP binding");
			return gateway.approve({
				tenantId,
				serverId: "server-a",
				toolsetHash: mcpToolsetHash(tools),
				bindingSha256: reviewed,
				approvedBy: "security-operator",
				reason: "approved manifest test",
				approvalKey: TEST_APPROVAL_KEY,
			});
		},
	};
}

export async function rpc(
	base,
	token,
	method = "tools/call",
	id = 1,
	params = { name: "search", arguments: { query: "ok" } },
	headers = {},
) {
	const response = await fetch(`${base}/mcp/server-a`, {
		method: "POST",
		headers: { authorization: `Bearer ${token}`, "content-type": "application/json", ...headers },
		body: JSON.stringify({ jsonrpc: "2.0", id, method, params }),
	});
	return { status: response.status, headers: response.headers, body: await response.json() };
}
