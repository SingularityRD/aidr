import { afterEach, describe, expect, it, vi } from "vitest";
import {
	encodeMcpStdioFrame,
	fetchMcpEndpoint,
	hashMcpSchema,
	interceptMcpToolCall,
	isPrivateIpAddress,
	JsonRpcStdioFramer,
	McpSchemaRegistry,
	validateMcpHttpRequest,
	validateMcpHttpResponse,
	validateMcpRemoteUrl,
} from "../mcp-transport.js";

describe("MCP transport framing", () => {
	it("parses bounded newline and Content-Length frames incrementally", () => {
		const framer = new JsonRpcStdioFramer({ maxFrameBytes: 256 });
		const newline = encodeMcpStdioFrame({ jsonrpc: "2.0", id: 1, method: "tools/list" });
		const contentLength = encodeMcpStdioFrame(
			{ jsonrpc: "2.0", id: 2, result: { ok: true } },
			true,
		);
		const combined = new Uint8Array(newline.length + contentLength.length);
		combined.set(newline);
		combined.set(contentLength, newline.length);

		expect(framer.push(combined.slice(0, 7))).toEqual([]);
		expect(framer.push(combined.slice(7))).toEqual([
			{ jsonrpc: "2.0", id: 1, method: "tools/list" },
			{ jsonrpc: "2.0", id: 2, result: { ok: true } },
		]);
	});

	it("rejects oversized and malformed frames", () => {
		const framer = new JsonRpcStdioFramer({ maxFrameBytes: 32, maxBufferedBytes: 64 });
		expect(() => framer.push(`${"x".repeat(40)}\n`)).toThrow(/exceeds/);
		expect(() => framer.push('{"jsonrpc":"1.0"}\n')).toThrow(/version 2.0/);
	});

	it.each([
		'{"jsonrpc":"2.0","id":1,"method":"tools/call","result":{}}\n',
		'{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":-1,"message":"failed"}}\n',
		'{"jsonrpc":"2.0","result":{}}\n',
		'{"jsonrpc":"2.0","id":1.5,"result":{}}\n',
	])("rejects contradictory or incomplete JSON-RPC frames", (frame) => {
		expect(() => new JsonRpcStdioFramer().push(frame)).toThrowError(
			expect.objectContaining({
				code: "invalid_json_rpc",
			}),
		);
	});

	it("rejects duplicate Content-Length headers before reading a body", () => {
		const frame =
			'Content-Length: 42\r\ncontent-length: 5\r\n\r\n{"jsonrpc":"2.0","id":1,"result":{}}';
		expect(() => new JsonRpcStdioFramer().push(frame)).toThrowError(
			expect.objectContaining({
				code: "invalid_content_length",
			}),
		);
	});
});

describe("MCP HTTP and SSRF controls", () => {
	it("requires JSON POST or SSE GET with bounded bodies", () => {
		expect(
			validateMcpHttpRequest({
				method: "POST",
				url: "https://mcp.example.test/message",
				headers: { "content-type": "application/json", accept: "application/json" },
				body: "{}",
			}),
		).toEqual({ ok: true });
		expect(
			validateMcpHttpRequest({
				method: "GET",
				url: "https://mcp.example.test/events",
				headers: { accept: "text/event-stream" },
			}),
		).toEqual({ ok: true });
		expect(
			validateMcpHttpRequest({
				method: "POST",
				url: "https://mcp.example.test/message",
				headers: { "content-type": "text/plain" },
				body: "{}",
			}),
		).toEqual({ ok: false, error: "invalid_content_type" });
	});

	it("blocks private IPs and DNS rebinding, including mapped IPv4", async () => {
		expect(isPrivateIpAddress("127.0.0.1")).toBe(true);
		expect(isPrivateIpAddress("::ffff:10.0.0.1")).toBe(true);
		expect(isPrivateIpAddress("::ffff:a00:1")).toBe(true);
		expect(isPrivateIpAddress("64:ff9b::10.0.0.1")).toBe(true);
		expect(isPrivateIpAddress("2002:0a00:0001::1")).toBe(true);
		expect(isPrivateIpAddress("2001:db8::1")).toBe(true);
		expect(isPrivateIpAddress("2606:4700:4700::1111")).toBe(false);
		expect(isPrivateIpAddress("::ffff:8.8.8.8")).toBe(false);
		expect(
			await validateMcpRemoteUrl("https://127.0.0.1", { lookup: async () => ["127.0.0.1"] }),
		).toEqual({
			ok: false,
			error: "private_address",
		});
		expect(
			await validateMcpRemoteUrl("https://attacker.example", {
				lookup: async () => ["93.184.216.34", "::ffff:a00:1"],
			}),
		).toEqual({ ok: false, error: "private_address" });
		expect(
			await validateMcpRemoteUrl("https://attacker.example", {
				lookup: async () => ["not-an-ip-address"],
			}),
		).toEqual({ ok: false, error: "dns_lookup_failed" });
		expect(
			await validateMcpRemoteUrl("https://attacker.example", { lookup: async () => ["10.0.0.2"] }),
		).toEqual({
			ok: false,
			error: "private_address",
		});
	});

	it("rejects redirects and unexpected upstream media types", () => {
		expect(
			validateMcpHttpResponse(
				new Response("", { status: 200, headers: { "content-type": "text/plain" } }),
				"json",
			),
		).toEqual({
			ok: false,
			error: "invalid_upstream_content_type",
		});
		expect(
			validateMcpHttpResponse(
				new Response("", { status: 200, headers: { "content-type": "text/event-stream" } }),
				"sse",
			),
		).toEqual({ ok: true });
	});

	it("pins the request to the complete validated DNS answer set", async () => {
		const pinnedFetch = vi.fn().mockResolvedValue(
			new Response('{"jsonrpc":"2.0","id":1,"result":{}}', {
				status: 200,
				headers: { "content-type": "application/json" },
			}),
		);
		await fetchMcpEndpoint(
			"https://mcp.example.test/message",
			{
				method: "POST",
				headers: { "content-type": "application/json", accept: "application/json" },
				body: "{}",
			},
			{
				lookup: async () => ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
				pinnedFetch,
			},
		);
		expect(pinnedFetch).toHaveBeenCalledWith(
			expect.objectContaining({
				url: new URL("https://mcp.example.test/message"),
				addresses: ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"],
				init: expect.objectContaining({ redirect: "error" }),
			}),
		);
	});

	it.each([
		["{", "invalid_json"],
		["{}", "invalid_json_rpc"],
		['{"jsonrpc":"2.0","id":1,"result":{},"error":{}}', "invalid_json_rpc"],
	])("rejects malformed upstream JSON-RPC before returning it to the caller", async (body, code) => {
		await expect(
			fetchMcpEndpoint(
				"https://mcp.example.test/message",
				{
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json" },
					body: '{"jsonrpc":"2.0","id":1,"method":"tools/list"}',
				},
				{
					lookup: async () => ["93.184.216.34"],
					pinnedFetch: async () =>
						new Response(body, { status: 200, headers: { "content-type": "application/json" } }),
				},
			),
		).rejects.toMatchObject({ code });
	});

	it("accepts only an explicitly opted-in empty 202 notification acknowledgement", async () => {
		const request = {
			method: "POST",
			headers: {
				"content-type": "application/json",
				accept: "application/json, text/event-stream",
			},
			body: '{"jsonrpc":"2.0","method":"notifications/initialized"}',
		};
		const options = {
			lookup: async () => ["93.184.216.34"],
			pinnedFetch: async () => new Response(null, { status: 202 }),
		};
		await expect(
			fetchMcpEndpoint("https://mcp.example.test/mcp", request, options),
		).rejects.toMatchObject({
			code: "invalid_upstream_content_type",
		});
		const accepted = await fetchMcpEndpoint("https://mcp.example.test/mcp", request, {
			...options,
			acceptNotificationResponse: true,
		});
		expect(accepted.status).toBe(202);
		expect(await accepted.text()).toBe("");
		await expect(
			fetchMcpEndpoint("https://mcp.example.test/mcp", request, {
				...options,
				acceptNotificationResponse: true,
				pinnedFetch: async () => new Response("hidden data", { status: 202 }),
			}),
		).rejects.toMatchObject({ code: "notification_response_body" });
		await expect(
			fetchMcpEndpoint(
				"https://mcp.example.test/mcp",
				{
					...request,
					body: '{"jsonrpc":"2.0","id":1,"method":"tools/call"}',
				},
				{ ...options, acceptNotificationResponse: true },
			),
		).rejects.toMatchObject({ code: "invalid_notification_request" });
		await expect(
			fetchMcpEndpoint(
				"https://mcp.example.test/mcp",
				{
					...request,
					body: '{"jsonrpc":"2.0","method":"notifications/initialized","result":{}}',
				},
				{ ...options, acceptNotificationResponse: true },
			),
		).rejects.toMatchObject({ code: "invalid_notification_request" });
	});

	it.each([
		["without Content-Length", {}],
		["with a deceptive Content-Length", { "content-length": "4" }],
		["after transport decompression", { "content-encoding": "gzip" }],
	])("rejects oversized JSON response bytes %s", async (_name, extraHeaders) => {
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("123"));
				controller.enqueue(new TextEncoder().encode("456"));
				controller.close();
			},
		});
		await expect(
			fetchMcpEndpoint(
				"https://mcp.example.test/message",
				{
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json" },
					body: "{}",
				},
				{
					lookup: async () => ["93.184.216.34"],
					maxBodyBytes: 5,
					pinnedFetch: async () =>
						new Response(body, {
							status: 200,
							headers: { "content-type": "application/json", ...extraHeaders },
						}),
				},
			),
		).rejects.toMatchObject({ code: "body_too_large" });
	});

	it("limits a chunked SSE stream while it is consumed", async () => {
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new TextEncoder().encode("abc"));
				controller.enqueue(new TextEncoder().encode("def"));
				controller.close();
			},
		});
		const response = await fetchMcpEndpoint(
			"https://mcp.example.test/events",
			{ method: "GET", headers: { accept: "text/event-stream" } },
			{
				lookup: async () => ["93.184.216.34"],
				maxBodyBytes: 5,
				pinnedFetch: async () =>
					new Response(body, {
						status: 200,
						headers: { "content-type": "text/event-stream" },
					}),
			},
		);
		await expect(response.text()).rejects.toMatchObject({ code: "body_too_large" });
	});
});

describe("MCP policy interception", () => {
	afterEach(() => vi.restoreAllMocks());

	it("invokes the central policy client and emits only hashes/metadata", async () => {
		const evaluateToolCall = vi.fn().mockResolvedValue({ decision: "allow" });
		const events: unknown[] = [];
		const prompt = "Authorization: Bearer secret-prompt-value";
		const result = await interceptMcpToolCall(
			{
				serverName: "github",
				toolName: "search",
				arguments: { query: prompt, token: "secret-token" },
				schema: { type: "object", properties: { query: { type: "string" } } },
			},
			{ evaluateToolCall },
			{
				eventSink: async (event) => events.push(event),
				now: () => new Date("2026-08-08T00:00:00.000Z"),
			},
		);
		expect(result.allowed).toBe(true);
		expect(evaluateToolCall).toHaveBeenCalledOnce();
		expect(JSON.stringify(events)).not.toContain(prompt);
		expect(JSON.stringify(events)).not.toContain("secret-token");
		expect(result.event).toMatchObject({ decision: "allow", reason: "policy_allowed" });
	});

	it.each([
		["timeout", () => new Promise<unknown>(() => {})],
		["outage", () => Promise.reject(new Error("network down"))],
		["malformed", () => Promise.resolve({ verdict: "allow" })],
	])("denies on policy %s", async (reason, evaluateToolCall) => {
		const result = await interceptMcpToolCall(
			{ serverName: "server", toolName: "tool", arguments: { value: 1 } },
			{ evaluateToolCall },
			{ policyTimeoutMs: 5 },
		);
		expect(result).toMatchObject({ allowed: false, decision: "deny" });
		expect(result.reason).toBe(
			reason === "timeout"
				? "policy_timeout"
				: reason === "outage"
					? "policy_unavailable"
					: "malformed_policy_response",
		);
	});

	it("detects schema drift and hashes schemas canonically", async () => {
		const registry = new McpSchemaRegistry();
		const client = { evaluateToolCall: vi.fn().mockResolvedValue({ decision: "allow" }) };
		const first = await interceptMcpToolCall(
			{ serverName: "s", toolName: "t", schema: { b: 2, a: 1 } },
			client,
			{ schemaRegistry: registry },
		);
		const reordered = await interceptMcpToolCall(
			{ serverName: "s", toolName: "t", schema: { a: 1, b: 2 } },
			client,
			{ schemaRegistry: registry },
		);
		const drifted = await interceptMcpToolCall(
			{ serverName: "s", toolName: "t", schema: { a: 1, b: 3 } },
			client,
			{ schemaRegistry: registry },
		);
		expect(first.allowed).toBe(true);
		expect(reordered.allowed).toBe(true);
		expect(drifted).toMatchObject({ allowed: false, reason: "schema_drift" });
		expect(hashMcpSchema({ a: 1, b: 2 })).toBe(hashMcpSchema({ b: 2, a: 1 }));
	});

	it("keeps rejecting a changed schema on retries without calling the policy service", async () => {
		const registry = new McpSchemaRegistry();
		const client = { evaluateToolCall: vi.fn().mockResolvedValue({ decision: "allow" }) };
		const options = { schemaRegistry: registry };
		const baseline = { serverName: "s", toolName: "t", schema: { description: "Read only" } };
		expect((await interceptMcpToolCall(baseline, client, options)).allowed).toBe(true);
		for (const description of ["Delete files", "Delete files", "Delete files and credentials"]) {
			const result = await interceptMcpToolCall(
				{ ...baseline, schema: { description } },
				client,
				options,
			);
			expect(result).toMatchObject({ allowed: false, reason: "schema_drift" });
		}
		expect(client.evaluateToolCall).toHaveBeenCalledTimes(1);
		expect((await interceptMcpToolCall(baseline, client, options)).allowed).toBe(true);
		expect(client.evaluateToolCall).toHaveBeenCalledTimes(2);
	});

	it("rejects omission of a previously observed schema", async () => {
		const registry = new McpSchemaRegistry();
		const client = { evaluateToolCall: vi.fn().mockResolvedValue({ decision: "allow" }) };
		registry.observe("s", "t", { type: "object" });
		const result = await interceptMcpToolCall(
			{ serverName: "s", toolName: "t", arguments: {} },
			client,
			{ schemaRegistry: registry },
		);
		expect(result).toMatchObject({ allowed: false, reason: "schema_missing" });
		expect(client.evaluateToolCall).not.toHaveBeenCalled();
	});

	it("does not conflate server and tool identities containing delimiters", () => {
		const registry = new McpSchemaRegistry();
		registry.observe("server\u0000tool", "name", { type: "string" });
		expect(registry.observe("server", "tool\u0000name", { type: "number" }).drift).toBe(false);
		expect(registry.observe("server\u0000tool", "name", { type: "number" }).drift).toBe(true);
	});
});
