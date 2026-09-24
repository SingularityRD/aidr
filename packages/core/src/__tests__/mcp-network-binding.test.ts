import { EventEmitter } from "node:events";
import { Readable } from "node:stream";
import { gzipSync } from "node:zlib";
import { describe, expect, it, vi } from "vitest";

const { httpRequestMock, httpsRequestMock } = vi.hoisted(() => ({
	httpRequestMock: vi.fn(),
	httpsRequestMock: vi.fn(),
}));
vi.mock("node:http", () => ({ request: httpRequestMock }));
vi.mock("node:https", () => ({ request: httpsRequestMock }));

import { fetchMcpEndpoint } from "../mcp-transport.js";

function mockResponse(rawHeaders: string[], chunks: Buffer[]): void {
	httpRequestMock.mockImplementationOnce(
		(_url: unknown, _options: unknown, onResponse: (incoming: unknown) => void) => {
			const nodeRequest = new EventEmitter() as EventEmitter & {
				end: () => void;
				destroy: (error: Error) => void;
			};
			nodeRequest.end = () => {
				queueMicrotask(() => {
					nodeRequest.emit("socket", { connecting: false, remoteAddress: "8.8.8.8" });
					const incoming = Object.assign(Readable.from(chunks), {
						rawHeaders,
						statusCode: 200,
						statusMessage: "OK",
					});
					onResponse(incoming);
				});
			};
			nodeRequest.destroy = (error) => nodeRequest.emit("error", error);
			return nodeRequest;
		},
	);
}

describe("MCP pinned HTTP connection", () => {
	it("requires upstream TLS certificate verification even when the process default is unsafe", async () => {
		const nodeRequest = new EventEmitter() as EventEmitter & { end: () => void };
		nodeRequest.end = () => queueMicrotask(() => nodeRequest.emit("error", new Error("mock transport")));
		httpsRequestMock.mockReturnValueOnce(nodeRequest);
		await expect(
			fetchMcpEndpoint(
				"https://mcp.example.test/messages",
				{
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json" },
					body: "{}",
				},
				{ lookup: async () => ["8.8.8.8"] },
			),
		).rejects.toThrow("mock transport");
		const options = httpsRequestMock.mock.calls.at(-1)?.[1] as { rejectUnauthorized?: boolean };
		expect(options.rejectUnauthorized).toBe(true);
	});

	it("uses the approved address for Node lookup and rejects a different connected peer", async () => {
		const nodeRequest = new EventEmitter() as EventEmitter & {
			end: () => void;
			destroy: (error: Error) => void;
		};
		nodeRequest.end = () => {
			queueMicrotask(() => {
				nodeRequest.emit("socket", { connecting: false, remoteAddress: "10.0.0.7" });
			});
		};
		nodeRequest.destroy = (error) => {
			nodeRequest.emit("error", error);
		};
		httpRequestMock.mockReturnValue(nodeRequest);

		await expect(
			fetchMcpEndpoint(
				"http://mcp.example.test/messages",
				{
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json" },
					body: "{}",
				},
				{ requireHttps: false, lookup: async () => ["8.8.8.8"] },
			),
		).rejects.toMatchObject({ code: "dns_rebinding_detected" });
		const requestOptions = httpRequestMock.mock.calls[0]?.[1] as {
			agent: boolean;
			lookup: (
				host: string,
				options: { all: boolean },
				callback: (...args: unknown[]) => void,
			) => void;
		};
		expect(requestOptions.agent).toBe(false);
		const lookupCallback = vi.fn();
		requestOptions.lookup("mcp.example.test", { all: true }, lookupCallback);
		expect(lookupCallback).toHaveBeenCalledWith(null, [{ address: "8.8.8.8", family: 4 }]);
	});

	it("destroys a pinned request when the upstream never sends response headers", async () => {
		const nodeRequest = new EventEmitter() as EventEmitter & {
			end: () => void;
			destroy: (error: Error) => void;
		};
		nodeRequest.end = () => {};
		nodeRequest.destroy = (error) => nodeRequest.emit("error", error);
		httpRequestMock.mockReturnValue(nodeRequest);

		await expect(
			fetchMcpEndpoint(
				"http://mcp.example.test/messages",
				{
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json" },
					body: "{}",
				},
				{
					requireHttps: false,
					lookup: async () => ["8.8.8.8"],
					responseHeadersTimeoutMs: 5,
				},
			),
		).rejects.toMatchObject({ code: "response_headers_timeout" });
	});

	it.each([
		["chunked gzip without Content-Length", ["transfer-encoding", "chunked"]],
		[
			"chunked gzip with a misleadingly small Content-Length",
			["transfer-encoding", "chunked", "content-length", "1"],
		],
	])("caps compressed wire bytes for %s", async (_label, lengthHeader) => {
		const decoded = Buffer.from('{"jsonrpc":"2.0","id":1,"result":{}}');
		const emptyMember = gzipSync(Buffer.alloc(0));
		const encoded = Buffer.concat([gzipSync(decoded), emptyMember, emptyMember, emptyMember]);
		expect(decoded.byteLength).toBeLessThanOrEqual(64);
		expect(encoded.byteLength).toBeGreaterThan(64);
		mockResponse(
			["content-type", "application/json", "content-encoding", "gzip", ...lengthHeader],
			[encoded.subarray(0, 12), encoded.subarray(12, 57), encoded.subarray(57)],
		);

		await expect(
			fetchMcpEndpoint(
				"http://mcp.example.test/messages",
				{
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json" },
					body: "{}",
				},
				{
					requireHttps: false,
					lookup: async () => ["8.8.8.8"],
					maxBodyBytes: 64,
				},
			),
		).rejects.toMatchObject({ code: "body_too_large" });
	});

	it("keeps the decoded-byte cap after accepting bounded gzip input", async () => {
		const decoded = Buffer.from(
			JSON.stringify({ jsonrpc: "2.0", id: 1, result: { x: "a".repeat(100) } }),
		);
		const encoded = gzipSync(decoded);
		expect(encoded.byteLength).toBeLessThanOrEqual(80);
		expect(decoded.byteLength).toBeGreaterThan(80);
		mockResponse(
			[
				"content-type",
				"application/json",
				"content-encoding",
				"gzip",
				"content-length",
				String(encoded.byteLength),
			],
			[encoded],
		);

		await expect(
			fetchMcpEndpoint(
				"http://mcp.example.test/messages",
				{
					method: "POST",
					headers: { "content-type": "application/json", accept: "application/json" },
					body: "{}",
				},
				{
					requireHttps: false,
					lookup: async () => ["8.8.8.8"],
					maxBodyBytes: 80,
				},
			),
		).rejects.toMatchObject({ code: "body_too_large" });
	});
});
