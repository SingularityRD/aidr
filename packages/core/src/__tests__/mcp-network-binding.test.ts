import { EventEmitter } from "node:events";
import { describe, expect, it, vi } from "vitest";

const { httpRequestMock } = vi.hoisted(() => ({ httpRequestMock: vi.fn() }));
vi.mock("node:http", () => ({ request: httpRequestMock }));

import { fetchMcpEndpoint } from "../mcp-transport.js";

describe("MCP pinned HTTP connection", () => {
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
});
