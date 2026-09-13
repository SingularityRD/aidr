import { describe, expect, it, vi } from "vitest";

import { fetchMcpEndpoint, isPrivateIpAddress, validateMcpRemoteUrl } from "../mcp-transport.js";

const post = {
	method: "POST",
	headers: { "content-type": "application/json", accept: "application/json" },
	body: "{}",
};

describe("MCP network egress boundaries", () => {
	it.each([
		"192.0.2.1", // TEST-NET-1 must not become an internal customer route.
		"198.51.100.1",
		"203.0.113.1",
		"::ffff:192.0.2.1",
		"64:ff9b::192.0.2.1",
		"2002:c000:0201::1",
	])("rejects special-use destination %s in direct and embedded forms", (address) => {
		expect(isPrivateIpAddress(address)).toBe(true);
	});

	it("rejects every mixed DNS answer before the transport hook can connect", async () => {
		const pinnedFetch = vi.fn();
		await expect(
			fetchMcpEndpoint("https://mcp.example.test/messages", post, {
				lookup: async () => ["8.8.8.8", "::ffff:192.0.2.1"],
				pinnedFetch,
			}),
		).rejects.toMatchObject({ code: "private_address" });
		expect(pinnedFetch).not.toHaveBeenCalled();
	});

	it("bounds a stalled DNS resolver before opening a connection", async () => {
		const pinnedFetch = vi.fn();
		await expect(
			fetchMcpEndpoint("https://mcp.example.test/messages", post, {
				lookup: () => new Promise<readonly string[]>(() => {}),
				dnsLookupTimeoutMs: 5,
				pinnedFetch,
			}),
		).rejects.toMatchObject({ code: "dns_lookup_timeout" });
		expect(pinnedFetch).not.toHaveBeenCalled();
	});

	it("rejects normalized special-use numeric URL forms", async () => {
		for (const url of ["https://0xc0000201/", "https://0300.0.2.1/"]) {
			expect(await validateMcpRemoteUrl(url)).toEqual({
				ok: false,
				error: "private_address",
			});
		}
	});

	it("rejects a streamed SSE body at its actual decoded byte limit", async () => {
		const body = new ReadableStream<Uint8Array>({
			start(controller) {
				controller.enqueue(new Uint8Array([65, 66]));
				controller.enqueue(new Uint8Array([67, 68]));
				controller.close();
			},
		});
		const response = await fetchMcpEndpoint(
			"https://mcp.example.test/events",
			{ method: "GET", headers: { accept: "text/event-stream" } },
			{
				lookup: async () => ["8.8.8.8"],
				maxBodyBytes: 3,
				pinnedFetch: async () =>
					new Response(body, {
						status: 200,
						headers: { "content-type": "text/event-stream", "content-length": "1" },
					}),
			},
		);
		await expect(response.arrayBuffer()).rejects.toMatchObject({ code: "body_too_large" });
	});
});
