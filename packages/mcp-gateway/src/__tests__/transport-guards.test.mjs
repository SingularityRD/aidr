import "./helpers/isolated-home.mjs";
import assert from "node:assert/strict";
import { request as httpRequest } from "node:http";
import { describe, it } from "node:test";
import { gzipSync } from "node:zlib";
import { fixture } from "./helpers/gateway-fixture.mjs";

/** A raw HTTP request, so the Host and encoding headers are exactly what the test sets. */
function raw(base, { method = "POST", path = "/mcp/server-a", headers = {}, body } = {}) {
	const url = new URL(base);
	return new Promise((resolve, reject) => {
		const outgoing = httpRequest(
			{ hostname: url.hostname, port: url.port, method, path, headers, setHost: false },
			(response) => {
				const chunks = [];
				response.on("data", (chunk) => chunks.push(chunk));
				response.on("end", () =>
					resolve({
						status: response.statusCode,
						body: chunks.length ? JSON.parse(Buffer.concat(chunks)) : null,
					}),
				);
			},
		);
		outgoing.on("error", reject);
		outgoing.end(body);
	});
}

const ping = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "ping" });

describe("MCP gateway transport guards", () => {
	it("rejects a foreign Host header (DNS rebinding), including on /healthz", async () => {
		const f = fixture();
		const base = await f.start();
		const port = new URL(base).port;
		const headers = { authorization: `Bearer ${f.tokenA}`, "content-type": "application/json" };
		for (const host of [
			"attacker.example:" + port,
			"attacker.example",
			`127.0.0.1:${Number(port) + 1}`,
		]) {
			const posted = await raw(base, { headers: { ...headers, host }, body: ping });
			assert.equal(posted.status, 421);
			assert.deepEqual(posted.body, { error: "host_forbidden" });
			const health = await raw(base, { method: "GET", path: "/healthz", headers: { host } });
			assert.equal(health.status, 421);
		}
		// Node's HTTP/1.1 parser already answers a request without Host with 400.
		const missing = await raw(base, { headers, body: ping });
		assert.ok([400, 421].includes(missing.status));
		assert.equal(f.upstreamCalls, 0);

		for (const host of [`127.0.0.1:${port}`, `localhost:${port}`, `LOCALHOST:${port}`]) {
			const health = await raw(base, { method: "GET", path: "/healthz", headers: { host } });
			assert.equal(health.status, 200);
		}
	});

	it("accepts operator-listed allowedHosts and validates them", async () => {
		const f = fixture({ gatewayConfig: { allowedHosts: ["Gateway.Internal.Example:8443"] } });
		const base = await f.start();
		const health = await raw(base, {
			method: "GET",
			path: "/healthz",
			headers: { host: "gateway.internal.example:8443" },
		});
		assert.equal(health.status, 200);
		for (const allowedHosts of [
			["no-port.example"],
			["bad host:1"],
			"x",
			Array(65).fill("a.example:1"),
		])
			assert.throws(() => fixture({ gatewayConfig: { allowedHosts } }), {
				code: "invalid_allowedhosts",
			});
	});

	it("names unsupported content encodings and non-UTF-8 bodies precisely", async () => {
		const f = fixture();
		const base = await f.start();
		const host = new URL(base).host;
		const headers = {
			host,
			authorization: `Bearer ${f.tokenA}`,
			"content-type": "application/json",
		};
		const cases = [
			[
				{ ...headers, "content-encoding": "gzip" },
				gzipSync(ping),
				415,
				"unsupported_content_encoding",
			],
			[
				{ ...headers, "content-type": "application/json; charset=utf-16" },
				Buffer.from(ping, "utf16le"),
				415,
				"unsupported_charset",
			],
			[headers, Buffer.from(ping, "utf16le"), 400, "invalid_request_encoding"],
			[
				headers,
				Buffer.concat([Buffer.from(ping.slice(0, -1)), Buffer.from([0xff, 0x7d])]),
				400,
				"invalid_request_encoding",
			],
			[headers, Buffer.from("{"), 400, "invalid_rpc_request"],
		];
		for (const [requestHeaders, body, status, reason] of cases) {
			const result = await raw(base, { headers: requestHeaders, body });
			assert.equal(result.status, status, reason);
			assert.equal(result.body.error.message, `AIDR blocked MCP request: ${reason}`);
		}
		const identity = await raw(base, {
			headers: {
				...headers,
				"content-type": "application/json; charset=UTF-8",
				"content-encoding": "identity",
			},
			body: ping,
		});
		assert.doesNotMatch(JSON.stringify(identity.body), /encoding|charset/);
		assert.equal(
			f.events.some((event) => event.reason === "gateway_unavailable"),
			false,
		);
	});
});
