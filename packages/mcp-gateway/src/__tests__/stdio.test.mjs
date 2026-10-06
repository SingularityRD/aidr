import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Readable, Writable } from "node:stream";
import { describe, it } from "node:test";
import { runStdioBridge, validateStdioBinding } from "../stdio.mjs";

const token = "s".repeat(48);
function fixture(maxBodyBytes = 4096) {
	let closed = false;
	const gateway = {
		config: {
			maxBodyBytes,
			clients: [
				{
					id: "client-a",
					tenantId: "tenant-a",
					tokenSha256: createHash("sha256").update(token).digest("hex"),
					allowedTools: { "server-a": ["search"] },
				},
			],
			servers: [{ id: "server-a", tenantId: "tenant-a" }],
		},
		async listen() {
			return { port: 7789 };
		},
		async close() {
			closed = true;
		},
	};
	return {
		gateway,
		get closed() {
			return closed;
		},
	};
}

function outputSink() {
	let output = "";
	return {
		stream: new Writable({
			write(chunk, _encoding, callback) {
				output += chunk.toString();
				callback();
			},
		}),
		get lines() {
			return output.trim().split("\n").filter(Boolean).map(JSON.parse);
		},
	};
}

describe("MCP stdio bridge", () => {
	it("binds the environment token to the exact tenant, client and allowed server", () => {
		const f = fixture();
		const options = {
			tenantId: "tenant-a",
			clientId: "client-a",
			serverId: "server-a",
			tokenEnv: "AIDR_TOKEN",
		};
		assert.equal(validateStdioBinding(f.gateway.config, options, { AIDR_TOKEN: token }), token);
		assert.throws(() =>
			validateStdioBinding(
				f.gateway.config,
				{ ...options, tenantId: "tenant-b" },
				{ AIDR_TOKEN: token },
			),
		);
		assert.throws(() => validateStdioBinding(f.gateway.config, options, { AIDR_TOKEN: "wrong" }));
		assert.throws(() =>
			validateStdioBinding(
				f.gateway.config,
				{ ...options, tokenEnv: "bad-env" },
				{ AIDR_TOKEN: token },
			),
		);
	});

	it("frames split input, keeps session binding and emits no response to initialized notification", async () => {
		const f = fixture();
		const output = outputSink();
		const requests = [];
		const messages = [
			{
				jsonrpc: "2.0",
				id: 1,
				method: "initialize",
				params: {
					protocolVersion: "2025-06-18",
					capabilities: {},
					clientInfo: { name: "test", version: "1" },
				},
			},
			{ jsonrpc: "2.0", method: "notifications/initialized" },
			{ jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "search", arguments: {} } },
		];
		const payload = messages.map((message) => JSON.stringify(message)).join("\n") + "\n";
		await runStdioBridge({
			gateway: f.gateway,
			tenantId: "tenant-a",
			clientId: "client-a",
			serverId: "server-a",
			tokenEnv: "AIDR_TOKEN",
			environment: { AIDR_TOKEN: token },
			input: Readable.from([payload.slice(0, 13), payload.slice(13)]),
			output: output.stream,
			fetchImpl: async (_url, init) => {
				requests.push(init);
				const rpc = JSON.parse(init.body);
				if (rpc.method === "notifications/initialized") return new Response(null, { status: 202 });
				return new Response(
					JSON.stringify({
						jsonrpc: "2.0",
						id: rpc.id,
						result:
							rpc.method === "initialize"
								? { protocolVersion: "2025-06-18", capabilities: {} }
								: { content: [{ type: "text", text: "clean" }] },
					}),
					{
						status: 200,
						headers: rpc.method === "initialize" ? { "mcp-session-id": "session-12345678" } : {},
					},
				);
			},
		});
		assert.equal(f.closed, true);
		assert.equal(output.lines.length, 2);
		assert.equal(output.lines[1].result.content[0].text, "clean");
		assert.equal(requests[0].headers["mcp-session-id"], undefined);
		assert.equal(requests[1].headers["mcp-session-id"], "session-12345678");
		assert.equal(requests[2].headers["mcp-session-id"], "session-12345678");
		assert.equal(requests[0].headers.authorization, `Bearer ${token}`);
		assert.equal(requests[0].headers["mcp-protocol-version"], undefined);
		assert.equal(requests[1].headers["mcp-protocol-version"], "2025-06-18");
		assert.equal(requests[2].headers["mcp-protocol-version"], "2025-06-18");
	});

	it("fails closed on oversized input or rejected notification", async () => {
		for (const { payload, fetchImpl } of [
			{
				payload: `${"x".repeat(1100)}\n`,
				fetchImpl: async () => {
					throw new Error("must not call");
				},
			},
			{
				payload: '{"jsonrpc":"2.0","method":"notifications/initialized"}\n',
				fetchImpl: async () => new Response(null, { status: 400 }),
			},
		]) {
			const f = fixture(1024);
			const output = outputSink();
			await assert.rejects(
				runStdioBridge({
					gateway: f.gateway,
					tenantId: "tenant-a",
					clientId: "client-a",
					serverId: "server-a",
					tokenEnv: "AIDR_TOKEN",
					environment: { AIDR_TOKEN: token },
					input: Readable.from([payload]),
					output: output.stream,
					fetchImpl,
				}),
			);
			assert.equal(f.closed, true);
			assert.deepEqual(output.lines, []);
		}
	});
});
