import "./helpers/isolated-home.mjs";
import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, before, describe, it } from "node:test";
import { detectionSessionId } from "../detection.mjs";
import { fixture, rpc } from "./helpers/gateway-fixture.mjs";

/**
 * The session-level detection layers (runaway guardrails, toxic-flow chains)
 * keep one record per session id. The gateway serves many clients and MCP
 * sessions, so each conversation must get its own record: pooling them would
 * let one client's history pause another and turn ordinary traffic at scale
 * into false `approval_required` blocks.
 */

const LIMIT = 2;
let root;
let agentConfigPath;

before(async () => {
	root = await mkdtemp(join(tmpdir(), "aidr-mcp-session-isolation-"));
	agentConfigPath = join(root, "agent-config.json");
	await writeFile(
		agentConfigPath,
		JSON.stringify({
			agent_safety: {
				runaway: {
					max_consecutive_identical_calls: LIMIT,
					max_identical_calls: 0,
					max_similar_calls: 0,
					max_calls_per_minute: 0,
				},
			},
		}),
	);
});

after(async () => {
	await rm(root, { recursive: true, force: true });
});

function limitedFixture(overrides = {}) {
	return fixture({ ...overrides, gatewayConfig: { detection: { agentConfigPath } } });
}

async function approvedGateway(overrides) {
	const f = limitedFixture(overrides);
	const base = await f.start();
	for (const [tenantId, token] of [
		["tenant-a", f.tokenA],
		["tenant-b", f.tokenB],
	]) {
		await rpc(base, token);
		await f.approve(tenantId);
	}
	return { f, base };
}

async function openSession(base, token) {
	const initialized = await rpc(base, token, "initialize", 1, {
		protocolVersion: "2025-03-26",
		capabilities: {},
		clientInfo: { name: "test", version: "1" },
	});
	const sessionId = initialized.headers.get("mcp-session-id");
	assert.ok(sessionId);
	return sessionId;
}

function call(base, token, sessionId, params = { name: "search", arguments: { query: "same" } }) {
	return rpc(
		base,
		token,
		"tools/call",
		7,
		params,
		sessionId ? { "mcp-session-id": sessionId } : {},
	);
}

function assertDelivered(result) {
	assert.equal(result.body.error, undefined, result.body.error?.message);
	assert.equal(result.body.result.content[0].text, "Normal result");
}

function assertRunawayPause(result) {
	assert.equal(result.body.result, undefined);
	assert.equal(result.body.error.data.type, "mcp_gateway_decision");
	assert.equal(result.body.error.data.code, "approval_required");
	assert.equal(result.body.error.data.verdict, "ask");
	assert.equal(result.body.error.data.category, "agent_runaway");
	assert.equal(result.body.error.data.operatorActionRequired, true);
}

describe("MCP gateway detection session isolation", () => {
	it("keys each MCP session separately and never stores the raw session id", () => {
		const client = { tenantId: "tenant-a", id: "client-a" };
		const server = { id: "server-a" };
		const one = detectionSessionId("instance-1", { client, server, mcpSessionId: "raw-session-1" });
		const two = detectionSessionId("instance-1", { client, server, mcpSessionId: "raw-session-2" });
		assert.notEqual(one, two);
		assert.equal(
			one,
			detectionSessionId("instance-1", { client, server, mcpSessionId: "raw-session-1" }),
		);
		assert.ok(!one.includes("raw-session-1"));
		assert.match(one, /^mcp-gateway:tenant-a:client-a:server-a:session:[0-9a-f]{32}$/);
		// Without a session the key is the client's connection through this gateway
		// process, never the client credential alone.
		assert.equal(
			detectionSessionId("instance-1", { client, server }),
			"mcp-gateway:tenant-a:client-a:server-a:connection:instance-1",
		);
		assert.notEqual(
			detectionSessionId("instance-1", { client, server }),
			detectionSessionId("instance-2", { client, server }),
		);
		assert.notEqual(
			detectionSessionId("instance-1", { client, server }),
			detectionSessionId("instance-1", { client, server: { id: "server-b" } }),
		);
	});

	it("does not let one MCP session's identical calls pause another session of the same client", async () => {
		const { f, base } = await approvedGateway({ sessionMode: "required", uniqueSessions: true });
		const first = await openSession(base, f.tokenA);
		const second = await openSession(base, f.tokenA);
		assert.notEqual(first, second);
		// Interleaved: pooled into one record this would be 2 * LIMIT identical calls in a row.
		for (let i = 0; i < LIMIT; i++) {
			assertDelivered(await call(base, f.tokenA, first));
			assertDelivered(await call(base, f.tokenA, second));
		}
		const callsBefore = f.toolCalls;
		// Each session still trips its own threshold, before upstream execution.
		assertRunawayPause(await call(base, f.tokenA, first));
		assertRunawayPause(await call(base, f.tokenA, second));
		assert.equal(f.toolCalls, callsBefore);
		// A fresh session of the same client starts clean.
		assertDelivered(await call(base, f.tokenA, await openSession(base, f.tokenA)));
	});

	it("does not let two clients' identical calls pause each other", async () => {
		const { f, base } = await approvedGateway();
		for (let i = 0; i < LIMIT; i++) {
			assertDelivered(await call(base, f.tokenA));
			assertDelivered(await call(base, f.tokenB));
		}
		assertRunawayPause(await call(base, f.tokenA));
		// Client A's pause does not reach client B until B crosses its own limit.
		assertRunawayPause(await call(base, f.tokenB));
		const other = { name: "search", arguments: { query: "different" } };
		assertDelivered(await call(base, f.tokenB, undefined, other));
	});

	it("does not carry a client's history into another gateway process (stdio bridges)", async () => {
		// Each stdio bridge runs its own gateway; the same client in two bridges is
		// two MCP connections, even though they share one on-disk state directory.
		const one = await approvedGateway();
		const two = await approvedGateway();
		for (let i = 0; i < LIMIT; i++) {
			assertDelivered(await call(one.base, one.f.tokenA));
			assertDelivered(await call(two.base, two.f.tokenA));
		}
		assertRunawayPause(await call(one.base, one.f.tokenA));
		assertRunawayPause(await call(two.base, two.f.tokenA));
	});

	it("decides deterministic pre-execution refusals before a runaway pause", async () => {
		const { f, base } = await approvedGateway({
			tools: [
				{
					name: "search",
					description: "Search trusted corpus",
					input_schema: { type: "object", properties: { query: { type: "string" } } },
				},
			],
		});
		for (let i = 0; i < LIMIT; i++) assertDelivered(await call(base, f.tokenA));
		assertRunawayPause(await call(base, f.tokenA));
		// The session is paused, yet a call the gateway refuses outright keeps its
		// own refusal code rather than being reported as a pending approval.
		const refused = await call(base, f.tokenA, undefined, { name: "not-allowed", arguments: {} });
		assert.match(refused.body.error.message, /tool_not_allowed/);
		const mismatched = await call(base, f.tokenA, undefined, {
			name: "search",
			arguments: { query: 5 },
		});
		assert.match(mismatched.body.error.message, /arguments_schema_mismatch/);
		const callsBefore = f.toolCalls;
		assertRunawayPause(await call(base, f.tokenA));
		assert.equal(f.toolCalls, callsBefore);
	});
});
