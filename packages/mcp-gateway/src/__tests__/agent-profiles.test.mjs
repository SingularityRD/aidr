import "./helpers/isolated-home.mjs";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { describe, it } from "node:test";
import { GatewayConfigError, validateGatewayConfig } from "../config.mjs";
import { fixture, rpc } from "./helpers/gateway-fixture.mjs";

function profiles(mcp, extra = {}) {
	return {
		version: 1,
		profiles: [
			{
				name: "gateway-clients",
				applies_to: { connectors: ["mcp-gateway"] },
				default: "deny",
				tools: { mcp: "allow" },
				mcp,
				...extra,
			},
		],
	};
}

async function approvedGateway(agentProfiles) {
	const f = fixture({ gatewayConfig: { agentProfiles } });
	const base = await f.start();
	await rpc(base, f.tokenA);
	await f.approve();
	return { f, base };
}

function search(base, token) {
	return rpc(base, token, "tools/call", 9, {
		name: "search",
		arguments: { query: "release notes" },
	});
}

describe("MCP gateway agent permission profiles", () => {
	it("forwards a tool the profile allows per server", async () => {
		const { f, base } = await approvedGateway(
			profiles({ servers: { "server-a": "allow" }, unmatched: "deny" }),
		);
		const result = await search(base, f.tokenA);
		assert.equal(result.body.error, undefined);
		assert.equal(f.toolCalls, 1);
	});

	it("blocks a tool the profile denies per tool before upstream execution", async () => {
		const { f, base } = await approvedGateway(
			profiles({ servers: { "server-a": "allow" }, tools: { "server-a": { search: "deny" } } }),
		);
		const result = await search(base, f.tokenA);
		assert.equal(result.body.error.message, "AIDR blocked MCP request: profile_denied");
		assert.equal(result.body.error.data.category, "agent_profile");
		assert.equal(result.body.error.data.threatId, "AGENT-PROFILE-MCP");
		assert.equal(f.toolCalls, 0);
	});

	it("holds a tool the profile routes to approval", async () => {
		const { f, base } = await approvedGateway(
			profiles({ tools: { "server-a": { search: "ask" } } }),
		);
		const result = await search(base, f.tokenA);
		assert.equal(result.body.error.message, "AIDR blocked MCP request: approval_required");
		assert.equal(result.body.error.data.operatorActionRequired, true);
		assert.equal(f.toolCalls, 0);
	});
});

describe("MCP gateway agent profile configuration", () => {
	function baseConfig(overrides = {}) {
		return {
			stateDir: "/tmp/aidr-gateway-profile-config",
			clients: [
				{
					id: "client-a",
					tenantId: "tenant-a",
					tokenSha256: createHash("sha256").update("a".repeat(48)).digest("hex"),
					allowedTools: { "server-a": ["search"] },
					...overrides.client,
				},
			],
			servers: [
				{
					tenantId: "tenant-a",
					id: "server-a",
					url: "https://mcp.example.test/mcp",
					transport: "json",
					sessionMode: "stateless",
					signedManifest: { manifest: { tools: [{ name: "search" }] } },
					trustedSigners: { publisher: "key" },
				},
			],
			...overrides.gateway,
		};
	}

	it("refuses an invalid profile document", () => {
		assert.throws(
			() => validateGatewayConfig(baseConfig({ gateway: { agentProfiles: { version: 2 } } })),
			(error) => error instanceof GatewayConfigError && error.code === "invalid_agent_profiles",
		);
	});

	it("refuses a client bound to a profile that does not exist", () => {
		assert.throws(
			() =>
				validateGatewayConfig(
					baseConfig({
						client: { profile: "missing" },
						gateway: { agentProfiles: profiles({ unmatched: "deny" }) },
					}),
				),
			/client profile is not defined in agentProfiles/,
		);
		assert.throws(
			() => validateGatewayConfig(baseConfig({ client: { profile: "gateway-clients" } })),
			/client profile requires agentProfiles/,
		);
	});

	it("accepts a client bound to a defined profile", () => {
		const config = validateGatewayConfig(
			baseConfig({
				client: { profile: "gateway-clients" },
				gateway: { agentProfiles: profiles({ servers: { "server-a": "allow" } }) },
			}),
		);
		assert.equal(config.clients[0].profile, "gateway-clients");
		assert.equal(config.agentProfiles.profiles[0].name, "gateway-clients");
	});
});
