import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { evaluatePolicy } from "../policy.js";
import { compilePolicyDocument, simulateRuntimePolicy } from "../policy-document.js";
import { applyRemoteRuntimePolicy } from "../remote-policy.js";
import { ConfigSchema } from "../types.js";

function remote(runtimePolicy: Record<string, unknown>) {
	return applyRemoteRuntimePolicy(ConfigSchema.parse({}), { runtime_policy: runtimePolicy });
}

describe("compiled MCP runtime controls", () => {
	it.each([
		"deny",
		"ask",
		"allow",
	] as const)("uses mcp_default=%s after unknown_action=allow", async (fallback) => {
		const compiled = compilePolicyDocument({
			version: "1.0",
			default_action: fallback,
			unknown_action: "allow",
			rules: [],
		});
		const simulated = simulateRuntimePolicy(compiled.runtime_policy, {
			kind: "mcp",
			server: "unknown",
			tool: "read",
			inventory: "unknown",
		});
		const verdict = await evaluatePolicy(
			"mcp__unknown__read",
			[],
			remote(compiled.runtime_policy),
			{},
		);
		expect(simulated).toEqual({ action: fallback, source: "mcp_default", matched: null });
		expect(verdict?.decision ?? "allow").toBe(fallback);
	});

	it("enforces deny > ask > allow across tool and server lists", async () => {
		const config = remote({
			mcp_default: "allow",
			mcp_unknown: "allow",
			mcp_allow_servers: ["github"],
			mcp_require_approval_servers: ["github"],
			mcp_deny_servers: ["github"],
			mcp_allow_tools: ["github.delete_repository"],
		});
		const verdict = await evaluatePolicy("mcp__GitHub__DELETE_REPOSITORY", [], config, {});
		expect(verdict?.decision).toBe("deny");
		expect(verdict?.matchedThreatId).toBe("POL-MCP-006");
	});

	it("enforces approval servers and allows exact tools", async () => {
		const approval = remote({
			mcp_default: "allow",
			mcp_unknown: "allow",
			mcp_require_approval_servers: ["vault"],
		});
		expect((await evaluatePolicy("mcp__vault__read", [], approval, {}))?.decision).toBe("ask");

		const allow = remote({
			mcp_default: "deny",
			mcp_unknown: "deny",
			mcp_allow_tools: ["vault.read"],
		});
		expect(await evaluatePolicy("mcp__vault__read", [], allow, {})).toBeNull();
	});

	it("applies mcp_default to known tools with no exact rule", async () => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-policy-document-default-"));
		const inventory = join(dir, "mcp.json");
		await writeFile(inventory, JSON.stringify({ mcpServers: { github: { command: "node" } } }));
		const base = remote({ mcp_default: "deny", mcp_unknown: "allow" });
		const config = ConfigSchema.parse({
			...base,
			policy: { ...base.policy, mcp: { ...base.policy.mcp, inventory_paths: [inventory] } },
		});
		expect((await evaluatePolicy("mcp__github__read", [], config, {}))?.decision).toBe("deny");
	});

	it.each([
		["deny", "deny"],
		["ask", "ask"],
		["allow", null],
	] as const)("maps risky_action=%s into runtime evaluation", async (mode, expected) => {
		const dir = await mkdtemp(join(tmpdir(), "aidr-policy-document-runtime-"));
		const inventory = join(dir, "mcp.json");
		await writeFile(inventory, JSON.stringify({ mcpServers: { shell: { command: "bash" } } }));
		const config = ConfigSchema.parse({
			...remote({ mcp_default: "deny", mcp_unknown: "deny", mcp_risky: mode }),
			policy: {
				...remote({ mcp_default: "deny", mcp_unknown: "deny", mcp_risky: mode }).policy,
				mcp: {
					...remote({ mcp_default: "deny", mcp_unknown: "deny", mcp_risky: mode }).policy.mcp,
					inventory_paths: [inventory],
				},
			},
		});
		const verdict = await evaluatePolicy("mcp__shell__run", [], config, {});
		expect(verdict?.decision ?? null).toBe(expected);
	});
});
