import { describe, expect, it } from "vitest";
import {
	compilePolicyDocument,
	compilePolicyDocumentYaml,
	simulateRuntimePolicy,
} from "../policy-document.js";

const BASE = {
	version: "1.0" as const,
	default_action: "ask" as const,
	unknown_action: "deny" as const,
	risky_action: "deny" as const,
	category_defaults: { command: "deny" as const, output: "allow" as const },
	rules: [],
};

describe("policy document compiler", () => {
	it("compiles category defaults and exact MCP selectors", () => {
		const result = compilePolicyDocument({
			...BASE,
			rules: [
				{
					name: "github read",
					condition: { mcp_tool: "github.get_issue" },
					action: "allow",
					priority: 20,
				},
				{
					name: "filesystem approval",
					condition: { mcp_server: "filesystem" },
					action: "ask",
					priority: 30,
				},
				{
					name: "deny delete",
					condition: { mcp_tool: "github.delete_repository" },
					action: "deny",
					priority: 100,
				},
			],
		});

		expect(result.runtime_policy).toMatchObject({
			command_default: "deny",
			file_default: "ask",
			output_default: "allow",
			mcp_default: "ask",
			mcp_unknown: "deny",
			mcp_allow_tools: ["github.get_issue"],
			mcp_require_approval_servers: ["filesystem"],
			mcp_deny_tools: ["github.delete_repository"],
		});
	});

	it("compiles dotted, case-sensitive MCP identities as collision-free tuples", () => {
		const result = compilePolicyDocument({
			...BASE,
			rules: [
				{
					name: "allow dotted server tool",
					condition: { mcp_tool: { server: "a.b", tool: "c" } },
					action: "allow",
					priority: 10,
				},
				{
					name: "deny dotted tool",
					condition: { mcp_tool: { server: "a", tool: "b.c" } },
					action: "deny",
					priority: 10,
				},
			],
		});

		expect(result.runtime_policy.mcp_allow_tools).toEqual(['["a.b","c"]']);
		expect(result.runtime_policy.mcp_deny_tools).toEqual(['["a","b.c"]']);
		expect(
			simulateRuntimePolicy(result.runtime_policy, {
				kind: "mcp",
				server: "a.b",
				tool: "c",
				inventory: "known",
			}),
		).toMatchObject({ action: "allow", source: "mcp_tool" });
		expect(
			simulateRuntimePolicy(result.runtime_policy, {
				kind: "mcp",
				server: "a",
				tool: "b.c",
				inventory: "known",
			}),
		).toMatchObject({ action: "deny", source: "mcp_tool" });
		expect(
			simulateRuntimePolicy(result.runtime_policy, {
				kind: "mcp",
				server: "a.b",
				tool: "C",
				inventory: "known",
			}),
		).toMatchObject({ action: "ask", source: "mcp_default" });
	});

	it("detects a simple legacy selector and an equivalent structured selector as the same tool", () => {
		const result = compilePolicyDocument({
			...BASE,
			rules: [
				{
					name: "legacy allow",
					condition: { mcp_tool: "github.read_file" },
					action: "allow",
					priority: 10,
				},
				{
					name: "structured deny",
					condition: { mcp_tool: { server: "github", tool: "read_file" } },
					action: "deny",
					priority: 20,
				},
			],
		});

		expect(result.runtime_policy.mcp_allow_tools).toEqual([]);
		expect(result.runtime_policy.mcp_deny_tools).toEqual(['["github","read_file"]']);
		expect(result.diagnostics).toMatchObject([
			expect.objectContaining({ rule: "legacy allow", winner: "structured deny" }),
		]);
	});

	it("resolves conflicts by priority, then deny > ask > allow", () => {
		const result = compilePolicyDocument({
			...BASE,
			rules: [
				{ name: "lower deny", condition: { mcp_server: "github" }, action: "deny", priority: 10 },
				{
					name: "higher allow",
					condition: { mcp_server: "github" },
					action: "allow",
					priority: 20,
				},
				{ name: "tie ask", condition: { mcp_tool: "vault.read" }, action: "ask", priority: 50 },
				{ name: "tie deny", condition: { mcp_tool: "vault.read" }, action: "deny", priority: 50 },
			],
		});
		expect(result.runtime_policy.mcp_allow_servers).toEqual(["github"]);
		expect(result.runtime_policy.mcp_deny_servers).toEqual([]);
		expect(result.runtime_policy.mcp_deny_tools).toEqual(["vault.read"]);
		expect(result.diagnostics).toHaveLength(2);
	});

	it("rejects unsupported and ambiguous fields instead of silently dropping them", () => {
		expect(() => compilePolicyDocument({ ...BASE, typo: true })).toThrow(/unrecognized/i);
		expect(() =>
			compilePolicyDocument({
				...BASE,
				rules: [{ name: "regex", condition: { pattern: ".*" }, action: "deny", priority: 1 }],
			}),
		).toThrow(/condition/);
		expect(() =>
			compilePolicyDocument({
				...BASE,
				rules: [
					{
						name: "ambiguous",
						condition: { mcp_server: "github", mcp_tool: "github.read" },
						action: "deny",
						priority: 1,
					},
				],
			}),
		).toThrow(/exactly one/);
	});

	it("rejects duplicate YAML keys and aliases", () => {
		expect(() =>
			compilePolicyDocumentYaml(
				"version: '1.0'\ndefault_action: ask\ndefault_action: deny\nrules: []\n",
			),
		).toThrow(/invalid_policy_yaml/);
		expect(() =>
			compilePolicyDocumentYaml(
				"version: '1.0'\ndefault_action: &action ask\nunknown_action: *action\nrules: []\n",
			),
		).toThrow(/invalid_policy_yaml/);
	});

	it("simulates explicit, risky, unknown and category decisions", () => {
		const policy = compilePolicyDocument({
			...BASE,
			rules: [
				{ name: "deny vault", condition: { mcp_server: "vault" }, action: "deny", priority: 100 },
			],
		}).runtime_policy;
		expect(simulateRuntimePolicy(policy, { kind: "command" })).toMatchObject({
			action: "deny",
			source: "category_default",
		});
		expect(
			simulateRuntimePolicy(policy, {
				kind: "mcp",
				server: "vault",
				tool: "read",
				inventory: "known",
			}),
		).toMatchObject({ action: "deny", source: "mcp_server" });
		expect(
			simulateRuntimePolicy(policy, {
				kind: "mcp",
				server: "github",
				tool: "read",
				inventory: "unknown",
			}),
		).toMatchObject({ action: "deny", source: "mcp_unknown" });
		expect(
			simulateRuntimePolicy(policy, {
				kind: "mcp",
				server: "github",
				tool: "read",
				inventory: "known",
			}),
		).toMatchObject({ action: "ask", source: "mcp_default" });
	});
});
