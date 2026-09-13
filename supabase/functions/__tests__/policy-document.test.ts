import { describe, expect, it } from "vitest";
import { compilePolicyDocument, simulateRuntimePolicy } from "../../../packages/core/src/policy-document.js";
import { compileRuntimePolicyDocument, simulateCompiledRuntimePolicy } from "../_shared/policy-document.ts";
import { validateRuntimePolicy } from "../_shared/runtime-policy.ts";

const document = {
	version: "1.0",
	default_action: "ask",
	unknown_action: "deny",
	risky_action: "ask",
	category_defaults: { command: "deny" },
	rules: [
		{ name: "allow read", condition: { mcp_tool: "github.read" }, action: "allow", priority: 20 },
		{ name: "deny lower", condition: { mcp_tool: "github.read" }, action: "deny", priority: 10 },
		{ name: "deny vault", condition: { mcp_server: "vault" }, action: "deny", priority: 100 },
	],
};

describe("server policy document compiler", () => {
	it("produces a runtime-validator compatible policy with deterministic diagnostics", () => {
		const result = compileRuntimePolicyDocument(document);
		expect(validateRuntimePolicy(result.runtime_policy)).toEqual(result.runtime_policy);
		expect(result.runtime_policy).toMatchObject({ command_default: "deny", file_default: "ask", mcp_default: "ask", mcp_unknown: "deny", mcp_risky: "ask", mcp_allow_tools: ["github.read"], mcp_deny_servers: ["vault"] });
		expect(result.diagnostics).toHaveLength(1);
		const core = compilePolicyDocument(document);
		expect(result.runtime_policy).toEqual(core.runtime_policy);
		expect(result.diagnostics).toEqual(core.diagnostics);
		expect(result.semantics).toEqual(core.semantics);
	});

	it("rejects fields the runtime cannot enforce", () => {
		expect(() => compileRuntimePolicyDocument({ ...document, rules: [{ name: "regex", condition: { pattern: ".*" }, action: "deny", priority: 1 }] })).toThrow(/unsupported_field:pattern/);
		expect(() => compileRuntimePolicyDocument({ ...document, unknown: true })).toThrow(/unsupported_field:unknown/);
	});

	it("returns explainable dry-run results", () => {
		const policy = compileRuntimePolicyDocument(document).runtime_policy;
		expect(simulateCompiledRuntimePolicy(policy, { kind: "mcp", server: "vault", tool: "read", inventory: "known" })).toEqual({ action: "deny", source: "mcp_server", matched: "vault" });
		expect(simulateCompiledRuntimePolicy(policy, { kind: "mcp", server: "newserver", tool: "read", inventory: "unknown" })).toEqual({ action: "deny", source: "mcp_unknown", matched: null });
	});

	it.each(["deny", "ask", "allow"] as const)("keeps server and core dry runs aligned when unknown_action=allow and mcp_default=%s", (fallback) => {
		const input = { kind: "mcp" as const, server: "newserver", tool: "read", inventory: "unknown" as const };
		const policyDocument = { ...document, default_action: fallback, unknown_action: "allow" };
		const serverPolicy = compileRuntimePolicyDocument(policyDocument).runtime_policy;
		const corePolicy = compilePolicyDocument(policyDocument).runtime_policy;
		expect(simulateCompiledRuntimePolicy(serverPolicy, input)).toEqual({ action: fallback, source: "mcp_default", matched: null });
		expect(simulateCompiledRuntimePolicy(serverPolicy, input)).toEqual(simulateRuntimePolicy(corePolicy, input));
	});
});
