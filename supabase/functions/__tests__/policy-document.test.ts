import { createHash } from "node:crypto";
import { describe, expect, it, vi } from "vitest";
import { compilePolicyDocument, simulateRuntimePolicy } from "../../../packages/core/src/policy-document.js";
import { compileRuntimePolicyDocument, compileRuntimePolicyDraft, simulateCompiledRuntimePolicy } from "../_shared/policy-document.ts";
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
	it("fingerprints exact submitted UTF-8 rather than normalized compiler output", async () => {
		const compact = JSON.stringify({ ...document, description: "café 雪" });
		const source = ` \r\n${compact}\r\n`;
		const parse = vi.fn(JSON.parse);
		const compiled = await compileRuntimePolicyDraft(source, parse);
		expect(parse).toHaveBeenCalledWith(source);
		expect(compiled.source_sha256).toBe(createHash("sha256").update(source, "utf8").digest("hex"));
		expect(compiled.source_sha256).not.toBe(createHash("sha256").update(compact, "utf8").digest("hex"));
		expect(compiled.runtime_policy).toEqual(compileRuntimePolicyDocument(document).runtime_policy);
	});

	it("bounds UTF-8 source bytes before any parsing", async () => {
		const parse = vi.fn();
		await expect(compileRuntimePolicyDraft("雪".repeat(21_846), parse)).rejects.toThrow("policy_document_too_large");
		await expect(compileRuntimePolicyDraft("", parse)).rejects.toThrow("policy_document_empty");
		await expect(compileRuntimePolicyDraft({}, parse)).rejects.toThrow("must_be_string");
		expect(parse).not.toHaveBeenCalled();
	});

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

	it("accepts the full MCP tool-name length allowed by the published document", () => {
		const tool = "t".repeat(160);
		const input = { kind: "mcp" as const, server: "github", tool, inventory: "known" as const };
		const policyDocument = {
			...document,
			rules: [{ name: "deny long tool", condition: { mcp_tool: `github.${tool}` }, action: "deny", priority: 1 }],
		};
		const serverPolicy = compileRuntimePolicyDocument(policyDocument).runtime_policy;
		const corePolicy = compilePolicyDocument(policyDocument).runtime_policy;
		expect(simulateCompiledRuntimePolicy(serverPolicy, input)).toEqual(simulateRuntimePolicy(corePolicy, input));
	});

	it("keeps dotted MCP identities distinct from another pair with the same dotted spelling", () => {
		const policyDocument = {
			...document,
			rules: [
				{ name: "deny first pair", condition: { mcp_tool: { server: "a.b", tool: "c" } }, action: "deny", priority: 1 },
			],
		};
		const server = compileRuntimePolicyDocument(policyDocument);
		const core = compilePolicyDocument(policyDocument);
		expect(server.runtime_policy).toEqual(core.runtime_policy);
		expect(validateRuntimePolicy(server.runtime_policy)).toEqual(server.runtime_policy);
		expect(server.runtime_policy.mcp_deny_tools).toEqual(['["a.b","c"]']);
		for (const input of [
			{ kind: "mcp", server: "a.b", tool: "c", inventory: "known" },
			{ kind: "mcp", server: "a", tool: "b.c", inventory: "known" },
		] as const) {
			expect(simulateCompiledRuntimePolicy(server.runtime_policy, input)).toEqual(simulateRuntimePolicy(core.runtime_policy, input));
		}
		expect(simulateCompiledRuntimePolicy(server.runtime_policy, { kind: "mcp", server: "a.b", tool: "c", inventory: "known" }).action).toBe("deny");
		expect(simulateCompiledRuntimePolicy(server.runtime_policy, { kind: "mcp", server: "a", tool: "b.c", inventory: "known" }).action).toBe("ask");
	});
});
