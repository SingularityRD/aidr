import { describe, expect, it } from "vitest";
import { membershipActive, validateRuntimePolicy } from "../_shared/runtime-policy.ts";
import { applyRemoteRuntimePolicy } from "../../../packages/core/src/remote-policy.js";
import { ConfigSchema } from "../../../packages/core/src/types.js";
import { evaluatePolicy } from "../../../packages/core/src/policy.js";

describe("published policy contract", () => {
	it("maps the server's accepted policy to enforcing runtime controls", async () => {
		const policy = validateRuntimePolicy({ command_default: "deny", mcp_unknown: "ask", mcp_deny_tools: ["github.delete_repository"] });
		const config = applyRemoteRuntimePolicy(ConfigSchema.parse({}), { runtime_policy: policy });
		expect(config.policy.enabled).toBe(true);
		expect(config.policy.runtime_defaults.command_action).toBe("block");
		expect(config.policy.mcp.unknown_server_action).toBe("require_approval");
		expect(config.policy.mcp.deny_tools).toEqual(["github.delete_repository"]);
		expect((await evaluatePolicy("mcp__github__delete_repository", [], config))?.decision).toBe("deny");
	});
	it.each([null, [], {}, { typo: "deny" }, { command_default: "block" }, { mcp_deny_tools: ["*"] }, { mcp_deny_tools: "all" }])("rejects unsupported policy %j", (value) => {
		expect(() => validateRuntimePolicy(value)).toThrow();
	});
	it("rejects expired and malformed memberships", () => {
		expect(membershipActive(null)).toBe(false);
		expect(membershipActive({ expires_at: "bad-date" })).toBe(false);
		expect(membershipActive({ expires_at: "2000-01-01" })).toBe(false);
		expect(membershipActive({ role: "admin", expires_at: null })).toBe(true);
	});
});
