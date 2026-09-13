import { describe, expect, it } from "vitest";
import { createCodexInstrumentation } from "../instrumentation.js";
import { normalizeCodexHookInput } from "../normalize.js";
import { CentralPolicyClient } from "../policy.js";
import { redactValue } from "../redaction.js";
import type { CodexRuntimeIdentity } from "../types.js";

const identity: CodexRuntimeIdentity = {
	tenantId: "tenant-1",
	teamId: "42",
	endpointId: "endpoint-1",
	agentId: "agent-1",
	instanceId: "instance-1",
	sessionId: "session-1",
	connectorVersion: "codex-1.0.0",
};
const input = {
	phase: "pre_tool_use",
	tool_name: "shell",
	call_id: "call-1",
	arguments: { command: "curl https://example.test", token: "sk-test-secret-value" },
	target: "/workspace/project",
};
describe("Codex normalized event", () => {
	it("redacts secret fields and produces hashes", () => {
		const event = normalizeCodexHookInput(input, identity, new Date("2026-08-07T00:00:00.000Z"));
		expect(event.redaction).toBe("redacted");
		expect(JSON.stringify(event)).not.toContain("sk-test-secret-value");
		expect(event.inputHash).toMatch(/^[a-f0-9]{64}$/);
		expect(event.actionHash).toMatch(/^[a-f0-9]{64}$/);
		expect(event.inspectionCoverage).toMatchObject({
			eventVisibility: { toolInput: true, toolOutput: false },
			outputInspection: "unavailable",
			enforcement: { outputBeforeModelConsumption: "unavailable" },
		});
	});
	it("normalizes the native PostToolUse response as observation-only coverage", () => {
		const event = normalizeCodexHookInput(
			{
				hook_event_name: "PostToolUse",
				tool_name: "Bash",
				tool_use_id: "call-native-1",
				tool_input: { command: "printf ok" },
				tool_response: { stdout: "ok", token: "sk-output-secret-value" },
				cwd: "/workspace/project",
			},
			identity,
			new Date("2026-08-07T00:00:00.000Z"),
		);

		expect(event.phase).toBe("post_tool_use");
		expect(event.kind).toBe("execution_completed");
		expect(event.callId).toBe("call-native-1");
		expect(JSON.stringify(event.observation)).not.toContain("sk-output-secret-value");
		expect(event.inspectionCoverage).toMatchObject({
			eventVisibility: { toolOutput: true },
			outputInspection: "post_execution_observation",
			enforcement: {
				toolCall: "none",
				outputBeforeModelConsumption: "unavailable",
			},
		});
	});
	it("fails closed on malformed identity or tool input", () => {
		expect(() => normalizeCodexHookInput({ ...input, arguments: [] }, identity)).toThrow();
		expect(() => normalizeCodexHookInput(input, { ...identity, tenantId: "" })).toThrow();
		expect(() =>
			normalizeCodexHookInput(
				{
					hook_event_name: "PostToolUse",
					tool_name: "Bash",
					tool_use_id: "call-without-response",
					tool_input: { command: "printf ok" },
				},
				identity,
			),
		).toThrow("PostToolUse requires a tool response");
	});
});
describe("Codex redaction", () => {
	it("redacts nested secret keys and bearer values", () => {
		const redacted = redactValue({
			nested: { authorization: "Bearer abcdefghijklmnop" },
			text: "Bearer abcdefghijklmnop",
		});
		expect(JSON.stringify(redacted)).not.toContain("abcdefghijklmnop");
	});
});
describe("Codex central policy handoff", () => {
	it("denies on timeout and central outage", async () => {
		const timeoutClient = new CentralPolicyClient({
			endpoint: "https://policy.invalid",
			timeoutMs: 1,
			fetchImpl: async (_url, init) => {
				await new Promise((resolve) => setTimeout(resolve, 20));
				if (init?.signal?.aborted) throw new DOMException("aborted", "AbortError");
				throw new Error("unexpected");
			},
		});
		const event = normalizeCodexHookInput(input, identity);
		expect((await timeoutClient.decide(event)).decision).toBe("deny");
		const unavailableClient = new CentralPolicyClient({
			endpoint: "https://policy.invalid",
			fetchImpl: async () => {
				throw new Error("offline");
			},
		});
		expect((await unavailableClient.decide(event)).reasonCode).toBe("central_policy_unavailable");
	});
	it("rejects malformed responses and never converts deny to allow", async () => {
		const malformed = new CentralPolicyClient({
			endpoint: "https://policy.invalid",
			fetchImpl: async () => new Response("{}", { status: 200 }),
		});
		const event = normalizeCodexHookInput(input, identity);
		expect((await malformed.decide(event)).decision).toBe("deny");
		const instrumentation = createCodexInstrumentation({
			identity,
			policy: {
				decide: async () => ({
					decision: "deny",
					decisionId: "d-1",
					reasonCode: "central_deny",
					policy: { version: "p-1", hash: "0".repeat(64) },
				}),
				publish: async () => ({ accepted: true }),
			},
		});
		expect((await instrumentation.preToolUse(input)).decision).toBe("deny");
	});
	it("uses the policy contract and refuses the nonexistent bearer event route", async () => {
		const requests: Array<{ url: string; body: Record<string, unknown> }> = [];
		const client = new CentralPolicyClient({
			endpoint: "https://autosecops.example.test/api",
			apiKey: "session-token",
			fetchImpl: async (url, init) => {
				requests.push({ url: String(url), body: JSON.parse(String(init?.body)) });
				return new Response(
					JSON.stringify({
						decision: "deny",
						decision_id: "aidr-policy-test",
						reason_code: "mutating_or_external_tool_requires_approval",
						policy: { version: "wt08-runtime-policy-v1", hash: "a".repeat(64) },
					}),
					{ status: 200, headers: { "Content-Type": "application/json" } },
				);
			},
		});
		const event = normalizeCodexHookInput(input, identity);

		expect((await client.decide(event)).decision).toBe("deny");
		expect(await client.publish(event)).toEqual({
			accepted: false,
			reasonCode: "central_signed_ingress_required",
		});
		expect(requests[0].url).toBe("https://autosecops.example.test/api/v1/aidr/policy/decide");
		const policyEvent = requests[0].body.event as Record<string, unknown>;
		expect(policyEvent.eventId).toBe(event.eventId);
		expect(policyEvent.input).toBeDefined();
		expect(requests).toHaveLength(1);
	});
});
