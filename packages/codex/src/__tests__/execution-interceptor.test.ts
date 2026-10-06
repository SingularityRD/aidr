import { describe, expect, it, vi } from "vitest";
import {
	CodexExecutionInterceptError,
	createCodexExecutionInterceptor,
	TypedCodexToolRegistry,
} from "../execution-interceptor.js";
import type { SignedIngressRequest, SignedIngressResponse } from "../signed-ingress.js";
import type { CodexRuntimeIdentity } from "../types.js";

const identity: CodexRuntimeIdentity = {
	tenantId: "tenant-1",
	teamId: "team-1",
	endpointId: "endpoint-1",
	agentId: "agent-1",
	instanceId: "instance-1",
	sessionId: "session-1",
	connectorVersion: "0.6.0",
};

function setup(route: "read_only" | "wt05" = "read_only") {
	const submit = vi.fn(
		async (_request: SignedIngressRequest): Promise<SignedIngressResponse> => ({
			schema_version: "aidr-signed-http-ingress/v1",
			route,
			receipt_digest: { algorithm: "sha256", value: "d".repeat(64) },
			replayed: false,
		}),
	);
	const registry = new TypedCodexToolRegistry([
		{
			toolName: "search_alerts",
			capability: "alerts.read",
			schemaHash: "a".repeat(64),
			riskClass: "read_only",
			dataClass: "internal",
			mutating: false,
			target: () => ({ kind: "resource", value: "alerts-index" }),
		},
		{
			toolName: "isolate_host",
			capability: "hosts.isolate",
			schemaHash: "b".repeat(64),
			riskClass: "high",
			dataClass: "sensitive",
			mutating: true,
			target: () => ({ kind: "host", value: "host-1" }),
		},
	]);
	const interceptor = createCodexExecutionInterceptor({
		identity,
		principal: { id: "principal-1", credentialDigest: "c".repeat(64) },
		policy: { version: "wt08-runtime-policy-v1", hash: "e".repeat(64) },
		registry,
		transport: { submit },
		now: () => new Date("2026-08-10T10:00:01Z"),
	});
	return { interceptor, submit };
}

describe("Codex execution interceptor", () => {
	it("maps a registered read-only tool and suppresses local execution", async () => {
		const { interceptor, submit } = setup();
		const result = await interceptor.execute({
			phase: "pre_tool_use",
			tool_name: "search_alerts",
			call_id: "call-1",
			arguments: { query: "severity:critical" },
			target: "alerts-index",
			sequence: 7,
		});

		expect(result).toMatchObject({
			decision: "suppress_local_execution",
			outcome: "server_executed",
			suppressLocalExecution: true,
			route: "read_only",
		});
		expect(submit).toHaveBeenCalledOnce();
		const request = submit.mock.calls[0][0];
		expect(request.event.scope).toEqual(request.tool.scope);
		expect(request.tool).toMatchObject({
			capability: "alerts.read",
			data_class: "internal",
			mutating: false,
			target: { kind: "resource", value: "alerts-index" },
		});
	});

	it("returns a governed handoff for mutating WT05 routing", async () => {
		const { interceptor } = setup("wt05");
		await expect(
			interceptor.execute({
				phase: "pre_tool_use",
				tool_name: "isolate_host",
				call_id: "call-2",
				arguments: { host_id: "host-1" },
				sequence: 8,
			}),
		).resolves.toMatchObject({
			decision: "suppress_local_execution",
			outcome: "governed_handoff",
			suppressLocalExecution: true,
			route: "wt05",
		});
	});

	it("rejects post-tool calls before transport to prevent duplicate execution", async () => {
		const { interceptor, submit } = setup();
		await expect(
			interceptor.execute({
				phase: "post_tool_use",
				tool_name: "search_alerts",
				call_id: "call-3",
				arguments: {},
			}),
		).rejects.toEqual(
			expect.objectContaining<CodexExecutionInterceptError>({
				code: "codex_post_tool_execution_forbidden",
			}),
		);
		expect(submit).not.toHaveBeenCalled();
	});

	it("rejects native PostToolUse and invalid phases before transport", async () => {
		const { interceptor, submit } = setup();
		await expect(
			interceptor.execute({
				hook_event_name: "PostToolUse",
				phase: "pre_tool_use",
				tool_name: "search_alerts",
				tool_use_id: "call-native-post",
				tool_input: {},
				tool_response: { alerts: [] },
			}),
		).rejects.toMatchObject({ code: "codex_post_tool_execution_forbidden" });
		await expect(
			interceptor.execute({
				phase: "unsupported_phase",
				tool_name: "search_alerts",
				call_id: "call-invalid-phase",
				arguments: {},
			}),
		).rejects.toThrow("unsupported Codex hook phase");
		expect(submit).not.toHaveBeenCalled();
	});

	it("rejects an unregistered tool before transport", async () => {
		const { interceptor, submit } = setup();
		await expect(
			interceptor.execute({
				phase: "pre_tool_use",
				tool_name: "unknown_tool",
				call_id: "call-4",
				arguments: {},
			}),
		).rejects.toEqual(
			expect.objectContaining<CodexExecutionInterceptError>({ code: "codex_tool_unregistered" }),
		);
		expect(submit).not.toHaveBeenCalled();
	});
});
