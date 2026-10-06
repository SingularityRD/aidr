import { generateKeyPairSync } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
	createCodexExecutionInterceptor,
	TypedCodexToolRegistry,
} from "../execution-interceptor.js";
import { createCodexInstrumentation } from "../instrumentation.js";
import { normalizeCodexHookInput } from "../normalize.js";
import { CentralPolicyClient } from "../policy.js";
import {
	SignedIngressClient,
	type SignedIngressRequest,
	type SignedIngressResponse,
} from "../signed-ingress.js";
import type { CodexRuntimeIdentity, PolicyHandoff } from "../types.js";

const config = vi.hoisted(() => ({
	mode: "normal" as "normal" | "required" | "invalid" | "load_error",
	loadConfig: vi.fn(),
	isInvalidConfig: vi.fn(),
}));

vi.mock("@singularityrd/aidr-core", () => ({
	loadConfig: config.loadConfig,
	isInvalidConfig: config.isInvalidConfig,
}));

const BLOCK_REASON = "mandatory_privacy_requires_owned_gateway";
const blockedProfiles = ["required", "invalid", "load_error"] as const;
const identity: CodexRuntimeIdentity = {
	tenantId: "tenant-1",
	teamId: "team-1",
	endpointId: "endpoint-1",
	agentId: "agent-1",
	instanceId: "instance-1",
	sessionId: "session-1",
	connectorVersion: "0.6.0",
};
const input = {
	hook_event_name: "PreToolUse",
	tool_name: "search_alerts",
	tool_use_id: "call-1",
	tool_input: { query: "severity:critical" },
};
const postInput = {
	...input,
	hook_event_name: "PostToolUse",
	tool_response: { alerts: [] },
};
const { privateKey } = generateKeyPairSync("ed25519");

beforeEach(() => {
	vi.clearAllMocks();
	config.mode = "normal";
	config.loadConfig.mockImplementation(async () => {
		if (config.mode === "load_error") throw new Error("configuration unavailable");
		return { privacy: { required: config.mode === "required" } };
	});
	config.isInvalidConfig.mockImplementation(() => config.mode === "invalid");
});

function policy() {
	const decide = vi.fn<PolicyHandoff["decide"]>(async () => ({
		decision: "allow",
		decisionId: "decision-1",
		reasonCode: "allowed",
		policy: { version: "policy-1", hash: "a".repeat(64) },
	}));
	const publish = vi.fn<PolicyHandoff["publish"]>(async () => ({ accepted: true }));
	return { decide, publish };
}

function signedRequest(): SignedIngressRequest {
	const scope = { tenant_id: "tenant-1", team_id: "team-1" };
	return {
		schema_version: "aidr-signed-http-ingress/v1",
		principal: {
			id: "principal-1",
			credential_digest: { algorithm: "sha256", value: "a".repeat(64) },
		},
		event: { kind: "tool_call_requested", scope, source: "codex" },
		tool: {
			scope,
			source: "codex",
			tool_name: "search_alerts",
			arguments: { query: "severity:critical" },
		},
		connector: "codex",
		title: "Read alerts",
	};
}

function signedClient() {
	const payload = signedRequest();
	const serialize = vi.fn(() => payload);
	const nextSequence = vi.fn(async () => 1);
	const requestId = vi.fn(() => "request-1");
	const now = vi.fn(() => new Date("2026-10-06T00:00:00Z"));
	const receipt: SignedIngressResponse = {
		schema_version: "aidr-signed-http-ingress/v1",
		route: "read_only",
		receipt_digest: { algorithm: "sha256", value: "b".repeat(64) },
		replayed: false,
	};
	const fetchImpl = vi.fn(async () => new Response(JSON.stringify(receipt), { status: 200 }));
	const client = new SignedIngressClient({
		endpoint: "https://ingress.example.test",
		tenantId: identity.tenantId,
		teamId: identity.teamId,
		callerId: "caller-1",
		keyGeneration: 1,
		privateKey,
		nextSequence,
		requestId,
		now,
		fetchImpl,
	});
	return {
		client,
		request: Object.assign({ ...payload }, { toJSON: serialize }),
		serialize,
		nextSequence,
		requestId,
		now,
		fetchImpl,
	};
}

function interceptor() {
	const target = vi.fn(() => ({ kind: "resource" as const, value: "alerts-index" }));
	const title = vi.fn(() => "Read alerts");
	const registry = new TypedCodexToolRegistry([
		{
			toolName: input.tool_name,
			capability: "alerts.read",
			schemaHash: "a".repeat(64),
			riskClass: "read_only",
			dataClass: "internal",
			mutating: false,
			target,
			title,
		},
	]);
	const requireTool = vi.spyOn(registry, "require");
	const submit = vi.fn(
		async (): Promise<SignedIngressResponse> => ({
			schema_version: "aidr-signed-http-ingress/v1",
			route: "read_only",
			receipt_digest: { algorithm: "sha256", value: "c".repeat(64) },
			replayed: false,
		}),
	);
	const adapter = createCodexExecutionInterceptor({
		identity,
		principal: { id: "principal-1", credentialDigest: "d".repeat(64) },
		policy: { version: "policy-1", hash: "e".repeat(64) },
		registry,
		transport: { submit },
	});
	return { adapter, requireTool, target, title, submit };
}

describe("Codex exported mandatory privacy boundary", () => {
	it.each(blockedProfiles)("%s blocks custom pre/post policy callbacks", async (mode) => {
		config.mode = mode;
		const handoff = policy();
		const adapter = createCodexInstrumentation({ identity, policy: handoff });
		for (const result of [await adapter.preToolUse(input), await adapter.postToolUse(postInput)]) {
			expect(result).toMatchObject({ decision: "deny", reasonCode: BLOCK_REASON, event: null });
		}
		expect(handoff.decide).not.toHaveBeenCalled();
		expect(handoff.publish).not.toHaveBeenCalled();
	});

	it("preserves ordinary pre/post instrumentation callbacks", async () => {
		const handoff = policy();
		const adapter = createCodexInstrumentation({ identity, policy: handoff });
		await expect(adapter.preToolUse(input)).resolves.toMatchObject({ decision: "allow" });
		await expect(adapter.postToolUse(postInput)).resolves.toMatchObject({ decision: "allow" });
		expect(handoff.decide).toHaveBeenCalledOnce();
		expect(handoff.publish).toHaveBeenCalledOnce();
	});

	it.each(["pre", "post"] as const)(
		"%s policy changing during await cannot return allow or event",
		async (phase) => {
			const handoff = policy();
			if (phase === "pre")
				handoff.decide.mockImplementation(async () => {
					await Promise.resolve();
					config.mode = "required";
					return {
						decision: "allow",
						decisionId: "d-1",
						reasonCode: "allowed",
						policy: { version: "p-1", hash: "a".repeat(64) },
					};
				});
			else
				handoff.publish.mockImplementation(async () => {
					await Promise.resolve();
					config.mode = "required";
					return { accepted: true };
				});
			const adapter = createCodexInstrumentation({ identity, policy: handoff });
			const result =
				phase === "pre" ? await adapter.preToolUse(input) : await adapter.postToolUse(postInput);
			expect(result).toMatchObject({ decision: "deny", reasonCode: BLOCK_REASON, event: null });
		},
	);

	it.each(blockedProfiles)("%s blocks central policy serialization and fetch", async (mode) => {
		config.mode = mode;
		const event = normalizeCodexHookInput(input, identity);
		const serialize = vi.fn(() => event);
		const fetchImpl = vi.fn();
		const client = new CentralPolicyClient({ endpoint: "https://policy.example.test", fetchImpl });
		await expect(
			client.decide(Object.assign({ ...event }, { toJSON: serialize })),
		).resolves.toMatchObject({
			decision: "deny",
			reasonCode: BLOCK_REASON,
		});
		expect(serialize).not.toHaveBeenCalled();
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it("preserves ordinary central policy fetch", async () => {
		const fetchImpl = vi.fn(
			async () =>
				new Response(
					JSON.stringify({
						decision: "allow",
						decision_id: "d-1",
						reason_code: "allowed",
						policy: { version: "p-1", hash: "a".repeat(64) },
					}),
					{ status: 200 },
				),
		);
		const client = new CentralPolicyClient({ endpoint: "https://policy.example.test", fetchImpl });
		await expect(client.decide(normalizeCodexHookInput(input, identity))).resolves.toMatchObject({
			decision: "allow",
		});
		expect(fetchImpl).toHaveBeenCalledOnce();
	});

	it("rechecks installed privacy after awaited central response before releasing allow", async () => {
		const response = new Response("{}", { status: 200 });
		const readJson = vi.spyOn(response, "json").mockImplementation(async () => {
			await Promise.resolve();
			config.mode = "required";
			return {
				decision: "allow",
				decision_id: "d-1",
				reason_code: "allowed",
				policy: { version: "p-1", hash: "a".repeat(64) },
			};
		});
		const fetchImpl = vi.fn(async () => response);
		const client = new CentralPolicyClient({ endpoint: "https://policy.example.test", fetchImpl });
		await expect(client.decide(normalizeCodexHookInput(input, identity))).resolves.toMatchObject({
			decision: "deny",
			reasonCode: BLOCK_REASON,
		});
		expect(fetchImpl).toHaveBeenCalledOnce();
		expect(readJson).toHaveBeenCalledOnce();
	});

	it("privacy installed by central event serialization prevents fetch", async () => {
		const event = normalizeCodexHookInput(input, identity);
		const serialize = vi.fn(() => {
			config.mode = "required";
			return event;
		});
		const fetchImpl = vi.fn();
		const client = new CentralPolicyClient({ endpoint: "https://policy.example.test", fetchImpl });
		await expect(
			client.decide(Object.assign({ ...event }, { toJSON: serialize })),
		).resolves.toMatchObject({
			decision: "deny",
			reasonCode: BLOCK_REASON,
		});
		expect(serialize).toHaveBeenCalledOnce();
		expect(fetchImpl).not.toHaveBeenCalled();
	});

	it.each(blockedProfiles)("%s blocks signed body, sequence and fetch", async (mode) => {
		config.mode = mode;
		const fixture = signedClient();
		await expect(fixture.client.submit(fixture.request)).rejects.toThrow(BLOCK_REASON);
		for (const callback of [
			fixture.serialize,
			fixture.nextSequence,
			fixture.requestId,
			fixture.now,
			fixture.fetchImpl,
		]) {
			expect(callback).not.toHaveBeenCalled();
		}
	});

	it("preserves ordinary signed request submission", async () => {
		const fixture = signedClient();
		await expect(fixture.client.submit(fixture.request)).resolves.toMatchObject({
			route: "read_only",
		});
		for (const callback of [
			fixture.serialize,
			fixture.nextSequence,
			fixture.requestId,
			fixture.now,
			fixture.fetchImpl,
		]) {
			expect(callback).toHaveBeenCalledOnce();
		}
	});

	it("rechecks installed privacy after awaited sequence before signing or fetch", async () => {
		const fixture = signedClient();
		fixture.nextSequence.mockImplementation(async () => {
			await Promise.resolve();
			config.mode = "required";
			return 1;
		});
		await expect(fixture.client.submit(fixture.request)).rejects.toThrow(BLOCK_REASON);
		expect(fixture.nextSequence).toHaveBeenCalledOnce();
		for (const callback of [fixture.requestId, fixture.now, fixture.fetchImpl])
			expect(callback).not.toHaveBeenCalled();
	});

	it.each(["requestId", "now"] as const)(
		"privacy installed by signed %s callback prevents fetch",
		async (callback) => {
			const fixture = signedClient();
			if (callback === "requestId")
				fixture.requestId.mockImplementation(() => {
					config.mode = "required";
					return "request-1";
				});
			else
				fixture.now.mockImplementation(() => {
					config.mode = "required";
					return new Date("2026-10-06T00:00:00Z");
				});
			await expect(fixture.client.submit(fixture.request)).rejects.toThrow(BLOCK_REASON);
			expect(fixture[callback]).toHaveBeenCalledOnce();
			expect(fixture.fetchImpl).not.toHaveBeenCalled();
		},
	);

	it.each(blockedProfiles)(
		"%s blocks interceptor registry, observers and transport",
		async (mode) => {
			config.mode = mode;
			const fixture = interceptor();
			await expect(fixture.adapter.execute(input)).rejects.toMatchObject({ code: BLOCK_REASON });
			for (const callback of [fixture.requireTool, fixture.target, fixture.title, fixture.submit]) {
				expect(callback).not.toHaveBeenCalled();
			}
		},
	);

	it("preserves ordinary interceptor handoff", async () => {
		const fixture = interceptor();
		await expect(fixture.adapter.execute(input)).resolves.toMatchObject({
			decision: "suppress_local_execution",
			outcome: "server_executed",
			suppressLocalExecution: true,
		});
		for (const callback of [fixture.requireTool, fixture.target, fixture.title, fixture.submit]) {
			expect(callback).toHaveBeenCalledOnce();
		}
	});

	it.each(["target", "title"] as const)(
		"privacy installed during %s callback prevents transport dispatch",
		async (callback) => {
			const fixture = interceptor();
			if (callback === "target")
				fixture.target.mockImplementation(() => {
					config.mode = "required";
					return { kind: "resource", value: "alerts-index" };
				});
			else
				fixture.title.mockImplementation(() => {
					config.mode = "required";
					return "Read alerts";
				});
			await expect(fixture.adapter.execute(input)).rejects.toMatchObject({ code: BLOCK_REASON });
			expect(fixture[callback]).toHaveBeenCalledOnce();
			expect(fixture.submit).not.toHaveBeenCalled();
		},
	);
});
