import { createHash } from "node:crypto";
import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";
import type { ControlPlaneConfig } from "../types.js";

const originalFetch = globalThis.fetch;

describe("control-plane outbound redaction canary", () => {
	let queueRoot: string | undefined;

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		if (queueRoot) await rm(queueRoot, { recursive: true, force: true });
	});

	it("scrubs credentials even when a caller sends a raw event", async () => {
		let captured: Record<string, unknown> | undefined;
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			captured = JSON.parse(String(init.body)) as Record<string, unknown>;
			return { ok: true, status: 200, json: async () => ({ ok: true }) } as unknown as Response;
		});

		const config = {
			endpoint: "https://control.example.test",
			timeout_seconds: 1,
		} as ControlPlaneConfig;
		queueRoot = join(tmpdir(), `aidr-control-plane-redaction-${crypto.randomUUID()}`);
		await mkdir(queueRoot, { recursive: true });
		const client = new ControlPlaneClient(config, "aidr-live-token", undefined, {
			telemetryQueueRoot: queueRoot,
		});
		await client.ingest({
			iid: "redaction-test-iid",
			events: [
				{
					type: "runtime_verdict",
					tool_input_summary: "curl https://example.test/?token=secret",
					api_key: "aidr-live-secret",
					prompt: "Authorization: Bearer prompt-secret",
				},
			],
		});

		const event = ((captured?.events as Array<Record<string, unknown>> | undefined) ?? [])[0];
		expect(event).toBeDefined();
		expect(JSON.stringify(event)).not.toContain("secret");
		expect(JSON.stringify(event)).not.toContain("aidr-live-secret");
		// The auth header is intentionally not part of the JSON body, and the
		// version field is still attached for server-side schema compatibility.
		expect(captured?.aidr_version).toBeDefined();
	});

	it("projects and hashes direct-client events before the queue or network", async () => {
		let captured: Record<string, unknown> | undefined;
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			captured = JSON.parse(String(init.body)) as Record<string, unknown>;
			const ids = ((captured.events as Array<{ event_id: string }>) ?? []).map(
				(event) => event.event_id,
			);
			return {
				ok: true,
				status: 200,
				json: async () => ({ acknowledged_event_ids: ids }),
			} as unknown as Response;
		});
		queueRoot = join(tmpdir(), `aidr-control-plane-redaction-${crypto.randomUUID()}`);
		await mkdir(queueRoot, { recursive: true });
		const client = new ControlPlaneClient(
			{
				endpoint: "https://control.example.test",
				timeout_seconds: 1,
			} as ControlPlaneConfig,
			"aidr-test-token",
			undefined,
			{ telemetryQueueRoot: queueRoot },
		);
		const input = {
			event_id: "evt-private",
			type: "runtime_verdict",
			tool_name: "Bash",
			session_id: "session_safe",
			verdict: "deny",
			severity: "high",
			findings_count: 2,
			duration_ms: 12.5,
			tool_input_summary: "private customer prompt",
			artifacts: ["private customer artifact"],
			reasons: ["private customer reason"],
			source: "private customer source",
			prompt: "private customer prompt field",
			nested: { content: "private customer nested" },
			recommended_actions: ["review", "private customer action"],
			runtime_policy_cache: {
				source: "valid",
				usable: true,
				policy_version: "pol_safe",
				content: "private customer cache",
			},
		};
		const result = await client.ingest({ iid: "redaction-test-iid", events: [input] });
		expect(result.ok).toBe(true);
		const event = ((captured?.events as Array<Record<string, unknown>> | undefined) ?? [])[0];
		expect(event).toMatchObject({
			event_id: "evt-private",
			type: "runtime_verdict",
			tool_name: "Bash",
			session_id: "session_safe",
			verdict: "deny",
			severity: "high",
			findings_count: 2,
			duration_ms: 12.5,
			reasons: [],
			recommended_actions: ["review"],
			runtime_policy_cache: { source: "valid", usable: true, policy_version: "pol_safe" },
		});
		expect(event?.tool_input_summary).toBe(
			`sha256:${createHash("sha256").update(input.tool_input_summary).digest("hex")}`,
		);
		expect(event?.artifacts).toEqual([
			`sha256:${createHash("sha256").update(input.artifacts[0]).digest("hex")}`,
		]);
		expect(JSON.stringify(captured)).not.toContain("private customer");
		expect(input.tool_input_summary).toBe("private customer prompt");
	});

	it("does not surface arbitrary upstream ingest errors or response fields", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 503,
			json: async () => ({
				error: "private_customer_secret",
				debug: { note: "private customer payload" },
			}),
		} as unknown as Response);
		const client = new ControlPlaneClient(
			{ endpoint: "https://control.example.test", timeout_seconds: 1 } as ControlPlaneConfig,
			"aidr-test-token",
		);
		const result = await client.ingest({ events: [] });

		expect(result.ok).toBe(false);
		expect(result.error).toBe("http_error");
		expect(JSON.stringify(result)).not.toContain("private customer");
	});

	it("retains only the published over-limit code and safe seat counts", async () => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: false,
			status: 402,
			json: async () => ({
				error: "agent_limit_exceeded",
				allowed_agents: 1,
				current_agents: 2,
				debug: "private customer payload",
			}),
		} as unknown as Response);
		const client = new ControlPlaneClient(
			{ endpoint: "https://control.example.test", timeout_seconds: 1 } as ControlPlaneConfig,
			"aidr-test-token",
		);
		const result = await client.ingest({ events: [] });

		expect(result.error).toBe("agent_limit_exceeded");
		expect(result.body).toMatchObject({
			error: "agent_limit_exceeded",
			allowed_agents: 1,
			current_agents: 2,
		});
		expect(JSON.stringify(result)).not.toContain("private customer");
	});
});
