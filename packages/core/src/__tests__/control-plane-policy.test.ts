import { afterEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";

const originalFetch = globalThis.fetch;

describe("control plane runtime policy sync", () => {
	afterEach(() => {
		globalThis.fetch = originalFetch;
	});

	it("fetches account runtime policy with the enrolled agent token", async () => {
		const calls: Array<{ url: string; init: RequestInit }> = [];
		globalThis.fetch = vi.fn().mockImplementation(async (url: string, init: RequestInit = {}) => {
			calls.push({ url, init });
			return {
				ok: true,
				status: 200,
				json: async () => ({
					ok: true,
					agent_id: "agent_1",
					cache_seconds: 60,
					runtime_policy: {
						command_default: "ask",
						mcp_unknown: "ask",
						mcp_risky: "deny",
						mcp_deny_servers: ["shell-wrapper"],
					},
				}),
			} as unknown as Response;
		});

		const client = new ControlPlaneClient(
			{
				enabled: true,
				endpoint: "https://control.example.test",
				timeout_seconds: 0.5,
				send_audit_logs: true,
				send_clean_verdicts: false,
				sync_incidents: false,
				grace_period_hours: 72,
				redact_mode: "hash",
			},
			"aidr_agent_token",
		);

		const result = await client.fetchRuntimePolicy();

		expect(result.ok).toBe(true);
		expect(result.body?.runtime_policy).toMatchObject({
			mcp_risky: "deny",
			mcp_deny_servers: ["shell-wrapper"],
		});
		expect(calls[0]?.url).toBe("https://control.example.test/v1/policy");
		expect(calls[0]?.init.method).toBe("GET");
		expect(calls[0]?.init.headers).toMatchObject({
			Authorization: "Bearer aidr_agent_token",
			Accept: "application/json",
		});
	});

	it("fails open when no agent token is configured", async () => {
		const client = new ControlPlaneClient(
			{
				enabled: true,
				endpoint: "https://control.example.test",
				timeout_seconds: 0.5,
				send_audit_logs: true,
				send_clean_verdicts: false,
				sync_incidents: false,
				grace_period_hours: 72,
				redact_mode: "hash",
			},
			"",
		);

		await expect(client.fetchRuntimePolicy()).resolves.toEqual({
			ok: false,
			error: "missing_api_key",
		});
	});
});
