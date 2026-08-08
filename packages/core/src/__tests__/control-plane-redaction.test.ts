import { afterEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";
import type { ControlPlaneConfig } from "../types.js";

const originalFetch = globalThis.fetch;

describe("control-plane outbound redaction canary", () => {
	afterEach(() => {
		globalThis.fetch = originalFetch;
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
		const client = new ControlPlaneClient(config, "aidr-live-token");
		await client.ingest({
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
});
