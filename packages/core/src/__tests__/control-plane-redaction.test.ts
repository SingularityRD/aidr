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
});
