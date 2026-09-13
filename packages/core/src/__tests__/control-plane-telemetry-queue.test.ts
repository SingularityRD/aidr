import { mkdir, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ControlPlaneClient } from "../clients/control-plane.js";
import type { ControlPlaneConfig } from "../types.js";

const originalFetch = globalThis.fetch;

describe("ControlPlaneClient durable telemetry delivery", () => {
	let queueRoot: string;
	const config = {
		endpoint: "https://control.example.test/functions/v1",
		timeout_seconds: 1,
	} as ControlPlaneConfig;

	beforeEach(async () => {
		queueRoot = join(tmpdir(), `aidr-control-plane-queue-${crypto.randomUUID()}`);
		await mkdir(queueRoot, { recursive: true });
	});

	afterEach(async () => {
		globalThis.fetch = originalFetch;
		await rm(queueRoot, { recursive: true, force: true });
	});

	it("preserves event_id across a failed request and a new client instance", async () => {
		const bodies: Array<Record<string, unknown>> = [];
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			const body = JSON.parse(String(init.body)) as Record<string, unknown>;
			bodies.push(body);
			if (bodies.length === 1) throw new Error("offline");
			const eventIds = (body.events as Array<Record<string, unknown>>).map(
				(event) => event.event_id,
			);
			return {
				ok: true,
				status: 200,
				json: async () => ({ ok: true, acknowledged_event_ids: eventIds }),
			} as unknown as Response;
		});

		const options = {
			telemetryQueueRoot: queueRoot,
			telemetryQueue: { initialRetryMs: 1 },
		};
		const first = new ControlPlaneClient(config, "aidr-test-key", undefined, options);
		const offline = await first.ingest({
			iid: "iid-durable",
			events: [{ type: "runtime_verdict", verdict: "deny" }],
		});
		expect(offline.ok).toBe(false);
		expect(offline.error).toBe("request_failed");
		expect(
			(offline.body?.telemetry_queue as { metrics?: { pendingEvents?: number } }).metrics
				?.pendingEvents,
		).toBe(1);

		await new Promise((resolve) => setTimeout(resolve, 5));
		const restarted = new ControlPlaneClient(config, "aidr-test-key", undefined, options);
		const delivered = await restarted.ingest({
			iid: "iid-durable",
			events: [],
		});
		expect(delivered.ok).toBe(true);
		const firstIds = (bodies[0]?.events as Array<Record<string, unknown>>).map(
			(event) => event.event_id,
		);
		const secondIds = (bodies[1]?.events as Array<Record<string, unknown>>).map(
			(event) => event.event_id,
		);
		expect(secondIds).toContain(firstIds[0]);
		expect(
			(delivered.body?.telemetry_queue as { metrics?: { pendingEvents?: number } }).metrics
				?.pendingEvents,
		).toBe(0);
	});

	it("returns an explicit storage error when the WAL cannot accept an event", async () => {
		globalThis.fetch = vi.fn();
		const client = new ControlPlaneClient(config, "aidr-test-key", undefined, {
			telemetryQueueRoot: queueRoot,
			telemetryQueue: {
				faultInjector(operation) {
					if (operation === "append") {
						throw Object.assign(new Error("disk full"), { code: "ENOSPC" });
					}
				},
			},
		});
		const result = await client.ingest({
			iid: "iid-disk-full",
			events: [{ type: "runtime_verdict" }],
		});
		expect(result).toMatchObject({ ok: false, error: "telemetry_storage_unavailable" });
		expect(globalThis.fetch).not.toHaveBeenCalled();
	});
});
