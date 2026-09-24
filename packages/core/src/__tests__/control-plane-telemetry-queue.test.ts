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

	it.each([
		["missing", { ok: true }],
		["not an array", { ok: true, acknowledged_event_ids: "evt" }],
		["mixed types", { ok: true, acknowledged_event_ids: [42] }],
	])("keeps events pending when a 2xx acknowledgement is %s", async (_label, responseBody) => {
		globalThis.fetch = vi.fn().mockResolvedValue({
			ok: true,
			status: 200,
			json: async () => responseBody,
		} as unknown as Response);

		const client = new ControlPlaneClient(config, "aidr-test-key", undefined, {
			telemetryQueueRoot: queueRoot,
			telemetryQueue: { initialRetryMs: 60_000 },
		});
		const result = await client.ingest({
			iid: "iid-invalid-ack",
			events: [{ type: "runtime_verdict", verdict: "deny" }],
		});

		expect(result).toMatchObject({ ok: false, error: "invalid_acknowledgement" });
		expect(
			(result.body?.telemetry_queue as { metrics?: { pendingEvents?: number } }).metrics
				?.pendingEvents,
		).toBe(1);
	});

	it("keeps unacknowledged events pending after an explicit partial acknowledgement", async () => {
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			const body = JSON.parse(String(init.body)) as { events: Array<{ event_id: string }> };
			return {
				ok: true,
				status: 200,
				json: async () => ({ acknowledged_event_ids: [body.events[0]?.event_id] }),
			} as unknown as Response;
		});

		const client = new ControlPlaneClient(config, "aidr-test-key", undefined, {
			telemetryQueueRoot: queueRoot,
			telemetryQueue: { initialRetryMs: 60_000 },
		});
		const result = await client.ingest({
			iid: "iid-partial-ack",
			events: [
				{ type: "runtime_verdict", verdict: "deny" },
				{ type: "runtime_verdict", verdict: "allow" },
			],
		});

		expect(result).toMatchObject({ ok: false, error: "partial_acknowledgement" });
		expect(
			(result.body?.telemetry_queue as { metrics?: { pendingEvents?: number } }).metrics
				?.pendingEvents,
		).toBe(1);
	});

	it("does not report success when an older backlog batch is acknowledged first", async () => {
		const postedIds: string[][] = [];
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			const body = JSON.parse(String(init.body)) as { events: Array<{ event_id: string }> };
			const ids = body.events.map((event) => event.event_id);
			postedIds.push(ids);
			if (postedIds.length === 1) throw new Error("offline");
			return {
				ok: true,
				status: 200,
				json: async () => ({ acknowledged_event_ids: ids }),
			} as unknown as Response;
		});

		const client = new ControlPlaneClient(config, "aidr-test-key", undefined, {
			telemetryQueueRoot: queueRoot,
			telemetryQueue: { batchSize: 1, initialRetryMs: 1 },
		});
		await client.ingest({
			iid: "iid-backlog-first",
			events: [{ event_id: "evt-older", type: "runtime_verdict" }],
		});
		await new Promise((resolve) => setTimeout(resolve, 5));

		const current = await client.ingest({
			iid: "iid-backlog-first",
			events: [{ event_id: "evt-current", type: "runtime_verdict" }],
		});

		expect(postedIds[1]).toEqual(["evt-older"]);
		expect(current).toMatchObject({ ok: false, error: "telemetry_queued" });
		expect(
			(current.body?.telemetry_queue as { metrics?: { pendingEvents?: number } }).metrics
				?.pendingEvents,
		).toBe(1);
	});

	it("does not report success when a pending duplicate is behind the acknowledged batch", async () => {
		const postedIds: string[][] = [];
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			const body = JSON.parse(String(init.body)) as { events: Array<{ event_id: string }> };
			const ids = body.events.map((event) => event.event_id);
			postedIds.push(ids);
			return {
				ok: true,
				status: 200,
				json: async () => ({ acknowledged_event_ids: ids }),
			} as unknown as Response;
		});

		const client = new ControlPlaneClient(config, "aidr-test-key", undefined, {
			telemetryQueueRoot: queueRoot,
			telemetryQueue: { batchSize: 1 },
		});
		await client.ingest({
			iid: "iid-pending-duplicate",
			events: [
				{ event_id: "evt-1", type: "runtime_verdict" },
				{ event_id: "evt-2", type: "runtime_verdict" },
				{ event_id: "evt-3", type: "runtime_verdict" },
			],
		});

		const duplicate = await client.ingest({
			iid: "iid-pending-duplicate",
			events: [{ event_id: "evt-3", type: "runtime_verdict" }],
		});

		expect(postedIds).toEqual([["evt-1"], ["evt-2"]]);
		expect(duplicate).toMatchObject({ ok: false, error: "telemetry_queued" });
		expect(
			(duplicate.body?.telemetry_queue as { metrics?: { pendingEvents?: number } }).metrics
				?.pendingEvents,
		).toBe(1);
	});

	it("does not require a new ACK for a duplicate that was already delivered", async () => {
		const postedIds: string[][] = [];
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			const body = JSON.parse(String(init.body)) as { events: Array<{ event_id: string }> };
			const ids = body.events.map((event) => event.event_id);
			postedIds.push(ids);
			return {
				ok: true,
				status: 200,
				json: async () => ({ acknowledged_event_ids: ids }),
			} as unknown as Response;
		});

		const client = new ControlPlaneClient(config, "aidr-test-key", undefined, {
			telemetryQueueRoot: queueRoot,
		});
		expect(
			await client.ingest({
				iid: "iid-delivered-duplicate",
				events: [{ event_id: "evt-delivered", type: "runtime_verdict" }],
			}),
		).toMatchObject({ ok: true });

		const mixed = await client.ingest({
			iid: "iid-delivered-duplicate",
			events: [
				{ event_id: "evt-delivered", type: "runtime_verdict" },
				{ event_id: "evt-new", type: "runtime_verdict" },
			],
		});

		expect(postedIds).toEqual([["evt-delivered"], ["evt-new"]]);
		expect(mixed).toMatchObject({ ok: true });
		expect(
			(mixed.body?.telemetry_queue as { metrics?: { pendingEvents?: number } }).metrics
				?.pendingEvents,
		).toBe(0);
	});

	it("treats an all-delivered duplicate batch as an idempotent no-op", async () => {
		const postedIds: string[][] = [];
		globalThis.fetch = vi.fn().mockImplementation(async (_url: string, init: RequestInit) => {
			const body = JSON.parse(String(init.body)) as { events: Array<{ event_id: string }> };
			const ids = body.events.map((event) => event.event_id);
			postedIds.push(ids);
			return {
				ok: true,
				status: 200,
				json: async () => ({ acknowledged_event_ids: ids }),
			} as unknown as Response;
		});

		const client = new ControlPlaneClient(config, "aidr-test-key", undefined, {
			telemetryQueueRoot: queueRoot,
		});
		const event = { event_id: "evt-idempotent", type: "runtime_verdict" };
		expect(await client.ingest({ iid: "iid-idempotent", events: [event] })).toMatchObject({
			ok: true,
		});

		const duplicate = await client.ingest({ iid: "iid-idempotent", events: [event] });
		expect(duplicate).toMatchObject({ ok: true });
		expect(duplicate.error).toBeUndefined();
		expect(postedIds).toEqual([["evt-idempotent"]]);
		expect(
			(duplicate.body?.telemetry_queue as { metrics?: { pendingEvents?: number } }).metrics
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
