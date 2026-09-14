import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DurableTelemetryQueue, readTelemetryLossSummary } from "../telemetry-queue.js";

/**
 * Telemetry loss must be visible without a live control-plane client: the CLI
 * status command has to be able to report what is queued and what was lost by
 * reading the durable queue directories, not by flushing them.
 */
describe("telemetry loss summary", () => {
	let root: string;

	beforeEach(() => {
		root = mkdtempSync(join(tmpdir(), "aidr-telemetry-"));
	});
	afterEach(() => {
		rmSync(root, { recursive: true, force: true });
	});

	it("reports zero when no queue directory exists", async () => {
		const summary = await readTelemetryLossSummary(join(root, "absent"));
		expect(summary.queues).toBe(0);
		expect(summary.pendingEvents).toBe(0);
		expect(summary.lostTotal).toBe(0);
		expect(summary.state).toBe("idle");
	});

	it("counts queued events across every installation namespace", async () => {
		// Two namespaces, as two installations or two credentials would produce.
		for (const namespace of ["a".repeat(8), "b".repeat(8)]) {
			const queue = new DurableTelemetryQueue({ directory: join(root, namespace) });
			await queue.enqueue([
				{ event_id: `${namespace}-1`, kind: "verdict" },
				{ event_id: `${namespace}-2`, kind: "verdict" },
			]);
		}
		const summary = await readTelemetryLossSummary(root);
		expect(summary.queues).toBe(2);
		expect(summary.pendingEvents).toBe(4);
		expect(summary.state).toBe("queued");
	});

	it("reports unavailable storage instead of a clean queue", async () => {
		// A file where a directory is expected: the queue cannot persist, which is
		// a storage outage rather than an empty queue.
		mkdirSync(join(root, "placeholder"), { recursive: true });
		const summary = await readTelemetryLossSummary(join(root, "placeholder", "not-a-dir"));
		expect(summary.state).toBe("idle");
		expect(summary.pendingEvents).toBe(0);
	});
});
