import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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

	it("treats an absent queue root as idle with no loss", async () => {
		// ENOENT means telemetry has never been queued on this machine, which is
		// genuinely idle rather than an unavailable storage failure.
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

	it("reports a corrupt namespace as unavailable rather than degraded and idle", async () => {
		const namespace = "a".repeat(8);
		const directory = join(root, namespace);
		mkdirSync(directory, { recursive: true });
		writeFileSync(join(directory, "events.wal"), '{"v":1,"op":"unknown"}\n', "utf8");

		const summary = await readTelemetryLossSummary(root);
		expect(summary.state).toBe("unavailable");
		expect(summary.namespaces).toEqual([
			{ namespace, pendingEvents: 0, lostTotal: 0, state: "unavailable" },
		]);
	});
});
