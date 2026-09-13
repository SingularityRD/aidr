import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DurableTelemetryQueue } from "../telemetry-queue.js";

describe("DurableTelemetryQueue", () => {
	let directory: string;

	beforeEach(async () => {
		directory = join(tmpdir(), `aidr-telemetry-${crypto.randomUUID()}`);
		await mkdir(directory, { recursive: true });
	});

	afterEach(async () => {
		await rm(directory, { recursive: true, force: true });
	});

	it("assigns a stable identity and de-duplicates the same event across restart", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		const first = await queue.enqueue([{ type: "runtime_verdict", verdict: "deny" }]);
		expect(first.acceptedEventIds).toHaveLength(1);
		expect(first.metrics.pendingEvents).toBe(1);

		const eventId = first.acceptedEventIds[0] as string;
		const restarted = new DurableTelemetryQueue({ directory });
		const duplicate = await restarted.enqueue([
			{ event_id: eventId, type: "runtime_verdict", verdict: "deny" },
		]);
		expect(duplicate.acceptedEventIds).toEqual([]);
		expect(duplicate.duplicateEventIds).toEqual([eventId]);
		expect(duplicate.metrics.duplicateEnqueuesTotal).toBe(1);
		expect(duplicate.metrics.pendingEvents).toBe(1);

		const conflict = await restarted.enqueue([
			{ event_id: eventId, type: "runtime_verdict", verdict: "allow" },
		]);
		expect(conflict.state).toBe("unavailable");
		expect(conflict.rejected).toEqual([{ eventId, reason: "event_id_conflict" }]);
		expect(conflict.metrics.lostTotal).toBe(1);
	});

	it("resends safely when the server accepted an event before the local ACK crashed", async () => {
		let appendCount = 0;
		const crashing = new DurableTelemetryQueue({
			directory,
			faultInjector(operation) {
				if (operation === "append" && ++appendCount === 2) {
					throw Object.assign(new Error("disk full"), { code: "ENOSPC" });
				}
			},
		});
		const queued = await crashing.enqueue([{ type: "runtime_verdict", verdict: "deny" }]);
		const eventId = queued.acceptedEventIds[0] as string;
		const serverRows = new Set<string>();
		const receive = async (events: Array<{ event_id: string }>) => {
			for (const event of events) serverRows.add(event.event_id);
			return { ok: true };
		};

		const interrupted = await crashing.flush(receive);
		expect(interrupted.state).toBe("unavailable");
		expect(interrupted.reason).toContain("ack_storage_unavailable");
		expect(serverRows).toEqual(new Set([eventId]));

		const restarted = new DurableTelemetryQueue({ directory });
		const recovered = await restarted.flush(receive);
		expect(recovered.acknowledgedEventIds).toEqual([eventId]);
		expect(recovered.metrics.pendingEvents).toBe(0);
		expect(recovered.metrics.deliveredTotal).toBe(1);
		// The server saw a retry, but tenant + event_id still represents one row.
		expect(serverRows.size).toBe(1);
	});

	it("backs off retries and drains after the clock advances", async () => {
		let now = 1_700_000_000_000;
		const queue = new DurableTelemetryQueue({
			directory,
			now: () => now,
			initialRetryMs: 1_000,
		});
		await queue.enqueue([{ type: "runtime_verdict" }]);
		let calls = 0;
		const failed = await queue.flush(async () => {
			calls += 1;
			return { ok: false, retryable: true, reason: "network_unavailable" };
		});
		expect(failed.state).toBe("queued");
		expect(failed.deliveryState).toBe("unavailable");
		expect(failed.metrics.deliveryFailuresTotal).toBe(1);

		await queue.flush(async () => {
			calls += 1;
			return { ok: true };
		});
		expect(calls).toBe(1);

		now += 1_000;
		const delivered = await queue.flush(async () => {
			calls += 1;
			return { ok: true };
		});
		expect(calls).toBe(2);
		expect(delivered.metrics.pendingEvents).toBe(0);
		expect(delivered.metrics.deliveredTotal).toBe(1);
	});

	it("applies bounded backpressure and exposes every rejected event as loss", async () => {
		const queue = new DurableTelemetryQueue({ directory, maxEvents: 1 });
		const result = await queue.enqueue([
			{ event_id: "evt-1", type: "runtime_verdict" },
			{ event_id: "evt-2", type: "runtime_verdict" },
		]);
		expect(result.acceptedEventIds).toEqual(["evt-1"]);
		expect(result.rejected).toEqual([{ eventId: "evt-2", reason: "queue_full" }]);
		expect(result.deliveryState).toBe("unavailable");
		expect(result.metrics).toMatchObject({
			pendingEvents: 1,
			lostTotal: 1,
			queueFullTotal: 1,
			lastLossReason: "queue_full",
		});
	});

	it("does not claim an event was queued when the disk write fails", async () => {
		const queue = new DurableTelemetryQueue({
			directory,
			faultInjector(operation) {
				if (operation === "append") {
					throw Object.assign(new Error("disk full"), { code: "ENOSPC" });
				}
			},
		});
		const result = await queue.enqueue([{ event_id: "evt-disk", type: "runtime_verdict" }]);
		expect(result.state).toBe("unavailable");
		expect(result.reason).toContain("storage_unavailable:ENOSPC");
		expect(result.acceptedEventIds).toEqual([]);
		expect(result.rejected).toEqual([{ reason: "storage_unavailable" }]);
		expect(result.metrics.lostTotal).toBe(1);
		expect(result.metrics.storageErrorsTotal).toBe(1);
	});

	it("never persists raw credentials in the telemetry WAL", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		await queue.enqueue([
			{
				event_id: "evt-redacted",
				type: "runtime_verdict",
				api_key: "aidr-live-secret",
				message: "Authorization: Bearer super-secret-token",
			},
		]);
		const wal = await readFile(join(directory, "events.wal"), "utf8");
		expect(wal).not.toContain("aidr-live-secret");
		expect(wal).not.toContain("super-secret-token");
		expect(wal).toContain("[Redacted]");
	});

	it("drops a permanently rejected event with an explicit loss counter", async () => {
		const queue = new DurableTelemetryQueue({ directory, maxAttempts: 5 });
		await queue.enqueue([{ event_id: "evt-invalid", type: "runtime_verdict" }]);
		const result = await queue.flush(async () => ({
			ok: false,
			retryable: false,
			reason: "schema_rejected",
		}));
		expect(result.metrics).toMatchObject({
			pendingEvents: 0,
			lostTotal: 1,
			deliveryFailuresTotal: 1,
			lastLossReason: "permanent_rejection",
		});
	});

	it("allows the producer to retry a lost event with its original ID after restart", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		const event = { event_id: "evt-retry-after-drop", type: "runtime_verdict" };
		await queue.enqueue([event]);
		await queue.flush(async () => ({ ok: false, retryable: false }));

		const restarted = new DurableTelemetryQueue({ directory });
		const retried = await restarted.enqueue([event]);
		expect(retried.acceptedEventIds).toEqual([event.event_id]);
		expect(retried.duplicateEventIds).toEqual([]);
		expect(retried.metrics).toMatchObject({
			enqueuedTotal: 2,
			lostTotal: 1,
			pendingEvents: 1,
		});
	});

	it("bounds repeated transient retries and records terminal loss", async () => {
		let now = 1_700_000_000_000;
		const queue = new DurableTelemetryQueue({
			directory,
			now: () => now,
			maxAttempts: 2,
			initialRetryMs: 10,
		});
		await queue.enqueue([{ event_id: "evt-retry-limit", type: "runtime_verdict" }]);
		await queue.flush(async () => ({ ok: false, retryable: true, reason: "offline" }));
		now += 10;
		const exhausted = await queue.flush(async () => ({
			ok: false,
			retryable: true,
			reason: "offline",
		}));
		expect(exhausted).toMatchObject({
			state: "idle",
			deliveryState: "unavailable",
			metrics: {
				pendingEvents: 0,
				lostTotal: 1,
				deliveryFailuresTotal: 2,
				lastLossReason: "max_attempts",
			},
		});
	});

	it("repairs only an incomplete crash tail and rejects corrupt committed records", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		await queue.enqueue([{ event_id: "evt-tail", type: "runtime_verdict" }]);
		const walPath = join(directory, "events.wal");
		await writeFile(walPath, `${await readFile(walPath, "utf8")}{\"v\":1,\"op\"`, "utf8");

		const restarted = new DurableTelemetryQueue({ directory });
		const repaired = await restarted.inspect();
		expect(repaired.metrics.pendingEvents).toBe(1);
		expect((await readFile(walPath, "utf8")).endsWith("\n")).toBe(true);

		await writeFile(walPath, '{"v":1,"op":"not-json"}\n{broken}\n', "utf8");
		const corrupt = await new DurableTelemetryQueue({ directory }).inspect();
		expect(corrupt.state).toBe("unavailable");
		expect(corrupt.reason).toBe("storage_unavailable");
	});

	it("rejects valid JSON WAL records whose operation or counters are corrupt", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		await queue.enqueue([{ event_id: "evt-committed", type: "runtime_verdict" }]);
		const walPath = join(directory, "events.wal");
		const validWal = await readFile(walPath, "utf8");

		for (const corruptRecord of [
			{ v: 1, op: "unknown" },
			{ v: 1, op: "loss", count: "1", reason: "queue_full" },
			{ v: 1, op: "retry", id: "evt-committed", attempts: -1, nextAttemptAt: 0 },
		]) {
			await writeFile(walPath, `${validWal}${JSON.stringify(corruptRecord)}\n`, "utf8");
			const corrupt = await new DurableTelemetryQueue({ directory }).inspect();
			expect(corrupt.state).toBe("unavailable");
			expect(await readFile(walPath, "utf8")).toBe(`${validWal}${JSON.stringify(corruptRecord)}\n`);
		}

		const tamperedWal = validWal.replace("runtime_verdict", "changed_verdict");
		expect(tamperedWal).not.toBe(validWal);
		await writeFile(walPath, tamperedWal, "utf8");
		expect((await new DurableTelemetryQueue({ directory }).inspect()).state).toBe("unavailable");
	});

	it("atomically writes the deployment readiness queue contract", async () => {
		let now = 1_700_000_005_000;
		const queue = new DurableTelemetryQueue({ directory, now: () => now });
		await queue.enqueue([{ event_id: "evt-health", type: "runtime_verdict" }]);
		now += 5_000;
		const evidencePath = join(directory, "readiness", "queue.json");
		const evidence = await queue.writeReadinessEvidence(evidencePath);
		expect(evidence).toEqual({
			schema_version: 1,
			status: "ok",
			checked_at: new Date(now).toISOString(),
			depth: 1,
			oldest_age_seconds: 5,
			failed_jobs: 0,
		});
		expect(JSON.parse(await readFile(evidencePath, "utf8"))).toEqual(evidence);
		now += 1_000;
		const refreshed = await queue.writeReadinessEvidence(evidencePath);
		expect(refreshed.checked_at).toBe(new Date(now).toISOString());
		expect(JSON.parse(await readFile(evidencePath, "utf8"))).toEqual(refreshed);
	});

	it("degrades readiness while retrying or when undelivered events age past the budget", async () => {
		let now = 1_700_000_000_000;
		const queue = new DurableTelemetryQueue({
			directory,
			now: () => now,
			initialRetryMs: 1_000,
			maxReadyPendingAgeMs: 5_000,
		});
		await queue.enqueue([{ event_id: "evt-backlog", type: "runtime_verdict" }]);
		now += 5_001;
		const aged = await queue.readinessEvidence();
		expect(aged).toMatchObject({ status: "degraded", depth: 1, oldest_age_seconds: 5 });

		await queue.flush(async () => ({ ok: false, retryable: true, reason: "offline" }));
		const restarted = new DurableTelemetryQueue({
			directory,
			now: () => now,
			maxReadyPendingAgeMs: 60_000,
		});
		expect((await restarted.inspect()).deliveryState).toBe("unavailable");
		expect((await restarted.readinessEvidence()).status).toBe("degraded");

		now += 1_000;
		await restarted.flush(async () => ({ ok: true }));
		expect((await restarted.readinessEvidence()).status).toBe("ok");
	});
});
