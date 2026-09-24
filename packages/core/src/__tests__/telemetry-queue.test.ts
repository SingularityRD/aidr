import { spawnSync } from "node:child_process";
import { chmod, mkdir, readFile, rm, stat, symlink, utimes, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { DurableTelemetryQueue } from "../telemetry-queue.js";

const VERIFY_WINDOWS_ACL = `
$ErrorActionPreference = 'Stop'
$path = [Environment]::GetEnvironmentVariable('AIDR_TEST_ACL_PATH')
$acl = if ([IO.Directory]::Exists($path)) { [IO.DirectoryInfo]::new($path).GetAccessControl() } else { [IO.FileInfo]::new($path).GetAccessControl() }
if (-not $acl.AreAccessRulesProtected) { throw 'Inherited ACL remains' }
$allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value, 'S-1-5-18', 'S-1-5-32-544')
foreach ($entry in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
  if ($entry.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
      $entry.IdentityReference.Value -notin $allowed) { throw 'Unexpected ACL grant' }
}
`;

describe("DurableTelemetryQueue", () => {
	it.each([{ maxBytes: Number.NaN }, { maxEvents: Number.POSITIVE_INFINITY }])(
		"rejects non-finite bounds instead of disabling queue limits: %o",
		(options) => {
			expect(() => new DurableTelemetryQueue({ directory, ...options })).toThrow(
				/positive safe integer/,
			);
		},
	);

	let directory: string;
	const ageLock = (path: string) => {
		const old = new Date(Date.now() - 60_000);
		return utimes(path, old, old);
	};

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
		expect(duplicate.pendingDuplicateEventIds).toEqual([eventId]);
		expect(duplicate.deliveredDuplicateEventIds).toEqual([]);
		expect(duplicate.metrics.duplicateEnqueuesTotal).toBe(1);
		expect(duplicate.metrics.pendingEvents).toBe(1);

		const conflict = await restarted.enqueue([
			{ event_id: eventId, type: "runtime_verdict", verdict: "allow" },
		]);
		expect(conflict.state).toBe("unavailable");
		expect(conflict.rejected).toEqual([{ eventId, reason: "event_id_conflict" }]);
		expect(conflict.metrics.lostTotal).toBe(1);
	});

	it("distinguishes an already-delivered duplicate from one still awaiting ACK", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		await queue.enqueue([{ event_id: "evt-delivered", type: "runtime_verdict" }]);
		await queue.flush(async () => ({ ok: true }));

		const duplicate = await queue.enqueue([{ event_id: "evt-delivered", type: "runtime_verdict" }]);
		expect(duplicate.duplicateEventIds).toEqual(["evt-delivered"]);
		expect(duplicate.pendingDuplicateEventIds).toEqual([]);
		expect(duplicate.deliveredDuplicateEventIds).toEqual(["evt-delivered"]);
	});

	it("compacts acknowledged event payloads while retaining delivered identity", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		const event = {
			event_id: "evt-private",
			type: "runtime_verdict",
			note: "private-local-canary",
		};
		await queue.enqueue([event]);
		const walPath = join(directory, "events.wal");
		expect(await readFile(walPath, "utf8")).toContain("private-local-canary");

		const delivered = await queue.flush(async () => ({ ok: true }));
		expect(delivered.acknowledgedEventIds).toEqual(["evt-private"]);
		expect(await readFile(walPath, "utf8")).not.toContain("private-local-canary");

		const restarted = new DurableTelemetryQueue({ directory });
		const duplicate = await restarted.enqueue([event]);
		expect(duplicate.deliveredDuplicateEventIds).toEqual(["evt-private"]);
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

	it("does not ACK or retry a different event that reused an in-flight ID", async () => {
		const first = new DurableTelemetryQueue({ directory });
		const second = new DurableTelemetryQueue({ directory });
		await first.enqueue([{ event_id: "evt-reused", verdict: "deny" }]);
		let releaseDelivery!: () => void;
		let deliveryStarted!: () => void;
		const heldDelivery = new Promise<void>((resolve) => {
			releaseDelivery = resolve;
		});
		const started = new Promise<void>((resolve) => {
			deliveryStarted = resolve;
		});
		const delayedFlush = first.flush(async () => {
			deliveryStarted();
			await heldDelivery;
			return { ok: true };
		});
		try {
			await started;
			await second.flush(async () => ({ ok: false, retryable: false }));
			const replacement = await second.enqueue([{ event_id: "evt-reused", verdict: "allow" }]);
			expect(replacement.acceptedEventIds).toEqual(["evt-reused"]);
		} finally {
			releaseDelivery();
		}

		const stale = await delayedFlush;
		expect(stale.acknowledgedEventIds).toEqual([]);
		expect(stale.reason).toBe("stale_delivery");
		expect(stale.metrics.pendingEvents).toBe(1);
		const delivered: string[] = [];
		const recovered = await second.flush(async (events) => {
			delivered.push(...events.map((event) => String(event.verdict)));
			return { ok: true };
		});
		expect(delivered).toEqual(["allow"]);
		expect(recovered.metrics.pendingEvents).toBe(0);
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

	it("does not write callback exception text into the retry WAL", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		await queue.enqueue([{ event_id: "evt-exception", type: "runtime_verdict" }]);
		const result = await queue.flush(async () => {
			throw new Error("delivery failed with private-token-canary");
		});
		expect(result.reason).toBe("delivery_exception");
		const wal = await readFile(join(directory, "events.wal"), "utf8");
		expect(wal).not.toContain("private-token-canary");
	});

	it("does not persist a callback-provided failure reason", async () => {
		const queue = new DurableTelemetryQueue({ directory });
		await queue.enqueue([{ event_id: "evt-retry", type: "runtime_verdict" }]);
		const result = await queue.flush(async () => ({
			ok: false,
			retryable: true,
			reason: "private-token-canary",
		}));
		expect(result.reason).toBe("delivery_failed");
		expect(await readFile(join(directory, "events.wal"), "utf8")).not.toContain(
			"private-token-canary",
		);
	});

	it("does not steal an old lock while its owner process is alive", async () => {
		let releaseAppend!: () => void;
		let markAppendEntered!: () => void;
		const appendEntered = new Promise<void>((resolve) => {
			markAppendEntered = resolve;
		});
		const holdAppend = new Promise<void>((resolve) => {
			releaseAppend = resolve;
		});
		const owner = new DurableTelemetryQueue({
			directory,
			lockTimeoutMs: 10,
			staleLockMs: 20,
			faultInjector: async (operation) => {
				if (operation !== "append") return;
				markAppendEntered();
				await holdAppend;
			},
		});
		const enqueue = owner.enqueue([{ event_id: "evt-live-lock", type: "runtime_verdict" }]);
		await appendEntered;
		await new Promise((resolve) => setTimeout(resolve, 30));

		const contender = new DurableTelemetryQueue({
			directory,
			lockTimeoutMs: 10,
			staleLockMs: 20,
		});
		const blocked = await contender.inspect();
		expect(blocked).toMatchObject({
			state: "unavailable",
			deliveryState: "unavailable",
			reason: "storage_unavailable",
		});

		releaseAppend();
		await enqueue;
		expect((await contender.inspect()).metrics.pendingEvents).toBe(1);
	});

	it("an old owner cannot remove a replacement lock", async () => {
		let releaseAppend!: () => void;
		let markAppendEntered!: () => void;
		const appendEntered = new Promise<void>((resolve) => {
			markAppendEntered = resolve;
		});
		const holdAppend = new Promise<void>((resolve) => {
			releaseAppend = resolve;
		});
		const owner = new DurableTelemetryQueue({
			directory,
			faultInjector: async (operation) => {
				if (operation !== "append") return;
				markAppendEntered();
				await holdAppend;
			},
		});
		const enqueue = owner.enqueue([{ event_id: "evt-replaced-lock", type: "runtime_verdict" }]);
		await appendEntered;

		const lockPath = join(directory, ".lock");
		await rm(lockPath, { recursive: true, force: true });
		await mkdir(lockPath);
		await writeFile(
			join(lockPath, "owner-replacement-owner.json"),
			JSON.stringify({
				v: 1,
				token: "replacement-owner",
				pid: process.pid,
				host: hostname(),
				acquiredAt: Date.now(),
			}),
		);

		releaseAppend();
		await enqueue;
		expect(
			JSON.parse(await readFile(join(lockPath, "owner-replacement-owner.json"), "utf8")),
		).toMatchObject({ token: "replacement-owner" });
	});

	it("recovers an old lock only after its same-host owner is dead", async () => {
		const lockPath = join(directory, ".lock");
		await mkdir(lockPath);
		await writeFile(
			join(lockPath, "owner-dead-owner.json"),
			JSON.stringify({
				v: 1,
				token: "dead-owner",
				pid: 2_147_483_647,
				host: hostname(),
				acquiredAt: Date.now() - 60_000,
			}),
		);
		await ageLock(lockPath);

		const recovered = new DurableTelemetryQueue({
			directory,
			lockTimeoutMs: 100,
			staleLockMs: 10,
		});
		expect(await recovered.inspect()).toMatchObject({ state: "idle", deliveryState: "available" });
	});

	it.each([
		["owner marker not yet published", undefined],
		["malformed owner marker", "{not-json"],
		[
			"owner from a previous process generation",
			JSON.stringify({
				v: 1,
				token: "stale-owner",
				pid: process.pid,
				host: hostname(),
				acquiredAt: Date.now() - 60_000,
				processStartedAtMs: 0,
			}),
		],
		[
			"owner from a previous hostname",
			JSON.stringify({
				v: 1,
				token: "stale-owner",
				pid: process.pid,
				host: `${hostname()}-previous`,
				acquiredAt: Date.now() - 60_000,
				processStartedAtMs: Date.now(),
			}),
		],
	])("handles an aged %s lock conservatively", async (label, marker) => {
		const lockPath = join(directory, ".lock");
		await mkdir(lockPath);
		if (marker !== undefined) {
			await writeFile(join(lockPath, "owner-stale-owner.json"), marker);
		}
		await ageLock(lockPath);

		const recovered = new DurableTelemetryQueue({
			directory,
			lockTimeoutMs: 100,
			staleLockMs: 10,
		});
		if (label === "owner from a previous process generation") {
			expect(await recovered.inspect()).toMatchObject({
				state: "idle",
				deliveryState: "available",
			});
			await expect(stat(lockPath)).rejects.toMatchObject({ code: "ENOENT" });
		} else {
			expect(await recovered.inspect()).toMatchObject({
				state: "unavailable",
				deliveryState: "unavailable",
			});
			expect((await stat(lockPath)).isDirectory()).toBe(true);
		}
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

	// AIDR-SKIP: AIDR-063 qa-owner - POSIX mode-bit repair and file symlink behavior need a Unix host; Windows DACLs are tested below
	it.skipIf(process.platform === "win32")(
		"repairs permissive queue storage and rejects a symlinked WAL",
		async () => {
			const queue = new DurableTelemetryQueue({ directory });
			await queue.enqueue([{ event_id: "evt-private-wal", type: "runtime_verdict" }]);
			const walPath = join(directory, "events.wal");

			await chmod(directory, 0o777);
			await chmod(walPath, 0o666);
			const repaired = await new DurableTelemetryQueue({ directory }).inspect();
			expect(repaired.metrics.pendingEvents).toBe(1);
			expect((await stat(directory)).mode & 0o777).toBe(0o700);
			expect((await stat(walPath)).mode & 0o777).toBe(0o600);

			const external = join(directory, "external.log");
			await writeFile(external, "do-not-follow\n", "utf8");
			await rm(walPath);
			await symlink(external, walPath);
			const rejected = await new DurableTelemetryQueue({ directory }).inspect();
			expect(rejected.state).toBe("unavailable");
			expect(await readFile(external, "utf8")).toBe("do-not-follow\n");
		},
	);

	// AIDR-SKIP: AIDR-063 qa-owner - NTFS DACL inspection requires Windows security semantics
	it.skipIf(process.platform !== "win32")(
		"hardens the Windows namespace and WAL before persisting telemetry",
		async () => {
			const queue = new DurableTelemetryQueue({ directory });
			const marker = "private-windows-wal-canary";
			const result = await queue.enqueue([{ event_id: "evt-windows-acl", note: marker }]);
			const walPath = join(directory, "events.wal");
			if (result.acceptedEventIds.length === 0) {
				expect(result).toMatchObject({ state: "unavailable", deliveryState: "unavailable" });
				expect(result.reason).toMatch(/^storage_unavailable/);
				expect(await readFile(walPath, "utf8").catch(() => "")).not.toContain(marker);
				return;
			}
			for (const path of [directory, walPath]) {
				const check = spawnSync(
					"powershell.exe",
					[
						"-NoProfile",
						"-NonInteractive",
						"-EncodedCommand",
						Buffer.from(VERIFY_WINDOWS_ACL, "utf16le").toString("base64"),
					],
					{
						env: { ...process.env, AIDR_TEST_ACL_PATH: path },
						encoding: "utf8",
						timeout: 30_000,
						windowsHide: true,
					},
				);
				expect(check.error).toBeUndefined();
				expect(check.status, check.stderr).toBe(0);
			}
		},
	);

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

	it.each([
		["permanent rejection", false],
		["retry limit", true],
	])("removes %s payload from the WAL immediately", async (_label, retryable) => {
		const queue = new DurableTelemetryQueue({ directory, maxAttempts: retryable ? 1 : 5 });
		const marker = "private-terminal-drop-canary";
		await queue.enqueue([{ event_id: "evt-terminal-private", note: marker }]);
		const walPath = join(directory, "events.wal");
		expect(await readFile(walPath, "utf8")).toContain(marker);
		const dropped = await queue.flush(async () => ({ ok: false, retryable }));
		expect(dropped.metrics).toMatchObject({ pendingEvents: 0, lostTotal: 1 });
		expect(await readFile(walPath, "utf8")).not.toContain(marker);
		expect((await new DurableTelemetryQueue({ directory }).inspect()).metrics.lostTotal).toBe(1);
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
		if (process.platform !== "win32") expect((await stat(evidencePath)).mode & 0o777).toBe(0o444);
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
