#!/usr/bin/env node
/**
 * siem-delivery-worker.test.mjs — `node --test` coverage for the scheduler entry point.
 *
 * The worker is the only thing that retries a failed SIEM delivery, so its exit codes
 * are the operational contract (`deploy/FIRST_CUSTOMER.md`, `aidr-siem-delivery.service`):
 * 0 healthy/empty, 2 queued/retrying/dead-lettered/stale lock, 3 configuration or worker
 * failure. A scheduler can only alarm on 2 and 3 if the process really returns them, so
 * these assertions pin the numbers instead of accepting "some non-zero code".
 *
 * Receipts here are LOCAL by design. Nothing in this file contacts a SIEM product: the
 * only endpoint is the reserved, never-dialled `siem.example.invalid` name, and the
 * malformed state file is rejected before any adapter request is built.
 *
 * The malformed-state and success paths drive the real child process, so they need the
 * compiled core producer. `pnpm check` builds it; when a checkout only runs this file,
 * the repository's own idempotent build guard (`scripts/ensure-core-build.mjs`) produces
 * it first rather than letting the test pass for the wrong reason.
 */

import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { runSiemDeliveryWorker } from "./siem-delivery-worker.mjs";

const scriptDir = dirname(fileURLToPath(import.meta.url));
const workerPath = join(scriptDir, "siem-delivery-worker.mjs");
const coreProducerPath = resolve(scriptDir, "..", "packages", "core", "dist", "siem-incident-producer.js");

function inTemporaryDirectory(t, run) {
	const directory = mkdtempSync(join(tmpdir(), "aidr-siem-worker-"));
	t.after(() => rmSync(directory, { recursive: true, force: true }));
	return run(directory);
}

/** Collect the worker's stdio so each assertion inspects one stream, not a mix. */
function capture() {
	const out = [];
	const err = [];
	return { out, err, io: { out: (value) => out.push(value), err: (value) => err.push(value) } };
}

/** The core writer's own wrapper: sha256 over the stringified payload. */
function hashJson(value) {
	return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function ensureCoreProducer() {
	if (existsSync(coreProducerPath)) return;
	execFileSync(process.execPath, [join(scriptDir, "ensure-core-build.mjs")], { stdio: ["ignore", "inherit", "inherit"] });
	assert.equal(existsSync(coreProducerPath), true, "the compiled core producer is required; run `pnpm check` first");
}

function writeSiemConfig(directory, stateFile) {
	const configPath = join(directory, "siem-config.json");
	writeFileSync(
		configPath,
		`${JSON.stringify(
			{
				state_file: stateFile,
				adapter: {
					provider: "webhook",
					endpoint: "https://siem.example.invalid/collect",
					bearerToken: "fixture-bearer-token",
				},
				request_timeout_ms: 1000,
			},
			null,
			2,
		)}\n`,
		// The producer rejects a config any group or other principal can read.
		{ mode: 0o600 },
	);
	return configPath;
}

function runWorkerChild(configPath) {
	return spawnSync(process.execPath, [workerPath, "--max-items", "25"], {
		encoding: "utf8",
		env: { ...process.env, SINGULARITY_AIDR_SIEM_CONFIG_PATH: configPath },
		timeout: 60_000,
	});
}

test("exits non-zero when deliveries remain queued and never reports healthy", async () => {
	const limits = [];
	const queued = capture();
	const queuedStatus = await runSiemDeliveryWorker(
		["--max-items", "25"],
		async () => ({
			drainConfiguredSiemDelivery: async (maxItems) => {
				limits.push(maxItems);
				return {
					status: "degraded",
					attempted: 2,
					delivered: 0,
					retrying: 2,
					deadLettered: 0,
					queueDepth: 2,
					lastErrorCode: "upstream_unavailable",
				};
			},
		}),
		queued.io,
	);
	assert.equal(queuedStatus, 2, "receipts left queued must exit 2 so the timer fails");
	const queuedReport = JSON.parse(queued.out.join(""));
	assert.equal(queuedReport.type, "aidr_siem_delivery");
	assert.equal(queuedReport.retrying, 2);
	assert.equal(queuedReport.queueDepth, 2);
	assert.notEqual(queuedReport.status, "healthy");
	assert.doesNotMatch(queued.out.join(""), /"status":"healthy"/);
	assert.equal(queued.err.join(""), "", "a queued drain is a reported state, not a worker error");
	assert.deepEqual(limits, [25], "the drain limit must reach the producer exactly as configured");

	// A dead-lettered queue is unhealthy, is never a pass, and stays non-zero.
	const dead = capture();
	const deadStatus = await runSiemDeliveryWorker(
		["--max-items", "25"],
		async () => ({
			drainConfiguredSiemDelivery: async () => ({
				status: "unhealthy",
				attempted: 3,
				delivered: 0,
				retrying: 0,
				deadLettered: 1,
				queueDepth: 0,
				lastErrorCode: "authorization_rejected",
			}),
		}),
		dead.io,
	);
	assert.equal(deadStatus, 2, "dead-lettered receipts must exit 2");
	assert.doesNotMatch(dead.out.join(""), /"status":"healthy"/);
	assert.equal(dead.err.join(""), "");
});

test("fails closed on a malformed state file rather than discarding receipts", (t) => {
	inTemporaryDirectory(t, (directory) => {
		ensureCoreProducer();
		const stateFile = join(directory, "aidr-siem-state.json");
		const retainedReceipt = {
			receiptId: "receipt-1",
			eventId: "aidr_fixture_event",
			provider: "webhook",
			endpointOrigin: "https://siem.example.invalid",
			status: "queued",
			enqueuedAtMs: 1,
			updatedAtMs: 2,
			attemptCount: 0,
		};
		const payload = { version: 1, queue: [], receipts: [retainedReceipt] };
		// A readable receipt list whose checksum no longer matches: the failure must be
		// "this state is untrustworthy", never "start from an empty queue".
		const malformed = `${JSON.stringify({ format: "aidr-siem-delivery-state/v1", payload, sha256: "0".repeat(64) })}\n`;
		writeFileSync(stateFile, malformed, "utf8");
		const configPath = writeSiemConfig(directory, stateFile);

		const failed = runWorkerChild(configPath);
		assert.equal(failed.status, 3, "an unreadable queue is a worker failure, not a healthy run");
		assert.equal(failed.stdout, "", "no delivery report may be printed for a state that was never read");
		assert.doesNotMatch(failed.stdout, /healthy/);
		assert.equal(
			failed.stderr,
			"siem_state_integrity_error\n",
			"the integrity failure must surface as its own safe diagnostic code, with no state path, endpoint or checksum echoed",
		);

		assert.equal(readFileSync(stateFile, "utf8"), malformed, "the unreadable receipt list must survive untouched for operator recovery");
		assert.deepEqual(
			readdirSync(directory).filter((name) => name.includes(".tmp") || name.endsWith(".lock")),
			[],
			"a failed drain must leave no lock or partial state file behind",
		);

		// Control: a state file the producer can verify drains to healthy. This proves the
		// real producer loaded above, so the exit 3 came from the malformed state and not
		// from a worker that could not start at all.
		const empty = { version: 1, queue: [], receipts: [] };
		writeFileSync(stateFile, `${JSON.stringify({ format: "aidr-siem-delivery-state/v1", payload: empty, sha256: hashJson(empty) })}\n`, "utf8");
		const recovered = runWorkerChild(configPath);
		assert.equal(recovered.status, 0, recovered.stderr);
		const recoveredReport = JSON.parse(recovered.stdout);
		assert.equal(recoveredReport.type, "aidr_siem_delivery");
		assert.equal(recoveredReport.status, "healthy");
		assert.equal(recoveredReport.queueDepth, 0);
	});
});

test("exits 0 with a healthy report on the success path", async () => {
	const healthy = capture();
	const status = await runSiemDeliveryWorker(
		["--max-items", "25"],
		async () => ({
			drainConfiguredSiemDelivery: async () => ({
				status: "healthy",
				attempted: 1,
				delivered: 1,
				retrying: 0,
				deadLettered: 0,
				queueDepth: 0,
			}),
		}),
		healthy.io,
	);
	assert.equal(status, 0);
	const report = JSON.parse(healthy.out.join(""));
	assert.equal(report.type, "aidr_siem_delivery");
	assert.equal(report.status, "healthy");
	assert.equal(report.delivered, 1);
	assert.equal(report.queueDepth, 0);
	assert.equal(healthy.err.join(""), "");
});

test("reports a stale lock as a failure and a fresh lock as healthy", async () => {
	const stale = capture();
	const staleStatus = await runSiemDeliveryWorker(
		["--status"],
		async () => ({ inspectConfiguredSiemLock: async () => ({ locked: true, ageMs: 30_000, ownerPid: 4242 }) }),
		stale.io,
	);
	assert.equal(staleStatus, 2, "a lock at or beyond the stale threshold must fail the scheduled run");
	assert.match(stale.out.join(""), /"type":"aidr_siem_lock"/);
	assert.match(stale.out.join(""), /"locked":true/);

	const fresh = capture();
	const freshStatus = await runSiemDeliveryWorker(
		["--status"],
		async () => ({ inspectConfiguredSiemLock: async () => ({ locked: true, ageMs: 1_000, ownerPid: 4242 }) }),
		fresh.io,
	);
	assert.equal(freshStatus, 0, "a lock held by a live drain is not a failure");
	assert.match(fresh.out.join(""), /"ownerPid":4242/);

	const unlocked = capture();
	const unlockedStatus = await runSiemDeliveryWorker(
		["--status"],
		async () => ({ inspectConfiguredSiemLock: async () => ({ locked: false }) }),
		unlocked.io,
	);
	assert.equal(unlockedStatus, 0);
	assert.match(unlocked.out.join(""), /"locked":false/);
});

test("rejects unknown flags and a missing configuration as worker failures", async () => {
	const unsupported = capture();
	const unsupportedStatus = await runSiemDeliveryWorker(["--apply"], async () => ({}), unsupported.io);
	assert.equal(unsupportedStatus, 3, "an argument the worker does not accept must not run a drain");
	assert.equal(unsupported.out.join(""), "");
	assert.match(unsupported.err.join(""), /^invalid_siem_worker_argument\n$/);

	const unconfigured = capture();
	const unconfiguredStatus = await runSiemDeliveryWorker(
		[],
		async () => {
			throw Object.assign(new Error("siem_not_configured"), { code: "siem_not_configured" });
		},
		unconfigured.io,
	);
	assert.equal(unconfiguredStatus, 3);
	assert.equal(unconfigured.out.join(""), "");
	assert.match(unconfigured.err.join(""), /^siem_not_configured\n$/);

	const help = capture();
	assert.equal(await runSiemDeliveryWorker(["--help"], async () => ({}), help.io), 0);
	assert.ok(help.out.join("").includes("--max-items"));
});

test("keeps the shipped drain limit inside what the worker accepts", () => {
	// The unit template and this contract must not drift apart: the worker rejects any
	// limit outside 1..100, and a rejected limit is exit 3 on every scheduled run.
	const unit = readFileSync(resolve(scriptDir, "..", "deploy", "maintenance", "aidr-siem-delivery.service"), "utf8");
	const limit = unit.match(/siem-delivery-worker\.mjs --max-items (\d+)/);
	assert.ok(limit, "the service must drain through the worker's supported flag syntax");
	const parsed = Number(limit[1]);
	assert.ok(parsed >= 1 && parsed <= 100, `unit limit ${parsed} is outside the worker's accepted range`);
	assert.doesNotMatch(unit, /^SuccessExitStatus=/m, "exit 2 and 3 must fail the unit instead of being masked");
});
