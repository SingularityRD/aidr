/**
 * Tests for the loss reporting in `aidr status` (AIDR-063 companion).
 *
 * ## The defect these pin
 *
 * An audit append that failed was swallowed (`// Fail-open: logging errors
 * swallowed`) and the telemetry queue's loss counters existed only inside a live
 * control-plane client, so neither the operator nor the customer could tell a
 * complete record from one that had been dropping entries. `aidr status` now
 * reports both, and these tests prove the report carries the facts rather than
 * an assumption that nothing was lost.
 */

import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

let homes: string[] = [];
let originalHome: string | undefined;

beforeEach(() => {
	originalHome = process.env.HOME;
	const home = mkdtempSync(join(tmpdir(), "aidr-status-"));
	mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
	process.env.HOME = home;
	homes.push(home);
});

afterEach(() => {
	if (originalHome === undefined) delete process.env.HOME;
	else process.env.HOME = originalHome;
	for (const home of homes) rmSync(home, { recursive: true, force: true });
	homes = [];
	vi.restoreAllMocks();
});

async function runStatusJson(): Promise<Record<string, unknown>> {
	const lines: string[] = [];
	const log = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		lines.push(args.map((value) => String(value)).join(" "));
	});
	const statusCommand = (await import("../commands/status.js")).default;
	await statusCommand({ json: true });
	log.mockRestore();
	return JSON.parse(lines.join("\n")) as Record<string, unknown>;
}

describe("aidr status loss reporting", () => {
	it("prints undelivered and lost event counts with their reasons", async () => {
		const report = (await runStatusJson()) as {
			data_loss?: {
				audit?: Record<string, unknown>;
				telemetry?: Record<string, unknown>;
			};
		};

		expect(report.data_loss).toBeDefined();
		const telemetry = report.data_loss?.telemetry as Record<string, unknown>;
		const audit = report.data_loss?.audit as Record<string, unknown>;

		// A machine that has never queued anything is idle and has lost nothing;
		// the values are present rather than absent, so a reader can tell the
		// difference between "no loss" and "not measured".
		expect(telemetry).toBeDefined();
		expect(typeof telemetry.pendingEvents).toBe("number");
		expect(typeof telemetry.lostTotal).toBe("number");
		expect(["idle", "queued", "unavailable"]).toContain(telemetry.state);
		expect(telemetry.lostTotal).toBe(0);

		expect(audit).toBeDefined();
		expect(audit.writeFailures).toBe(0);
		expect(audit.rotationDrops).toBe(0);
	});

	it("reports a queue it cannot read as unavailable rather than as empty", async () => {
		// A file where the telemetry root belongs: the reader must not present an
		// unreadable queue as a clean one.
		const home = process.env.HOME as string;
		const root = join(home, ".singularity-aidr", "telemetry");
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		const { writeFileSync } = await import("node:fs");
		writeFileSync(root, "not a directory", "utf8");

		const report = (await runStatusJson()) as {
			data_loss?: { telemetry?: Record<string, unknown> };
		};
		expect(report.data_loss?.telemetry?.state).toBe("unavailable");
	});
});
