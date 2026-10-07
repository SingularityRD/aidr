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

import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
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
	const originalExitCode = process.exitCode;
	try {
		const statusCommand = (await import("../commands/status.js")).default;
		await statusCommand({ json: true });
		return JSON.parse(lines.join("\n")) as Record<string, unknown>;
	} finally {
		process.exitCode = originalExitCode;
		log.mockRestore();
	}
}

async function runStatusText(): Promise<string> {
	const lines: string[] = [];
	const log = vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
		lines.push(args.map((value) => String(value)).join(" "));
	});
	const originalExitCode = process.exitCode;
	try {
		const statusCommand = (await import("../commands/status.js")).default;
		await statusCommand();
		return lines.join("\n");
	} finally {
		process.exitCode = originalExitCode;
		log.mockRestore();
	}
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

	it("prints loss counters in text without claiming an unavailable queue", async () => {
		const output = await runStatusText();
		expect(output).toContain(
			"Telemetry queue: idle; 0 event(s) undelivered, 0 lost.",
		);
		expect(output).not.toContain("at least one queue could not be read");
		expect(output).toContain(
			"Audit log: 0 append(s) could not be written, 0 rotation(s) dropped the oldest file.",
		);
	});

	it("labels an unreadable telemetry root as unavailable in text output", async () => {
		const home = process.env.HOME as string;
		const root = join(home, ".singularity-aidr", "telemetry");
		writeFileSync(root, "not a directory", "utf8");

		const output = await runStatusText();
		expect(output).toContain("Telemetry queue: unavailable;");
		expect(output).toContain("at least one queue could not be read");
	});

	it("reports a queue it cannot read as unavailable rather than as empty", async () => {
		// A file where the telemetry root belongs: the reader must not present an
		// unreadable queue as a clean one.
		const home = process.env.HOME as string;
		const root = join(home, ".singularity-aidr", "telemetry");
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		writeFileSync(root, "not a directory", "utf8");

		const report = (await runStatusJson()) as {
			data_loss?: { telemetry?: Record<string, unknown> };
		};
		expect(report.data_loss?.telemetry?.state).toBe("unavailable");
	});
	it("reports managed features as inactive in local mode", async () => {
		const output = await runStatusText();
		expect(output).toContain("Managed: inactive (mode: local)");
		expect(output).not.toMatch(/Managed: enabled/);
		const report = (await runStatusJson()) as { managed?: Record<string, unknown> };
		expect(report.managed).toMatchObject({
			active: false,
			enabled: false,
			control_plane_enabled: true,
		});
	});

	it("reports managed state only in managed mode", async () => {
		const home = process.env.HOME as string;
		writeFileSync(
			join(home, ".singularity-aidr", "config.json"),
			JSON.stringify({
				mode: "managed",
				control_plane: { enabled: true, endpoint: "https://cp.example.test" },
			}),
			"utf8",
		);
		const output = await runStatusText();
		expect(output).toContain("Managed: enabled; endpoint configured.");
		const report = (await runStatusJson()) as { managed?: Record<string, unknown> };
		expect(report.managed).toMatchObject({ active: true, enabled: true });
	});
});
