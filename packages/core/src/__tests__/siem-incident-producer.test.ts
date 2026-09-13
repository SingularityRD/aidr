import { mkdir, mkdtemp, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { afterEach, describe, expect, it, vi } from "vitest";

// @ts-expect-error The standalone JavaScript worker intentionally has no type declarations.
import { runSiemDeliveryWorker } from "../../../../scripts/siem-delivery-worker.mjs";
import { persistIncidentRecords } from "../incidents/persist.js";
import type { Incident } from "../incidents/types.js";
import {
	drainConfiguredSiemDelivery,
	inspectConfiguredSiemLock,
	produceConfiguredSiemIncident,
	SIEM_CONFIG_PATH_ENV,
} from "../siem-incident-producer.js";
import type { LoggingConfig } from "../types.js";

const tempDirectories: string[] = [];

async function fixture() {
	const directory = await mkdtemp(join(tmpdir(), "aidr-siem-producer-"));
	tempDirectories.push(directory);
	const configPath = join(directory, "siem-config.json");
	const stateFile = join(directory, "siem-state.json");
	const auditPath = join(directory, "audit.jsonl");
	const config: LoggingConfig = {
		enabled: true,
		log_clean: false,
		path: auditPath,
		max_bytes: 0,
		max_files: 0,
	};
	await writeFile(
		configPath,
		JSON.stringify({
			state_file: stateFile,
			adapter: {
				provider: "webhook",
				endpoint: "https://siem.example.test/ingest",
				bearerToken: "private-siem-token",
			},
			request_timeout_ms: 200,
		}),
		{ mode: 0o600 },
	);
	return { configPath, stateFile, auditPath, config, directory };
}

function incident(id: string): Incident {
	return {
		incident_id: `inc-${id}`,
		opened_at_ms: 1_700_000_000_000,
		last_seen_ms: 1_700_000_000_100,
		severity: "critical",
		status: "open",
		session_id: `session-${id}`,
		events: [
			{
				signal_id: `signal-${id}`,
				timestamp_ms: 1_700_000_000_000,
				signal_type: "runtime_verdict",
				severity: "critical",
				summary: "blocked secret Bearer private-bearer-secret",
			},
		],
	};
}

function workerIo() {
	const output: string[] = [];
	const errors: string[] = [];
	return {
		output,
		errors,
		io: {
			out: (value: string) => output.push(value),
			err: (value: string) => errors.push(value),
		},
	};
}

afterEach(async () => {
	vi.unstubAllEnvs();
	vi.unstubAllGlobals();
	vi.restoreAllMocks();
	await Promise.all(
		tempDirectories.splice(0).map((directory) => rm(directory, { recursive: true, force: true })),
	);
});

describe("configured SIEM incident producer", () => {
	it("is inert without explicit configuration", async () => {
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, "");
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		expect(await produceConfiguredSiemIncident(incident("disabled"))).toEqual({
			status: "disabled",
		});
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("delivers JSONL and SQLite incidents through the same durable queue", async () => {
		const { configPath, stateFile, auditPath, config, directory } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const fetcher = vi.fn(async () => new Response(null, { status: 202 }));
		vi.stubGlobal("fetch", fetcher);
		await persistIncidentRecords({ store: "jsonl", logging: config }, [incident("jsonl")]);
		expect(await readFile(auditPath, "utf8")).toContain("inc-jsonl");

		let sqliteAvailable = true;
		try {
			await import("node:sqlite");
		} catch {
			sqliteAvailable = false;
		}
		if (sqliteAvailable) {
			const sqlitePath = join(directory, "incidents.db");
			await persistIncidentRecords({ store: "sqlite", logging: config }, [incident("sqlite")], {
				sqlite_path: sqlitePath,
			});
			expect((await stat(sqlitePath)).size).toBeGreaterThan(0);
		}

		expect(fetcher).toHaveBeenCalledTimes(sqliteAvailable ? 2 : 1);
		const firstPayload = JSON.stringify(fetcher.mock.calls[0]);
		expect(firstPayload).toContain("inc-jsonl");
		expect(firstPayload).not.toContain("private-bearer-secret");
		const state = await readFile(stateFile, "utf8");
		expect(state).not.toContain("private-siem-token");
		expect(state).not.toContain("private-bearer-secret");
	});

	it("serializes concurrent producers without losing receipts", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const fetcher = vi.fn(async () => new Response(null, { status: 202 }));
		vi.stubGlobal("fetch", fetcher);
		const results = await Promise.all(
			Array.from({ length: 5 }, (_, index) =>
				produceConfiguredSiemIncident(incident(`concurrent-${index}`)),
			),
		);
		expect(results.every((result) => result.status === "delivered")).toBe(true);
		expect(fetcher).toHaveBeenCalledTimes(5);
		const stored = JSON.parse(await readFile(stateFile, "utf8"));
		expect(stored.payload.receipts).toHaveLength(5);
		expect(stored.payload.queue).toHaveLength(0);
	});

	it("preserves local logs and reports a sanitized sink failure", async () => {
		const { configPath, stateFile, auditPath, config } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response(null, { status: 503 })),
		);
		const stderr = vi.spyOn(process.stderr, "write").mockImplementation(() => true);
		await persistIncidentRecords({ store: "jsonl", logging: config }, [incident("retry")]);
		expect(await readFile(auditPath, "utf8")).toContain("inc-retry");
		const stored = JSON.parse(await readFile(stateFile, "utf8"));
		expect(stored.payload.queue).toHaveLength(1);
		const diagnostic = stderr.mock.calls.map((call) => String(call[0])).join("");
		expect(diagnostic).toContain("AIDR SIEM delivery degraded:");
		expect(diagnostic).not.toContain("private-siem-token");
		expect(diagnostic).not.toContain("/ingest");
	});

	it("retries a due queue record without a new incident", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const fetcher = vi
			.fn()
			.mockResolvedValueOnce(new Response(null, { status: 503 }))
			.mockResolvedValueOnce(new Response(null, { status: 202 }));
		vi.stubGlobal("fetch", fetcher);
		expect((await produceConfiguredSiemIncident(incident("scheduled"))).status).toBe("degraded");
		await delay(1_100);
		const { io, output, errors } = workerIo();
		const exit = await runSiemDeliveryWorker(
			["--max-items", "5"],
			async () => ({ drainConfiguredSiemDelivery }),
			io,
		);
		expect(exit).toBe(0);
		expect(errors).toEqual([]);
		expect(JSON.parse(output[0])).toMatchObject({
			type: "aidr_siem_delivery",
			attempted: 1,
			delivered: 1,
			queueDepth: 0,
			status: "healthy",
		});
		expect(fetcher).toHaveBeenCalledTimes(2);
		expect(JSON.parse(await readFile(stateFile, "utf8")).payload.queue).toHaveLength(0);
	});

	it("signals permanent dead letters and retains their receipts", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response(null, { status: 401 })),
		);
		expect((await produceConfiguredSiemIncident(incident("rejected"))).status).toBe("degraded");
		const { io, output } = workerIo();
		const exit = await runSiemDeliveryWorker([], async () => ({ drainConfiguredSiemDelivery }), io);
		expect(exit).toBe(2);
		expect(JSON.parse(output[0])).toMatchObject({ status: "unhealthy", queueDepth: 0 });
		const state = JSON.parse(await readFile(stateFile, "utf8"));
		expect(state.payload.receipts[0].status).toBe("dead_letter");
	});

	it("reports a stale lock without removing delivery state", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const lockPath = `${stateFile}.lock`;
		await mkdir(lockPath);
		await writeFile(join(lockPath, "owner.json"), JSON.stringify({ pid: 987654 }));
		const old = new Date(Date.now() - 60_000);
		await utimes(lockPath, old, old);
		const { io, output } = workerIo();
		const exit = await runSiemDeliveryWorker(
			["--status"],
			async () => ({ inspectConfiguredSiemLock }),
			io,
		);
		expect(exit).toBe(2);
		expect(JSON.parse(output[0])).toMatchObject({ locked: true, ownerPid: 987654 });
		expect((await stat(lockPath)).isDirectory()).toBe(true);
	});
});
