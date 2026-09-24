import { mkdir, mkdtemp, readdir, readFile, rm, stat, utimes, writeFile } from "node:fs/promises";
import { createServer } from "node:http";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";

import { afterEach, describe, expect, it, vi } from "vitest";

// @ts-expect-error The standalone JavaScript worker intentionally has no type declarations.
import { runSiemDeliveryWorker } from "../../../../scripts/siem-delivery-worker.mjs";
import { persistIncidentRecords } from "../incidents/persist.js";
import type { Incident } from "../incidents/types.js";
import { DurableSiemDelivery } from "../siem-delivery.js";
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

function parseFirstOutput(output: string[]): unknown {
	const first = output[0];
	if (first === undefined) throw new Error("Expected worker output");
	return JSON.parse(first);
}

function acknowledgedWebhookResponse(init: RequestInit | undefined): Response {
	const eventId = new Headers(init?.headers).get("x-aidr-event-id");
	return new Response(null, {
		status: 202,
		headers: eventId ? { "x-aidr-event-id": eventId } : undefined,
	});
}

async function tokenOwnerPath(lockPath: string): Promise<string> {
	const names = (await readdir(lockPath)).filter((name) => /^owner\..+\.json$/.test(name));
	expect(names).toHaveLength(1);
	return join(lockPath, names[0] as string);
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
	it("delivers a persisted incident to a loopback receiver only after a correlated receipt", async () => {
		const { configPath, stateFile } = await fixture();
		const received: Array<{ eventId: string | undefined; body: string }> = [];
		const server = createServer(async (request, response) => {
			let body = "";
			for await (const chunk of request) body += chunk.toString();
			const eventId = request.headers["x-aidr-event-id"];
			received.push({ eventId: typeof eventId === "string" ? eventId : undefined, body });
			if (received.length === 1) {
				response.writeHead(429, { "retry-after": "1" }).end();
			} else {
				response.writeHead(202, { "x-aidr-event-id": eventId }).end();
			}
		});
		await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
		try {
			const address = server.address();
			if (!address || typeof address === "string") throw new Error("loopback_server_unavailable");
			await writeFile(configPath, JSON.stringify({
				state_file: stateFile,
				adapter: {
					provider: "webhook",
					endpoint: `http://127.0.0.1:${address.port}/ingest`,
					allowInsecureLoopback: true,
				},
				request_timeout_ms: 1_000,
			}), { mode: 0o600 });
			vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
			expect((await produceConfiguredSiemIncident(incident("loopback"))).status).toBe("queued");
			expect(received).toHaveLength(0);

			const first = workerIo();
			expect(await runSiemDeliveryWorker(["--max-items", "1"], async () => ({ drainConfiguredSiemDelivery }), first.io)).toBe(2);
			expect(parseFirstOutput(first.output)).toMatchObject({ attempted: 1, delivered: 0, retrying: 1 });
			const retryState = JSON.parse(await readFile(stateFile, "utf8"));
			expect(retryState.payload.receipts[0]).toMatchObject({ status: "retrying", lastStatusCode: 429 });
			expect(received).toHaveLength(1);

			await delay(1_050);
			const second = workerIo();
			expect(await runSiemDeliveryWorker(["--max-items", "1"], async () => ({ drainConfiguredSiemDelivery }), second.io)).toBe(0);
			expect(parseFirstOutput(second.output)).toMatchObject({ attempted: 1, delivered: 1, queueDepth: 0 });
			const deliveredState = JSON.parse(await readFile(stateFile, "utf8"));
			expect(deliveredState.payload.receipts[0]).toMatchObject({ status: "delivered", attemptCount: 2 });
			expect(received).toHaveLength(2);
			expect(received[0]?.eventId).toBe(received[1]?.eventId);
			expect(JSON.parse(received[1]?.body ?? "{}").event_id).toBe(received[1]?.eventId);
			expect(received[1]?.body).not.toContain("private-bearer-secret");
		} finally {
			await new Promise<void>((resolve) => server.close(() => resolve()));
		}
	});

	it("is inert without explicit configuration", async () => {
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, "");
		const fetcher = vi.fn();
		vi.stubGlobal("fetch", fetcher);
		expect(await produceConfiguredSiemIncident(incident("disabled"))).toEqual({
			status: "disabled",
		});
		expect(fetcher).not.toHaveBeenCalled();
	});

	it("queues JSONL and SQLite incidents for the same scheduled delivery worker", async () => {
		const { configPath, stateFile, auditPath, config, directory } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) =>
			acknowledgedWebhookResponse(init),
		);
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

		const queued = JSON.parse(await readFile(stateFile, "utf8"));
		expect(queued.payload.queue).toHaveLength(sqliteAvailable ? 2 : 1);
		expect(fetcher).not.toHaveBeenCalled();
		const { io } = workerIo();
		expect(
			await runSiemDeliveryWorker(
				["--max-items", "5"],
				async () => ({ drainConfiguredSiemDelivery }),
				io,
			),
		).toBe(0);
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
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) =>
			acknowledgedWebhookResponse(init),
		);
		vi.stubGlobal("fetch", fetcher);
		const results = await Promise.all(
			Array.from({ length: 5 }, (_, index) =>
				produceConfiguredSiemIncident(incident(`concurrent-${index}`)),
			),
		);
		expect(results.every((result) => result.status === "queued")).toBe(true);
		expect(fetcher).not.toHaveBeenCalled();
		const stored = JSON.parse(await readFile(stateFile, "utf8"));
		expect(stored.payload.receipts).toHaveLength(5);
		expect(stored.payload.queue).toHaveLength(5);
		const { io } = workerIo();
		expect(
			await runSiemDeliveryWorker(
				["--max-items", "5"],
				async () => ({ drainConfiguredSiemDelivery }),
				io,
			),
		).toBe(0);
		expect(fetcher).toHaveBeenCalledTimes(5);
		expect(JSON.parse(await readFile(stateFile, "utf8")).payload.queue).toHaveLength(0);
	}, 60_000);

	it("allows a concurrent producer to enqueue while a claimed delivery is in flight", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		let requestStarted!: () => void;
		let finishRequest!: () => void;
		const started = new Promise<void>((resolve) => {
			requestStarted = resolve;
		});
		const finish = new Promise<void>((resolve) => {
			finishRequest = resolve;
		});
		vi.stubGlobal(
			"fetch",
			vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
				requestStarted();
				await finish;
				return acknowledgedWebhookResponse(init);
			}),
		);

		expect((await produceConfiguredSiemIncident(incident("in-flight"))).status).toBe("queued");
		const draining = drainConfiguredSiemDelivery(1);
		await started;
		expect((await produceConfiguredSiemIncident(incident("concurrent"))).status).toBe("queued");
		expect(JSON.parse(await readFile(stateFile, "utf8")).payload.queue).toHaveLength(2);
		finishRequest();
		expect(await draining).toMatchObject({ attempted: 1, delivered: 1, queueDepth: 1 });
		expect(JSON.parse(await readFile(stateFile, "utf8")).payload.queue).toHaveLength(1);
	});

	it("preserves local logs and durably queues redacted incidents without foreground network I/O", async () => {
		const { configPath, stateFile, auditPath, config } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		vi.stubGlobal(
			"fetch",
			vi.fn(async () => new Response(null, { status: 503 })),
		);
		await persistIncidentRecords({ store: "jsonl", logging: config }, [incident("retry")]);
		expect(await readFile(auditPath, "utf8")).toContain("inc-retry");
		expect(fetch).not.toHaveBeenCalled();
		const stored = JSON.parse(await readFile(stateFile, "utf8"));
		expect(stored.payload.queue).toHaveLength(1);
		expect(JSON.stringify(stored)).not.toContain("private-siem-token");
		expect(JSON.stringify(stored)).not.toContain("private-bearer-secret");
	});

	it("retries a due queue record without a new incident", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		let attempts = 0;
		const fetcher = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			attempts += 1;
			return attempts === 1
				? new Response(null, { status: 503 })
				: acknowledgedWebhookResponse(init);
		});
		vi.stubGlobal("fetch", fetcher);
		expect((await produceConfiguredSiemIncident(incident("scheduled"))).status).toBe("queued");
		expect(fetcher).not.toHaveBeenCalled();
		const first = workerIo();
		expect(
			await runSiemDeliveryWorker(
				["--max-items", "1"],
				async () => ({ drainConfiguredSiemDelivery }),
				first.io,
			),
		).toBe(2);
		await delay(1_100);
		const { io, output, errors } = workerIo();
		const exit = await runSiemDeliveryWorker(
			["--max-items", "5"],
			async () => ({ drainConfiguredSiemDelivery }),
			io,
		);
		expect(exit).toBe(0);
		expect(errors).toEqual([]);
		expect(parseFirstOutput(output)).toMatchObject({
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
		expect((await produceConfiguredSiemIncident(incident("rejected"))).status).toBe("queued");
		const { io, output } = workerIo();
		const exit = await runSiemDeliveryWorker([], async () => ({ drainConfiguredSiemDelivery }), io);
		expect(exit).toBe(2);
		expect(parseFirstOutput(output)).toMatchObject({ status: "unhealthy", queueDepth: 0 });
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
		expect(parseFirstOutput(output)).toMatchObject({ locked: true, ownerPid: 987654 });
		expect((await stat(lockPath)).isDirectory()).toBe(true);
	});

	it("recovers a same-host dead owner but preserves stale ownerless locks", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const lockPath = `${stateFile}.lock`;
		await mkdir(lockPath);
		const deadToken = "11111111-1111-4111-8111-111111111111";
		await writeFile(
			join(lockPath, `owner.${deadToken}.json`),
			JSON.stringify({
				pid: 2_147_483_647,
				host: hostname(),
				token: deadToken,
				acquired_at_ms: Date.now(),
			}),
		);
		expect((await produceConfiguredSiemIncident(incident("dead-lock"))).status).toBe("queued");

		await mkdir(lockPath);
		const old = new Date(Date.now() - 60_000);
		await utimes(lockPath, old, old);
		await expect(produceConfiguredSiemIncident(incident("ownerless-lock"))).rejects.toThrow(
			"siem_state_lock_unavailable",
		);
		expect(JSON.parse(await readFile(stateFile, "utf8")).payload.queue).toHaveLength(1);
		expect((await stat(lockPath)).isDirectory()).toBe(true);
		expect(await readdir(lockPath)).toEqual([]);
	});

	it("preserves malformed markers and recovers a same-host reused PID generation", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const lockPath = `${stateFile}.lock`;
		const stale = new Date(Date.now() - 60_000);

		await mkdir(lockPath);
		const malformedToken = "33333333-3333-4333-8333-333333333333";
		await writeFile(join(lockPath, `owner.${malformedToken}.json`), "{partial");
		await utimes(lockPath, stale, stale);
		await expect(produceConfiguredSiemIncident(incident("malformed-lock"))).rejects.toThrow(
			"siem_state_lock_unavailable",
		);
		await expect(readFile(join(lockPath, `owner.${malformedToken}.json`), "utf8")).resolves.toBe(
			"{partial",
		);
		await rm(lockPath, { recursive: true, force: true });

		await mkdir(lockPath);
		const reusedToken = "44444444-4444-4444-8444-444444444444";
		await writeFile(
			join(lockPath, `owner.${reusedToken}.json`),
			JSON.stringify({
				pid: process.pid,
				host: hostname(),
				token: reusedToken,
				acquired_at_ms: Date.now() - 60_000,
				process_started_at_ms: 0,
			}),
		);
		expect((await produceConfiguredSiemIncident(incident("reused-pid-lock"))).status).toBe(
			"queued",
		);
		expect(JSON.parse(await readFile(stateFile, "utf8")).payload.queue).toHaveLength(1);
	});

	it("does not reclaim a dead PID marker from another host", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const lockPath = `${stateFile}.lock`;
		await mkdir(lockPath);
		const token = "55555555-5555-4555-8555-555555555555";
		const markerPath = join(lockPath, `owner.${token}.json`);
		await writeFile(
			markerPath,
			JSON.stringify({
				pid: 2_147_483_647,
				host: `${hostname()}-other`,
				token,
				acquired_at_ms: Date.now() - 60_000,
				process_started_at_ms: 0,
			}),
		);
		await expect(produceConfiguredSiemIncident(incident("foreign-host-lock"))).rejects.toThrow(
			"siem_state_lock_unavailable",
		);
		expect(JSON.parse(await readFile(markerPath, "utf8"))).toMatchObject({
			host: `${hostname()}-other`,
		});
	});

	it("never steals a stale legacy lock from a live owner PID", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const lockPath = `${stateFile}.lock`;
		await mkdir(lockPath);
		await writeFile(join(lockPath, "owner.json"), JSON.stringify({ pid: process.pid }));
		const old = new Date(Date.now() - 60_000);
		await utimes(lockPath, old, old);
		let clock = Date.now();
		vi.spyOn(Date, "now").mockImplementation(() => (clock += 1_000));

		await expect(produceConfiguredSiemIncident(incident("live-legacy-lock"))).rejects.toThrow(
			"siem_state_lock_unavailable",
		);
		expect(JSON.parse(await readFile(join(lockPath, "owner.json"), "utf8"))).toEqual({
			pid: process.pid,
		});
	});

	it("never lets an old owner remove a replacement lock generation", async () => {
		const { configPath, stateFile } = await fixture();
		vi.stubEnv(SIEM_CONFIG_PATH_ENV, configPath);
		const originalOpen = DurableSiemDelivery.open;
		let entered!: () => void;
		let resume!: () => void;
		const opened = new Promise<void>((resolve) => {
			entered = resolve;
		});
		const resumed = new Promise<void>((resolve) => {
			resume = resolve;
		});
		vi.spyOn(DurableSiemDelivery, "open").mockImplementationOnce(async (options) => {
			entered();
			await resumed;
			return originalOpen(options);
		});

		const producing = produceConfiguredSiemIncident(incident("replaced-lock"));
		await opened;
		const lockPath = `${stateFile}.lock`;
		const originalOwner = JSON.parse(await readFile(await tokenOwnerPath(lockPath), "utf8"));
		await rm(lockPath, { recursive: true, force: true });
		await mkdir(lockPath);
		const replacement = {
			pid: process.pid,
			host: hostname(),
			token: "22222222-2222-4222-8222-222222222222",
			acquired_at_ms: Date.now(),
		};
		const replacementPath = join(lockPath, `owner.${replacement.token}.json`);
		await writeFile(replacementPath, JSON.stringify(replacement));
		resume();

		expect((await producing).status).toBe("queued");
		expect(originalOwner.token).not.toBe(replacement.token);
		expect(JSON.parse(await readFile(replacementPath, "utf8"))).toEqual(replacement);
	});
});
