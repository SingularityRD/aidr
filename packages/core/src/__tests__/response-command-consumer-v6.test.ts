import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
	type FleetResponseActionAdapter,
	type FleetResponseCommand,
	type FleetResponseAuditEvent,
	FleetResponseCommandConsumer,
} from "../response-command-consumer-v6.js";
import { FleetResponseJournal } from "../response-command-journal-v6.js";
import { FleetResponseCommandWorker } from "../response-command-worker-v6.js";
import { hashDeviceKey } from "../device-attestation.js";

const tenantId = "11111111-1111-4111-8111-111111111111";
const agentId = "22222222-2222-4222-8222-222222222222";
const installationId = "installation-test-001";
const commandId = "33333333-3333-4333-8333-333333333333";
const now = Date.parse("2026-09-13T12:00:00.000Z");
const temporaryDirectories: string[] = [];

afterEach(async () => {
	for (const directory of temporaryDirectories.splice(0))
		await rm(directory, { recursive: true, force: true });
});

async function journalPath(): Promise<string> {
	const directory = await mkdtemp(join(tmpdir(), "aidr-response-v6-"));
	temporaryDirectories.push(directory);
	return join(directory, "fleet-state");
}

function typedCommand(): FleetResponseCommand {
	return {
		id: commandId,
		commandType: "agent_pause",
		expiresAt: new Date(now + 60_000).toISOString(),
		attempt: 1,
		rollbackOf: null,
	};
}

function worker(
	statePath: string,
	fetchImpl: typeof fetch,
	localAdapter: FleetResponseActionAdapter = adapter(),
) {
	return new FleetResponseCommandWorker({
		endpoint: "http://127.0.0.1:8000/functions",
		developmentLoopback: true,
		apiKey: "enrollment-secret",
		identity: { tenantId, agentId },
		installationId,
		adapter: localAdapter,
		statePath,
		fetchImpl,
		now: () => now,
	});
}

async function seedJournal(
	statePath: string,
	phase: "polled" | "acknowledged" | "execute_intent" | "result_pending",
) {
	const journal = new FleetResponseJournal(statePath, { tenantId, agentId }, "enrollment-secret", installationId);
	const state = await journal.load();
	await journal.save({
		...state,
		current: { command: typedCommand(), phase, resultCode: null },
	});
}

function command(overrides: Record<string, unknown> = {}) {
	return {
		id: commandId,
		command_type: "agent_pause",
		expires_at: new Date(now + 60_000).toISOString(),
		attempt: 1,
		rollback_of: null,
		...overrides,
	};
}

function json(value: unknown, status = 200): Response {
	return new Response(JSON.stringify(value), {
		status,
		headers: { "Content-Type": "application/json" },
	});
}

function transport(responses: Response[]) {
	const requests: Array<{ url: string; body: Record<string, unknown>; auth: string | null }> = [];
	const fetchImpl = vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
		requests.push({
			url: String(input),
			body: JSON.parse(String(init?.body)) as Record<string, unknown>,
			auth: new Headers(init?.headers).get("Authorization"),
		});
		const response = responses.shift();
		if (!response) throw new Error("unexpected_request");
		return response;
	}) as typeof fetch;
	return { fetchImpl, requests };
}

function adapter(overrides: Partial<FleetResponseActionAdapter> = {}): FleetResponseActionAdapter {
	return {
		identity: { tenantId, agentId },
		supportedCommands: ["agent_pause"],
		execute: vi.fn(async (_command: FleetResponseCommand) => ({ ok: true as const })),
		verify: vi.fn(async (_command: FleetResponseCommand) => ({ observed: true as const })),
		...overrides,
	};
}

function consumer(
	fetchImpl: typeof fetch,
	localAdapter?: FleetResponseActionAdapter,
	clock = () => now,
	audit?: (event: FleetResponseAuditEvent) => void | Promise<void>,
) {
	return new FleetResponseCommandConsumer({
		endpoint: "http://127.0.0.1:8000/functions",
		developmentLoopback: true,
		apiKey: "enrollment-secret",
		identity: { tenantId, agentId },
		installationId,
		adapter: localAdapter,
		audit,
		fetchImpl,
		now: clock,
	});
}

describe("fleet response command consumer", () => {
	it("rejects insecure remote transport and an adapter for another device", () => {
		expect(
			() =>
				new FleetResponseCommandConsumer({
					endpoint: "http://customer.example/functions",
					apiKey: "secret",
					identity: { tenantId, agentId },
					installationId,
				}),
		).toThrow("fleet_endpoint_requires_https");
		expect(
			() =>
				new FleetResponseCommandConsumer({
					endpoint: "https://customer.example/functions",
					apiKey: "secret",
					identity: { tenantId, agentId },
					installationId,
					adapter: adapter({ identity: { tenantId, agentId: tenantId } }),
				}),
		).toThrow("fleet_adapter_identity_mismatch");
	});

	it("does not execute without an installed adapter and records a rejection", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command() }),
			json({ ok: true, command_id: commandId, state: "failed" }),
		]);
		expect(await consumer(fetchImpl).pollOnce()).toEqual({
			status: "rejected",
			commandId,
			code: "unsupported_action",
		});
		expect(requests.map((request) => request.body.action)).toEqual(["poll", "ack"]);
		expect(requests[1]?.body).toMatchObject({
			command_id: commandId,
			outcome: "rejected",
			result_code: "unsupported_action",
		});
		expect(requests[0]?.body.tenant_id).toBe(tenantId);
		expect(requests[0]?.auth).toBe("Bearer enrollment-secret");
		expect(requests[0]?.url).toBe("http://127.0.0.1:8000/functions/v1/revocations");
	});

	it("emits an attestation audit event without allowing audit failure to change the result", async () => {
		const { fetchImpl } = transport([
			json({ ok: true, command: null }),
		]);
		const audit = vi.fn(async (event: FleetResponseAuditEvent) => {
			expect(event.attestation.installationId).toBe(installationId);
			expect(event.attestation.keyHash).toBe(hashDeviceKey("enrollment-secret"));
			throw new Error("audit sink unavailable");
		});
		expect(await consumer(fetchImpl, undefined, () => now, audit).pollOnce()).toEqual({ status: "idle" });
		expect(audit).toHaveBeenCalledOnce();
	});

	it("executes only after confirmed ACK and records success only after independent verification", async () => {
		const order: string[] = [];
		const localAdapter = adapter({
			execute: vi.fn(async () => {
				order.push("execute");
				return { ok: true as const };
			}),
			verify: vi.fn(async () => {
				order.push("verify");
				return { observed: true as const };
			}),
		});
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toEqual({
			status: "succeeded",
			commandId,
		});
		expect(requests.map((request) => request.body.action)).toEqual(["poll", "ack", "result"]);
		expect(requests[1]?.body.outcome).toBe("accepted");
		expect(requests[2]?.body.outcome).toBe("succeeded");
		expect(order).toEqual(["execute", "verify"]);
		expect(requests.map((request) => request.body.device_attestation)).toEqual([
			{
				schema_version: 1,
				installation_id: installationId,
				key_hash: hashDeviceKey("enrollment-secret"),
			},
			{
				schema_version: 1,
				installation_id: installationId,
				key_hash: hashDeviceKey("enrollment-secret"),
			},
			{
				schema_version: 1,
				installation_id: installationId,
				key_hash: hashDeviceKey("enrollment-secret"),
			},
		]);
	});

	it("never executes after an ambiguous ACK", async () => {
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command() }),
			json({ ok: true, command_id: commandId, state: "delivered" }),
		]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toMatchObject({
			status: "outcome_unknown",
			stage: "ack",
			reason: "ack_unconfirmed",
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect(requests).toHaveLength(2);
	});

	it("reports failed when verification cannot observe the action", async () => {
		const localAdapter = adapter({
			verify: vi.fn(async () => ({ observed: false, code: "not_observed" })),
		});
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "failed" }),
		]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toEqual({
			status: "failed",
			commandId,
			code: "not_observed",
		});
		expect(requests[2]?.body).toMatchObject({ outcome: "failed", result_code: "not_observed" });
	});

	it("does not execute if TTL expires after ACK", async () => {
		let observedTime = now;
		const localAdapter = adapter();
		const fetchImpl = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			const action = (JSON.parse(String(init?.body)) as Record<string, unknown>).action;
			if (action === "poll") return json({ ok: true, command: command() });
			if (action === "ack") {
				observedTime = now + 61_000;
				return json({ ok: true, command_id: commandId, state: "acknowledged" });
			}
			return json({ ok: true, command_id: commandId, state: "failed" });
		}) as typeof fetch;
		expect(await consumer(fetchImpl, localAdapter, () => observedTime).pollOnce()).toEqual({
			status: "failed",
			commandId,
			code: "ttl_elapsed",
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("ignores a forged device target and sends no acknowledgement", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command({ agent_id: tenantId }) }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "invalid_command",
			reason: "agent_mismatch",
		});
		expect(requests).toHaveLength(1);
	});

	it("rejects a forged reverse action without its rollback reference", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command({ command_type: "network_release" }) }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "invalid_command",
			reason: "rollback_reference_mismatch",
		});
		expect(requests).toHaveLength(1);
	});

	it("does not acknowledge a command already expired on receipt", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command({ expires_at: new Date(now - 1).toISOString() }) }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "expired",
			commandId,
		});
		expect(requests).toHaveLength(1);
	});

	it("does not report success if the result receipt is not confirmed", async () => {
		const { fetchImpl } = transport([
			json({ ok: true, command: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "result",
			reason: "result_unconfirmed",
		});
	});

	it("rejects oversized poll data before inspecting a command", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command(), padding: "x".repeat(9000) }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "outcome_unknown",
			stage: "poll",
			reason: "poll_unavailable",
		});
		expect(requests).toHaveLength(1);
	});
});

describe("durable fleet response worker", () => {
	it("persists a completed command cursor and never executes a replay", async () => {
		const statePath = await journalPath();
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "succeeded" }),
			json({ ok: true, command: command({ attempt: 2 }) }),
		]);
		const subject = worker(statePath, fetchImpl, localAdapter);
		expect(await subject.tick()).toEqual({ status: "succeeded", commandId });
		expect(await subject.tick()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "poll",
			reason: "replayed_command_id",
		});
		expect(localAdapter.execute).toHaveBeenCalledTimes(1);
		expect(requests.map((request) => request.body.action)).toEqual([
			"poll",
			"ack",
			"result",
			"poll",
		]);
		const saved = await new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		).load();
		expect(saved.current).toBeNull();
		expect(saved.recent_ids).toEqual([commandId]);
	});

	it("persists the device binding without the bearer and rejects another installation", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "polled");
		const raw = await readFile(`${statePath}.a`, "utf8");
		expect(raw).toContain('"installation_id":"installation-test-001"');
		expect(raw).toContain(`"key_hash":"${hashDeviceKey("enrollment-secret")}"`);
		expect(raw).not.toContain("enrollment-secret");
		const otherInstallation = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			"installation-other",
		);
		await expect(otherInstallation.load()).rejects.toThrow("invalid_fleet_journal_state");
	});

	it("resumes a saved result without polling or repeating the host action", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "result_pending");
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "succeeded",
			commandId,
		});
		expect(requests.map((request) => request.body.action)).toEqual(["result"]);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("recovers execution intent by observing host state without replaying execute", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "execute_intent");
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "succeeded",
			commandId,
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect(localAdapter.verify).toHaveBeenCalledOnce();
		expect(requests.map((request) => request.body.action)).toEqual(["result"]);
	});

	it("starts a previously acknowledged command after recording execution intent", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "acknowledged");
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "succeeded",
			commandId,
		});
		expect(localAdapter.execute).toHaveBeenCalledOnce();
		expect(requests.map((request) => request.body.action)).toEqual(["result"]);
	});

	it("does not execute a persisted acknowledgement after adapter support is removed", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "acknowledged");
		const localAdapter = adapter({ supportedCommands: [] });
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_id: commandId, state: "failed" }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "failed",
			commandId,
			code: "unsupported_action",
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect(localAdapter.verify).not.toHaveBeenCalled();
		expect(requests.map((request) => request.body)).toMatchObject([
			{ action: "result", outcome: "failed", result_code: "unsupported_action" },
		]);
	});

	it("holds an unverified restart outcome without retrying the side effect", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "execute_intent");
		const localAdapter = adapter({
			verify: vi.fn(async () => ({ observed: false, code: "not_observed" })),
		});
		const { fetchImpl, requests } = transport([]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "result",
			reason: "execution_state_unverified",
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect(requests).toHaveLength(0);
		const saved = await new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		).load();
		expect(saved.current?.phase).toBe("execute_intent");
	});

	it("retries an ambiguous ACK after restart, then applies exactly once", async () => {
		const statePath = await journalPath();
		const localAdapter = adapter();
		const first = transport([
			json({ ok: true, command: command() }),
			json({ ok: true, command_id: commandId, state: "delivered" }),
		]);
		expect(await worker(statePath, first.fetchImpl, localAdapter).tick()).toMatchObject({
			status: "outcome_unknown",
			stage: "ack",
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
		const second = transport([
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await worker(statePath, second.fetchImpl, localAdapter).tick()).toEqual({
			status: "succeeded",
			commandId,
		});
		expect(second.requests.map((request) => request.body.action)).toEqual(["ack", "result"]);
		expect(localAdapter.execute).toHaveBeenCalledOnce();
	});

	it("retries a result receipt after restart without repeating execute", async () => {
		const statePath = await journalPath();
		const localAdapter = adapter();
		const first = transport([
			json({ ok: true, command: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ error: "unavailable" }, 503),
		]);
		expect(await worker(statePath, first.fetchImpl, localAdapter).tick()).toMatchObject({
			status: "outcome_unknown",
			stage: "result",
		});
		const second = transport([json({ ok: true, command_id: commandId, state: "succeeded" })]);
		expect(await worker(statePath, second.fetchImpl, localAdapter).tick()).toEqual({
			status: "succeeded",
			commandId,
		});
		expect(second.requests.map((request) => request.body.action)).toEqual(["result"]);
		expect(localAdapter.execute).toHaveBeenCalledOnce();
	});

	it("fails closed on journal corruption or another live worker lock", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "polled");
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([]);
		const journal = new FleetResponseJournal(statePath, { tenantId, agentId }, "enrollment-secret", installationId);
		await journal.withLock(async () => {
			expect(await worker(statePath, fetchImpl, localAdapter).tick()).toMatchObject({
				status: "outcome_unknown",
				reason: "journal_unavailable",
			});
		});
		const slot = `${statePath}.a`;
		const envelope = JSON.parse(await readFile(slot, "utf8")) as Record<string, unknown>;
		(envelope.payload as Record<string, unknown>).agent_id = tenantId;
		await writeFile(slot, JSON.stringify(envelope));
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toMatchObject({
			status: "outcome_unknown",
			reason: "journal_unavailable",
		});
		expect(requests).toHaveLength(0);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("recovers a dead process lock but rejects a journal signed for another enrollment key", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "result_pending");
		await writeFile(
			`${statePath}.lock`,
			JSON.stringify({
				pid: 2147483647,
				token: "44444444-4444-4444-8444-444444444444",
			}),
		);
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await worker(statePath, fetchImpl).tick()).toEqual({ status: "succeeded", commandId });
		expect(requests).toHaveLength(1);
		const wrongKeyJournal = new FleetResponseJournal(statePath, { tenantId, agentId }, "other-key", installationId);
		await expect(wrongKeyJournal.load()).rejects.toThrow("fleet_journal_integrity_failed");
	});

	it("stops the polling loop when its service supervisor aborts", async () => {
		const statePath = await journalPath();
		const abort = new AbortController();
		const fetchImpl = vi.fn(async () => {
			abort.abort();
			return json({ ok: true, command: null });
		}) as typeof fetch;
		await worker(statePath, fetchImpl).run(abort.signal);
		expect(fetchImpl).toHaveBeenCalledOnce();
	});

	it("halts its service loop and reports journal failure to the supervisor", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "polled");
		await writeFile(`${statePath}.a`, "tampered");
		const onCycle = vi.fn();
		const subject = new FleetResponseCommandWorker({
			endpoint: "http://127.0.0.1:8000/functions",
			developmentLoopback: true,
			apiKey: "enrollment-secret",
			identity: { tenantId, agentId },
			installationId,
			adapter: adapter(),
			statePath,
			fetchImpl: transport([]).fetchImpl,
			onCycle,
		});
		await expect(subject.run(new AbortController().signal)).rejects.toThrow(
			"fleet_response_worker_journal_unavailable",
		);
		expect(onCycle).toHaveBeenCalledWith({
			status: "outcome_unknown",
			stage: "poll",
			reason: "journal_unavailable",
		});
	});
});
