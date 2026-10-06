import { createHmac, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, utimes, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { hashDeviceKey } from "../device-attestation.js";
import {
	type FleetResponseActionAdapter,
	type FleetResponseAuditEvent,
	type FleetResponseCommand,
	FleetResponseCommandConsumer,
	type FleetResponseSignedDelivery,
} from "../response-command-consumer-v6.js";
import { FleetResponseJournal as ProductionFleetResponseJournal } from "../response-command-journal-v6.js";
import { FleetResponseCommandWorker } from "../response-command-worker-v6.js";

const tenantId = "11111111-1111-4111-8111-111111111111";
const agentId = "22222222-2222-4222-8222-222222222222";
const installationId = "installation-test-001";
const commandId = "33333333-3333-4333-8333-333333333333";
const now = Date.parse("2026-09-13T12:00:00.000Z");
const signingKey = generateKeyPairSync("ed25519");
const rotatedSigningKey = generateKeyPairSync("ed25519");
const trustedCommandKeys = {
	"response-current": signingKey.publicKey.export({ type: "spki", format: "pem" }).toString(),
	"response-next": rotatedSigningKey.publicKey.export({ type: "spki", format: "pem" }).toString(),
};
const stableJournalKey = randomBytes(32).toString("base64");
const temporaryDirectories: string[] = [];

class FleetResponseJournal extends ProductionFleetResponseJournal {
	constructor(
		...[path, identity, apiKey, installation, stableKey, clock]: ConstructorParameters<
			typeof ProductionFleetResponseJournal
		>
	) {
		super(path, identity, apiKey, installation, stableKey, clock ?? (() => now));
	}
}

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
	actionTimeoutMs?: number,
	keys: Readonly<Record<string, string>> = trustedCommandKeys,
	options: { apiKey?: string; stableJournalKey?: string; now?: () => number } = {},
) {
	return new FleetResponseCommandWorker({
		endpoint: "http://127.0.0.1:8000/functions",
		developmentLoopback: true,
		apiKey: options.apiKey ?? "enrollment-secret",
		identity: { tenantId, agentId },
		installationId,
		trustedCommandKeys: keys,
		adapter: localAdapter,
		statePath,
		fetchImpl,
		now: options.now ?? (() => now),
		actionTimeoutMs,
		stableJournalKey: options.stableJournalKey,
	});
}

async function seedJournal(
	statePath: string,
	phase: "polled" | "acknowledged" | "execute_intent" | "result_pending",
	options: {
		delivery?: FleetResponseSignedDelivery;
		view?: FleetResponseCommand;
		stableJournalKey?: string;
	} = {},
) {
	const journal = new FleetResponseJournal(
		statePath,
		{ tenantId, agentId },
		"enrollment-secret",
		installationId,
		options.stableJournalKey,
	);
	if (options.stableJournalKey) await journal.bootstrapResponseControl();
	const state = await journal.load();
	await journal.save({
		...state,
		current: {
			command: options.view ?? typedCommand(),
			delivery: options.delivery ?? command(),
			phase,
			resultCode: null,
		},
	});
}

function canonical(value: unknown): string {
	if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
	if (value && typeof value === "object") {
		const entries = Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
		return `{${entries.map(([key, item]) => `${JSON.stringify(key)}:${canonical(item)}`).join(",")}}`;
	}
	return JSON.stringify(value);
}

function command(
	overrides: Record<string, unknown> = {},
	keyId = "response-current",
): FleetResponseSignedDelivery {
	const payload = {
		schema_version: 1,
		purpose: "aidr.fleet-response.command",
		key_id: keyId,
		tenant_id: tenantId,
		agent_id: agentId,
		installation_id: installationId,
		key_hash: hashDeviceKey("enrollment-secret"),
		id: commandId,
		command_type: "agent_pause",
		payload: {},
		created_at: new Date(now - 60_000).toISOString(),
		expires_at: new Date(now + 60_000).toISOString(),
		attempt: 1,
		rollback_of: null,
		...overrides,
	};
	return {
		alg: "ed25519",
		key_id: keyId,
		sig_b64: sign(
			null,
			Buffer.from(canonical(payload)),
			keyId === "response-next" ? rotatedSigningKey.privateKey : signingKey.privateKey,
		).toString("base64"),
		payload,
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
	keys: Readonly<Record<string, string>> = trustedCommandKeys,
) {
	return new FleetResponseCommandConsumer({
		endpoint: "http://127.0.0.1:8000/functions",
		developmentLoopback: true,
		apiKey: "enrollment-secret",
		identity: { tenantId, agentId },
		installationId,
		trustedCommandKeys: keys,
		adapter: localAdapter,
		audit,
		fetchImpl,
		now: clock,
	});
}

describe("fleet response command consumer", () => {
	it("consumes an actual server-produced payload signed with the shared canonical wire format", async () => {
		// Dynamic source URLs keep the independently deployed Edge module outside core's build root.
		const producerUrl = new URL(
			"../../../../supabase/functions/revocations/commands.ts",
			import.meta.url,
		).href;
		const canonicalUrl = new URL(
			"../../../../supabase/functions/_shared/policy-signature.ts",
			import.meta.url,
		).href;
		const { commandSigningPayload } = await import(producerUrl);
		const { canonicalJson } = await import(canonicalUrl);
		const payload = commandSigningPayload(
			{
				id: commandId,
				tenant_id: tenantId,
				agent_id: agentId,
				command_type: "agent_pause",
				created_at: new Date(now - 60_000).toISOString(),
				expires_at: new Date(now + 60_000).toISOString(),
				attempts: 1,
				rollback_of: null,
				reason: "private operator reason",
				payload: {},
			},
			{ tenantId, agentId, installationId, keyHash: hashDeviceKey("enrollment-secret") },
			"response-current",
			now,
		);
		expect(payload).not.toBeNull();
		const signingMaterial = signingKey.privateKey.export({ type: "pkcs8", format: "der" });
		const cryptoKey = await crypto.subtle.importKey(
			"pkcs8",
			new Uint8Array(signingMaterial),
			{ name: "Ed25519" },
			false,
			["sign"],
		);
		const signature = await crypto.subtle.sign(
			"Ed25519",
			cryptoKey,
			new TextEncoder().encode(canonicalJson(payload)),
		);
		const delivery = {
			alg: "ed25519",
			key_id: "response-current",
			sig_b64: Buffer.from(signature).toString("base64"),
			payload,
		};
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: delivery }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toEqual({
			status: "succeeded",
			commandId,
		});
		expect(localAdapter.execute).toHaveBeenCalledWith(
			typedCommand(),
			expect.any(AbortSignal),
			delivery,
		);
		expect(requests.map((request) => request.body.action)).toEqual(["poll", "ack", "result"]);
		expect(fetchImpl).toHaveBeenCalledWith(
			expect.anything(),
			expect.objectContaining({ redirect: "error" }),
		);
		expect(JSON.stringify(delivery)).not.toContain("private operator reason");
	});

	it("requires installed signing trust without a development bypass", () => {
		expect(() => consumer(transport([]).fetchImpl, undefined, () => now, undefined, {})).toThrow(
			"missing_fleet_command_trust",
		);
	});

	it("rejects legacy unsigned replies without acknowledging them", async () => {
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([json({ ok: true, command: command().payload })]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toEqual({
			status: "outcome_unknown",
			stage: "poll",
			reason: "invalid_poll_response",
		});
		expect(requests).toHaveLength(1);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it.each([
		["tenant_id", tenantId],
		["agent_id", agentId],
		["installation_id", installationId],
		["key_hash", hashDeviceKey("enrollment-secret")],
		["created_at", new Date(now).toISOString()],
		["expires_at", new Date(now + 60_000).toISOString()],
		["rollback_of", null],
		["attempt", 1],
	])("requires the signed %s field", async (field, _expectedValue) => {
		const signed = command();
		delete (signed.payload as Record<string, unknown>)[field as string];
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([json({ ok: true, command_signed: signed })]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toMatchObject({
			status: "invalid_command",
		});
		expect(requests).toHaveLength(1);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it.each([
		["id", tenantId],
		["command_type", "network_isolate"],
		["attempt", 2],
		["rollback_of", tenantId],
		["tenant_id", agentId],
		["agent_id", tenantId],
		["installation_id", "another-installation"],
		["key_hash", "f".repeat(64)],
		["created_at", new Date(now - 30_000).toISOString()],
		["expires_at", new Date(now + 90_000).toISOString()],
	])("rejects tampered %s before acknowledgement or action", async (field, replacement) => {
		const signed = command();
		(signed.payload as Record<string, unknown>)[field] = replacement;
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([json({ ok: true, command_signed: signed })]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toEqual({
			status: "invalid_command",
			reason: "invalid_command_signature",
		});
		expect(requests).toHaveLength(1);
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect(localAdapter.verify).not.toHaveBeenCalled();
	});

	it.each([
		[{ tenant_id: agentId }, "tenant_mismatch"],
		[{ agent_id: tenantId }, "agent_mismatch"],
		[{ installation_id: "another-installation" }, "installation_mismatch"],
		[{ key_hash: hashDeviceKey("retired-enrollment-secret") }, "credential_mismatch"],
		[{ payload: { script: "untrusted" } }, "invalid_command_payload"],
		[{ extra: true }, "invalid_command_payload"],
		[{ purpose: "aidr.policy" }, "invalid_command_payload"],
		[{ created_at: new Date(now + 60_001).toISOString() }, "invalid_created_at"],
		[{ created_at: "2026-02-30T00:00:00.000Z" }, "invalid_created_at"],
		[{ expires_at: new Date(now + 3_600_000).toISOString() }, "invalid_command_lifetime"],
		[{ expires_at: new Date(now - 60_000).toISOString() }, "invalid_command_lifetime"],
		[{ attempt: 6 }, "invalid_attempt"],
		[{ command_type: "shell" }, "unsupported_command_type"],
		[{ command_type: "agent_resume", rollback_of: commandId }, "invalid_rollback_reference"],
	])("rejects an authentic but invalid command %j", async (overrides, reason) => {
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command(overrides) }),
		]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toEqual({
			status: "invalid_command",
			reason,
		});
		expect(requests).toHaveLength(1);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("binds a signature to its configured signer ID, including key rotation", async () => {
		for (const keyId of ["response-current", "response-next"]) {
			const { fetchImpl } = transport([
				json({ ok: true, command_signed: command({}, keyId) }),
				json({ ok: true, command_id: commandId, state: "acknowledged" }),
				json({ ok: true, command_id: commandId, state: "succeeded" }),
			]);
			expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
				status: "succeeded",
				commandId,
			});
		}
		const { fetchImpl, requests } = transport([json({ ok: true, command_signed: command() })]);
		expect(
			await consumer(fetchImpl, adapter(), () => now, undefined, {
				"response-current": trustedCommandKeys["response-next"],
			}).pollOnce(),
		).toEqual({
			status: "invalid_command",
			reason: "invalid_command_signature",
		});
		expect(requests).toHaveLength(1);
	});

	it("rejects an unknown signer and differing inner/outer signer IDs", async () => {
		for (const signed of [
			command({}, "unknown-signer"),
			{ ...command(), key_id: "response-next" },
		]) {
			const localAdapter = adapter();
			const { fetchImpl, requests } = transport([json({ ok: true, command_signed: signed })]);
			expect(await consumer(fetchImpl, localAdapter).pollOnce()).toMatchObject({
				status: "invalid_command",
			});
			expect(requests).toHaveLength(1);
			expect(localAdapter.execute).not.toHaveBeenCalled();
		}
	});

	it("does not repeat a signed command on a later delivery attempt", async () => {
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "succeeded" }),
			json({ ok: true, command_signed: command({ attempt: 2 }) }),
		]);
		const client = consumer(fetchImpl, localAdapter);
		expect(await client.pollOnce()).toEqual({ status: "succeeded", commandId });
		expect(await client.pollOnce()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "poll",
			reason: "replayed_command_id",
		});
		expect(localAdapter.execute).toHaveBeenCalledOnce();
		expect(requests).toHaveLength(4);
	});

	it("keeps an ambiguous acknowledgement from becoming a second execution attempt", async () => {
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command() }),
			json({ ok: true, command_id: commandId, state: "delivered" }),
			json({ ok: true, command_signed: command({ attempt: 2 }) }),
		]);
		const client = consumer(fetchImpl, localAdapter);
		expect(await client.pollOnce()).toMatchObject({ reason: "ack_unconfirmed" });
		expect(await client.pollOnce()).toMatchObject({ reason: "replayed_command_id" });
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect(requests).toHaveLength(3);
	});

	it("allows only one consumer cycle at a time", async () => {
		let resolvePoll: (response: Response) => void = () => {};
		const fetchImpl = vi.fn(
			() =>
				new Promise<Response>((resolve) => {
					resolvePoll = resolve;
				}),
		) as typeof fetch;
		const client = consumer(fetchImpl, adapter());
		const pending = client.pollOnce();
		expect(await client.pollOnce()).toEqual({
			status: "outcome_unknown",
			stage: "poll",
			reason: "cycle_in_progress",
		});
		resolvePoll(json({ ok: true, command_signed: null }));
		expect(await pending).toEqual({ status: "idle" });
		expect(fetchImpl).toHaveBeenCalledOnce();
	});

	it("rejects insecure remote transport and an adapter for another device", () => {
		expect(
			() =>
				new FleetResponseCommandConsumer({
					endpoint: "http://customer.example/functions",
					apiKey: "secret",
					identity: { tenantId, agentId },
					installationId,
					trustedCommandKeys,
				}),
		).toThrow("fleet_endpoint_requires_https");
		expect(
			() =>
				new FleetResponseCommandConsumer({
					endpoint: "https://customer.example/functions",
					apiKey: "secret",
					identity: { tenantId, agentId },
					installationId,
					trustedCommandKeys,
					adapter: adapter({ identity: { tenantId, agentId: tenantId } }),
				}),
		).toThrow("fleet_adapter_identity_mismatch");
	});

	it("does not execute without an installed adapter and records a rejection", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command() }),
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
		const { fetchImpl } = transport([json({ ok: true, command_signed: null })]);
		const audit = vi.fn(async (event: FleetResponseAuditEvent) => {
			expect(event.attestation.installationId).toBe(installationId);
			expect(event.attestation.keyHash).toBe(hashDeviceKey("enrollment-secret"));
			throw new Error("audit sink unavailable");
		});
		expect(await consumer(fetchImpl, undefined, () => now, audit).pollOnce()).toEqual({
			status: "idle",
		});
		expect(audit).toHaveBeenCalledOnce();
	});

	it("does not reuse a credential after a definitive control-plane rejection", async () => {
		const { fetchImpl, requests } = transport([json({ error: "invalid_api_key" }, 401)]);
		const client = consumer(fetchImpl);
		const rejected = { status: "access_rejected", stage: "poll", code: "http_401" } as const;
		expect(await client.pollOnce()).toEqual(rejected);
		expect(await client.pollOnce()).toEqual(rejected);
		expect(requests).toHaveLength(1);
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
			json({ ok: true, command_signed: command() }),
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
			json({ ok: true, command_signed: command() }),
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

	it("preserves uncertainty when verification cannot observe an applied action", async () => {
		const localAdapter = adapter({
			verify: vi.fn(async () => ({ observed: false, code: "not_observed" })),
		});
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
		]);
		expect(await consumer(fetchImpl, localAdapter).pollOnce()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "result",
			reason: "execution_state_unverified",
		});
		expect(requests.map((request) => request.body.action)).toEqual(["poll", "ack"]);
	});

	it("does not execute if TTL expires after ACK", async () => {
		let observedTime = now;
		const localAdapter = adapter();
		const fetchImpl = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			const action = (JSON.parse(String(init?.body)) as Record<string, unknown>).action;
			if (action === "poll") return json({ ok: true, command_signed: command() });
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
			json({ ok: true, command_signed: command({ agent_id: tenantId }) }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "invalid_command",
			reason: "agent_mismatch",
		});
		expect(requests).toHaveLength(1);
	});

	it("rejects a forged reverse action without its rollback reference", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command({ command_type: "network_release" }) }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "invalid_command",
			reason: "rollback_reference_mismatch",
		});
		expect(requests).toHaveLength(1);
	});

	it("does not acknowledge a command already expired on receipt", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command({ expires_at: new Date(now - 1).toISOString() }) }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "expired",
			commandId,
		});
		expect(requests).toHaveLength(1);
	});

	it("does not report success if the result receipt is not confirmed", async () => {
		const { fetchImpl } = transport([
			json({ ok: true, command_signed: command() }),
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

	it("keeps the outcome unknown if a revoked key prevents recording the verified action", async () => {
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ error: "invalid_api_key" }, 401),
		]);
		const client = consumer(fetchImpl, localAdapter);
		expect(await client.pollOnce()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "result",
			reason: "access_rejected_after_execution",
		});
		expect(localAdapter.execute).toHaveBeenCalledOnce();
		expect(localAdapter.verify).toHaveBeenCalledOnce();
		expect(await client.pollOnce()).toMatchObject({ status: "access_rejected", stage: "poll" });
		expect(requests).toHaveLength(3);
	});

	it("rejects oversized poll data before inspecting a command", async () => {
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command(), padding: "x".repeat(9000) }),
		]);
		expect(await consumer(fetchImpl, adapter()).pollOnce()).toEqual({
			status: "outcome_unknown",
			stage: "poll",
			reason: "poll_unavailable",
		});
		expect(requests).toHaveLength(1);
	});

	it("stops its service loop after a definitive API-key rejection", async () => {
		const { fetchImpl, requests } = transport([json({ error: "invalid_api_key" }, 401)]);
		const instance = worker(await journalPath(), fetchImpl);
		await expect(instance.run(new AbortController().signal)).rejects.toThrow(
			"fleet_response_worker_access_rejected",
		);
		expect(requests).toHaveLength(1);
	});
});

describe("durable fleet response worker", () => {
	it("records one bounded bootstrap grace without extending it on reinstall", async () => {
		const statePath = await journalPath();
		let clock = now - 180_000;
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
			() => clock,
		);
		const initial = await journal.bootstrapResponseControl();
		expect(initial.bootstrap_at).toBe(new Date(clock).toISOString());
		expect(initial.last_successful_poll_at).toBeNull();
		clock = now;
		expect(await journal.bootstrapResponseControl()).toEqual(initial);
	});

	it("persists a successful idle poll before returning and keeps the original bootstrap", async () => {
		const statePath = await journalPath();
		let clock = now - 180_000;
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
			() => clock,
		);
		const initial = await journal.bootstrapResponseControl();
		clock = now;
		const localAdapter = adapter();
		const { fetchImpl } = transport([json({ ok: true, command_signed: null })]);
		expect(
			await worker(statePath, fetchImpl, localAdapter, undefined, trustedCommandKeys, {
				stableJournalKey,
				now: () => clock,
			}).tick(),
		).toEqual({ status: "idle" });
		const persisted = await journal.inspect();
		expect(persisted?.last_successful_poll_at).toBe(new Date(clock).toISOString());
		expect(persisted?.bootstrap_at).toBe(initial.bootstrap_at);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it.each([
		["network", () => transport([]).fetchImpl],
		["server", () => transport([json({ error: "unavailable" }, 500)]).fetchImpl],
		["unauthorized", () => transport([json({ error: "invalid_api_key" }, 401)]).fetchImpl],
		["forbidden", () => transport([json({ error: "forbidden" }, 403)]).fetchImpl],
		["schema", () => transport([json({ ok: true })]).fetchImpl],
		[
			"signature",
			() =>
				transport([
					json({ ok: true, command_signed: { ...command(), sig_b64: "A".repeat(86) + "==" } }),
				]).fetchImpl,
		],
		[
			"identity",
			() =>
				transport([json({ ok: true, command_signed: command({ tenant_id: agentId }) })]).fetchImpl,
		],
		[
			"expired",
			() =>
				transport([
					json({ ok: true, command_signed: command({ expires_at: new Date(now).toISOString() }) }),
				]).fetchImpl,
		],
	] as const)("does not renew freshness after a %s poll failure", async (_name, fetchFactory) => {
		const statePath = await journalPath();
		let clock = now - 180_000;
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
			() => clock,
		);
		const initial = await journal.bootstrapResponseControl();
		const prior = await journal.save({ ...initial, last_successful_poll_at: initial.bootstrap_at });
		clock = now;
		const localAdapter = adapter();
		const result = await worker(
			statePath,
			fetchFactory(),
			localAdapter,
			undefined,
			trustedCommandKeys,
			{ stableJournalKey, now: () => clock },
		).tick();
		expect(result.status).not.toBe("idle");
		expect(await journal.inspect()).toEqual(prior);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("persists a new signed poll before execution even when its result receipt fails", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
		);
		await journal.bootstrapResponseControl();
		const localAdapter = adapter({
			execute: vi.fn(async () => {
				const persisted = await journal.inspect();
				expect(persisted?.last_successful_poll_at).toBe(new Date(now).toISOString());
				expect(persisted?.current?.phase).toBe("execute_intent");
				return { ok: true as const };
			}),
		});
		const { fetchImpl } = transport([
			json({ ok: true, command_signed: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ error: "unavailable" }, 500),
		]);
		expect(
			await worker(statePath, fetchImpl, localAdapter, undefined, trustedCommandKeys, {
				stableJournalKey,
			}).tick(),
		).toMatchObject({ status: "outcome_unknown", stage: "result" });
		expect(localAdapter.execute).toHaveBeenCalledOnce();
		expect((await journal.inspect())?.last_successful_poll_at).toBe(new Date(now).toISOString());
	});

	it.each(["polled", "acknowledged", "execute_intent", "result_pending"] as const)(
		"does not renew freshness when recovering %s state",
		async (phase) => {
			const statePath = await journalPath();
			let clock = now - 180_000;
			const journal = new FleetResponseJournal(
				statePath,
				{ tenantId, agentId },
				"enrollment-secret",
				installationId,
				stableJournalKey,
				() => clock,
			);
			const initial = await journal.bootstrapResponseControl();
			await journal.save({
				...initial,
				last_successful_poll_at: initial.bootstrap_at,
				current: { command: typedCommand(), delivery: command(), phase, resultCode: null },
			});
			clock = now;
			const responses = [json({ ok: true, command_id: commandId, state: "succeeded" })];
			if (phase === "polled")
				responses.unshift(json({ ok: true, command_id: commandId, state: "acknowledged" }));
			const { fetchImpl, requests } = transport(responses);
			expect(
				await worker(statePath, fetchImpl, adapter(), undefined, trustedCommandKeys, {
					stableJournalKey,
					now: () => clock,
				}).tick(),
			).toEqual({ status: "succeeded", commandId });
			expect(requests.every((request) => request.body.action !== "poll")).toBe(true);
			expect((await journal.inspect())?.last_successful_poll_at).toBe(initial.bootstrap_at);
		},
	);

	it.each([
		["bootstrap_at", undefined],
		["bootstrap_at", null],
		["bootstrap_at", "1970-01-01T00:00:00.000Z"],
		["bootstrap_at", new Date(now + 1).toISOString()],
		["bootstrap_at", "2026-09-13T12:00:00Z"],
		["last_successful_poll_at", undefined],
		["last_successful_poll_at", "1970-01-01T00:00:00.000Z"],
		["last_successful_poll_at", new Date(now - 1).toISOString()],
		["last_successful_poll_at", new Date(now + 1).toISOString()],
	] as const)("rejects invalid authenticated freshness %s=%s", async (field, value) => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
		);
		const initial = await journal.bootstrapResponseControl();
		const invalid = { ...initial, [field]: value };
		if (value === undefined) Reflect.deleteProperty(invalid, field);
		await expect(journal.save(invalid)).rejects.toThrow("invalid_fleet_journal_state");
		await writeFile(
			`${statePath}.a`,
			JSON.stringify({
				payload: invalid,
				mac: createHmac("sha256", stableJournalKey).update(canonical(invalid)).digest("hex"),
			}),
		);
		await expect(journal.inspect()).rejects.toThrow("invalid_fleet_journal_state");
	});

	it("does not move a successful poll checkpoint backwards when the clock changes during polling", async () => {
		const statePath = await journalPath();
		let clock = now - 180_000;
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
			() => clock,
		);
		const initial = await journal.bootstrapResponseControl();
		clock = now;
		const prior = await journal.save({
			...initial,
			last_successful_poll_at: new Date(now).toISOString(),
		});
		const fetchImpl = vi.fn(async () => {
			clock = now - 1;
			return json({ ok: true, command_signed: null });
		}) as typeof fetch;
		expect(
			await worker(statePath, fetchImpl, adapter(), undefined, trustedCommandKeys, {
				stableJournalKey,
				now: () => clock,
			}).tick(),
		).toEqual({ status: "outcome_unknown", stage: "poll", reason: "journal_unavailable" });
		clock = now;
		expect(await journal.inspect()).toEqual(prior);
	});

	it.each([0, NaN, Infinity])("rejects an invalid journal clock %s", async (invalidClock) => {
		const statePath = await journalPath();
		let clock = now;
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
			() => clock,
		);
		await journal.bootstrapResponseControl();
		clock = invalidClock;
		await expect(journal.inspect()).rejects.toThrow("invalid_fleet_journal_state");
	});

	it("preserves still-valid replay IDs beyond the former 256-command cursor", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
		const state = await journal.load();
		const ids = [
			commandId,
			...Array.from(
				{ length: 300 },
				(_, index) => `${index.toString(16).padStart(8, "0")}-aaaa-4aaa-8aaa-aaaaaaaaaaaa`,
			),
		];
		await journal.save({
			...state,
			recent_ids: ids,
			recent_expiries: Object.fromEntries(
				ids.map((id) => [id, new Date(now + 60_000).toISOString()]),
			),
		});
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command({ attempt: 2 }) }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "poll",
			reason: "replayed_command_id",
		});
		expect(requests).toHaveLength(1);
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect((await journal.inspect())?.last_successful_poll_at).toBeNull();
	});

	it("fails closed when all 1024 replay entries remain valid, then prunes only expired entries", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
		const state = await journal.load();
		const ids = Array.from(
			{ length: 1024 },
			(_, index) => `${index.toString(16).padStart(8, "0")}-aaaa-4aaa-8aaa-aaaaaaaaaaaa`,
		);
		const full = await journal.save({
			...state,
			recent_ids: ids,
			recent_expiries: Object.fromEntries(
				ids.map((id) => [id, new Date(now + 60_000).toISOString()]),
			),
		});
		const { fetchImpl, requests } = transport([json({ ok: true, command_signed: null })]);
		const subject = worker(statePath, fetchImpl);
		expect(await subject.tick()).toEqual({
			status: "outcome_unknown",
			stage: "poll",
			reason: "command_replay_cache_full",
		});
		expect(requests).toHaveLength(0);
		await journal.save({
			...full,
			recent_expiries: {
				...full.recent_expiries,
				[ids[0] as string]: new Date(now - 1).toISOString(),
			},
		});
		expect(await subject.tick()).toEqual({ status: "idle" });
		expect(requests).toHaveLength(1);
	});

	it("never unpauses a retained control head when the signed command TTL expires", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
		const state = await journal.load();
		const pause = command({ expires_at: new Date(now - 1).toISOString() });
		await journal.save({
			...state,
			response_control: { status: "paused", pause_delivery: pause, resume_delivery: null },
		});
		const { fetchImpl } = transport([json({ ok: true, command_signed: null })]);
		expect(await worker(statePath, fetchImpl).tick()).toEqual({ status: "idle" });
		expect((await journal.inspect())?.response_control).toEqual({
			status: "paused",
			pause_delivery: pause,
			resume_delivery: null,
		});
	});

	it("inspects a missing journal without creating directories or locks", async () => {
		const prefix = await journalPath();
		const statePath = join(prefix, "missing", "state");
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
		);
		expect(await journal.inspect()).toBeNull();
		expect(await readdir(join(prefix, ".."))).toEqual([]);
	});

	it("requires explicit operator bootstrap and preserves existing control on reinstall", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
		);
		await expect(journal.load()).rejects.toThrow("fleet_journal_bootstrap_required");
		const initial = await journal.bootstrapResponseControl();
		expect(initial.response_control).toEqual({
			status: "running",
			pause_delivery: null,
			resume_delivery: null,
		});
		const pause = command();
		const paused = await journal.save({
			...initial,
			response_control: { status: "paused", pause_delivery: pause, resume_delivery: null },
		});
		expect(await journal.bootstrapResponseControl()).toEqual(paused);
		expect(await journal.inspect()).toEqual(paused);
		const persisted = await readFile(`${statePath}.b`, "utf8");
		expect(persisted).not.toContain(stableJournalKey);
		expect(persisted).not.toContain("enrollment-secret");
	});

	it("does not bootstrap over corrupt required state or a lost vault secret", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
		);
		await journal.bootstrapResponseControl();
		const otherKey = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			randomBytes(32).toString("base64"),
		);
		await expect(otherKey.bootstrapResponseControl()).rejects.toThrow(
			"fleet_journal_integrity_failed",
		);
		await writeFile(`${statePath}.a`, "corrupt");
		await expect(journal.inspect()).rejects.toThrow();
		await expect(journal.bootstrapResponseControl()).rejects.toThrow();
		expect(await readFile(`${statePath}.a`, "utf8")).toBe("corrupt");
	});

	it("retains historical pause across bearer rotation only with the stable private MAC secret", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
		);
		const initial = await journal.bootstrapResponseControl();
		const paused = await journal.save({
			...initial,
			response_control: { status: "paused", pause_delivery: command(), resume_delivery: null },
		});
		const rotated = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"new-enrollment-secret",
			installationId,
			stableJournalKey,
		);
		expect(await rotated.inspect()).toEqual(paused);
		const withoutStableKey = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"new-enrollment-secret",
			installationId,
		);
		await expect(withoutStableKey.inspect()).rejects.toThrow("fleet_journal_integrity_failed");
		const otherInstallation = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"new-enrollment-secret",
			"other-installation",
			stableJournalKey,
		);
		await expect(otherInstallation.inspect()).rejects.toThrow("invalid_fleet_journal_state");
	});

	it("keeps signed pause and matching resume evidence after both result receipts drain", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
		);
		await journal.bootstrapResponseControl();
		const resumeId = "99999999-9999-4999-8999-999999999999";
		const pause = command();
		const resume = command({
			id: resumeId,
			command_type: "agent_resume",
			rollback_of: commandId,
			created_at: new Date(now).toISOString(),
		});
		const localAdapter = adapter({ supportedCommands: ["agent_pause", "agent_resume"] });
		const { fetchImpl } = transport([
			json({ ok: true, command_signed: pause }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "succeeded" }),
			json({ ok: true, command_signed: resume }),
			json({ ok: true, command_id: resumeId, state: "acknowledged" }),
			json({ ok: true, command_id: resumeId, state: "succeeded" }),
		]);
		const subject = worker(statePath, fetchImpl, localAdapter, undefined, trustedCommandKeys, {
			stableJournalKey,
		});
		expect(await subject.tick()).toEqual({ status: "succeeded", commandId });
		const paused = await journal.inspect();
		expect(paused?.current).toBeNull();
		expect(paused?.response_control).toEqual({
			status: "paused",
			pause_delivery: pause,
			resume_delivery: null,
		});
		expect(await subject.tick()).toEqual({ status: "succeeded", commandId: resumeId });
		const running = await journal.inspect();
		expect(running?.current).toBeNull();
		expect(running?.response_control).toEqual({
			status: "running",
			pause_delivery: pause,
			resume_delivery: resume,
		});
	});

	it("rejects resume without the matching local paused command", async () => {
		const statePath = await journalPath();
		const localAdapter = adapter({ supportedCommands: ["agent_resume"] });
		const { fetchImpl, requests } = transport([
			json({
				ok: true,
				command_signed: command({ command_type: "agent_resume", rollback_of: tenantId }),
			}),
			json({ ok: true, command_id: commandId, state: "failed" }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "rejected",
			commandId,
			code: "rollback_state_mismatch",
		});
		expect(requests.map((request) => request.body.action)).toEqual(["poll", "ack"]);
		expect(requests[1]?.body.outcome).toBe("rejected");
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("rejects an older signed resume before any action on the current pause", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
		const state = await journal.load();
		await journal.save({
			...state,
			response_control: { status: "paused", pause_delivery: command(), resume_delivery: null },
		});
		const resumeId = "99999999-9999-4999-8999-999999999999";
		const localAdapter = adapter({ supportedCommands: ["agent_resume"] });
		const { fetchImpl, requests } = transport([
			json({
				ok: true,
				command_signed: command({
					id: resumeId,
					command_type: "agent_resume",
					rollback_of: commandId,
					created_at: new Date(now - 120_000).toISOString(),
				}),
			}),
			json({ ok: true, command_id: resumeId, state: "failed" }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "rejected",
			commandId: resumeId,
			code: "rollback_state_mismatch",
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect(requests[1]?.body.outcome).toBe("rejected");
		expect((await journal.inspect())?.response_control.status).toBe("paused");
	});

	it.each(["execute", "verify"] as const)(
		"keeps native %s ambiguity as persisted execution intent",
		async (stage) => {
			const statePath = await journalPath();
			await seedJournal(statePath, "acknowledged");
			const localAdapter = adapter(
				stage === "execute"
					? {
							execute: vi.fn(async () => ({ ok: false, code: "native_action_outcome_unknown" })),
						}
					: {
							verify: vi.fn(async () => ({
								observed: false,
								code: "native_action_outcome_unknown",
							})),
						},
			);
			const { fetchImpl, requests } = transport([]);
			expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
				status: "outcome_unknown",
				commandId,
				stage: "result",
				reason: "execution_state_unverified",
			});
			const saved = await new FleetResponseJournal(
				statePath,
				{ tenantId, agentId },
				"enrollment-secret",
				installationId,
			).inspect();
			expect(saved?.current?.phase).toBe("execute_intent");
			expect(saved?.current?.delivery).toEqual(command());
			expect(requests).toHaveLength(0);
		},
	);

	it.each(["false", "throw"] as const)(
		"retains intent after a successful apply followed by generic verification %s",
		async (failure) => {
			const statePath = await journalPath();
			await seedJournal(statePath, "acknowledged");
			const localAdapter = adapter({
				verify: vi.fn(async () => {
					if (failure === "throw") throw new Error("host state read failed");
					return { observed: false, code: "firewall_owned_rule_not_enforced" };
				}),
			});
			const { fetchImpl, requests } = transport([]);
			expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
				status: "outcome_unknown",
				commandId,
				stage: "result",
				reason: "execution_state_unverified",
			});
			const journal = new FleetResponseJournal(
				statePath,
				{ tenantId, agentId },
				"enrollment-secret",
				installationId,
			);
			expect((await journal.inspect())?.current?.phase).toBe("execute_intent");
			expect(localAdapter.execute).toHaveBeenCalledOnce();
			expect(requests).toHaveLength(0);

			const recoveryAdapter = adapter();
			const recovered = transport([json({ ok: true, command_id: commandId, state: "succeeded" })]);
			expect(await worker(statePath, recovered.fetchImpl, recoveryAdapter).tick()).toEqual({
				status: "succeeded",
				commandId,
			});
			expect(recoveryAdapter.execute).not.toHaveBeenCalled();
			expect(recoveryAdapter.verify).toHaveBeenCalledOnce();
			expect(recovered.requests.map((request) => request.body.action)).toEqual(["result"]);
			expect((await journal.inspect())?.response_control.status).toBe("paused");
		},
	);

	it("still records a definite execution preflight refusal without invoking verification", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "acknowledged");
		const localAdapter = adapter({
			execute: vi.fn(async () => ({ ok: false, code: "preflight_refused" })),
		});
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_id: commandId, state: "failed" }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "failed",
			commandId,
			code: "preflight_refused",
		});
		expect(localAdapter.verify).not.toHaveBeenCalled();
		expect(requests[0]?.body).toMatchObject({
			action: "result",
			outcome: "failed",
			result_code: "preflight_refused",
		});
		const saved = await new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		).inspect();
		expect(saved?.current).toBeNull();
		expect(saved?.response_control.status).toBe("running");
	});

	it("rejects a historical credential on a fresh command after stable-journal bearer rotation", async () => {
		const statePath = await journalPath();
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
			stableJournalKey,
		);
		await journal.bootstrapResponseControl();
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([json({ ok: true, command_signed: command() })]);
		expect(
			await worker(statePath, fetchImpl, localAdapter, undefined, trustedCommandKeys, {
				apiKey: "new-enrollment-secret",
				stableJournalKey,
			}).tick(),
		).toEqual({
			status: "invalid_command",
			reason: "credential_mismatch",
		});
		expect(requests).toHaveLength(1);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it.each(["polled", "acknowledged"] as const)(
		"revalidates the signature before resuming %s",
		async (phase) => {
			const statePath = await journalPath();
			const delivery = { ...command(), sig_b64: Buffer.alloc(64).toString("base64") };
			await seedJournal(statePath, phase, { delivery });
			const localAdapter = adapter();
			const { fetchImpl, requests } = transport([]);
			expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
				status: "invalid_command",
				reason: "invalid_command_signature",
			});
			expect(requests).toHaveLength(0);
			expect(localAdapter.execute).not.toHaveBeenCalled();
			expect(localAdapter.verify).not.toHaveBeenCalled();
		},
	);

	it("rejects a retired signing key before resuming a saved acknowledgement", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "acknowledged");
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([]);
		expect(
			await worker(statePath, fetchImpl, localAdapter, undefined, {
				"response-next": trustedCommandKeys["response-next"],
			}).tick(),
		).toEqual({
			status: "invalid_command",
			reason: "unknown_command_signing_key",
		});
		expect(requests).toHaveLength(0);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("fails closed on a legacy unsigned journal even when its local MAC is valid", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "polled");
		const envelope = JSON.parse(await readFile(`${statePath}.a`, "utf8"));
		delete envelope.payload.current.delivery;
		envelope.mac = createHmac("sha256", "enrollment-secret")
			.update(canonical(envelope.payload))
			.digest("hex");
		await writeFile(`${statePath}.a`, JSON.stringify(envelope));
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "outcome_unknown",
			stage: "poll",
			reason: "journal_unavailable",
		});
		expect(requests).toHaveLength(0);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("clears an expired never-acknowledged cursor without blocking subsequent polls", async () => {
		const statePath = await journalPath();
		const expiresAt = new Date(now - 1).toISOString();
		await seedJournal(statePath, "polled", {
			delivery: command({ expires_at: expiresAt }),
			view: { ...typedCommand(), expiresAt },
		});
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([json({ ok: true, command_signed: null })]);
		const subject = worker(statePath, fetchImpl, localAdapter);
		expect(await subject.tick()).toEqual({ status: "expired", commandId });
		expect(await subject.tick()).toEqual({ status: "idle" });
		expect(requests.map((request) => request.body.action)).toEqual(["poll"]);
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("observes an expired execution intent and reports the actual state without repeating execution", async () => {
		const statePath = await journalPath();
		const expiresAt = new Date(now - 1).toISOString();
		const delivery = command({ expires_at: expiresAt });
		await seedJournal(statePath, "execute_intent", {
			delivery,
			view: { ...typedCommand(), expiresAt },
		});
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await worker(statePath, fetchImpl, localAdapter).tick()).toEqual({
			status: "succeeded",
			commandId,
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
		expect(localAdapter.verify).toHaveBeenCalledWith(
			{ ...typedCommand(), expiresAt },
			expect.any(AbortSignal),
			delivery,
		);
		expect(requests.map((request) => request.body.action)).toEqual(["result"]);
	});

	it("persists a completed command cursor and never executes a replay", async () => {
		const statePath = await journalPath();
		const localAdapter = adapter();
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_signed: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
			json({ ok: true, command_id: commandId, state: "succeeded" }),
			json({ ok: true, command_signed: command({ attempt: 2 }) }),
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

	it("does not execute a freshly polled command after its supervisor aborts during acknowledgement", async () => {
		const statePath = await journalPath();
		const abort = new AbortController();
		const localAdapter = adapter();
		const responses = [
			json({ ok: true, command_signed: command() }),
			json({ ok: true, command_id: commandId, state: "acknowledged" }),
		];
		const fetchImpl = vi.fn(async (_input: string | URL | Request, init?: RequestInit) => {
			const body = JSON.parse(String(init?.body)) as { action?: string };
			const response = responses.shift();
			if (!response) throw new Error("unexpected_request");
			if (body.action === "ack") abort.abort();
			return response;
		}) as typeof fetch;

		expect(await worker(statePath, fetchImpl, localAdapter).tick(abort.signal)).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "result",
			reason: "execution_state_unverified",
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
	});

	it("does not execute a persisted polled command after its supervisor aborts during acknowledgement", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "polled");
		const abort = new AbortController();
		const localAdapter = adapter();
		const fetchImpl = vi.fn(async () => {
			abort.abort();
			return json({ ok: true, command_id: commandId, state: "acknowledged" });
		}) as typeof fetch;

		expect(await worker(statePath, fetchImpl, localAdapter).tick(abort.signal)).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "result",
			reason: "execution_state_unverified",
		});
		expect(localAdapter.execute).not.toHaveBeenCalled();
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

	it("bounds execute and preserves intent when the side effect outcome is unknown", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "acknowledged");
		let actionSignal: AbortSignal | undefined;
		const localAdapter = adapter({
			execute: vi.fn(async (_command, signal) => {
				actionSignal = signal;
				return new Promise<{ ok: true }>((resolve) => {
					signal?.addEventListener("abort", () => resolve({ ok: true }), { once: true });
				});
			}),
		});
		const { fetchImpl, requests } = transport([]);
		expect(await worker(statePath, fetchImpl, localAdapter, 100).tick()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "result",
			reason: "execution_state_unverified",
		});
		expect(actionSignal?.aborted).toBe(true);
		expect(localAdapter.verify).not.toHaveBeenCalled();
		expect(requests).toHaveLength(0);
		const saved = await new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		).load();
		expect(saved.current?.phase).toBe("execute_intent");
	});

	it("bounds recovery verification without replaying the host action", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "execute_intent");
		let actionSignal: AbortSignal | undefined;
		const localAdapter = adapter({
			verify: vi.fn(async (_command, signal) => {
				actionSignal = signal;
				return new Promise<never>(() => {});
			}),
		});
		const { fetchImpl, requests } = transport([]);
		expect(await worker(statePath, fetchImpl, localAdapter, 100).tick()).toEqual({
			status: "outcome_unknown",
			commandId,
			stage: "result",
			reason: "execution_state_unverified",
		});
		expect(actionSignal?.aborted).toBe(true);
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
			json({ ok: true, command_signed: command() }),
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
			json({ ok: true, command_signed: command() }),
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
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
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
		await writeFile(`${statePath}.lock.recovery`, "crashed recovery generation");
		await writeFile(
			`${statePath}.lock`,
			JSON.stringify({
				pid: 2147483647,
				host: hostname(),
				token: "44444444-4444-4444-8444-444444444444",
				process_started_at_ms: 0,
			}),
		);
		const { fetchImpl, requests } = transport([
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await worker(statePath, fetchImpl).tick()).toEqual({ status: "succeeded", commandId });
		expect(requests).toHaveLength(1);
		const wrongKeyJournal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"other-key",
			installationId,
		);
		await expect(wrongKeyJournal.load()).rejects.toThrow("fleet_journal_integrity_failed");
	});

	it("recovers a reused same PID only when its process-start marker is stale", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "result_pending");
		const token = "55555555-5555-4555-8555-555555555555";
		const lockPath = `${statePath}.lock`;
		await mkdir(lockPath);
		await writeFile(
			join(lockPath, `owner.${token}.json`),
			JSON.stringify({ pid: process.pid, host: hostname(), token, process_started_at_ms: 0 }),
		);
		const { fetchImpl } = transport([
			json({ ok: true, command_id: commandId, state: "succeeded" }),
		]);
		expect(await worker(statePath, fetchImpl).tick()).toEqual({ status: "succeeded", commandId });
	});

	it("fails closed on an ownerless lock directory left by an acquisition crash", async () => {
		const statePath = await journalPath();
		const lockPath = `${statePath}.lock`;
		await mkdir(lockPath);
		const stale = new Date(Date.now() - 60_000);
		await utimes(lockPath, stale, stale);
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
		await expect(journal.withLock(async () => undefined)).rejects.toThrow("fleet_journal_locked");
		expect(await readdir(lockPath)).toEqual([]);
	});

	it("fails closed on an aged malformed owner marker", async () => {
		const statePath = await journalPath();
		const lockPath = `${statePath}.lock`;
		const token = "77777777-7777-4777-8777-777777777777";
		await mkdir(lockPath);
		await writeFile(join(lockPath, `owner.${token}.json`), "{partial");
		const stale = new Date(Date.now() - 60_000);
		await utimes(lockPath, stale, stale);
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
		await expect(journal.withLock(async () => undefined)).rejects.toThrow(
			"fleet_journal_lock_invalid",
		);
		expect(await readFile(join(lockPath, `owner.${token}.json`), "utf8")).toBe("{partial");
	});

	it("does not reclaim a dead PID lock from another host", async () => {
		const statePath = await journalPath();
		const lockPath = `${statePath}.lock`;
		const token = "88888888-8888-4888-8888-888888888888";
		await mkdir(lockPath);
		const ownerPath = join(lockPath, `owner.${token}.json`);
		await writeFile(
			ownerPath,
			JSON.stringify({
				pid: 2_147_483_647,
				host: `${hostname()}-other`,
				token,
				process_started_at_ms: 0,
			}),
		);
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
		await expect(journal.withLock(async () => undefined)).rejects.toThrow("fleet_journal_locked");
		expect(await readFile(ownerPath, "utf8")).toContain(`${hostname()}-other`);
	});

	it("does not let an old owner release a replacement lock generation", async () => {
		const statePath = await journalPath();
		const lockPath = `${statePath}.lock`;
		const replacementToken = "66666666-6666-4666-8666-666666666666";
		const journal = new FleetResponseJournal(
			statePath,
			{ tenantId, agentId },
			"enrollment-secret",
			installationId,
		);
		await journal.withLock(async () => {
			await rm(lockPath, { recursive: true });
			await mkdir(lockPath);
			await writeFile(
				join(lockPath, `owner.${replacementToken}.json`),
				JSON.stringify({
					pid: process.pid,
					host: hostname(),
					token: replacementToken,
					process_started_at_ms: 0,
				}),
			);
		});
		expect(await readdir(lockPath)).toEqual([`owner.${replacementToken}.json`]);
	});

	it("stops the polling loop when its service supervisor aborts", async () => {
		const statePath = await journalPath();
		const abort = new AbortController();
		const fetchImpl = vi.fn(async () => {
			abort.abort();
			return json({ ok: true, command_signed: null });
		}) as typeof fetch;
		await worker(statePath, fetchImpl).run(abort.signal);
		expect(fetchImpl).toHaveBeenCalledOnce();
	});

	it("bounds a stuck cycle hook and aborts its cleanup signal", async () => {
		const statePath = await journalPath();
		let cycleSignal: AbortSignal | undefined;
		const onCycle = vi.fn(async (_result, signal?: AbortSignal) => {
			cycleSignal = signal;
			return new Promise<void>(() => {});
		});
		const subject = new FleetResponseCommandWorker({
			endpoint: "http://127.0.0.1:8000/functions",
			developmentLoopback: true,
			apiKey: "enrollment-secret",
			identity: { tenantId, agentId },
			installationId,
			trustedCommandKeys,
			adapter: adapter(),
			statePath,
			fetchImpl: transport([json({ ok: true, command_signed: null })]).fetchImpl,
			actionTimeoutMs: 100,
			onCycle,
		});
		await expect(subject.run(new AbortController().signal)).rejects.toThrow(
			"fleet_response_worker_cycle_hook_failed",
		);
		expect(cycleSignal?.aborted).toBe(true);
	});

	it("reports a cycle hook failure to the service supervisor", async () => {
		const statePath = await journalPath();
		await seedJournal(statePath, "result_pending");
		const subject = new FleetResponseCommandWorker({
			endpoint: "http://127.0.0.1:8000/functions",
			developmentLoopback: true,
			apiKey: "enrollment-secret",
			identity: { tenantId, agentId },
			installationId,
			trustedCommandKeys,
			adapter: adapter(),
			statePath,
			fetchImpl: transport([json({ ok: true, command_id: commandId, state: "succeeded" })])
				.fetchImpl,
			onCycle: async () => {
				throw new Error("telemetry unavailable");
			},
		});
		await expect(subject.run(new AbortController().signal)).rejects.toThrow(
			"fleet_response_worker_cycle_hook_failed",
		);
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
			trustedCommandKeys,
			adapter: adapter(),
			statePath,
			fetchImpl: transport([]).fetchImpl,
			onCycle,
		});
		await expect(subject.run(new AbortController().signal)).rejects.toThrow(
			"fleet_response_worker_journal_unavailable",
		);
		expect(onCycle).toHaveBeenCalledWith(
			{
				status: "outcome_unknown",
				stage: "poll",
				reason: "journal_unavailable",
			},
			expect.any(AbortSignal),
		);
	});
});
