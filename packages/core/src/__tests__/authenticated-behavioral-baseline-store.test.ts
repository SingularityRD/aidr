import { createHmac, generateKeyPairSync, randomUUID } from "node:crypto";
import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { FileAuthenticatedBehavioralBaselineStore } from "../authenticated-behavioral-baseline-store.js";
import {
	createLearningApprovalReceipt,
	createLearningExecutionReceipt,
	type LearningReceiptBundle,
	type LearningReceiptContext,
	learningInputDigest,
} from "../behavioral-learning-receipt.js";
import {
	type BehavioralDetectionInput,
	BehavioralDetectionOrchestrator,
	behavioralObservationForInput,
} from "../behavioral-orchestrator.js";

const fault = vi.hoisted(() => ({ write: false }));
vi.mock("../private-local-file.js", () => ({
	preparePrivateLocalDirectory: vi.fn(),
	preparePrivateLocalFile: vi.fn(),
}));
vi.mock("../file-utils.js", async (importOriginal) => {
	const actual = await importOriginal<typeof import("../file-utils.js")>();
	return {
		...actual,
		atomicWriteJson: async (...args: Parameters<typeof actual.atomicWriteJson>) => {
			if (fault.write) {
				fault.write = false;
				throw new Error("simulated durable write failure");
			}
			return actual.atomicWriteJson(...args);
		},
	};
});

const NOW = Date.parse("2026-10-06T01:00:00.000Z");
const execution = generateKeyPairSync("ed25519");
const approval = generateKeyPairSync("ed25519");
const pem = (key: typeof execution.publicKey) =>
	key.export({ type: "spki", format: "pem" }).toString();
const privatePem = (key: typeof execution.privateKey) =>
	key.export({ type: "pkcs8", format: "pem" }).toString();
const KEY = Buffer.alloc(32, 19);
let dir: string;

function context(overrides: Partial<LearningReceiptContext> = {}): LearningReceiptContext {
	return {
		tenantId: "tenant-a",
		deviceId: "device-a",
		agentRuntime: "claude-code",
		policyDigest: "a".repeat(64),
		corpusDigest: "b".repeat(64),
		modelVersion: "model-v1",
		entitlementSerial: "entitlement-a",
		validFromMs: NOW - 60_000,
		validUntilMs: NOW + 40 * 86_400_000,
		authorities: {
			execution: { runner: pem(execution.publicKey) },
			approval: { operator: pem(approval.publicKey) },
		},
		...overrides,
	};
}

function input(sessionId = "session-a", command = "npm test"): BehavioralDetectionInput {
	return {
		tenantId: "tenant-a",
		sessionId,
		toolName: "Bash",
		riskScore: 0,
		timestamp: Date.now() - 100,
		durationMs: 20,
		command,
		learningAllowed: true,
	};
}

function bundle(
	event = input(),
	ctx = context(),
	executionId = randomUUID(),
): LearningReceiptBundle {
	const { observation, fingerprint } = behavioralObservationForInput(event);
	const receipt = createLearningExecutionReceipt(
		{
			kind: "aidr.behavioral.execution.v1",
			schemaVersion: 1,
			executionId,
			tenantId: ctx.tenantId,
			deviceId: ctx.deviceId,
			agentRuntime: ctx.agentRuntime,
			policyDigest: ctx.policyDigest,
			corpusDigest: ctx.corpusDigest,
			modelVersion: ctx.modelVersion,
			entitlementSerial: ctx.entitlementSerial,
			sessionId: event.sessionId,
			toolName: event.toolName,
			inputDigest: learningInputDigest({ command: event.command }),
			startedAt: new Date(observation.timestamp - 20).toISOString(),
			completedAt: new Date(observation.timestamp).toISOString(),
			issuedAt: new Date().toISOString(),
			expiresAt: new Date(Date.now() + 30_000).toISOString(),
			outcome: "success",
			outputInspection: "clean",
			observation,
			fingerprint,
		},
		privatePem(execution.privateKey),
		"runner",
		ctx,
	);
	return {
		execution: receipt,
		approval: createLearningApprovalReceipt(
			receipt,
			privatePem(approval.privateKey),
			"operator",
			ctx,
		),
	};
}

function store(ctx = context(), bounds = {}) {
	return new FileAuthenticatedBehavioralBaselineStore({
		context: ctx,
		authenticationKey: KEY,
		storeDir: dir,
		...bounds,
	});
}

async function accept(
	target: FileAuthenticatedBehavioralBaselineStore,
	proof: LearningReceiptBundle,
) {
	return target.transact(
		proof.execution.payload.sessionId,
		proof,
		async (_receipt, observations) => ({ value: observations.length + 1, accept: true }),
	);
}

function detector(target: FileAuthenticatedBehavioralBaselineStore) {
	return new BehavioralDetectionOrchestrator(
		{ minBaselineSamples: 2 },
		{
			provisionedPolicy: { tenantId: "tenant-a", learningAllowed: true },
			authenticatedBaselineStore: target,
			mlModel: {
				load: async () => undefined,
				findSimilarThreats: async () => [],
				getStats: async () => ({
					isLoaded: true,
					threatCount: 1,
					vectorSize: 64,
					modelSizeBytes: 1280,
				}),
			},
		},
	);
}

async function journalPath(): Promise<string> {
	const name = (await readdir(dir)).find((name) => name.endsWith(".v3.json"));
	if (!name) throw new Error("Expected authenticated journal");
	return join(dir, name);
}

async function replaceAuthenticated(edit: (payload: Record<string, unknown>) => void) {
	const path = await journalPath();
	const envelope = JSON.parse(await readFile(path, "utf8"));
	edit(envelope.payload);
	// A test with the vault key separates receipt-verification checks from HMAC checks.
	const mac = createHmac("sha256", KEY).update(JSON.stringify(envelope.payload)).digest("hex");
	await writeFile(path, JSON.stringify({ payload: envelope.payload, mac }));
}

beforeEach(async () => {
	vi.useFakeTimers({ toFake: ["Date"] });
	vi.setSystemTime(NOW);
	fault.write = false;
	dir = await mkdtemp(join(tmpdir(), "aidr-authenticated-baseline-"));
});
afterEach(async () => {
	vi.useRealTimers();
	await rm(dir, { recursive: true, force: true });
});

describe("authenticated V3 baseline transactions", () => {
	it("restores signed observations after restart and receipt TTL expiry, without raw payloads", async () => {
		const event = input("session-a", "private-command-value");
		const proof = bundle(event);
		expect(await accept(store(), proof)).toBe(1);
		vi.setSystemTime(NOW + 31_000);
		const loaded = await store().load("session-a");
		expect(loaded).toEqual([
			{ ...proof.execution.payload.observation, fingerprint: proof.execution.payload.fingerprint },
		]);
		expect(await readFile(await journalPath(), "utf8")).not.toContain("private-command-value");
		await expect(accept(store(), proof)).rejects.toThrow("authorized window");
	});

	it("serializes competing store instances and consumes each execution only once", async () => {
		const proof = bundle();
		const results = await Promise.allSettled([accept(store(), proof), accept(store(), proof)]);
		expect(results.filter((result) => result.status === "fulfilled")).toHaveLength(1);
		expect(results.filter((result) => result.status === "rejected")).toHaveLength(1);
		expect(await store().load("session-a")).toHaveLength(1);
		const anotherApproval = {
			...proof,
			approval: createLearningApprovalReceipt(
				proof.execution,
				privatePem(approval.privateKey),
				"operator",
				context(),
			),
		};
		await expect(accept(store(), anotherApproval)).rejects.toThrow("already been consumed");
	});

	it("supports valid session names inherited from Object.prototype without bypassing session bounds", async () => {
		const target = store(context(), { maxSessionsPerTenant: 1 });
		for (const sessionId of ["toString", "hasOwnProperty"]) {
			await accept(target, bundle(input(sessionId)));
			expect(await target.load(sessionId)).toHaveLength(1);
		}
		expect(await target.load("toString")).toEqual([]);
	});

	it("snapshots receipts before awaited analysis and isolates callback mutations", async () => {
		const proof = bundle();
		const original = structuredClone(proof);
		const replacement = bundle(input("session-a", "changed-command"));
		await store().transact("session-a", proof, async (receipt) => {
			Object.assign(proof, replacement);
			receipt.executionId = randomUUID();
			receipt.observation.commandToken = `command:sha256:${"f".repeat(64)}`;
			await Promise.resolve();
			return { value: true, accept: true };
		});
		expect(await store().load("session-a")).toEqual([
			{
				...original.execution.payload.observation,
				fingerprint: original.execution.payload.fingerprint,
			},
		]);
		await expect(accept(store(), original)).rejects.toThrow("already been consumed");
	});

	it("retains spent receipt tombstones through session clear, tenant clear and corpus rotation", async () => {
		const proof = bundle();
		const target = store();
		await accept(target, proof);
		await target.clearSession("tenant-a", "session-a");
		expect(await target.load("session-a")).toEqual([]);
		await expect(accept(target, proof)).rejects.toThrow("already been consumed");
		await target.clearTenant("tenant-a");
		await expect(accept(store(), proof)).rejects.toThrow("already been consumed");
		const rotated = context({ corpusDigest: "c".repeat(64), policyDigest: "d".repeat(64) });
		expect(await store(rotated).load("session-a")).toEqual([]);
		const reissued = bundle(input(), rotated, proof.execution.payload.executionId);
		await expect(accept(store(rotated), reissued)).rejects.toThrow("already been consumed");
	});

	it("bounds sessions and observations without discarding live replay protection", async () => {
		const target = store(context(), { maxSessionsPerTenant: 1, maxEventsPerSession: 1 });
		const first = bundle(input("first"));
		await accept(target, first);
		const second = bundle(input("second"));
		await accept(target, second);
		expect(await target.load("first")).toEqual([]);
		expect(await target.load("second")).toHaveLength(1);
		await expect(accept(target, first)).rejects.toThrow("already been consumed");
		await expect(accept(target, bundle(input("third")))).rejects.toThrow("ledger is full");
		expect(await target.load("second")).toHaveLength(1);
	});

	it("expires old samples rather than carrying a lifetime baseline count", async () => {
		const target = store(context(), { retentionMs: 1_000 });
		await accept(target, bundle());
		vi.setSystemTime(NOW + 1_000);
		expect(await target.load("session-a")).toEqual([]);
		const persisted = JSON.parse(await readFile(await journalPath(), "utf8"));
		expect(persisted.payload.sessions).toEqual({});
		// Expired observations never erase a still-valid one-time execution ledger.
		expect(persisted.payload.spent).toHaveLength(1);
	});

	it("rejects corrupted HMAC state without overwriting its receipt ledger", async () => {
		await accept(store(), bundle());
		const path = await journalPath();
		const raw = await readFile(path, "utf8");
		const forged = JSON.parse(raw);
		forged.payload.spent = [];
		await writeFile(path, JSON.stringify(forged));
		const corrupted = await readFile(path, "utf8");
		await expect(store().load("session-a")).rejects.toThrow("authentication");
		await expect(accept(store(), bundle())).rejects.toThrow("authentication");
		expect(await readFile(path, "utf8")).toBe(corrupted);
	});

	it("reverifies receipt signatures and rejects duplicate signed observations on restore", async () => {
		await accept(store(), bundle());
		await replaceAuthenticated((payload) => {
			const sessions = payload.sessions as Record<
				string,
				{ entries: Array<{ bundle: LearningReceiptBundle }> }
			>;
			const session = sessions["session-a"];
			const entry = session?.entries[0];
			if (!session || !entry) throw new Error("Expected persisted receipt");
			session.entries.push(structuredClone(entry));
		});
		await expect(store().load("session-a")).rejects.toThrow("identity");
		await replaceAuthenticated((payload) => {
			const sessions = payload.sessions as Record<
				string,
				{ entries: Array<{ bundle: LearningReceiptBundle }> }
			>;
			const session = sessions["session-a"];
			const entry = session?.entries[0];
			if (!session || !entry) throw new Error("Expected persisted receipt");
			session.entries = [entry];
			entry.bundle.execution.payload.observation.commandToken = `command:sha256:${"f".repeat(64)}`;
		});
		await expect(store().load("session-a")).rejects.toThrow("signature");
	});

	it("isolates tenant/device namespaces and current policy/corpus/model bindings", async () => {
		await accept(store(), bundle());
		for (const change of [
			{ tenantId: "tenant-b" },
			{ deviceId: "device-b" },
			{ agentRuntime: "cursor" as const },
			{ policyDigest: "e".repeat(64) },
			{ corpusDigest: "f".repeat(64) },
			{ modelVersion: "model-v2" },
		]) {
			expect(await store(context(change)).load("session-a")).toEqual([]);
		}
		expect(await store().load("session-a")).toHaveLength(1);
	});

	it("retains verified accepted history through routine entitlement renewal but requires the current serial for ingestion", async () => {
		const prior = context({ validUntilMs: NOW + 30_000 });
		const proof = bundle(input(), prior);
		await accept(store(prior), proof);
		vi.setSystemTime(NOW + 31_000);
		const renewed = context({
			entitlementSerial: "renewed-entitlement",
			validFromMs: NOW + 30_000,
		});
		const target = store(renewed);
		expect(await target.load("session-a")).toHaveLength(1);
		await expect(accept(target, proof)).rejects.toThrow("entitlementSerial binding failed");
		expect(await accept(target, bundle(input(), renewed))).toBe(2);
	});

	it("fails closed on an expired current entitlement and revoked historical accepted authority", async () => {
		const prior = context({ validUntilMs: NOW + 30_000 });
		await accept(store(prior), bundle(input(), prior));
		vi.setSystemTime(NOW + 31_000);
		await expect(store(prior).load("session-a")).rejects.toThrow("expired or unavailable");
		const renewed = context({
			entitlementSerial: "renewed-entitlement",
			validFromMs: NOW + 30_000,
			revokedEntitlementSerials: [prior.entitlementSerial],
		});
		await expect(store(renewed).load("session-a")).rejects.toThrow("revoked");
	});

	it("discards observation history on revocation epoch changes while preserving spent receipt IDs", async () => {
		const proof = bundle();
		await accept(store(), proof);
		const changedEpoch = context({ revocationEpoch: 1 });
		const target = store(changedEpoch);
		expect(await target.load("session-a")).toEqual([]);
		await expect(accept(target, proof)).rejects.toThrow("already been consumed");
	});

	it("does not commit or consume a receipt after an awaited analysis outlives its signed expiry", async () => {
		const proof = bundle();
		await expect(
			store().transact("session-a", proof, async () => {
				vi.setSystemTime(NOW + 31_000);
				return { value: true, accept: true };
			}),
		).rejects.toThrow("authorized window");
		expect(await store().load("session-a")).toEqual([]);
		vi.setSystemTime(NOW);
		expect(await accept(store(), proof)).toBe(1);
	});

	it("requires the final current-authority check before committing accepted observations", async () => {
		const target = store();
		const event = input();
		const proof = bundle(event);
		const runtime = detector(target);
		const currentAuthority = vi.fn(async () => {
			throw new Error("current tenant authority changed");
		});
		await expect(
			runtime.ingestAuthenticatedExecution(
				event,
				proof,
				{ command: event.command },
				currentAuthority,
			),
		).rejects.toThrow("current tenant authority changed");
		expect(currentAuthority).toHaveBeenCalledOnce();
		expect(await target.load("session-a")).toEqual([]);
		expect(runtime.getStats().totalBaselineSamples).toBe(0);
		const accepted = await runtime.ingestAuthenticatedExecution(event, proof, {
			command: event.command,
		});
		expect(accepted.learning.accepted).toBe(true);
	});

	it("commits nothing when durable writing fails and accepts a safe retry once", async () => {
		const target = store();
		const event = input();
		const proof = bundle(event);
		const runtime = detector(target);
		fault.write = true;
		await expect(
			runtime.ingestAuthenticatedExecution(event, proof, { command: event.command }),
		).rejects.toThrow("durable write failure");
		expect(await target.load("session-a")).toEqual([]);
		expect(runtime.getStats().totalBaselineSamples).toBe(0);
		const retried = await runtime.ingestAuthenticatedExecution(event, proof, {
			command: event.command,
		});
		expect(retried.learning).toMatchObject({ accepted: true, baselineSamplesAfter: 1 });
		await expect(
			runtime.ingestAuthenticatedExecution(event, proof, { command: event.command }),
		).rejects.toThrow("already been consumed");
	});

	it("restores only authenticated learning while production preflight remains read-only", async () => {
		const target = store();
		const runtime = detector(target);
		const candidate = await runtime.evaluate(input());
		expect(candidate.learning).toMatchObject({
			accepted: false,
			reason: "explicitly_disabled",
			baselineSamplesAfter: 0,
		});
		for (let i = 0; i < 2; i++) {
			const event = input();
			await runtime.ingestAuthenticatedExecution(event, bundle(event), { command: event.command });
		}
		const restarted = detector(store());
		const ready = await restarted.evaluate(input());
		expect(ready).toMatchObject({
			outcome: "normal",
			learning: { accepted: false, baselineSamplesBefore: 2, baselineSamplesAfter: 2 },
		});
		await expect(
			restarted.ingestAuthenticatedExecution(input("session-a", "other-command"), bundle(), {
				command: "other-command",
			}),
		).rejects.toThrow("binding failed");
		expect(await target.load("session-a")).toHaveLength(2);
	});
});
