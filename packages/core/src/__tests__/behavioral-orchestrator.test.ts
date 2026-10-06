import { mkdtemp, readdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { FileBehavioralBaselineStore } from "../behavioral-baseline-store.js";
import {
	BehavioralDetectionOrchestrator,
	type BehavioralEmbeddingModel,
	LOCAL_EMBEDDER_MODEL_VERSION,
} from "../behavioral-orchestrator.js";
import { LocalEmbeddingModel } from "../ml-model.js";

const NOW = Date.parse("2026-09-12T12:00:00.000Z");

async function temporaryStoreDir(): Promise<string> {
	return await mkdtemp(join(tmpdir(), "aidr-behavioral-store-"));
}

/** Locate the persisted session records without assuming the on-disk naming. */
async function findStoredRecords(dir: string): Promise<string[]> {
	const entries = await readdir(dir, { recursive: true });
	return entries.filter((entry) => entry.endsWith(".json")).map((entry) => join(dir, entry));
}

function readyModel(
	classify: (
		text: string,
	) => Awaited<ReturnType<BehavioralEmbeddingModel["findSimilarThreats"]>> = () => [],
): BehavioralEmbeddingModel {
	return {
		load: async () => undefined,
		findSimilarThreats: async (text) => classify(text),
		getStats: async () => ({
			isLoaded: true,
			threatCount: 1,
			vectorSize: 64,
			modelSizeBytes: 1280,
		}),
	};
}

function input(
	overrides: Partial<Parameters<BehavioralDetectionOrchestrator["evaluate"]>[0]> = {},
) {
	return {
		tenantId: "tenant-a",
		sessionId: "session-a",
		toolName: "Read",
		riskScore: 10,
		timestamp: NOW,
		command: "npm test",
		// Direct orchestrator fixtures model trusted observations after execution.
		learningAllowed: true,
		...overrides,
	};
}

function orchestrator(
	overrides: ConstructorParameters<typeof BehavioralDetectionOrchestrator>[0] = {},
	model: BehavioralEmbeddingModel = readyModel(),
	baselineStore?: FileBehavioralBaselineStore,
) {
	return new BehavioralDetectionOrchestrator(
		{
			minBaselineSamples: 2,
			modelVersion: "test-model-v1",
			...overrides,
		},
		{ mlModel: model, now: () => NOW, ...(baselineStore ? { baselineStore } : {}) },
	);
}

describe("BehavioralDetectionOrchestrator", () => {
	it("does not promote a direct candidate unless a trusted caller opts in", async () => {
		const dir = await temporaryStoreDir();
		try {
			const store = new FileBehavioralBaselineStore({ storeDir: dir, now: () => NOW });
			const detector = orchestrator({}, readyModel(), store);
			const result = await detector.evaluate(input({ learningAllowed: undefined }));

			expect(result).toMatchObject({
				outcome: "learning",
				learning: {
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				},
			});
			expect(await store.load("tenant-a", "session-a")).toBeNull();
			expect(detector.getStats().totalBaselineSamples).toBe(0);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("does not persist accepted observations without authenticated receipts", async () => {
		const dir = await temporaryStoreDir();
		try {
			const store = new FileBehavioralBaselineStore({ storeDir: dir, now: () => NOW });
			const firstProcess = orchestrator({}, readyModel(), store);
			const accepted = await firstProcess.evaluate(input());
			expect(accepted.learning.accepted).toBe(true);
			expect(await store.load("tenant-a", "session-a")).toBeNull();

			const nextProcess = orchestrator({}, readyModel(), store);
			const cold = await nextProcess.evaluate(input({ learningAllowed: false }));
			expect(cold.learning.baselineSamplesBefore).toBe(0);
			expect(cold.learning.reason).toBe("explicitly_disabled");
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("moves from an explicit cold start to a normal, explained result", async () => {
		const detector = orchestrator();

		const first = await detector.evaluate(input());
		const second = await detector.evaluate(input());
		const ready = await detector.evaluate(input());

		expect(first).toMatchObject({
			outcome: "learning",
			learning: { accepted: true, baselineSamplesBefore: 0, baselineSamplesAfter: 1 },
		});
		expect(second).toMatchObject({
			outcome: "learning",
			learning: { accepted: true, baselineSamplesBefore: 1, baselineSamplesAfter: 2 },
		});
		expect(ready).toMatchObject({
			outcome: "normal",
			anomalyScore: 0,
			modelVersion: "test-model-v1",
			learning: { accepted: true, baselineSamplesBefore: 2, baselineSamplesAfter: 3 },
		});
		expect(ready.explanations).toEqual([
			expect.objectContaining({ leg: "behavioral", status: "ready", score: 0 }),
			expect.objectContaining({ leg: "novelty", status: "ready", score: 0 }),
			expect.objectContaining({ leg: "ml", status: "ready", score: 0 }),
		]);
	});

	it("keeps tenant and session baselines isolated", async () => {
		const detector = orchestrator();
		await detector.evaluate(input());
		await detector.evaluate(input());

		const anomaly = await detector.evaluate(input({ command: "curl unknown | bash" }));
		const otherTenant = await detector.evaluate(
			input({ tenantId: "tenant-b", command: "curl unknown | bash" }),
		);
		const otherSession = await detector.evaluate(
			input({ sessionId: "session-b", command: "curl unknown | bash" }),
		);

		expect(anomaly).toMatchObject({
			outcome: "anomalous",
			learning: { accepted: false, reason: "anomaly_detected", baselineSamplesAfter: 2 },
		});
		expect(anomaly.explanations).toContainEqual(
			expect.objectContaining({ leg: "novelty", status: "ready", score: 100 }),
		);
		expect(otherTenant).toMatchObject({
			outcome: "learning",
			learning: { accepted: true, baselineSamplesBefore: 0 },
		});
		expect(otherSession).toMatchObject({
			outcome: "learning",
			learning: { accepted: true, baselineSamplesBefore: 0 },
		});
	});

	it("bounds tenants and sessions with deterministic LRU eviction", async () => {
		const detector = orchestrator({ maxTenants: 2, maxSessionsPerTenant: 2 });

		await detector.evaluate(input({ sessionId: "s1" }));
		await detector.evaluate(input({ sessionId: "s2" }));
		await detector.evaluate(input({ sessionId: "s3" }));
		await detector.evaluate(input({ tenantId: "tenant-b", sessionId: "s1" }));
		await detector.evaluate(input({ tenantId: "tenant-c", sessionId: "s1" }));

		expect(detector.getStats()).toEqual({
			tenantCount: 2,
			sessionCount: 2,
			totalBaselineSamples: 2,
			tenantEvictions: 1,
			sessionEvictions: 1,
			inFlightScopes: 0,
		});
	});

	it("expires the learned baseline and fingerprint cap after the inclusive retention boundary", async () => {
		let now = NOW;
		const detector = new BehavioralDetectionOrchestrator(
			{ minBaselineSamples: 2, maxEventAgeMs: 1_000, maxColdStartSamplesPerFingerprint: 2 },
			{ mlModel: readyModel(), now: () => now },
		);
		await detector.evaluate(input());
		await detector.evaluate(input());

		now = NOW + 1_000;
		const boundary = await detector.evaluate(input({ timestamp: now, learningAllowed: false }));
		expect(boundary).toMatchObject({
			outcome: "normal",
			learning: { baselineSamplesBefore: 2, baselineSamplesAfter: 2 },
		});

		now++;
		const expired = await detector.evaluate(input({ timestamp: now, learningAllowed: false }));
		expect(expired).toMatchObject({
			outcome: "learning",
			learning: { baselineSamplesBefore: 0, baselineSamplesAfter: 0 },
		});
		const relearned = await detector.evaluate(input({ timestamp: now }));
		expect(relearned.learning).toMatchObject({
			accepted: true,
			reason: "accepted",
			baselineSamplesBefore: 0,
			baselineSamplesAfter: 1,
		});
		expect(detector.getStats().totalBaselineSamples).toBe(1);
	});

	it("retains younger samples and rebuilds novelty without crossing tenant or session boundaries", async () => {
		let now = NOW;
		const detector = new BehavioralDetectionOrchestrator(
			{ minBaselineSamples: 2, maxEventAgeMs: 1_000 },
			{ mlModel: readyModel(), now: () => now },
		);
		// Accepted timestamps may arrive out of order; expiration must filter the full window.
		await detector.evaluate(input({ command: "young-command", timestamp: NOW - 100 }));
		await detector.evaluate(input({ command: "old-command", timestamp: NOW - 900 }));
		await detector.evaluate(input({ command: "young-command", timestamp: NOW - 100 }));
		for (const scope of [{ tenantId: "tenant-b" }, { sessionId: "session-b" }]) {
			await detector.evaluate(input({ ...scope, command: "old-command", timestamp: NOW - 100 }));
			await detector.evaluate(input({ ...scope, command: "old-command", timestamp: NOW - 100 }));
		}

		now = NOW + 500;
		const oldCommand = await detector.evaluate(
			input({ command: "old-command", timestamp: now, learningAllowed: false }),
		);
		expect(oldCommand).toMatchObject({
			outcome: "anomalous",
			learning: { baselineSamplesBefore: 2, baselineSamplesAfter: 2 },
		});
		expect(oldCommand.explanations).toContainEqual(
			expect.objectContaining({ leg: "novelty", status: "ready", score: 100 }),
		);
		const youngCommand = await detector.evaluate(
			input({ command: "young-command", timestamp: now, learningAllowed: false }),
		);
		expect(youngCommand.outcome).toBe("normal");
		for (const scope of [{ tenantId: "tenant-b" }, { sessionId: "session-b" }]) {
			const unaffected = await detector.evaluate(
				input({ ...scope, command: "old-command", timestamp: now, learningAllowed: false }),
			);
			expect(unaffected).toMatchObject({
				outcome: "normal",
				learning: { baselineSamplesBefore: 2, baselineSamplesAfter: 2 },
			});
		}
		expect(detector.getStats().totalBaselineSamples).toBe(6);
	});

	it("removes evicted observations from novelty and sample counters", async () => {
		const detector = orchestrator({ maxEventsPerSession: 2 });
		await detector.evaluate(input({ command: "old-command" }));
		await detector.evaluate(input({ command: "retained-command" }));
		const replacement = await detector.evaluate(input({ command: "retained-command" }));
		expect(replacement.learning).toMatchObject({
			accepted: true,
			baselineSamplesBefore: 2,
			baselineSamplesAfter: 2,
		});
		const evicted = await detector.evaluate(
			input({ command: "old-command", learningAllowed: false }),
		);
		expect(evicted.outcome).toBe("anomalous");
		expect(evicted.explanations).toContainEqual(
			expect.objectContaining({ leg: "novelty", status: "ready", score: 100 }),
		);
		expect(detector.getStats().totalBaselineSamples).toBe(2);
	});

	it("does not learn high-risk, ML-matched, or repetitive cold-start poison", async () => {
		const model = readyModel((text) =>
			text.includes("known-malware")
				? [
						{
							threatId: "threat-1",
							similarity: 0.99,
							metadata: {
								category: "execution",
								severity: "critical",
								description: "known threat",
							},
						},
					]
				: [],
		);
		const detector = orchestrator(
			{ minBaselineSamples: 5, maxColdStartSamplesPerFingerprint: 2 },
			model,
		);

		const highRisk = await detector.evaluate(input({ riskScore: 90 }));
		const mlMatch = await detector.evaluate(
			input({ command: "known-malware", classificationText: "known-malware" }),
		);
		const safeOne = await detector.evaluate(input());
		const safeTwo = await detector.evaluate(input());
		const capped = await detector.evaluate(input());

		expect(highRisk.learning).toMatchObject({
			accepted: false,
			reason: "high_risk_event",
			baselineSamplesAfter: 0,
		});
		expect(mlMatch).toMatchObject({
			outcome: "anomalous",
			anomalyScore: 99,
			learning: { accepted: false, reason: "anomaly_detected", baselineSamplesAfter: 0 },
		});
		expect(safeOne.learning.baselineSamplesAfter).toBe(1);
		expect(safeTwo.learning.baselineSamplesAfter).toBe(2);
		expect(capped.learning).toMatchObject({
			accepted: false,
			reason: "fingerprint_limit",
			baselineSamplesAfter: 2,
		});
	});

	it("fails closed when the ML leg is absent or fails", async () => {
		const absent = new BehavioralDetectionOrchestrator(
			{ minBaselineSamples: 1 },
			{ now: () => NOW },
		);
		const failing = orchestrator(
			{},
			{
				...readyModel(),
				findSimilarThreats: async () => {
					throw new Error("provider internals must not escape");
				},
			},
		);

		const absentResult = await absent.evaluate(input());
		const failingResult = await failing.evaluate(input());

		expect(absentResult).toMatchObject({
			outcome: "unavailable",
			modelVersion: null,
			learning: { accepted: false, reason: "detection_unavailable", baselineSamplesAfter: 0 },
		});
		// The ML leg is no longer absent when no caller supplies a model: it runs
		// the built-in deterministic embedder, so it reports the state it reached
		// (an empty threat corpus) and names the model version it used. This is the
		// one existing assertion changed by this fix: it keeps asserting the same
		// fail-closed leg (`unavailable`, `ml detection unavailable`) and adds a
		// required `modelVersion`, so it is strictly stronger than the old
		// "not_configured" placeholder, which no longer describes the leg.
		expect(absentResult.explanations).toContainEqual(
			expect.objectContaining({
				leg: "ml",
				status: "unavailable",
				unavailableReason: "empty_corpus",
				summary: "ml detection unavailable",
				modelVersion: LOCAL_EMBEDDER_MODEL_VERSION,
			}),
		);
		expect(failingResult).toMatchObject({
			outcome: "unavailable",
			learning: { accepted: false, reason: "detection_unavailable" },
		});
		expect(failingResult.explanations).toContainEqual(
			expect.objectContaining({ unavailableReason: "inference_failed" }),
		);
		expect(JSON.stringify(failingResult)).not.toContain("provider internals");
	});

	it("serializes concurrent observations in one scope", async () => {
		const detector = orchestrator({ minBaselineSamples: 3 });

		const results = await Promise.all([
			detector.evaluate(input({ command: "npm test a" })),
			detector.evaluate(input({ command: "npm test b" })),
		]);

		expect(results.map((result) => result.learning.baselineSamplesAfter)).toEqual([1, 2]);
		expect(detector.getStats().totalBaselineSamples).toBe(2);
	});

	it("uses LocalEmbeddingModel and activates refreshed models atomically", async () => {
		const localModel = new LocalEmbeddingModel({
			modelPath: "memory://test",
			vectorSize: 64,
			similarityThreshold: 0.99,
		});
		await localModel.load();
		await localModel.addThreat({
			threatId: "embedded-threat",
			embedding: await localModel.computeEmbedding("exact known malicious command"),
			metadata: {
				category: "command-execution",
				severity: "critical",
				description: "fixture",
			},
		});
		const detector = orchestrator({}, localModel);

		const matched = await detector.evaluate(
			input({ classificationText: "exact known malicious command" }),
		);
		const emptyModel = new LocalEmbeddingModel({
			modelPath: "memory://empty",
			vectorSize: 64,
			similarityThreshold: 0.99,
		});
		await expect(detector.refreshModel(emptyModel, "empty-v2")).rejects.toThrow(
			"empty threat corpus",
		);
		const stillMatched = await detector.evaluate(
			input({ sessionId: "session-b", classificationText: "exact known malicious command" }),
		);

		expect(matched).toMatchObject({ outcome: "anomalous", anomalyScore: 100 });
		expect(stillMatched).toMatchObject({
			outcome: "anomalous",
			anomalyScore: 100,
			modelVersion: "test-model-v1",
		});
	});

	it("ignores a forged and replayed v2 baseline until receipt verification is available", async () => {
		const dir = await temporaryStoreDir();
		try {
			const corpusDigest = "a".repeat(64);
			const store = new FileBehavioralBaselineStore({
				storeDir: dir,
				corpusDigest,
				now: () => NOW,
			});
			const observations = Array.from({ length: 10 }, (_, index) => ({
				toolName: "Read",
				timestamp: NOW - index,
				riskScore: 10,
				commandToken: `command:sha256:${String(index).padStart(64, "0")}`,
			}));
			await store.save("tenant-a", "session-a", {
				baselineSamples: 10,
				observations,
				fingerprintCounts: { [`event:sha256:${"f".repeat(64)}`]: 10 },
			});

			const [recordPath] = await findStoredRecords(dir);
			if (!recordPath) throw new Error("Expected a persisted baseline record");
			const forged = JSON.parse(await readFile(recordPath, "utf8")) as Record<string, unknown>;
			const oneSample = (forged.observations as Array<Record<string, unknown>>)[0];
			if (!oneSample) throw new Error("Expected one persisted sample");
			forged.observations = Array.from({ length: 10 }, () => ({ ...oneSample, tool_name: "Bash" }));
			await writeFile(recordPath, JSON.stringify(forged));

			// The file parser accepts this structurally valid but unauthenticated v2
			// record. The detector must still start cold because no receipt verifier
			// is wired into restoration.
			expect((await store.load("tenant-a", "session-a"))?.baselineSamples).toBe(10);
			const detector = new BehavioralDetectionOrchestrator(
				{ minBaselineSamples: 2, modelVersion: "test-model-v1" },
				{
					mlModel: readyModel(),
					now: () => NOW,
					baselineStore: store,
					provisionedPolicy: { tenantId: "tenant-a", learningAllowed: true },
				},
			);
			const result = await detector.evaluate(input({ learningAllowed: false }));
			expect(result).toMatchObject({
				outcome: "learning",
				learning: {
					accepted: false,
					reason: "explicitly_disabled",
					baselineSamplesBefore: 0,
					baselineSamplesAfter: 0,
				},
			});
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});

	it("runs the local model leg and reports its model version", async () => {
		const dir = await temporaryStoreDir();
		try {
			const store = new FileBehavioralBaselineStore({ storeDir: dir, now: () => NOW });
			// No caller-supplied model: the leg must run the built-in deterministic
			// embedder rather than reporting "not configured".
			const detector = new BehavioralDetectionOrchestrator(
				{ minBaselineSamples: 1 },
				{ now: () => NOW, baselineStore: store },
			);

			const cold = await detector.evaluate(input());
			expect(cold.explanations).toContainEqual(
				expect.objectContaining({
					leg: "ml",
					status: "unavailable",
					unavailableReason: "empty_corpus",
					modelVersion: LOCAL_EMBEDDER_MODEL_VERSION,
				}),
			);
			// Nothing scored, so the result claims no model version.
			expect(cold.modelVersion).toBeNull();

			// Given a corpus, the same local embedder scores and the eval result
			// exposes the configured model version.
			const localModel = new LocalEmbeddingModel({
				modelPath: "memory://behavioral",
				vectorSize: 64,
				similarityThreshold: 0.99,
			});
			await localModel.load();
			await localModel.addThreat({
				threatId: "embedded-threat",
				embedding: await localModel.computeEmbedding("exact known malicious command"),
				metadata: {
					category: "command-execution",
					severity: "critical",
					description: "fixture",
				},
			});
			await detector.refreshModel(localModel, LOCAL_EMBEDDER_MODEL_VERSION);

			const scored = await detector.evaluate(
				input({ classificationText: "exact known malicious command" }),
			);
			expect(scored).toMatchObject({
				outcome: "anomalous",
				anomalyScore: 100,
				modelVersion: LOCAL_EMBEDDER_MODEL_VERSION,
			});
			expect(scored.explanations).toContainEqual(
				expect.objectContaining({
					leg: "ml",
					status: "ready",
					score: 100,
					modelVersion: LOCAL_EMBEDDER_MODEL_VERSION,
				}),
			);
		} finally {
			await rm(dir, { recursive: true, force: true });
		}
	});
});
