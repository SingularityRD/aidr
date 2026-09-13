import { describe, expect, it } from "vitest";
import {
	BehavioralDetectionOrchestrator,
	type BehavioralEmbeddingModel,
} from "../behavioral-orchestrator.js";
import { LocalEmbeddingModel } from "../ml-model.js";

const NOW = Date.parse("2026-09-12T12:00:00.000Z");

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
		...overrides,
	};
}

function orchestrator(
	overrides: ConstructorParameters<typeof BehavioralDetectionOrchestrator>[0] = {},
	model: BehavioralEmbeddingModel = readyModel(),
) {
	return new BehavioralDetectionOrchestrator(
		{
			minBaselineSamples: 2,
			modelVersion: "test-model-v1",
			...overrides,
		},
		{ mlModel: model, now: () => NOW },
	);
}

describe("BehavioralDetectionOrchestrator", () => {
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
		expect(absentResult.explanations).toContainEqual(
			expect.objectContaining({
				leg: "ml",
				status: "unavailable",
				unavailableReason: "not_configured",
				summary: "ml detection unavailable",
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
});
