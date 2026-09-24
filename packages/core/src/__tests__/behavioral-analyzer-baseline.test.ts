import { describe, expect, it } from "vitest";
import { BehavioralAnalyzer } from "../behavioral-analyzer.js";
import { BehavioralDetectionOrchestrator } from "../behavioral-orchestrator.js";

describe("BehavioralAnalyzer candidate baseline", () => {
	it("compares the latest risk against earlier observations in the same session", () => {
		const analyzer = new BehavioralAnalyzer();
		for (let timestamp = 1; timestamp <= 3; timestamp++) {
			analyzer.recordEvent({
				toolName: "Read",
				timestamp,
				sessionId: "target",
				riskScore: 10,
			});
		}
		analyzer.recordEvent({
			toolName: "Read",
			timestamp: 4,
			sessionId: "other",
			riskScore: 100,
		});
		analyzer.recordEvent({
			toolName: "Read",
			timestamp: 5,
			sessionId: "target",
			riskScore: 70,
		});

		expect(analyzer.detectAnomaly("target")).toMatchObject({
			isAnomaly: true,
			confidence: 0.7,
			reason: expect.stringContaining("above baseline"),
		});
	});

	it("keeps one session's baseline when another session exceeds the analysis window", () => {
		const analyzer = new BehavioralAnalyzer(3);
		for (let timestamp = 1; timestamp <= 3; timestamp++) {
			analyzer.recordEvent({
				toolName: "Read",
				timestamp,
				sessionId: "target",
				riskScore: 10,
			});
		}
		for (let timestamp = 4; timestamp <= 6; timestamp++) {
			analyzer.recordEvent({
				toolName: "Bash",
				timestamp,
				sessionId: "other",
				riskScore: 10,
			});
		}
		analyzer.recordEvent({
			toolName: "Read",
			timestamp: 7,
			sessionId: "target",
			riskScore: 70,
		});

		expect(analyzer.detectAnomaly("target")).toMatchObject({ isAnomaly: true });
		expect(analyzer.getSessionStats()).toEqual({
			totalEvents: 6,
			uniqueSessions: 2,
			averageSessionLength: 3,
		});
	});

	it("does not invent a risk baseline for a single cold-start observation", () => {
		const analyzer = new BehavioralAnalyzer();
		analyzer.recordEvent({
			toolName: "Read",
			timestamp: 1,
			sessionId: "new-session",
			riskScore: 90,
		});

		expect(analyzer.detectAnomaly("new-session").isAnomaly).toBe(false);
	});

	it("reports the spike through the active behavioral orchestrator", async () => {
		const now = Date.parse("2026-09-12T12:00:00.000Z");
		const detector = new BehavioralDetectionOrchestrator(
			{ minBaselineSamples: 2 },
			{
				now: () => now,
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
		const event = {
			tenantId: "tenant-a",
			sessionId: "session-a",
			toolName: "Read",
			riskScore: 10,
			timestamp: now,
			command: "npm test",
			learningAllowed: true,
		};
		await detector.evaluate(event);
		await detector.evaluate(event);

		const result = await detector.evaluate({ ...event, riskScore: 90 });
		expect(result.outcome).toBe("anomalous");
		expect(result.explanations).toContainEqual(
			expect.objectContaining({ leg: "behavioral", status: "ready", score: 90 }),
		);
	});
});
