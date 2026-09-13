import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

export interface ToolCallEvent {
	toolName: string;
	timestamp: number;
	sessionId: string;
	riskScore: number;
}

export interface BehavioralProfile {
	sessionId: string;
	toolFrequency: Map<string, number>;
	averageRiskScore: number;
	toolSequences: string[][];
	suspiciousPatterns: SuspiciousPattern[];
}

export interface SuspiciousPattern {
	type: "frequency_anomaly" | "sequence_risk" | "temporal_spike";
	description: string;
	confidence: number;
	tools: string[];
}

export interface AnomalyDetectionResult {
	isAnomaly: boolean;
	confidence: number;
	reason: string;
	pattern?: SuspiciousPattern;
}

export class BehavioralAnalyzer {
	private events: ToolCallEvent[] = [];
	private readonly logger: Logger;
	private readonly windowSize: number;
	private readonly anomalyThreshold: number;

	constructor(windowSize = 100, anomalyThreshold = 2.5, logger: Logger = nullLogger) {
		this.windowSize = windowSize;
		this.anomalyThreshold = anomalyThreshold;
		this.logger = logger;
	}

	recordEvent(event: ToolCallEvent): void {
		this.events.push(event);

		if (this.events.length > this.windowSize) {
			this.events.shift();
		}

		this.logger.debug("Recorded tool call event", {
			tool: event.toolName,
			risk: event.riskScore,
			session: event.sessionId,
		});
	}

	analyzeCurrentSession(sessionId: string): BehavioralProfile {
		const sessionEvents = this.events.filter((e) => e.sessionId === sessionId);

		const toolFrequency = this.calculateToolFrequency(sessionEvents);
		const averageRiskScore = this.calculateAverageRisk(sessionEvents);
		const toolSequences = this.extractSequences(sessionEvents);
		const suspiciousPatterns = this.detectSuspiciousPatterns(sessionEvents);

		return {
			sessionId,
			toolFrequency,
			averageRiskScore,
			toolSequences,
			suspiciousPatterns,
		};
	}

	detectAnomaly(sessionId: string): AnomalyDetectionResult {
		const profile = this.analyzeCurrentSession(sessionId);
		const sessionEvents = this.events.filter((event) => event.sessionId === sessionId);
		// The newest observation is the candidate being scored. It must not set its
		// own baseline, and observations from another session must not affect it.
		const baselineEvents = sessionEvents.slice(0, -1);
		const baseline = this.calculateBaseline(baselineEvents);

		for (const pattern of profile.suspiciousPatterns) {
			if (pattern.confidence > 0.7) {
				return {
					isAnomaly: true,
					confidence: pattern.confidence,
					reason: pattern.description,
					pattern,
				};
			}
		}

		if (baselineEvents.length > 0) {
			const frequencyAnomaly = this.checkFrequencyAnomaly(profile.toolFrequency, baseline);
			if (frequencyAnomaly.isAnomaly) {
				return frequencyAnomaly;
			}

			const candidate = sessionEvents[sessionEvents.length - 1];
			if (candidate) {
				const riskAnomaly = this.checkRiskAnomaly(candidate.riskScore, baseline);
				if (riskAnomaly.isAnomaly) {
					return riskAnomaly;
				}
			}
		}

		return {
			isAnomaly: false,
			confidence: 0,
			reason: "No behavioral anomalies detected",
		};
	}

	private calculateToolFrequency(events: ToolCallEvent[]): Map<string, number> {
		const frequency = new Map<string, number>();

		for (const event of events) {
			const count = frequency.get(event.toolName) || 0;
			frequency.set(event.toolName, count + 1);
		}

		return frequency;
	}

	private calculateAverageRisk(events: ToolCallEvent[]): number {
		if (events.length === 0) return 0;

		const total = events.reduce((sum, e) => sum + e.riskScore, 0);
		return total / events.length;
	}

	private extractSequences(events: ToolCallEvent[]): string[][] {
		const sequences: string[][] = [];
		const sequenceLength = 3;

		for (let i = 0; i <= events.length - sequenceLength; i++) {
			const sequence = events.slice(i, i + sequenceLength).map((e) => e.toolName);
			sequences.push(sequence);
		}

		return sequences;
	}

	private detectSuspiciousPatterns(events: ToolCallEvent[]): SuspiciousPattern[] {
		const patterns: SuspiciousPattern[] = [];

		const highRiskTools = events.filter((e) => e.riskScore > 70);
		if (highRiskTools.length >= 3) {
			patterns.push({
				type: "sequence_risk",
				description: `Multiple high-risk tool calls (${highRiskTools.length}) in session`,
				confidence: Math.min(highRiskTools.length / 5, 1.0),
				tools: [...new Set(highRiskTools.map((e) => e.toolName))],
			});
		}

		const bashEvents = events.filter((e) => e.toolName === "Bash");
		if (bashEvents.length > 10) {
			patterns.push({
				type: "frequency_anomaly",
				description: `Excessive Bash commands (${bashEvents.length}) detected`,
				confidence: Math.min(bashEvents.length / 20, 1.0),
				tools: ["Bash"],
			});
		}

		const webFetchEvents = events.filter((e) => e.toolName === "WebFetch");
		if (webFetchEvents.length > 15) {
			patterns.push({
				type: "frequency_anomaly",
				description: `High volume of WebFetch calls (${webFetchEvents.length})`,
				confidence: Math.min(webFetchEvents.length / 25, 1.0),
				tools: ["WebFetch"],
			});
		}

		return patterns;
	}

	private calculateBaseline(events: ToolCallEvent[]): {
		avgToolFrequency: number;
		avgRiskScore: number;
	} {
		if (events.length === 0) {
			return { avgToolFrequency: 0, avgRiskScore: 0 };
		}

		const toolCounts = new Map<string, number>();
		let totalRisk = 0;

		for (const event of events) {
			const count = toolCounts.get(event.toolName) || 0;
			toolCounts.set(event.toolName, count + 1);
			totalRisk += event.riskScore;
		}

		const avgToolFrequency = events.length / toolCounts.size;
		const avgRiskScore = totalRisk / events.length;

		return { avgToolFrequency, avgRiskScore };
	}

	private checkFrequencyAnomaly(
		currentFrequency: Map<string, number>,
		baseline: { avgToolFrequency: number; avgRiskScore: number },
	): AnomalyDetectionResult {
		for (const [tool, count] of currentFrequency.entries()) {
			if (count > baseline.avgToolFrequency * this.anomalyThreshold) {
				return {
					isAnomaly: true,
					confidence: 0.8,
					reason: `Abnormal frequency of ${tool} (${count} calls)`,
				};
			}
		}

		return { isAnomaly: false, confidence: 0, reason: "" };
	}

	private checkRiskAnomaly(
		currentRisk: number,
		baseline: { avgToolFrequency: number; avgRiskScore: number },
	): AnomalyDetectionResult {
		if (currentRisk > baseline.avgRiskScore * this.anomalyThreshold && currentRisk > 50) {
			return {
				isAnomaly: true,
				confidence: Math.min(currentRisk / 100, 1.0),
				reason: `Session risk score (${currentRisk.toFixed(1)}) significantly above baseline`,
			};
		}

		return { isAnomaly: false, confidence: 0, reason: "" };
	}

	getSessionStats(): { totalEvents: number; uniqueSessions: number; averageSessionLength: number } {
		const sessionIds = [...new Set(this.events.map((e) => e.sessionId))];
		const totalEvents = this.events.length;

		return {
			totalEvents,
			uniqueSessions: sessionIds.length,
			averageSessionLength: sessionIds.length > 0 ? totalEvents / sessionIds.length : 0,
		};
	}
}

export function createBehavioralAnalyzer(
	windowSize?: number,
	anomalyThreshold?: number,
	logger?: Logger,
): BehavioralAnalyzer {
	return new BehavioralAnalyzer(windowSize, anomalyThreshold, logger);
}
