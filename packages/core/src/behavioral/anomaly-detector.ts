/**
 * Anomaly detection engine for user behavior analysis.
 * Detects deviations from established baselines including:
 * - Command frequency spikes
 * - Unusual file access patterns
 * - Off-hours activity
 * - Tool usage changes
 */

import type { BaselineStats } from "./baseline.js";

export interface AnomalyDetails {
	expected: number;
	actual: number;
	deviation: number;
	context?: Record<string, unknown>;
}

export interface AnomalyResult {
	score: number; // 0.0 to 1.0
	type: AnomalyType;
	details: AnomalyDetails;
	confidence: number;
	severity: "low" | "medium" | "high" | "critical";
}

export type AnomalyType =
	| "frequency_spike"
	| "file_access_deviation"
	| "off_hours_activity"
	| "tool_usage_change"
	| "new_directory_access"
	| "command_pattern_change";

export interface DetectionContext {
	currentHour: number;
	currentTool: string;
	currentDirectory: string;
	commandCount: number;
	recentCommands: string[];
}

// Z-score threshold for anomaly detection
const Z_SCORE_THRESHOLD = 2.5;
const OFF_HOURS_START = 23;
const OFF_HOURS_END = 6;

export class AnomalyDetector {
	/**
	 * Detect command frequency anomaly
	 * Compares current command rate against historical average
	 */
	detectFrequencySpike(
		history: { timestamp: number }[],
		baselineStats: BaselineStats,
		windowHours: number = 1,
	): AnomalyResult | null {
		const now = Date.now();
		const windowMs = windowHours * 60 * 60 * 1000;
		const recentCount = history.filter((h) => now - h.timestamp < windowMs).length;
		const expectedCount = baselineStats.avgCommandsPerHour * windowHours;

		if (expectedCount === 0) {
			// No baseline yet, any activity is "normal"
			return null;
		}

		// Calculate deviation ratio
		const deviation = recentCount / expectedCount;

		// Z-score approximation (assuming Poisson-like distribution)
		const variance = expectedCount;
		const stdDev = Math.sqrt(variance);
		const zScore = (recentCount - expectedCount) / stdDev;

		if (zScore < Z_SCORE_THRESHOLD) {
			return null;
		}

		// Score: 0.5 at threshold, approaches 1.0 as deviation increases
		const score = Math.min(0.5 + (zScore - Z_SCORE_THRESHOLD) * 0.1, 1.0);

		return {
			score,
			type: "frequency_spike",
			confidence: Math.min(zScore / 5, 1.0),
			severity: score > 0.8 ? "critical" : score > 0.7 ? "high" : "medium",
			details: {
				expected: expectedCount,
				actual: recentCount,
				deviation,
				context: { windowHours, zScore },
			},
		};
	}

	/**
	 * Detect off-hours activity anomaly
	 */
	detectOffHoursActivity(
		history: { timestamp: number }[],
		baselineStats: BaselineStats,
		currentHour: number,
	): AnomalyResult | null {
		const isOffHours = currentHour >= OFF_HOURS_START || currentHour < OFF_HOURS_END;
		if (!isOffHours) {
			return null;
		}

		// Check if user has any history of off-hours work
		const totalCommands = history.length;
		const offHoursRatio = baselineStats.offHoursCommands / totalCommands;

		// If off-hours ratio is very low (< 5%), this is anomalous
		if (offHoursRatio > 0.05) {
			return null; // User regularly works off-hours
		}

		const score = 0.6 + (1 - offHoursRatio * 20) * 0.4; // Higher score for lower off-hours ratio

		return {
			score: Math.min(score, 1.0),
			type: "off_hours_activity",
			confidence: 1 - offHoursRatio * 20,
			severity: score > 0.8 ? "high" : "medium",
			details: {
				expected: baselineStats.offHoursCommands,
				actual: 1,
				deviation: 1 / (offHoursRatio + 0.001),
				context: { currentHour, typicalHours: baselineStats.typicalHours },
			},
		};
	}

	/**
	 * Detect file access pattern deviation
	 */
	detectFileAccessDeviation(
		currentDirectory: string,
		baselineStats: BaselineStats,
		sensitivePaths: string[] = ["/etc", "/sys", "/proc", "/var", "/usr/bin", "/bin", "/sbin"],
	): AnomalyResult | null {
		const commonDirs = baselineStats.commonDirectories || [];

		// Check if accessing sensitive/unusual directory
		const isSensitive = sensitivePaths.some((p) => currentDirectory.startsWith(p));
		const isCommon = commonDirs.some(
			(d) => currentDirectory.startsWith(d) || d.startsWith(currentDirectory),
		);

		if (!isSensitive && isCommon) {
			return null;
		}

		if (isSensitive) {
			return {
				score: 0.75,
				type: "new_directory_access",
				confidence: 0.8,
				severity: "high",
				details: {
					expected: commonDirs.length,
					actual: 1,
					deviation: 5,
					context: { directory: currentDirectory, isSensitive: true },
				},
			};
		}

		// Accessing new/uncommon directory
		const deviation = commonDirs.length > 0 ? 2 : 1;
		const score = commonDirs.length > 0 ? 0.4 : 0.3;

		return {
			score,
			type: "new_directory_access",
			confidence: commonDirs.length > 0 ? 0.6 : 0.5,
			severity: "low",
			details: {
				expected: commonDirs.length,
				actual: 1,
				deviation,
				context: { directory: currentDirectory, isCommon: false },
			},
		};
	}

	/**
	 * Detect tool usage change
	 */
	detectToolUsageChange(
		currentTool: string,
		baselineStats: BaselineStats,
		recentTools: string[],
	): AnomalyResult | null {
		const toolDistribution = baselineStats.toolDistribution || {};
		const totalCommands = Object.values(toolDistribution).reduce((a, b) => a + b, 0);

		if (totalCommands === 0) {
			return null; // No baseline yet
		}

		const currentToolCount = toolDistribution[currentTool] || 0;
		const currentToolRatio = currentToolCount / totalCommands;

		// Calculate recent tool ratio (last N commands)
		const recentSameTool = recentTools.filter((t) => t === currentTool).length;
		const recentRatio = recentTools.length > 0 ? recentSameTool / recentTools.length : 0;

		// Check for suspicious tools
		const suspiciousTools = ["curl", "wget", "nc", "netcat", "bash", "sh", "python", "perl"];
		const isSuspicious = suspiciousTools.some((t) => currentTool.toLowerCase().includes(t));

		// If tool is rarely used historically but heavily used recently
		if (currentToolRatio < 0.05 && recentRatio > 0.5) {
			const baseScore = 0.5;
			const suspiciousBoost = isSuspicious ? 0.3 : 0;
			const score = Math.min(baseScore + suspiciousBoost, 1.0);

			return {
				score,
				type: "tool_usage_change",
				confidence: 0.7,
				severity: score > 0.7 ? "high" : "medium",
				details: {
					expected: currentToolRatio * 100,
					actual: recentRatio * 100,
					deviation: recentRatio / (currentToolRatio + 0.001),
					context: { tool: currentTool, isSuspicious },
				},
			};
		}

		return null;
	}

	/**
	 * Detect command pattern change using simple sequence analysis
	 */
	detectCommandPatternChange(
		recentCommands: string[],
		history: { context: string }[],
	): AnomalyResult | null {
		if (recentCommands.length < 3 || history.length < 10) {
			return null;
		}

		// Parse command patterns from history
		const historicalPatterns = this.extractPatterns(history);
		const currentPattern = recentCommands.join(" | ");

		// Check if current pattern has been seen before
		const seenBefore = historicalPatterns.some((p) => this.similarity(p, currentPattern) > 0.8);

		if (seenBefore) {
			return null;
		}

		// Check for dangerous patterns (piping to shell, etc.)
		const dangerousPatterns = [
			"| bash",
			"| sh",
			"| python",
			"> /etc",
			"chmod +x",
			"curl.*|",
			"wget.*|",
		];
		const isDangerous = dangerousPatterns.some((p) => new RegExp(p, "i").test(currentPattern));

		const score = isDangerous ? 0.85 : 0.5;

		return {
			score,
			type: "command_pattern_change",
			confidence: isDangerous ? 0.85 : 0.6,
			severity: isDangerous ? "critical" : "medium",
			details: {
				expected: historicalPatterns.length,
				actual: 1,
				deviation: 3,
				context: { pattern: currentPattern, isDangerous, isNovel: true },
			},
		};
	}

	/**
	 * Main detection method - runs all detectors and returns merged results
	 */
	detectAnomalies(
		history: { timestamp: number; context: string }[],
		baselineStats: BaselineStats,
		context: DetectionContext,
	): AnomalyResult[] {
		const results: AnomalyResult[] = [];

		// Frequency spike
		const freqAnomaly = this.detectFrequencySpike(history, baselineStats);
		if (freqAnomaly) results.push(freqAnomaly);

		// Off-hours
		const hoursAnomaly = this.detectOffHoursActivity(history, baselineStats, context.currentHour);
		if (hoursAnomaly) results.push(hoursAnomaly);

		// File access
		const fileAnomaly = this.detectFileAccessDeviation(context.currentDirectory, baselineStats);
		if (fileAnomaly) results.push(fileAnomaly);

		// Tool usage
		const toolAnomaly = this.detectToolUsageChange(
			context.currentTool,
			baselineStats,
			context.recentCommands.slice(0, 10),
		);
		if (toolAnomaly) results.push(toolAnomaly);

		// Pattern change
		const patternAnomaly = this.detectCommandPatternChange(context.recentCommands, history);
		if (patternAnomaly) results.push(patternAnomaly);

		return results.sort((a, b) => b.score - a.score);
	}

	/**
	 * Calculate aggregate anomaly score from multiple results
	 */
	calculateAggregateScore(anomalies: AnomalyResult[]): {
		score: number;
		primaryType: AnomalyType | null;
	} {
		if (anomalies.length === 0) {
			return { score: 0, primaryType: null };
		}

		// Weighted average with diminishing returns for multiple anomalies
		const weights = anomalies.map((a) => a.score);
		const maxWeight = Math.max(...weights);
		const sumWeights = weights.reduce((a, b) => a + b, 0);

		// Score formula: max + (sum - max) * 0.3 (multiple anomalies amplify but don't linearly add)
		const aggregateScore = Math.min(maxWeight + (sumWeights - maxWeight) * 0.3, 1.0);

		return {
			score: aggregateScore,
			primaryType: anomalies[0]?.type ?? null,
		};
	}

	private extractPatterns(history: { context: string }[]): string[] {
		const patterns: string[] = [];
		const windowSize = 3;

		for (let i = 0; i <= history.length - windowSize; i++) {
			const window = history.slice(i, i + windowSize);
			const cmds = window.map((h) => {
				try {
					const ctx = JSON.parse(h.context) as { command?: string };
					return ctx.command ?? "";
				} catch {
					return "";
				}
			});
			patterns.push(cmds.join(" | "));
		}

		return [...new Set(patterns)];
	}

	private similarity(a: string, b: string): number {
		if (a === b) return 1;
		const longer = a.length > b.length ? a : b;
		const shorter = a.length > b.length ? b : a;
		if (longer.length === 0) return 1;
		const distance = this.levenshteinDistance(longer, shorter);
		return (longer.length - distance) / longer.length;
	}

	private levenshteinDistance(a: string, b: string): number {
		const matrix: number[][] = [];

		for (let i = 0; i <= b.length; i++) {
			matrix[i] = [i];
		}

		for (let j = 0; j <= a.length; j++) {
			matrix[0]![j] = j;
		}

		for (let i = 1; i <= b.length; i++) {
			for (let j = 1; j <= a.length; j++) {
				if (b.charAt(i - 1) === a.charAt(j - 1)) {
					matrix[i]![j] = matrix[i - 1]?.[j - 1]!;
				} else {
					matrix[i]![j] = Math.min(
						matrix[i - 1]?.[j - 1]! + 1,
						Math.min(matrix[i]?.[j - 1]! + 1, matrix[i - 1]?.[j]! + 1),
					);
				}
			}
		}

		return matrix[b.length]?.[a.length]!;
	}
}

export function createAnomalyDetector(): AnomalyDetector {
	return new AnomalyDetector();
}
