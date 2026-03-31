export interface BehaviorProfile {
	userId: string;
	installationId: string;
	baseline: {
		// Normal command patterns
		commonCommands: Map<string, number>;
		commonPaths: Map<string, number>;
		commonUrls: Map<string, number>;
		// Timing patterns
		avgSessionDuration: number;
		peakActivityHours: number[];
		// Tool usage patterns
		toolFrequency: Map<string, number>;
	};
	updatedAt: Date;
}

export interface AnomalyEvent {
	id: string;
	timestamp: Date;
	userId: string;
	anomalyType:
		| "novel_command_sequence"
		| "unusual_timing"
		| "unusual_tool_usage"
		| "unusual_path_access";
	severity: "low" | "medium" | "high" | "critical";
	score: number; // 0-100, higher = more anomalous
	details: {
		expected?: string;
		actual: string;
		similarPastEvents?: number;
	};
	escalated: boolean;
}

interface ProfileData {
	commands: Map<string, number>;
	paths: Map<string, number>;
	urls: Map<string, number>;
	tools: Map<string, number>;
	sessionDurations: number[];
	activityHours: Map<number, number>;
	sampleCount: number;
}

export class NoveltyDetector {
	private profiles = new Map<string, ProfileData>();
	private anomalies: AnomalyEvent[] = [];
	private config: {
		windowSizeDays: number;
		anomalyThreshold: number; // z-score threshold
		minBaselineSamples: number;
		escalationThreshold: number;
	};

	constructor(config: Partial<NoveltyDetector["config"]> = {}) {
		this.config = {
			windowSizeDays: 30,
			anomalyThreshold: 2.5, // 2.5 sigma
			minBaselineSamples: 10,
			escalationThreshold: 80, // score out of 100
			...config,
		};
	}

	/**
	 * Update a user's behavior profile with a new event
	 */
	async updateProfile(
		userId: string,
		event: {
			command?: string;
			path?: string;
			url?: string;
			tool?: string;
			duration?: number;
			hour?: number;
		},
	): Promise<void> {
		let profile = this.profiles.get(userId);

		if (!profile) {
			profile = {
				commands: new Map(),
				paths: new Map(),
				urls: new Map(),
				tools: new Map(),
				sessionDurations: [],
				activityHours: new Map(),
				sampleCount: 0,
			};
			this.profiles.set(userId, profile);
		}

		// Update frequency maps
		if (event.command) {
			const count = profile.commands.get(event.command) || 0;
			profile.commands.set(event.command, count + 1);
		}

		if (event.path) {
			const count = profile.paths.get(event.path) || 0;
			profile.paths.set(event.path, count + 1);
		}

		if (event.url) {
			const count = profile.urls.get(event.url) || 0;
			profile.urls.set(event.url, count + 1);
		}

		if (event.tool) {
			const count = profile.tools.get(event.tool) || 0;
			profile.tools.set(event.tool, count + 1);
		}

		// Update timing patterns
		if (event.duration !== undefined) {
			profile.sessionDurations.push(event.duration);
			// Keep only window size worth of data
			const maxSamples = this.config.windowSizeDays * 10;
			if (profile.sessionDurations.length > maxSamples) {
				profile.sessionDurations = profile.sessionDurations.slice(-maxSamples);
			}
		}

		if (event.hour !== undefined) {
			const count = profile.activityHours.get(event.hour) || 0;
			profile.activityHours.set(event.hour, count + 1);
		}

		profile.sampleCount++;
	}

	/**
	 * Detect anomalies in user behavior
	 */
	async detectAnomaly(
		userId: string,
		event: {
			command?: string;
			path?: string;
			url?: string;
			tool?: string;
			timestamp: Date;
			duration?: number;
			hour?: number;
		},
	): Promise<AnomalyEvent | null> {
		const profile = this.profiles.get(userId);

		// Not enough baseline data - silently collect more
		if (!profile || profile.sampleCount < this.config.minBaselineSamples) {
			return null;
		}

		const anomalyScores: {
			type: AnomalyEvent["anomalyType"];
			score: number;
			details: AnomalyEvent["details"];
		}[] = [];

		// Check command anomaly
		if (event.command) {
			const cmdFreq = profile.commands.get(event.command) || 0;
			const totalCommands = profile.sampleCount;
			const cmdRate = cmdFreq / totalCommands;

			// Rare command (never seen or very rare)
			if (cmdRate < 0.05) {
				const commandScores = Array.from(profile.commands.values());
				const mean = this.calculateMean(commandScores);
				const stdDev = this.calculateStdDev(commandScores, mean);
				const zScore = stdDev > 0 ? this.calculateZScore(cmdFreq, mean, stdDev) : 3;

				anomalyScores.push({
					type: "novel_command_sequence",
					score: Math.min(100, Math.abs(zScore) * 20 + 50),
					details: {
						expected: `Common commands: ${this.getTopKeys(profile.commands, 3).join(", ")}`,
						actual: event.command,
						similarPastEvents: cmdFreq,
					},
				});
			}
		}

		// Check path anomaly
		if (event.path) {
			const pathFreq = profile.paths.get(event.path) || 0;
			const totalPaths = profile.sampleCount;
			const pathRate = pathFreq / totalPaths;

			if (pathRate < 0.03) {
				anomalyScores.push({
					type: "unusual_path_access",
					score: Math.min(100, 70 + (1 - pathRate) * 30),
					details: {
						expected: `Common paths: ${this.getTopKeys(profile.paths, 3).join(", ")}`,
						actual: event.path,
						similarPastEvents: pathFreq,
					},
				});
			}
		}

		// Check tool usage anomaly
		if (event.tool) {
			const toolFreq = profile.tools.get(event.tool) || 0;
			const totalTools = Array.from(profile.tools.values()).reduce((a, b) => a + b, 0);
			const toolRate = totalTools > 0 ? toolFreq / totalTools : 0;

			if (toolRate < 0.1) {
				anomalyScores.push({
					type: "unusual_tool_usage",
					score: Math.min(100, 60 + (1 - toolRate) * 40),
					details: {
						expected: `Common tools: ${this.getTopKeys(profile.tools, 3).join(", ")}`,
						actual: event.tool,
						similarPastEvents: toolFreq,
					},
				});
			}
		}

		// Check timing anomaly
		if (event.hour !== undefined) {
			const hourFreq = profile.activityHours.get(event.hour) || 0;
			const totalHours = profile.sampleCount;
			const hourRate = hourFreq / totalHours;

			// Activity during unusual hours (e.g., 2 AM when user usually works 9-5)
			if (hourRate < 0.05) {
				const hourScores = Array.from(profile.activityHours.values());
				const mean = this.calculateMean(hourScores);
				const stdDev = this.calculateStdDev(hourScores, mean);
				const zScore = stdDev > 0 ? this.calculateZScore(hourFreq, mean, stdDev) : 2.5;

				if (Math.abs(zScore) > this.config.anomalyThreshold) {
					anomalyScores.push({
						type: "unusual_timing",
						score: Math.min(100, Math.abs(zScore) * 15 + 40),
						details: {
							expected: `Peak hours: ${this.getPeakHours(profile.activityHours, 3).join(", ")}`,
							actual: `${event.hour}:00`,
							similarPastEvents: hourFreq,
						},
					});
				}
			}
		}

		// No anomalies detected
		if (anomalyScores.length === 0) {
			return null;
		}

		// Pick the highest scoring anomaly
		const highestAnomaly = anomalyScores.reduce((max, current) =>
			current.score > max.score ? current : max,
		);

		// Determine severity based on score
		let severity: AnomalyEvent["severity"];
		if (highestAnomaly.score >= 90) severity = "critical";
		else if (highestAnomaly.score >= 70) severity = "high";
		else if (highestAnomaly.score >= 50) severity = "medium";
		else severity = "low";

		const anomaly: AnomalyEvent = {
			id: this.generateId(),
			timestamp: event.timestamp,
			userId,
			anomalyType: highestAnomaly.type,
			severity,
			score: Math.round(highestAnomaly.score),
			details: highestAnomaly.details,
			escalated: highestAnomaly.score >= this.config.escalationThreshold,
		};

		// Store anomaly
		this.anomalies.push(anomaly);

		// Prune old anomalies
		const cutoffDate = new Date(event.timestamp);
		cutoffDate.setDate(cutoffDate.getDate() - this.config.windowSizeDays);
		this.anomalies = this.anomalies.filter((a) => a.timestamp > cutoffDate);

		return anomaly;
	}

	/**
	 * Check if an anomaly should be escalated
	 */
	async shouldEscalate(anomaly: AnomalyEvent): Promise<boolean> {
		// Check if score exceeds threshold
		if (anomaly.score < this.config.escalationThreshold) {
			return false;
		}

		// Check for repeated similar anomalies
		const recentSimilar = this.anomalies.filter(
			(a) =>
				a.userId === anomaly.userId &&
				a.anomalyType === anomaly.anomalyType &&
				a.id !== anomaly.id &&
				Math.abs(a.score - anomaly.score) < 15, // Similar score range
		);

		// Escalate if multiple similar anomalies in recent history
		if (recentSimilar.length >= 3) {
			return true;
		}

		// Always escalate critical severity
		if (anomaly.severity === "critical") {
			return true;
		}

		return true; // Score already passed threshold check
	}

	/**
	 * Get anomalies with optional filtering
	 */
	async getAnomalies(userId?: string, from?: Date, to?: Date): Promise<AnomalyEvent[]> {
		let filtered = [...this.anomalies];

		if (userId) {
			filtered = filtered.filter((a) => a.userId === userId);
		}

		if (from) {
			filtered = filtered.filter((a) => a.timestamp >= from);
		}

		if (to) {
			filtered = filtered.filter((a) => a.timestamp <= to);
		}

		return filtered.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());
	}

	/**
	 * Get user behavior profile
	 */
	async getProfile(userId: string): Promise<BehaviorProfile | null> {
		const profile = this.profiles.get(userId);
		if (!profile) return null;

		return {
			userId,
			installationId: "", // Would be populated from actual data
			baseline: {
				commonCommands: new Map(profile.commands),
				commonPaths: new Map(profile.paths),
				commonUrls: new Map(profile.urls),
				avgSessionDuration: this.calculateMean(profile.sessionDurations),
				peakActivityHours: this.getPeakHours(profile.activityHours, 5),
				toolFrequency: new Map(profile.tools),
			},
			updatedAt: new Date(),
		};
	}

	/**
	 * Calculate z-score for statistical anomalies
	 */
	private calculateZScore(value: number, mean: number, stdDev: number): number {
		if (stdDev === 0) return 0;
		return (value - mean) / stdDev;
	}

	/**
	 * Calculate cosine similarity between two vectors
	 * Useful for comparing command sequences
	 */
	cosineSimilarity(a: number[], b: number[]): number {
		if (a.length !== b.length) {
			throw new Error("Vectors must have same length");
		}

		let dotProduct = 0;
		let normA = 0;
		let normB = 0;

		for (let i = 0; i < a.length; i++) {
			dotProduct += (a[i] ?? 0) * (b[i] ?? 0);
			normA += (a[i] ?? 0) * (a[i] ?? 0);
			normB += (b[i] ?? 0) * (b[i] ?? 0);
		}

		if (normA === 0 || normB === 0) return 0;

		return dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
	}

	/**
	 * Calculate mean of an array
	 */
	private calculateMean(values: number[]): number {
		if (values.length === 0) return 0;
		return values.reduce((sum, val) => sum + val, 0) / values.length;
	}

	/**
	 * Calculate standard deviation
	 */
	private calculateStdDev(values: number[], mean: number): number {
		if (values.length === 0) return 0;
		const variance = values.reduce((sum, val) => sum + (val - mean) ** 2, 0) / values.length;
		return Math.sqrt(variance);
	}

	/**
	 * Get top N keys from a frequency map
	 */
	private getTopKeys(map: Map<string, number>, n: number): string[] {
		return Array.from(map.entries())
			.sort((a, b) => {
				const countA = a[1] ?? 0;
				const countB = b[1] ?? 0;
				return countB - countA;
			})
			.slice(0, n)
			.map((entry) => entry[0]);
	}

	/**
	 * Get peak hours from activity map
	 */
	private getPeakHours(map: Map<number, number>, n: number): number[] {
		return Array.from(map.entries())
			.sort((a, b) => {
				const countA = a[1] ?? 0;
				const countB = b[1] ?? 0;
				return countB - countA;
			})
			.slice(0, n)
			.map((entry) => entry[0]);
	}

	/**
	 * Generate unique ID for anomaly
	 */
	private generateId(): string {
		return `anom_${Date.now()}_${Math.random().toString(36).substring(2, 11)}`;
	}
}

/**
 * Factory function to create a NoveltyDetector instance
 */
export function createNoveltyDetector(
	config?: Partial<NoveltyDetector["config"]>,
): NoveltyDetector {
	return new NoveltyDetector(config);
}
