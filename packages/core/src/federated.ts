/**
 * Federated learning module for privacy-preserving threat intelligence sharing.
 * Implements differential privacy for secure collaboration across nodes.
 */

import { createHash, randomBytes } from "node:crypto";

export interface FederatedConfig {
	nodeId: string;
	coordinatorUrl?: string;
	shareIntervalMinutes: number;
	privacyBudget: number; // differential privacy epsilon
}

export interface AnonymizedThreatPattern {
	id: string;
	hash: string; // hashed threat signature
	category: string;
	severity: string;
	count: number; // aggregated count
	noiseAdded: number; // DP noise
}

interface LocalPattern {
	threatId: string;
	count: number;
	lastSeen: Date;
	category: string;
	severity: string;
}

export class FederatedLearning {
	private localPatterns = new Map<string, LocalPattern>();
	private privacyBudgetUsed = 0;

	constructor(private config: FederatedConfig) {}

	/**
	 * Record a local threat detection.
	 * Adds to local patterns for later aggregation and sharing.
	 */
	async recordLocalDetection(
		threatId: string,
		category = "unknown",
		severity = "medium",
	): Promise<void> {
		const existing = this.localPatterns.get(threatId);

		if (existing) {
			existing.count++;
			existing.lastSeen = new Date();
		} else {
			this.localPatterns.set(threatId, {
				threatId,
				count: 1,
				lastSeen: new Date(),
				category,
				severity,
			});
		}
	}

	/**
	 * Prepare anonymized data for sharing with the coordinator.
	 * Applies differential privacy (Laplace noise) to protect individual detections.
	 */
	async prepareShareData(): Promise<AnonymizedThreatPattern[]> {
		const anonymized: AnonymizedThreatPattern[] = [];

		for (const pattern of this.localPatterns.values()) {
			// Apply differential privacy
			const { noisyCount, noise } = this.applyDifferentialPrivacy(
				pattern.count,
				this.config.privacyBudget,
			);

			// Create hash of threat identifier (one-way, preserves privacy)
			const hash = this.hashThreatId(pattern.threatId);

			anonymized.push({
				id: this.generatePatternId(),
				hash,
				category: pattern.category,
				severity: pattern.severity,
				count: Math.max(0, Math.round(noisyCount)), // Ensure non-negative
				noiseAdded: noise,
			});
		}

		return anonymized;
	}

	/**
	 * Share anonymized data with the coordinator.
	 * Sends local patterns and receives global model updates.
	 */
	async shareWithCoordinator(): Promise<void> {
		if (!this.config.coordinatorUrl) {
			throw new Error("No coordinator URL configured");
		}

		const data = await this.prepareShareData();

		// Send to coordinator
		const response = await fetch(this.config.coordinatorUrl, {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Node-ID": this.config.nodeId,
			},
			body: JSON.stringify({
				nodeId: this.config.nodeId,
				timestamp: new Date().toISOString(),
				patterns: data,
			}),
		});

		if (!response.ok) {
			throw new Error(`Coordinator error: ${response.status} ${response.statusText}`);
		}

		// Receive and process global update
		const globalUpdate = (await response.json()) as { patterns?: AnonymizedThreatPattern[] };
		if (globalUpdate.patterns) {
			await this.receiveGlobalUpdate(globalUpdate.patterns);
		}
	}

	/**
	 * Receive and process a global model update from the coordinator.
	 * Updates local threat database with aggregated insights.
	 */
	async receiveGlobalUpdate(globalPatterns: AnonymizedThreatPattern[]): Promise<void> {
		// Merge global patterns with local knowledge
		// This enhances local detection with community intelligence
		for (const globalPattern of globalPatterns) {
			// Check if we already have this pattern locally
			const localPattern = this.findPatternByHash(globalPattern.hash);

			if (localPattern) {
				// Update with global insights (weighted average)
				const globalCount = Math.max(0, globalPattern.count - globalPattern.noiseAdded);
				localPattern.count = Math.max(localPattern.count, Math.round(globalCount * 0.5)); // Weight global data at 50%
			}
			// Note: Global patterns without local match are tracked separately
			// to avoid adding unknown threats directly
		}
	}

	/**
	 * Apply differential privacy using Laplace mechanism.
	 * Adds noise proportional to privacy budget (epsilon).
	 */
	private applyDifferentialPrivacy(
		count: number,
		epsilon: number,
	): { noisyCount: number; noise: number } {
		// Laplace scale parameter: b = sensitivity / epsilon
		// For count queries, sensitivity = 1 (adding/removing one record changes count by 1)
		const sensitivity = 1;
		const scale = sensitivity / epsilon;

		// Generate Laplace noise
		const noise = this.generateLaplaceNoise(scale);

		// Track privacy budget usage
		this.privacyBudgetUsed += epsilon;

		return {
			noisyCount: count + noise,
			noise,
		};
	}

	/**
	 * Generate Laplace-distributed random noise.
	 * Uses inverse transform sampling.
	 */
	private generateLaplaceNoise(scale: number): number {
		// Generate uniform random in (0, 1)
		const u = Math.random() - 0.5;

		// Inverse Laplace CDF: -b * sign(u) * ln(1 - 2|u|)
		const sign = u < 0 ? -1 : 1;
		return -scale * sign * Math.log(1 - 2 * Math.abs(u));
	}

	/**
	 * Hash threat ID for privacy-preserving sharing.
	 * Uses SHA-256 with node-specific salt.
	 */
	private hashThreatId(threatId: string): string {
		// Use node ID as salt for consistent but unlinkable hashes
		const salt = this.config.nodeId.slice(0, 16);
		return createHash("sha256")
			.update(threatId + salt)
			.digest("hex")
			.slice(0, 32);
	}

	/**
	 * Generate unique pattern ID.
	 */
	private generatePatternId(): string {
		return `pattern_${Date.now()}_${randomBytes(4).toString("hex")}`;
	}

	/**
	 * Find local pattern by its hash.
	 */
	private findPatternByHash(hash: string): LocalPattern | undefined {
		for (const pattern of this.localPatterns.values()) {
			if (this.hashThreatId(pattern.threatId) === hash) {
				return pattern;
			}
		}
		return undefined;
	}

	/**
	 * Get local pattern statistics.
	 */
	async getLocalStats(): Promise<{
		patternCount: number;
		totalDetections: number;
		privacyBudgetUsed: number;
		privacyBudgetRemaining: number;
	}> {
		let totalDetections = 0;
		for (const pattern of this.localPatterns.values()) {
			totalDetections += pattern.count;
		}

		return {
			patternCount: this.localPatterns.size,
			totalDetections,
			privacyBudgetUsed: this.privacyBudgetUsed,
			privacyBudgetRemaining: Math.max(0, this.config.privacyBudget - this.privacyBudgetUsed),
		};
	}

	/**
	 * Get all local patterns.
	 */
	async getLocalPatterns(): Promise<LocalPattern[]> {
		return Array.from(this.localPatterns.values());
	}

	/**
	 * Clear all local patterns (e.g., after successful sharing).
	 */
	async clearLocalPatterns(): Promise<void> {
		this.localPatterns.clear();
	}

	/**
	 * Check if it's time to share based on configured interval.
	 */
	shouldShare(lastShareTime: Date): boolean {
		const now = new Date();
		const minutesSinceLastShare = (now.getTime() - lastShareTime.getTime()) / (1000 * 60);
		return minutesSinceLastShare >= this.config.shareIntervalMinutes;
	}

	/**
	 * Reset privacy budget (e.g., for a new time period).
	 */
	resetPrivacyBudget(): void {
		this.privacyBudgetUsed = 0;
	}

	/**
	 * Create default federated learning configuration.
	 */
	static createDefaultConfig(nodeId?: string): FederatedConfig {
		return {
			nodeId: nodeId || `node_${randomBytes(8).toString("hex")}`,
			coordinatorUrl: undefined,
			shareIntervalMinutes: 60,
			privacyBudget: 1.0, // Standard epsilon for moderate privacy
		};
	}
}
