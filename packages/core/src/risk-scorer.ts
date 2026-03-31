import type { HeuristicMatch, PackageCheckResult, UrlCheckResult, Verdict } from "./types.js";

export interface RiskFactor {
	name: string;
	score: number;
	weight: number;
	description: string;
}

export interface MultiFactorRiskResult {
	totalScore: number;
	confidence: number;
	factors: RiskFactor[];
	severity: "info" | "warning" | "critical";
	recommendation: string;
}

export interface RiskContext {
	environment: "development" | "staging" | "production" | "unknown";
	userRole: "admin" | "user" | "guest" | "unknown";
	timeOfDay: number;
	historicalRisk: number;
	sessionAge: number;
}

export class MultiFactorRiskScorer {
	private readonly baseWeights = {
		cvss: 0.25,
		exploitability: 0.2,
		agentContext: 0.15,
		historicalRisk: 0.15,
		behavioralAnomaly: 0.15,
		commandChain: 0.1,
	};

	calculateRisk(
		heuristicMatches: HeuristicMatch[],
		urlResults: UrlCheckResult[],
		packageResults: PackageCheckResult[],
		context: RiskContext,
		behavioralScore: number,
		commandChainScore: number,
	): MultiFactorRiskResult {
		const factors: RiskFactor[] = [];

		const cvssFactor = this.calculateCvssFactor(heuristicMatches, urlResults);
		factors.push({
			name: "CVSS Base",
			score: cvssFactor.score,
			weight: this.baseWeights.cvss,
			description: cvssFactor.description,
		});

		const exploitabilityFactor = this.calculateExploitabilityFactor(heuristicMatches, urlResults);
		factors.push({
			name: "Exploitability",
			score: exploitabilityFactor.score,
			weight: this.baseWeights.exploitability,
			description: exploitabilityFactor.description,
		});

		const contextFactor = this.calculateContextFactor(context);
		factors.push({
			name: "Agent Context",
			score: contextFactor.score,
			weight: this.baseWeights.agentContext,
			description: contextFactor.description,
		});

		const historicalFactor = this.calculateHistoricalFactor(context.historicalRisk);
		factors.push({
			name: "Historical Risk",
			score: historicalFactor.score,
			weight: this.baseWeights.historicalRisk,
			description: historicalFactor.description,
		});

		factors.push({
			name: "Behavioral Anomaly",
			score: Math.min(behavioralScore, 100),
			weight: this.baseWeights.behavioralAnomaly,
			description: behavioralScore > 50 ? "Unusual behavior pattern detected" : "Normal behavior",
		});

		factors.push({
			name: "Command Chain",
			score: Math.min(commandChainScore, 100),
			weight: this.baseWeights.commandChain,
			description: commandChainScore > 50 ? "Suspicious command sequence" : "Normal command flow",
		});

		const totalScore = this.computeWeightedScore(factors);
		const confidence = this.calculateConfidence(factors);
		const severity = this.determineSeverity(totalScore);

		return {
			totalScore,
			confidence,
			factors,
			severity,
			recommendation: this.generateRecommendation(totalScore, severity),
		};
	}

	private calculateCvssFactor(
		heuristicMatches: HeuristicMatch[],
		urlResults: UrlCheckResult[],
	): { score: number; description: string } {
		let maxCvss = 0;

		for (const match of heuristicMatches) {
			const confidence = match.threat.confidence;
			const severityScore = this.severityToScore(match.threat.severity);
			const cvss = confidence * severityScore * 10;
			maxCvss = Math.max(maxCvss, cvss);
		}

		for (const urlResult of urlResults) {
			if (urlResult.isMalicious) {
				maxCvss = Math.max(maxCvss, 9.0);
			}
		}

		return {
			score: maxCvss,
			description:
				maxCvss > 7 ? `High CVSS score: ${maxCvss.toFixed(1)}` : `Base risk: ${maxCvss.toFixed(1)}`,
		};
	}

	private calculateExploitabilityFactor(
		heuristicMatches: HeuristicMatch[],
		urlResults: UrlCheckResult[],
	): { score: number; description: string } {
		let trivialExploitCount = 0;
		let easyExploitCount = 0;

		for (const match of heuristicMatches) {
			if (match.threat.action === "block" && match.threat.confidence > 0.9) {
				trivialExploitCount++;
			} else if (match.threat.action === "block") {
				easyExploitCount++;
			}
		}

		const score = Math.min(100, trivialExploitCount * 30 + easyExploitCount * 15);

		let description = "Low exploitability";
		if (trivialExploitCount > 0) {
			description = `${trivialExploitCount} trivially exploitable threats`;
		} else if (easyExploitCount > 0) {
			description = `${easyExploitCount} easily exploitable threats`;
		}

		return { score, description };
	}

	private calculateContextFactor(context: RiskContext): { score: number; description: string } {
		let score = 50;
		const factors: string[] = [];

		if (context.environment === "production") {
			score += 20;
			factors.push("production environment");
		}

		if (context.userRole === "admin") {
			score += 15;
			factors.push("admin privileges");
		} else if (context.userRole === "guest") {
			score -= 10;
		}

		const hour = new Date(context.timeOfDay).getHours();
		if (hour < 6 || hour > 22) {
			score += 10;
			factors.push("off-hours activity");
		}

		if (context.sessionAge < 60000) {
			score += 5;
			factors.push("new session");
		}

		const description =
			factors.length > 0 ? `Context risk: ${factors.join(", ")}` : "Normal context";

		return { score: Math.min(100, score), description };
	}

	private calculateHistoricalFactor(historicalRisk: number): {
		score: number;
		description: string;
	} {
		const score = Math.min(100, historicalRisk * 1.2);
		return {
			score,
			description:
				historicalRisk > 50
					? `Elevated historical risk: ${historicalRisk.toFixed(1)}`
					: `Historical risk: ${historicalRisk.toFixed(1)}`,
		};
	}

	private computeWeightedScore(factors: RiskFactor[]): number {
		let totalWeight = 0;
		let weightedSum = 0;

		for (const factor of factors) {
			totalWeight += factor.weight;
			weightedSum += factor.score * factor.weight;
		}

		return totalWeight > 0 ? weightedSum / totalWeight : 0;
	}

	private calculateConfidence(factors: RiskFactor[]): number {
		const knownFactors = factors.filter((f) => f.score > 0).length;
		return Math.min(1.0, knownFactors / factors.length);
	}

	private determineSeverity(score: number): "info" | "warning" | "critical" {
		if (score >= 80) return "critical";
		if (score >= 50) return "warning";
		return "info";
	}

	private generateRecommendation(score: number, severity: string): string {
		if (severity === "critical") {
			return `CRITICAL RISK (${score.toFixed(0)}): Immediate action required. Block this operation and investigate.`;
		}
		if (severity === "warning") {
			return `WARNING (${score.toFixed(0)}): Review required. Consider blocking or requiring explicit approval.`;
		}
		return `Info (${score.toFixed(0)}): Standard risk level. Proceed with monitoring.`;
	}

	private severityToScore(severity: string): number {
		switch (severity) {
			case "critical":
				return 1.0;
			case "high":
				return 0.8;
			case "medium":
				return 0.5;
			case "low":
				return 0.2;
			default:
				return 0.5;
		}
	}

	adjustWeights(adjustments: Partial<typeof this.baseWeights>): void {
		Object.assign(this.baseWeights, adjustments);
	}
}

export function createMultiFactorRiskScorer(): MultiFactorRiskScorer {
	return new MultiFactorRiskScorer();
}
