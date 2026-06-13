/**
 * Community rule registry for crowd-sourced threat detection patterns.
 * Implements voting, reputation, and promotion workflows for user-contributed rules.
 */

import { randomUUID } from "node:crypto";
import type { Logger } from "./types.js";
import { nullLogger } from "./types.js";

export interface CommunityRule {
	id: string;
	authorId: string;
	name: string;
	description: string;
	pattern: string;
	category: string;
	severity: "low" | "medium" | "high" | "critical";
	votes: {
		up: number;
		down: number;
	};
	reputation: number;
	status: "pending" | "approved" | "rejected" | "promoted";
	submittedAt: Date;
	reviewedAt?: Date;
}

export interface RuleContributor {
	userId: string;
	reputation: number;
	rulesSubmitted: number;
	rulesApproved: number;
	rulesPromoted: number;
}

interface VoteRecord {
	userId: string;
	ruleId: string;
	direction: "up" | "down";
	votedAt: Date;
}

export interface CommunityRuleRegistryConfig {
	promotionThreshold: number;
	autoPromoteEnabled: boolean;
}

export class CommunityRuleRegistry {
	private rules = new Map<string, CommunityRule>();
	private contributors = new Map<string, RuleContributor>();
	private votes = new Map<string, VoteRecord>(); // key: `${userId}:${ruleId}`
	private readonly logger: Logger;

	constructor(
		private config: CommunityRuleRegistryConfig,
		logger: Logger = nullLogger,
	) {
		this.logger = logger;
	}

	/**
	 * Submit a new community rule for review.
	 * Returns the generated rule ID.
	 */
	async submitRule(
		authorId: string,
		rule: Omit<CommunityRule, "id" | "votes" | "reputation" | "status">,
	): Promise<string> {
		// Generate unique rule ID
		const id = randomUUID();

		// Ensure contributor exists
		this.ensureContributor(authorId);

		// Create the rule
		const communityRule: CommunityRule = {
			...rule,
			id,
			authorId,
			votes: { up: 0, down: 0 },
			reputation: 0,
			status: "pending",
			submittedAt: new Date(),
		};

		this.rules.set(id, communityRule);

		// Update contributor stats
		const contributor = this.contributors.get(authorId);
		if (contributor) {
			contributor.rulesSubmitted++;
		}

		this.logger.info("Community rule submitted", {
			ruleId: id,
			authorId,
			category: rule.category,
		});

		return id;
	}

	/**
	 * Vote on a community rule.
	 * Validates user hasn't voted before and recalculates reputation.
	 */
	async vote(ruleId: string, userId: string, direction: "up" | "down"): Promise<void> {
		const rule = this.rules.get(ruleId);
		if (!rule) {
			throw new Error(`Rule not found: ${ruleId}`);
		}

		// Check if user already voted
		const voteKey = `${userId}:${ruleId}`;
		if (this.votes.has(voteKey)) {
			throw new Error(`User ${userId} has already voted on rule ${ruleId}`);
		}

		// Record the vote
		this.votes.set(voteKey, {
			userId,
			ruleId,
			direction,
			votedAt: new Date(),
		});

		// Update vote counts
		if (direction === "up") {
			rule.votes.up++;
		} else {
			rule.votes.down++;
		}

		// Recalculate reputation
		rule.reputation = this.calculateReputation(rule);

		// Check for auto-promotion
		if (
			this.config.autoPromoteEnabled &&
			rule.status === "approved" &&
			rule.reputation >= this.config.promotionThreshold
		) {
			rule.status = "promoted";

			// Update contributor stats
			const contributor = this.contributors.get(rule.authorId);
			if (contributor) {
				contributor.rulesPromoted++;
			}

			this.logger.info("Rule auto-promoted based on reputation", {
				ruleId,
				reputation: rule.reputation,
				threshold: this.config.promotionThreshold,
			});
		}

		this.logger.info("Vote recorded", {
			ruleId,
			userId,
			direction,
			newReputation: rule.reputation,
		});
	}

	/**
	 * Review a pending rule (moderator action).
	 */
	async reviewRule(
		ruleId: string,
		moderatorId: string,
		decision: "approved" | "rejected",
	): Promise<void> {
		const rule = this.rules.get(ruleId);
		if (!rule) {
			throw new Error(`Rule not found: ${ruleId}`);
		}

		if (rule.status !== "pending") {
			throw new Error(`Rule ${ruleId} is not in pending status`);
		}

		rule.status = decision;
		rule.reviewedAt = new Date();

		// Update contributor reputation
		const contributor = this.contributors.get(rule.authorId);
		if (contributor) {
			if (decision === "approved") {
				contributor.rulesApproved++;
				contributor.reputation += 10;
			} else {
				contributor.reputation -= 5;
			}
		}

		this.logger.info("Rule reviewed", {
			ruleId,
			moderatorId,
			decision,
		});
	}

	/**
	 * Get all promoted rules that have reached the promotion threshold.
	 */
	async getPromotedRules(): Promise<CommunityRule[]> {
		const promoted: CommunityRule[] = [];

		for (const rule of this.rules.values()) {
			if (
				rule.status === "promoted" ||
				(rule.status === "approved" && rule.reputation >= this.config.promotionThreshold)
			) {
				promoted.push(rule);
			}
		}

		return promoted.sort((a, b) => b.reputation - a.reputation);
	}

	/**
	 * Get rules by status.
	 */
	async getRulesByStatus(status: CommunityRule["status"]): Promise<CommunityRule[]> {
		const filtered: CommunityRule[] = [];

		for (const rule of this.rules.values()) {
			if (rule.status === status) {
				filtered.push(rule);
			}
		}

		return filtered.sort((a, b) => b.submittedAt.getTime() - a.submittedAt.getTime());
	}

	/**
	 * Get the contributor leaderboard sorted by reputation.
	 */
	async getLeaderboard(): Promise<RuleContributor[]> {
		const contributors = Array.from(this.contributors.values());
		return contributors.sort((a, b) => {
			if (b.reputation !== a.reputation) return b.reputation - a.reputation;
			if (b.rulesPromoted !== a.rulesPromoted) return b.rulesPromoted - a.rulesPromoted;
			return b.rulesApproved - a.rulesApproved;
		});
	}

	/**
	 * Get a specific rule by ID.
	 */
	async getRule(id: string): Promise<CommunityRule | undefined> {
		return this.rules.get(id);
	}

	/**
	 * Get a specific contributor by ID.
	 */
	async getContributor(userId: string): Promise<RuleContributor | undefined> {
		return this.contributors.get(userId);
	}

	/**
	 * Ensure a contributor exists in the registry.
	 */
	private ensureContributor(userId: string): void {
		if (!this.contributors.has(userId)) {
			this.contributors.set(userId, {
				userId,
				reputation: 0,
				rulesSubmitted: 0,
				rulesApproved: 0,
				rulesPromoted: 0,
			});
		}
	}

	/**
	 * Calculate reputation using Wilson score interval.
	 * This gives better confidence for rules with more votes.
	 */
	private calculateReputation(rule: CommunityRule): number {
		const { up, down } = rule.votes;
		const n = up + down;

		if (n === 0) {
			return 0;
		}

		// Wilson score interval lower bound (95% confidence)
		// This prevents rules with few votes from having inflated scores
		const p = up / n;
		const z = 1.96; // 95% confidence

		const numerator = p + (z * z) / (2 * n) - z * Math.sqrt((p * (1 - p) + (z * z) / (4 * n)) / n);
		const denominator = 1 + (z * z) / n;

		const wilsonScore = numerator / denominator;

		// Scale to 0-100 range
		return Math.round(wilsonScore * 100);
	}
}
