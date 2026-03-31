/**
 * Tests for Community Rules Registry
 */
import { beforeEach, describe, expect, it } from "vitest";
import { CommunityRuleRegistry, type CommunityRuleRegistryConfig } from "../community-rules.js";
import { nullLogger } from "../types.js";

describe("CommunityRuleRegistry", () => {
	let registry: CommunityRuleRegistry;
	let config: CommunityRuleRegistryConfig;

	beforeEach(() => {
		config = {
			promotionThreshold: 70,
			autoPromoteEnabled: true,
		};
		registry = new CommunityRuleRegistry(config, nullLogger);
	});

	describe("submitRule", () => {
		it("should submit a rule and return an ID", async () => {
			const rule = {
				authorId: "user1",
				name: "Suspicious Pattern",
				description: "Detects suspicious activity",
				pattern: "suspicious.*pattern",
				category: "security",
				severity: "high" as const,
			};

			const id = await registry.submitRule("user1", rule);

			expect(id).toBeDefined();
			expect(typeof id).toBe("string");

			const storedRule = await registry.getRule(id);
			expect(storedRule).toBeDefined();
			expect(storedRule?.name).toBe("Suspicious Pattern");
			expect(storedRule?.status).toBe("pending");
			expect(storedRule?.votes.up).toBe(0);
			expect(storedRule?.votes.down).toBe(0);
			expect(storedRule?.reputation).toBe(0);
		});

		it("should create contributor entry for new author", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			await registry.submitRule("user1", rule);

			const contributor = await registry.getContributor("user1");
			expect(contributor).toBeDefined();
			expect(contributor?.userId).toBe("user1");
			expect(contributor?.rulesSubmitted).toBe(1);
			expect(contributor?.reputation).toBe(0);
		});
	});

	describe("vote", () => {
		it("should record upvote and update reputation", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "approved");
			await registry.vote(id, "voter1", "up");

			const storedRule = await registry.getRule(id);
			expect(storedRule?.votes.up).toBe(1);
			expect(storedRule?.votes.down).toBe(0);
			expect(storedRule?.reputation).toBeGreaterThan(0);
		});

		it("should prevent duplicate voting", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.vote(id, "voter1", "up");

			await expect(registry.vote(id, "voter1", "up")).rejects.toThrow(
				"User voter1 has already voted on rule",
			);
		});

		it("should allow different users to vote on same rule", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.vote(id, "voter1", "up");
			await registry.vote(id, "voter2", "up");

			const storedRule = await registry.getRule(id);
			expect(storedRule?.votes.up).toBe(2);
		});

		it("should auto-promote rule when threshold reached", async () => {
			const rule = {
				authorId: "user1",
				name: "Popular Rule",
				description: "Very popular",
				pattern: "popular",
				category: "security",
				severity: "high" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "approved");

			// Add many upvotes to reach threshold
			for (let i = 0; i < 20; i++) {
				await registry.vote(id, `voter${i}`, "up");
			}

			const storedRule = await registry.getRule(id);
			expect(storedRule?.status).toBe("promoted");
			expect(storedRule?.reputation).toBeGreaterThanOrEqual(70);
		});
	});

	describe("reviewRule", () => {
		it("should approve pending rule", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "approved");

			const storedRule = await registry.getRule(id);
			expect(storedRule?.status).toBe("approved");
			expect(storedRule?.reviewedAt).toBeDefined();
		});

		it("should reject pending rule", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "rejected");

			const storedRule = await registry.getRule(id);
			expect(storedRule?.status).toBe("rejected");
		});

		it("should update contributor reputation on approve", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "approved");

			const contributor = await registry.getContributor("user1");
			expect(contributor?.rulesApproved).toBe(1);
			expect(contributor?.reputation).toBe(10);
		});

		it("should penalize contributor on reject", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "rejected");

			const contributor = await registry.getContributor("user1");
			expect(contributor?.reputation).toBe(-5);
		});

		it("should throw error for non-existent rule", async () => {
			await expect(registry.reviewRule("non-existent", "mod1", "approved")).rejects.toThrow(
				"Rule not found",
			);
		});

		it("should throw error for already-reviewed rule", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "approved");

			await expect(registry.reviewRule(id, "mod2", "approved")).rejects.toThrow(
				"is not in pending status",
			);
		});
	});

	describe("getPromotedRules", () => {
		it("should return rules with promoted status", async () => {
			const rule1 = {
				authorId: "user1",
				name: "Rule 1",
				description: "Test",
				pattern: "test1",
				category: "test",
				severity: "high" as const,
			};
			const rule2 = {
				authorId: "user2",
				name: "Rule 2",
				description: "Test",
				pattern: "test2",
				category: "test",
				severity: "medium" as const,
			};

			const id1 = await registry.submitRule("user1", rule1);
			const id2 = await registry.submitRule("user2", rule2);

			await registry.reviewRule(id1, "mod1", "approved");
			await registry.reviewRule(id2, "mod1", "approved");

			// Add votes to first rule to promote it
			for (let i = 0; i < 20; i++) {
				await registry.vote(id1, `voter${i}`, "up");
			}

			const promoted = await registry.getPromotedRules();
			expect(promoted.length).toBe(1);
			expect(promoted[0].id).toBe(id1);
		});

		it("should sort by reputation descending", async () => {
			const rule1 = {
				authorId: "user1",
				name: "Rule 1",
				description: "Test",
				pattern: "test1",
				category: "test",
				severity: "high" as const,
			};
			const rule2 = {
				authorId: "user2",
				name: "Rule 2",
				description: "Test",
				pattern: "test2",
				category: "test",
				severity: "medium" as const,
			};

			const id1 = await registry.submitRule("user1", rule1);
			const id2 = await registry.submitRule("user2", rule2);

			await registry.reviewRule(id1, "mod1", "approved");
			await registry.reviewRule(id2, "mod1", "approved");

			// Add more votes to rule2
			for (let i = 0; i < 30; i++) {
				await registry.vote(id2, `voter${i}`, "up");
			}
			for (let i = 0; i < 15; i++) {
				await registry.vote(id1, `voter${i}`, "up");
			}

			const promoted = await registry.getPromotedRules();
			expect(promoted.length).toBe(2);
			expect(promoted[0].id).toBe(id2);
			expect(promoted[1].id).toBe(id1);
		});
	});

	describe("getLeaderboard", () => {
		it("should return contributors sorted by reputation", async () => {
			const rule1 = {
				authorId: "user1",
				name: "Rule 1",
				description: "Test",
				pattern: "test1",
				category: "test",
				severity: "high" as const,
			};
			const rule2 = {
				authorId: "user2",
				name: "Rule 2",
				description: "Test",
				pattern: "test2",
				category: "test",
				severity: "medium" as const,
			};

			const id1 = await registry.submitRule("user1", rule1);
			const id2 = await registry.submitRule("user2", rule2);

			// Approve both - user1 gets 10, user2 gets 10
			await registry.reviewRule(id1, "mod1", "approved");
			await registry.reviewRule(id2, "mod1", "approved");

			// Promote rule2 - user2 gets promoted credit
			for (let i = 0; i < 20; i++) {
				await registry.vote(id2, `voter${i}`, "up");
			}

			const leaderboard = await registry.getLeaderboard();
			expect(leaderboard.length).toBe(2);
			// user2 should have higher reputation (10 base + promotion activity)
			expect(leaderboard[0].userId).toBe("user2");
		});

		it("should return empty array when no contributors", async () => {
			const leaderboard = await registry.getLeaderboard();
			expect(leaderboard).toEqual([]);
		});
	});

	describe("Wilson score calculation", () => {
		it("should return 0 for no votes", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "approved");

			const storedRule = await registry.getRule(id);
			expect(storedRule?.reputation).toBe(0);
		});

		it("should calculate Wilson score correctly for all upvotes", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "approved");

			// Many upvotes should give high reputation
			for (let i = 0; i < 50; i++) {
				await registry.vote(id, `voter${i}`, "up");
			}

			const storedRule = await registry.getRule(id);
			expect(storedRule?.reputation).toBeGreaterThan(90);
			expect(storedRule?.reputation).toBeLessThanOrEqual(100);
		});

		it("should calculate Wilson score correctly with mixed votes", async () => {
			const rule = {
				authorId: "user1",
				name: "Test Rule",
				description: "Test",
				pattern: "test",
				category: "test",
				severity: "low" as const,
			};

			const id = await registry.submitRule("user1", rule);
			await registry.reviewRule(id, "mod1", "approved");

			// Mixed votes - 10 up, 5 down (66% positive)
			for (let i = 0; i < 10; i++) {
				await registry.vote(id, `voter${i}`, "up");
			}
			for (let i = 10; i < 15; i++) {
				await registry.vote(id, `voter${i}`, "down");
			}

			const storedRule = await registry.getRule(id);
			// Wilson score for 10/15 with 95% confidence should be moderate
			expect(storedRule?.reputation).toBeGreaterThan(30);
			expect(storedRule?.reputation).toBeLessThan(80);
		});
	});
});
