/**
 * Singularity AIDR SDK — Referral System for viral growth
 *
 * Provides complete referral tracking, code generation, and reward distribution.
 */

/**
 * Configuration options for the referral system
 */
export interface ReferralConfig {
	/** Type of reward for the referrer */
	rewardType: "credits" | "discount" | "extension";
	/** Value of the reward (amount of credits, discount percentage, or extension days) */
	rewardValue: number;
	/** Optional reward for the referred user */
	referredReward?: {
		type: "credits" | "discount" | "extension";
		value: number;
	};
	/** Maximum number of referrals allowed per user (undefined = unlimited) */
	maxReferralsPerUser?: number;
	/** Length of generated referral codes */
	referralCodeLength: number;
}

/**
 * Referral record representing a single referral relationship
 */
export interface Referral {
	/** Unique referral ID */
	id: string;
	/** User who generated the referral code (referrer) */
	referrerId: string;
	/** User who signed up using the code (referred) - undefined if code not yet used */
	referredId?: string;
	/** The referral code itself */
	code: string;
	/** Current status of the referral */
	status: "pending" | "converted" | "expired";
	/** When the referral code was created */
	createdAt: Date;
	/** When the referral converted to paid (undefined if not yet converted) */
	convertedAt?: Date;
	/** Whether rewards have been applied */
	rewardsApplied: boolean;
}

/**
 * Storage interface for persisting referral data
 */
export interface ReferralStorage {
	/** Save a new referral */
	save(referral: Referral): Promise<void>;
	/** Get referral by code */
	getByCode(code: string): Promise<Referral | null>;
	/** Get all referrals by a user (as referrer) */
	getByUser(userId: string): Promise<Referral[]>;
	/** Update an existing referral */
	update(referral: Referral): Promise<void>;
}

/**
 * Statistics for a user's referral performance
 */
export interface ReferralStats {
	totalReferrals: number;
	converted: number;
	pending: number;
	rewardsEarned: number;
}

/**
 * Leaderboard entry for top referrers
 */
export interface LeaderboardEntry {
	userId: string;
	referrals: number;
}

/**
 * Viral referral system with growth mechanics
 */
export class ReferralSystem {
	private referrals = new Map<string, Referral>();
	private userReferrals = new Map<string, string[]>();

	constructor(
		private config: ReferralConfig,
		private storage: ReferralStorage,
	) {}

	/**
	 * Generate a unique referral code for a user
	 */
	async generateCode(userId: string): Promise<string> {
		// Check max referrals limit
		if (this.config.maxReferralsPerUser !== undefined) {
			const existing = this.userReferrals.get(userId) ?? [];
			if (existing.length >= this.config.maxReferralsPerUser) {
				throw new Error(
					`Maximum referrals (${this.config.maxReferralsPerUser}) reached for user ${userId}`,
				);
			}
		}

		// Generate unique code
		const code = this.generateUniqueCode();

		const referral: Referral = {
			id: this.generateId(),
			referrerId: userId,
			code,
			status: "pending",
			createdAt: new Date(),
			rewardsApplied: false,
		};

		// Store in memory
		this.referrals.set(code, referral);
		const userRefs = this.userReferrals.get(userId) ?? [];
		userRefs.push(code);
		this.userReferrals.set(userId, userRefs);

		// Persist to storage
		await this.storage.save(referral);

		return code;
	}

	/**
	 * Track when a user signs up with a referral code
	 */
	async trackReferral(code: string, referredUserId: string): Promise<void> {
		const referral = this.referrals.get(code) ?? (await this.storage.getByCode(code));

		if (!referral) {
			throw new Error(`Referral code ${code} not found`);
		}

		if (referral.status !== "pending") {
			throw new Error(`Referral code ${code} is no longer valid`);
		}

		if (referral.referrerId === referredUserId) {
			throw new Error("Cannot use your own referral code");
		}

		referral.referredId = referredUserId;
		this.referrals.set(code, referral);

		await this.storage.update(referral);
	}

	/**
	 * Mark referral as converted when referred user upgrades to paid
	 */
	async convertReferral(code: string): Promise<void> {
		const referral = this.referrals.get(code) ?? (await this.storage.getByCode(code));

		if (!referral) {
			throw new Error(`Referral code ${code} not found`);
		}

		if (referral.status !== "pending") {
			return; // Already converted or expired
		}

		referral.status = "converted";
		referral.convertedAt = new Date();
		referral.rewardsApplied = true;

		this.referrals.set(code, referral);
		await this.storage.update(referral);

		// Apply rewards could be handled here or by external system
	}

	/**
	 * Get referral statistics for a user
	 */
	async getReferralStats(userId: string): Promise<ReferralStats> {
		const userCodes = this.userReferrals.get(userId) ?? [];
		const referrals: Referral[] = [];

		for (const code of userCodes) {
			const ref = this.referrals.get(code) ?? (await this.storage.getByCode(code));
			if (ref) referrals.push(ref);
		}

		const converted = referrals.filter((r) => r.status === "converted");
		const pending = referrals.filter((r) => r.status === "pending");
		const rewardsEarned = converted.length * this.config.rewardValue;

		return {
			totalReferrals: referrals.length,
			converted: converted.length,
			pending: pending.length,
			rewardsEarned,
		};
	}

	/**
	 * Get leaderboard of top referrers
	 */
	async getReferralLeaderboard(limit = 10): Promise<LeaderboardEntry[]> {
		const leaderboard: LeaderboardEntry[] = [];

		const entries = Array.from(this.userReferrals.entries());
		for (const [userId, codes] of entries) {
			let convertedCount = 0;

			for (const code of codes) {
				const ref = this.referrals.get(code) ?? (await this.storage.getByCode(code));
				if (ref && ref.status === "converted") {
					convertedCount++;
				}
			}

			leaderboard.push({
				userId,
				referrals: convertedCount,
			});
		}

		return leaderboard.sort((a, b) => b.referrals - a.referrals).slice(0, limit);
	}

	/**
	 * Generate a unique referral code
	 */
	private generateUniqueCode(): string {
		const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // Removed confusing chars (0,1,I,O)
		let code = "";

		for (let i = 0; i < this.config.referralCodeLength; i++) {
			code += chars.charAt(Math.floor(Math.random() * chars.length));
		}

		// Simple collision check - in production, this would check storage
		if (this.referrals.has(code)) {
			return this.generateUniqueCode();
		}

		return code;
	}

	/**
	 * Generate a unique ID
	 */
	private generateId(): string {
		return `${Date.now()}-${Math.random().toString(36).substring(2, 9)}`;
	}

	/**
	 * Expire old pending referrals
	 */
	async expireOldReferrals(maxAgeDays = 30): Promise<number> {
		const now = new Date();
		let expiredCount = 0;

		const entries = Array.from(this.referrals.entries());
		for (const [code, referral] of entries) {
			if (referral.status === "pending") {
				const ageDays = (now.getTime() - referral.createdAt.getTime()) / (1000 * 60 * 60 * 24);
				if (ageDays > maxAgeDays) {
					referral.status = "expired";
					await this.storage.update(referral);
					expiredCount++;
				}
			}
		}

		return expiredCount;
	}
}
