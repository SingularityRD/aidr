import type { LicenseValidationResult } from "./license.js";
import type { Logger } from "./client.js";

/**
 * License information stored for a user
 */
export interface LicenseInfo extends LicenseValidationResult {
	licenseKey: string;
	userId: string;
	tier: "free" | "pro" | "enterprise";
	activatedAt?: Date;
}

/**
 * Usage tracking information
 */
export interface UsageRecord {
	userId: string;
	operation: string;
	timestamp: Date;
	count: number;
}

/**
 * Freemium check result
 */
export interface FreemiumCheckResult {
	allowed: boolean;
	tier: "free" | "pro";
	remaining: number;
	upgradePrompt?: string;
}

/**
 * License manager interface - can be implemented with different storage backends
 */
export interface LicenseManager {
	/**
	 * Get license information for a user
	 */
	getLicense(userId: string): Promise<LicenseInfo | null>;

	/**
	 * Store license information
	 */
	setLicense(userId: string, license: LicenseInfo): Promise<void>;

	/**
	 * Get current usage for a user
	 */
	getUsage(userId: string): Promise<{ used: number; resetDate: Date }>;

	/**
	 * Increment usage counter
	 */
	incrementUsage(userId: string, operation: string): Promise<void>;

	/**
	 * Reset usage for a user
	 */
	resetUsage(userId: string): Promise<void>;
}

/**
 * In-memory license manager for development/testing
 */
export class InMemoryLicenseManager implements LicenseManager {
	private licenses: Map<string, LicenseInfo> = new Map();
	private usage: Map<string, { used: number; resetDate: Date }> = new Map();
	private usageRecords: Map<string, UsageRecord[]> = new Map();

	async getLicense(userId: string): Promise<LicenseInfo | null> {
		return this.licenses.get(userId) || null;
	}

	async setLicense(userId: string, license: LicenseInfo): Promise<void> {
		this.licenses.set(userId, license);
	}

	async getUsage(userId: string): Promise<{ used: number; resetDate: Date }> {
		const usage = this.usage.get(userId);
		if (!usage) {
			// Initialize usage
			const resetDate = new Date();
			resetDate.setDate(resetDate.getDate() + 30); // 30 days from now
			this.usage.set(userId, { used: 0, resetDate });
			return { used: 0, resetDate };
		}

		// Check if we need to reset
		if (new Date() > usage.resetDate) {
			const resetDate = new Date();
			resetDate.setDate(resetDate.getDate() + 30);
			this.usage.set(userId, { used: 0, resetDate });
			return { used: 0, resetDate };
		}

		return usage;
	}

	async incrementUsage(userId: string, operation: string): Promise<void> {
		const usage = await this.getUsage(userId);
		this.usage.set(userId, { ...usage, used: usage.used + 1 });

		// Track detailed records
		const record: UsageRecord = {
			userId,
			operation,
			timestamp: new Date(),
			count: 1,
		};

		const records = this.usageRecords.get(userId) || [];
		records.push(record);
		this.usageRecords.set(userId, records);
	}

	async resetUsage(userId: string): Promise<void> {
		const resetDate = new Date();
		resetDate.setDate(resetDate.getDate() + 30);
		this.usage.set(userId, { used: 0, resetDate });
		this.usageRecords.delete(userId);
	}

	/**
	 * Get detailed usage records for a user
	 */
	async getUsageRecords(userId: string): Promise<UsageRecord[]> {
		return this.usageRecords.get(userId) || [];
	}
}

/**
 * Freemium manager options
 */
export interface FreemiumOptions {
	/** Number of free daily checks allowed */
	freeDailyChecks: number;
	/** Number of free seats allowed */
	freeSeats: number;
	/** Whether to prompt for upgrade when approaching limits */
	enableUpgradePrompts?: boolean;
	/** Custom upgrade prompt message */
	upgradePromptMessage?: string;
}

/**
 * Default freemium options
 */
export const DEFAULT_FREEMIUM_OPTIONS: FreemiumOptions = {
	freeDailyChecks: 100,
	freeSeats: 1,
	enableUpgradePrompts: true,
	upgradePromptMessage:
		"You've reached your free tier limit. Upgrade to Pro for unlimited checks and team seats.",
};

/**
 * Freemium manager for handling free tier limits and license validation
 */
export class FreemiumManager {
	private options: FreemiumOptions;
	private licenseManager: LicenseManager;
	private logger?: Logger;

	constructor(
		licenseManager: LicenseManager,
		options: Partial<FreemiumOptions> = {},
		logger?: Logger,
	) {
		this.licenseManager = licenseManager;
		this.options = { ...DEFAULT_FREEMIUM_OPTIONS, ...options };
		this.logger = logger;
	}

	/**
	 * Check if a user can execute an operation based on their tier
	 */
	async canExecute(userId: string): Promise<FreemiumCheckResult> {
		// First, check if user has a valid license
		const license = await this.licenseManager.getLicense(userId);

		if (license?.valid && license.tier === "pro") {
			// Pro users have unlimited access (but track usage for analytics)
			return {
				allowed: true,
				tier: "pro",
				remaining: Number.POSITIVE_INFINITY,
			};
		}

		// Check free tier limits
		const usage = await this.licenseManager.getUsage(userId);
		const remaining = Math.max(0, this.options.freeDailyChecks - usage.used);

		if (remaining <= 0) {
			// Free tier exhausted
			const upgradePrompt = this.options.enableUpgradePrompts
				? this.options.upgradePromptMessage
				: undefined;

			return {
				allowed: false,
				tier: "free",
				remaining: 0,
				upgradePrompt,
			};
		}

		return {
			allowed: true,
			tier: "free",
			remaining,
		};
	}

	/**
	 * Track usage for an operation
	 */
	async trackUsage(userId: string, operation: string): Promise<void> {
		await this.licenseManager.incrementUsage(userId, operation);
		this.logger?.info?.(`Usage tracked for user ${userId}`, { operation });
	}

	/**
	 * Activate a licence for a user from an already-issued entitlement.
	 *
	 * This deliberately does NOT contact a payment provider. Entitlements are
	 * issued server-side by a signature-verified webhook; the SDK only records the
	 * resulting entitlement, and the caller is responsible for having obtained it
	 * through the entitlement API rather than by trusting client input.
	 */
	async activateLicense(
		userId: string,
		licenseKey: string,
		issue: (licenseKey: string) => Promise<LicenseValidationResult>,
	): Promise<{ success: boolean; error?: string; license?: LicenseInfo }> {
		try {
			const validation = await issue(licenseKey);

			if (!validation.valid) {
				return {
					success: false,
					error: "Invalid or expired license key",
				};
			}

			// Determine tier based on seats (this is a simple heuristic)
			const tier: LicenseInfo["tier"] = validation.seats > 1 ? "enterprise" : "pro";

			const license: LicenseInfo = {
				...validation,
				licenseKey,
				userId,
				tier,
				activatedAt: new Date(),
			};

			// Store the license
			await this.licenseManager.setLicense(userId, license);

			this.logger?.info?.(`License activated for user ${userId}`, { tier });

			return {
				success: true,
				license,
			};
		} catch (error) {
			this.logger?.error?.(
				`License activation failed for user ${userId}: ${error instanceof Error ? error.message : String(error)}`,
			);
			return {
				success: false,
				error: error instanceof Error ? error.message : String(error),
			};
		}
	}

	/**
	 * Deactivate a license for a user
	 */
	async deactivateLicense(userId: string): Promise<boolean> {
		const license = await this.licenseManager.getLicense(userId);

		if (!license) {
			return false;
		}

		// Local deactivation only: this clears the locally recorded licence. Server
		// side revocation is authoritative and is handled by the control plane
		// (signed revocation lists), not by the SDK.
		await this.licenseManager.setLicense(userId, {
			...license,
			valid: false,
			tier: "free",
		});

		this.logger?.info?.(`License deactivated for user ${userId}`);
		return true;
	}

	/**
	 * Get current status for a user
	 */
	async getStatus(userId: string): Promise<{
		tier: "free" | "pro" | "enterprise";
		usage: { used: number; total: number; remaining: number };
		license?: LicenseInfo;
	}> {
		const license = await this.licenseManager.getLicense(userId);
		const usage = await this.licenseManager.getUsage(userId);

		if (license?.valid && license.tier !== "free") {
			return {
				tier: license.tier,
				usage: {
					used: usage.used,
					total: Number.POSITIVE_INFINITY,
					remaining: Number.POSITIVE_INFINITY,
				},
				license,
			};
		}

		return {
			tier: "free",
			usage: {
				used: usage.used,
				total: this.options.freeDailyChecks,
				remaining: Math.max(0, this.options.freeDailyChecks - usage.used),
			},
		};
	}

	/**
	 * Return a checkout URL for upgrading.
	 *
	 * The SDK no longer talks to a payment provider. Checkout is created
	 * server-side (the direct-GA model is invoice/order based), so the caller must
	 * supply the URL its own server issued. Refusing here rather than fabricating a
	 * URL keeps the failure visible instead of sending a user to a dead link.
	 */
	async createUpgradeCheckout(
		_userId: string,
		_options?: {
			variantId?: string;
			redirectUrl?: string;
		},
	): Promise<string> {
		throw new Error(
			"Checkout is created server-side. The SDK does not construct payment-provider checkout URLs; " +
				"obtain the checkout/order URL from your control plane and present it to the user.",
		);
	}

	/**
	 * Get remaining free checks for a user
	 */
	async getRemainingFreeChecks(userId: string): Promise<number> {
		const usage = await this.licenseManager.getUsage(userId);
		return Math.max(0, this.options.freeDailyChecks - usage.used);
	}

	/**
	 * Check if user is approaching their free limit
	 */
	async isApproachingLimit(userId: string, threshold = 0.8): Promise<boolean> {
		const license = await this.licenseManager.getLicense(userId);

		if (license?.valid && license.tier !== "free") {
			return false; // Pro users don't have limits
		}

		const usage = await this.licenseManager.getUsage(userId);
		const ratio = usage.used / this.options.freeDailyChecks;
		return ratio >= threshold;
	}
}
