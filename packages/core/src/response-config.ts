/**
 * Response configuration system for Singularity AIDR.
 * Configures automated response modes based on threat categories and severity levels.
 */

import { type FSWatcher, watch } from "node:fs";
import { parse as parseYaml } from "yaml";
import { resolvePath } from "./config.js";
import { atomicWriteJson, getFileContent } from "./file-utils.js";
import type { ResponseAuditEntry, ResponseAuditor } from "./response-audit.js";
import type { Logger, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/** Available response modes for threat handling */
export type ResponseMode = "block" | "quarantine" | "contain" | "notify" | "log";

/** Severity levels for response rules */
export type ResponseSeverity = "low" | "medium" | "high" | "critical";

/** Response rule defining action for a threat category and severity */
export interface ResponseRule {
	/** Threat category this rule applies to */
	threatCategory: string;
	/** Minimum severity level for this rule */
	severity: ResponseSeverity;
	/** Response mode to apply */
	mode: ResponseMode;
	/** Whether to auto-escalate to security team */
	autoEscalate?: boolean;
	/** Optional custom message for the response */
	customMessage?: string;
	/** Optional metadata for the rule */
	metadata?: Record<string, unknown>;
}

/** Configuration format for response rules (YAML/JSON) */
export interface ResponseConfigFile {
	version?: number;
	defaultMode?: ResponseMode;
	rules?: Array<{
		threat_category: string;
		severity: string;
		mode: string;
		auto_escalate?: boolean;
		custom_message?: string;
		metadata?: Record<string, unknown>;
	}>;
	severityOverrides?: Record<ResponseSeverity, ResponseMode>;
}

/** Severity ranking for comparison */
const SEVERITY_RANK: Record<ResponseSeverity, number> = {
	low: 1,
	medium: 2,
	high: 3,
	critical: 4,
};

/**
 * Response configurator for managing automated threat responses.
 * Supports rule-based response selection and hot-reloading configuration.
 */
export class ResponseConfigurator {
	private rules: ResponseRule[] = [];
	private configPath?: string;
	private defaultMode: ResponseMode = "log";
	private severityOverrides?: Record<ResponseSeverity, ResponseMode>;
	private watcher?: FSWatcher;
	private logger: Logger;
	private reloadCallbacks: Array<() => void> = [];

	/**
	 * Creates a ResponseConfigurator instance.
	 * @param configPath - Optional path to YAML/JSON configuration file
	 * @param logger - Optional logger for operations
	 * @param auditor - Optional response auditor for logging response decisions
	 */
	constructor(
		configPath?: string,
		logger?: Logger,
		private auditor?: ResponseAuditor,
	) {
		this.configPath = configPath ? resolvePath(configPath) : undefined;
		this.logger = logger ?? nullLogger;
	}

	/**
	 * Initialize by loading config if a path was provided.
	 * Call this after construction if you want to load and watch config.
	 */
	async initialize(): Promise<void> {
		if (this.configPath) {
			await this.loadConfig(this.configPath);
			this.setupHotReload();
		}
	}

	/**
	 * Load configuration from a YAML or JSON file.
	 * @param path - Path to the configuration file
	 */
	async loadConfig(path: string): Promise<void> {
		const resolvedPath = resolvePath(path);

		try {
			const content = await getFileContent(resolvedPath);
			const ext = resolvedPath.toLowerCase();

			let data: ResponseConfigFile;
			if (ext.endsWith(".yaml") || ext.endsWith(".yml")) {
				data = parseYaml(content) as ResponseConfigFile;
			} else {
				data = JSON.parse(content) as ResponseConfigFile;
			}

			this.parseConfig(data);
			this.configPath = resolvedPath;
			this.logger.info(`Response configuration loaded from ${resolvedPath}`);
		} catch (error) {
			this.logger.error(`Failed to load response config from ${resolvedPath}`, {
				error: String(error),
			});
			throw new Error(
				`Failed to load response config: ${error instanceof Error ? error.message : String(error)}`,
			);
		}
	}

	/**
	 * Parse and validate configuration data.
	 */
	private parseConfig(data: ResponseConfigFile): void {
		// Reset previous state
		this.rules = [];
		this.severityOverrides = undefined;

		// Set default mode if provided
		if (data.defaultMode && this.isValidResponseMode(data.defaultMode)) {
			this.defaultMode = data.defaultMode;
		}

		// Set severity overrides if provided
		if (data.severityOverrides) {
			this.severityOverrides = data.severityOverrides;
		}

		// Parse rules
		if (data.rules && Array.isArray(data.rules)) {
			this.rules = data.rules
				.map((rule) => this.parseRule(rule))
				.filter((rule): rule is ResponseRule => rule !== null);
		}
	}

	/**
	 * Parse a single rule from config format.
	 */
	private parseRule(rule: NonNullable<ResponseConfigFile["rules"]>[number]): ResponseRule | null {
		const severity = this.validateSeverity(rule.severity);
		const mode = this.validateResponseMode(rule.mode);

		if (!severity || !mode) {
			this.logger.warn(`Invalid response rule: severity=${rule.severity}, mode=${rule.mode}`);
			return null;
		}

		return {
			threatCategory: rule.threat_category,
			severity,
			mode,
			autoEscalate: rule.auto_escalate ?? false,
			customMessage: rule.custom_message,
			metadata: rule.metadata,
		};
	}

	/**
	 * Validate severity string.
	 */
	private validateSeverity(severity: string): ResponseSeverity | null {
		const validSeverities: ResponseSeverity[] = ["low", "medium", "high", "critical"];
		return validSeverities.includes(severity as ResponseSeverity)
			? (severity as ResponseSeverity)
			: null;
	}

	/**
	 * Validate response mode string.
	 */
	private isValidResponseMode(mode: string): mode is ResponseMode {
		const validModes: ResponseMode[] = ["block", "quarantine", "contain", "notify", "log"];
		return validModes.includes(mode as ResponseMode);
	}

	/**
	 * Validate response mode string (returns validated or null).
	 */
	private validateResponseMode(mode: string): ResponseMode | null {
		return this.isValidResponseMode(mode) ? mode : null;
	}

	/**
	 * Get the response mode for a given threat category and severity.
	 * Matches based on category and minimum severity threshold.
	 * @param threatCategory - Category of the threat
	 * @param severity - Severity level of the threat
	 * @returns The configured response mode
	 */
	getResponseFor(threatCategory: string, severity: string): ResponseMode {
		const validSeverity = this.validateSeverity(severity);
		if (!validSeverity) {
			this.logger.warn(`Invalid severity level: ${severity}, using default mode`);
			return this.defaultMode;
		}

		// Check severity overrides first
		if (this.severityOverrides?.[validSeverity]) {
			return this.severityOverrides[validSeverity];
		}

		// Find matching rules (exact category match, severity >= threshold)
		const matchingRules = this.rules.filter((rule) => {
			const categoryMatch = rule.threatCategory === threatCategory || rule.threatCategory === "*";
			const severityMatch = SEVERITY_RANK[rule.severity] <= SEVERITY_RANK[validSeverity];
			return categoryMatch && severityMatch;
		});

		// Sort by priority: most specific category first, then highest severity threshold
		matchingRules.sort((a, b) => {
			// Exact match beats wildcard
			const aExact = a.threatCategory === threatCategory ? 1 : 0;
			const bExact = b.threatCategory === threatCategory ? 1 : 0;
			if (aExact !== bExact) return bExact - aExact;

			// Higher severity threshold beats lower
			return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
		});

		// Return mode from highest priority matching rule, or default
		return matchingRules[0]?.mode ?? this.defaultMode;
	}

	/**
	 * Get the response mode and log it to the auditor if available.
	 * This is the preferred method when responding to actual threats.
	 * @param threatCategory - Category of the threat
	 * @param severity - Severity level of the threat
	 * @param context - Context information for audit logging
	 * @returns The configured response mode
	 */
	async getAndLogResponse(
		threatCategory: string,
		severity: string,
		context: {
			tool: string;
			input: string;
			verdict: Verdict;
			threatId: string;
		},
	): Promise<ResponseMode> {
		const mode = this.getResponseFor(threatCategory, severity);

		// Log to response auditor if available
		if (this.auditor) {
			const action: ResponseAuditEntry["action"] =
				mode === "block"
					? "block"
					: mode === "notify"
						? "notify"
						: mode === "quarantine"
							? "quarantine"
							: mode === "contain"
								? "contain"
								: "block"; // "log" maps to "block" for audit purposes

			await this.auditor.log({
				action,
				threatId: context.threatId,
				tool: context.tool,
				input: context.input,
				verdict: context.verdict,
				responseTaken: mode,
				metadata: {
					userNotified: mode === "notify" || mode === "block",
					notificationSent: mode === "notify",
				},
				outcome: "success",
			});
		}

		return mode;
	}

	/**
	 * Check if a threat should be auto-escalated.
	 * @param threatCategory - Category of the threat
	 * @param severity - Severity level of the threat
	 * @returns Whether to auto-escalate
	 */
	shouldAutoEscalate(threatCategory: string, severity: string): boolean {
		const validSeverity = this.validateSeverity(severity);
		if (!validSeverity) return false;

		const matchingRules = this.rules.filter((rule) => {
			const categoryMatch = rule.threatCategory === threatCategory || rule.threatCategory === "*";
			const severityMatch = SEVERITY_RANK[rule.severity] <= SEVERITY_RANK[validSeverity];
			return categoryMatch && severityMatch && rule.autoEscalate;
		});

		return matchingRules.length > 0;
	}

	/**
	 * Get custom message for a threat response.
	 * @param threatCategory - Category of the threat
	 * @param severity - Severity level of the threat
	 * @returns Custom message or undefined
	 */
	getCustomMessage(threatCategory: string, severity: string): string | undefined {
		const validSeverity = this.validateSeverity(severity);
		if (!validSeverity) return undefined;

		const matchingRules = this.rules.filter((rule) => {
			const categoryMatch = rule.threatCategory === threatCategory || rule.threatCategory === "*";
			const severityMatch = SEVERITY_RANK[rule.severity] <= SEVERITY_RANK[validSeverity];
			return categoryMatch && severityMatch && rule.customMessage;
		});

		// Sort to get highest priority rule with custom message
		matchingRules.sort((a, b) => {
			const aExact = a.threatCategory === threatCategory ? 1 : 0;
			const bExact = b.threatCategory === threatCategory ? 1 : 0;
			if (aExact !== bExact) return bExact - aExact;
			return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
		});

		return matchingRules[0]?.customMessage;
	}

	/**
	 * Add a new response rule.
	 * @param rule - The rule to add
	 */
	addRule(rule: ResponseRule): void {
		this.rules.push(rule);
		this.logger.debug(
			`Added response rule for ${rule.threatCategory} (${rule.severity}) -> ${rule.mode}`,
		);
	}

	/**
	 * Remove all rules for a specific threat category.
	 * @param threatCategory - Category to remove rules for
	 */
	removeRulesForCategory(threatCategory: string): void {
		const beforeCount = this.rules.length;
		this.rules = this.rules.filter((rule) => rule.threatCategory !== threatCategory);
		const removed = beforeCount - this.rules.length;
		if (removed > 0) {
			this.logger.info(`Removed ${removed} rules for category ${threatCategory}`);
		}
	}

	/**
	 * Get all configured rules.
	 * @returns Array of all response rules
	 */
	getAllRules(): ResponseRule[] {
		return [...this.rules];
	}

	/**
	 * Set the default response mode.
	 * @param mode - Default mode to use when no rules match
	 */
	setDefaultMode(mode: ResponseMode): void {
		this.defaultMode = mode;
	}

	/**
	 * Get the current default mode.
	 * @returns The default response mode
	 */
	getDefaultMode(): ResponseMode {
		return this.defaultMode;
	}

	/**
	 * Set severity-level overrides.
	 * @param overrides - Map of severity to response mode
	 */
	setSeverityOverrides(overrides: Record<ResponseSeverity, ResponseMode>): void {
		this.severityOverrides = overrides;
	}

	/**
	 * Save current configuration to a file.
	 * @param path - Path to save the configuration
	 */
	async saveConfig(path: string): Promise<void> {
		const resolvedPath = resolvePath(path);

		const config: ResponseConfigFile = {
			version: 1,
			defaultMode: this.defaultMode,
			severityOverrides: this.severityOverrides,
			rules: this.rules.map((rule) => ({
				threat_category: rule.threatCategory,
				severity: rule.severity,
				mode: rule.mode,
				auto_escalate: rule.autoEscalate,
				custom_message: rule.customMessage,
				metadata: rule.metadata,
			})),
		};

		try {
			const ext = resolvedPath.toLowerCase();
			if (ext.endsWith(".yaml") || ext.endsWith(".yml")) {
				// Simple YAML serialization (would use a library in production)
				const yaml = this.toYaml(config);
				await atomicWriteJson(resolvedPath, yaml);
			} else {
				await atomicWriteJson(resolvedPath, config);
			}
			this.logger.info(`Response configuration saved to ${resolvedPath}`);
		} catch (error) {
			this.logger.error(`Failed to save response config to ${resolvedPath}`, {
				error: String(error),
			});
			throw error;
		}
	}

	/**
	 * Simple YAML serialization.
	 */
	private toYaml(config: ResponseConfigFile): string {
		// This is a simplified YAML serialization
		// In production, you'd use a proper YAML library
		let yaml = `version: ${config.version ?? 1}\n`;
		yaml += `defaultMode: ${config.defaultMode}\n`;
		yaml += `rules:\n`;

		for (const rule of config.rules ?? []) {
			yaml += `  - threat_category: ${rule.threat_category}\n`;
			yaml += `    severity: ${rule.severity}\n`;
			yaml += `    mode: ${rule.mode}\n`;
			if (rule.auto_escalate) {
				yaml += `    auto_escalate: true\n`;
			}
			if (rule.custom_message) {
				yaml += `    custom_message: "${rule.custom_message}"\n`;
			}
		}

		return yaml;
	}

	/**
	 * Reload configuration without restarting.
	 * If a config path was provided initially, reloads from that path.
	 */
	async hotReload(): Promise<void> {
		if (!this.configPath) {
			this.logger.warn("Cannot hot reload: no config path configured");
			return;
		}

		this.logger.info(`Hot reloading response configuration from ${this.configPath}`);

		try {
			const oldRules = [...this.rules];
			await this.loadConfig(this.configPath);

			// Notify callbacks
			for (const callback of this.reloadCallbacks) {
				try {
					callback();
				} catch (error) {
					this.logger.warn("Reload callback failed", { error: String(error) });
				}
			}

			this.logger.info(`Configuration reloaded: ${oldRules.length} -> ${this.rules.length} rules`);
		} catch (error) {
			this.logger.error("Hot reload failed", { error: String(error) });
		}
	}

	/**
	 * Register a callback to be invoked when configuration is reloaded.
	 * @param callback - Function to call on reload
	 */
	onReload(callback: () => void): void {
		this.reloadCallbacks.push(callback);
	}

	/**
	 * Stop watching for configuration changes.
	 */
	stopWatching(): void {
		if (this.watcher) {
			this.watcher.close();
			this.watcher = undefined;
			this.logger.info("Stopped watching configuration file");
		}
	}

	/**
	 * Set up file watching for hot reload.
	 */
	private setupHotReload(): void {
		if (!this.configPath) return;

		try {
			this.watcher = watch(this.configPath, (eventType) => {
				if (eventType === "change") {
					this.logger.debug(`Configuration file changed: ${this.configPath}`);
					void this.hotReload();
				}
			});

			this.logger.debug(`Watching configuration file for changes: ${this.configPath}`);
		} catch (error) {
			this.logger.warn("Failed to set up file watcher", { error: String(error) });
		}
	}

	/**
	 * Get response mode priority (for merging decisions).
	 * Higher number = higher priority.
	 */
	static getModePriority(mode: ResponseMode): number {
		const priorities: Record<ResponseMode, number> = {
			block: 5,
			quarantine: 4,
			contain: 3,
			notify: 2,
			log: 1,
		};
		return priorities[mode];
	}

	/**
	 * Merge multiple response modes to get the most restrictive.
	 * @param modes - Array of response modes to merge
	 * @returns The most restrictive mode
	 */
	static mergeModes(modes: ResponseMode[]): ResponseMode {
		if (modes.length === 0) return "log";

		return modes.reduce((mostRestrictive, current) => {
			return ResponseConfigurator.getModePriority(current) >
				ResponseConfigurator.getModePriority(mostRestrictive)
				? current
				: mostRestrictive;
		});
	}
}

/** Default response rules */
export function getDefaultResponseRules(): ResponseRule[] {
	return [
		{
			threatCategory: "malware",
			severity: "critical",
			mode: "block",
			autoEscalate: true,
		},
		{
			threatCategory: "malware",
			severity: "high",
			mode: "quarantine",
			autoEscalate: true,
		},
		{
			threatCategory: "data_exfiltration",
			severity: "high",
			mode: "block",
			autoEscalate: true,
		},
		{
			threatCategory: "credential_theft",
			severity: "critical",
			mode: "block",
			autoEscalate: true,
		},
		{
			threatCategory: "supply_chain",
			severity: "high",
			mode: "quarantine",
			autoEscalate: true,
		},
		{
			threatCategory: "suspicious_command",
			severity: "medium",
			mode: "contain",
		},
		{
			threatCategory: "suspicious_command",
			severity: "high",
			mode: "block",
			autoEscalate: true,
		},
		{
			threatCategory: "network_threat",
			severity: "high",
			mode: "block",
		},
		{
			threatCategory: "network_threat",
			severity: "medium",
			mode: "notify",
		},
	];
}

/** Default response configuration */
export function getDefaultResponseConfig(): {
	defaultMode: ResponseMode;
	severityOverrides: Record<ResponseSeverity, ResponseMode>;
	rules: ResponseRule[];
} {
	return {
		defaultMode: "log",
		severityOverrides: {
			critical: "block",
			high: "quarantine",
			medium: "notify",
			low: "log",
		},
		rules: getDefaultResponseRules(),
	};
}
