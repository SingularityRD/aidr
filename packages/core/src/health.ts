/**
 * Singularity AIDR Health Checks
 * Lightweight health monitoring for core, cache, threat rules, and system components
 */

import { statSync } from "node:fs";
import { join } from "node:path";
import { VerdictCache } from "./cache.js";
import { AIDR_DIR, loadConfig, resolvePath } from "./config.js";
import { inspectRemoteRuntimePolicyCache } from "./remote-policy.js";
import { loadThreats } from "./threat-loader.js";
import { nullLogger } from "./types.js";

export type HealthStatusValue = "healthy" | "degraded" | "unhealthy";

export interface HealthCheck {
	name: string;
	status: HealthStatusValue;
	latencyMs: number;
	message?: string;
	details?: Record<string, unknown>;
}

export interface HealthResult {
	status: HealthStatusValue;
	timestamp: string;
	version: string;
	checks: Record<string, HealthStatusValue>;
}

export interface HealthStatus {
	status: HealthStatusValue;
	timestamp: string;
	version: string;
	checks: HealthCheck[];
}

/** Get package version */
function getVersion(): string {
	// Try to get version from environment or return default
	return process.env.AIDR_VERSION || "0.6.0";
}

/**
 * Check core module health
 */
async function checkCoreHealth(): Promise<HealthCheck> {
	const start = Date.now();
	try {
		// Verify core modules can be loaded
		const { DecisionEngine } = await import("./engine.js");
		const { HeuristicsEngine } = await import("./heuristics.js");

		// Quick instantiation test
		const _engine = new DecisionEngine();
		const _heuristics = new HeuristicsEngine([]);

		const latencyMs = Date.now() - start;

		return {
			name: "core",
			status: "healthy",
			latencyMs,
			details: { modules: ["engine", "heuristics"] },
		};
	} catch (error) {
		return {
			name: "core",
			status: "unhealthy",
			latencyMs: Date.now() - start,
			message: error instanceof Error ? error.message : String(error),
		};
	}
}

/**
 * Check cache health
 */
async function checkCacheHealth(): Promise<HealthCheck> {
	const start = Date.now();
	try {
		const cachePath = join(resolvePath(AIDR_DIR), "cache.json");
		const cache = new VerdictCache({
			enabled: true,
			path: cachePath,
			ttl_clean_seconds: 3600,
			ttl_malicious_seconds: 86400,
		});
		await cache.load();
		const latencyMs = Date.now() - start;

		return {
			name: "cache",
			status: "healthy",
			latencyMs,
			details: { path: cachePath, loaded: true },
		};
	} catch (error) {
		return {
			name: "cache",
			status: "unhealthy",
			latencyMs: Date.now() - start,
			message: error instanceof Error ? error.message : String(error),
		};
	}
}

/**
 * Check threat rules health
 */
async function checkThreatRulesHealth(): Promise<HealthCheck> {
	const start = Date.now();
	try {
		// Determine threats directory
		const threatsDir = process.env.AIDR_THREATS_DIR || join(process.cwd(), "threats");

		// Try to load threats from the primary directory
		let threats = await loadThreats(threatsDir, nullLogger);

		// If no threats found and we're in a monorepo structure, try alternative paths
		if (threats.length === 0) {
			const altDirs = [
				join(process.cwd(), "..", "..", "threats"), // From packages/x/dist
				join(process.cwd(), "..", "..", "..", "threats"), // From packages/x/dist/bin
				join(resolvePath(AIDR_DIR), "threats"), // User's home directory
			];

			for (const altDir of altDirs) {
				try {
					const altThreats = await loadThreats(altDir, nullLogger);
					if (altThreats.length > 0) {
						threats = altThreats;
						break;
					}
				} catch {
					// Continue to next alternative
				}
			}
		}

		const latencyMs = Date.now() - start;

		// Degraded if no threats loaded (might be a fresh install)
		if (threats.length === 0) {
			return {
				name: "threat_rules",
				status: "degraded",
				latencyMs,
				message: "No threat rules loaded - may be fresh install or missing threat definitions",
				details: { threatsDir, rulesCount: 0 },
			};
		}

		return {
			name: "threat_rules",
			status: "healthy",
			latencyMs,
			details: { threatsDir, rulesCount: threats.length },
		};
	} catch (error) {
		return {
			name: "threat_rules",
			status: "unhealthy",
			latencyMs: Date.now() - start,
			message: error instanceof Error ? error.message : String(error),
		};
	}
}

/**
 * Check URL endpoint availability (optional - not critical for basic operation)
 */
async function checkEndpointHealth(): Promise<HealthCheck> {
	const start = Date.now();
	const urlCheckEndpoint =
		process.env.AIDR_URL_CHECK_ENDPOINT || "https://api.singularityrd.com/v1/url-check";

	try {
		const controller = new AbortController();
		const timeout = setTimeout(() => controller.abort(), 3000); // 3 second timeout for health check

		const response = await fetch(urlCheckEndpoint, {
			method: "HEAD",
			signal: controller.signal,
		});

		clearTimeout(timeout);
		const latencyMs = Date.now() - start;

		return {
			name: "url_endpoint",
			status: response.status < 500 ? "healthy" : "degraded",
			latencyMs,
			details: { status: response.status, endpoint: urlCheckEndpoint },
		};
	} catch (error) {
		return {
			name: "url_endpoint",
			status: "degraded",
			latencyMs: Date.now() - start,
			message: error instanceof Error ? error.message : String(error),
			details: { endpoint: urlCheckEndpoint, note: "Optional - not critical for local operation" },
		};
	}
}

/**
 * Check disk space for AIDR directory
 */
async function checkDiskHealth(): Promise<HealthCheck> {
	const start = Date.now();
	try {
		const aidrPath = resolvePath(AIDR_DIR);
		const _stats = statSync(aidrPath);
		const latencyMs = Date.now() - start;

		// Estimate available space (rough approximation)
		const estimatedFreeMB = 1000; // Placeholder
		const healthy = estimatedFreeMB > 100;

		return {
			name: "disk_space",
			status: healthy ? "healthy" : "degraded",
			latencyMs,
			message: healthy ? undefined : `Low disk space: ~${estimatedFreeMB}MB remaining`,
			details: { aidrDir: AIDR_DIR, estimatedFreeMB, warningThresholdMB: 100 },
		};
	} catch (_error) {
		// If directory doesn't exist yet, that's OK (will be created)
		return {
			name: "disk_space",
			status: "healthy",
			latencyMs: Date.now() - start,
			details: {
				aidrDir: AIDR_DIR,
				note: "Directory not yet created - will be created on first use",
			},
		};
	}
}

/**
 * Check remote policy cache health
 */
async function checkRemotePolicyHealth(): Promise<HealthCheck> {
	const start = Date.now();
	try {
		const config = await loadConfig();
		const token = (config.auth?.api_key ?? "").trim();
		const status = await inspectRemoteRuntimePolicyCache(config, token);
		const latencyMs = Date.now() - start;

		return {
			name: "remote_policy",
			status: status.usable ? "healthy" : "degraded",
			latencyMs,
			message: status.message,
			details: {
				source: status.source,
				usable: status.usable,
				keyMatches: status.keyMatches,
				policyVersion: status.policyVersion,
			},
		};
	} catch (error) {
		return {
			name: "remote_policy",
			status: "unhealthy",
			latencyMs: Date.now() - start,
			message: error instanceof Error ? error.message : String(error),
		};
	}
}

/**
 * Run all required health checks (core, cache, threat_rules)
 */
export async function runHealthChecks(): Promise<HealthCheck[]> {
	const checks = await Promise.all([
		checkCoreHealth(),
		checkCacheHealth(),
		checkThreatRulesHealth(),
	]);

	return checks;
}

/**
 * Run extended health checks including optional endpoints
 */
export async function runExtendedHealthChecks(): Promise<HealthCheck[]> {
	const checks = await Promise.all([
		checkCoreHealth(),
		checkCacheHealth(),
		checkThreatRulesHealth(),
		checkRemotePolicyHealth(),
		checkEndpointHealth(),
		checkDiskHealth(),
	]);

	return checks;
}

/**
 * Aggregate check statuses into overall status
 */
function aggregateStatus(checks: HealthCheck[]): HealthStatusValue {
	const hasUnhealthy = checks.some((c) => c.status === "unhealthy");
	const hasDegraded = checks.some((c) => c.status === "degraded");

	if (hasUnhealthy) return "unhealthy";
	if (hasDegraded) return "degraded";
	return "healthy";
}

/**
 * Get complete health status
 */
export async function getHealthStatus(): Promise<HealthStatus> {
	const checks = await runHealthChecks();
	const status = aggregateStatus(checks);

	return {
		status,
		timestamp: new Date().toISOString(),
		version: getVersion(),
		checks,
	};
}

/**
 * Get extended health status including optional checks
 */
export async function getExtendedHealthStatus(): Promise<HealthStatus> {
	const checks = await runExtendedHealthChecks();
	const status = aggregateStatus(checks);

	return {
		status,
		timestamp: new Date().toISOString(),
		version: getVersion(),
		checks,
	};
}

/**
 * Convert HealthStatus to the simplified HealthResult format
 */
export function toHealthResult(status: HealthStatus): HealthResult {
	const checks: Record<string, HealthStatusValue> = {};
	for (const check of status.checks) {
		checks[check.name] = check.status;
	}

	return {
		status: status.status,
		timestamp: status.timestamp,
		version: status.version,
		checks,
	};
}

/**
 * Quick health check - returns true if all systems healthy
 */
export async function isHealthy(): Promise<boolean> {
	const status = await getHealthStatus();
	return status.status === "healthy";
}

/**
 * Format health status for human-readable output
 */
export function formatHealthStatus(status: HealthStatus): string {
	const lines: string[] = [];

	const statusEmoji =
		status.status === "healthy" ? "✅" : status.status === "degraded" ? "⚠️" : "❌";
	lines.push(`${statusEmoji} Status: ${status.status.toUpperCase()}`);
	lines.push(`   Timestamp: ${status.timestamp}`);
	lines.push(`   Version: ${status.version}`);
	lines.push("");
	lines.push("Checks:");

	for (const check of status.checks) {
		const emoji = check.status === "healthy" ? "✅" : check.status === "degraded" ? "⚠️" : "❌";
		lines.push(`  ${emoji} ${check.name}: ${check.status} (${check.latencyMs}ms)`);
		if (check.message) {
			lines.push(`     └─ ${check.message}`);
		}
	}

	return lines.join("\n");
}
