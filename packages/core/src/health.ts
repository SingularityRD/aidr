/**
 * Singularity AIDR Health Checks
 * Lightweight health monitoring for core, cache, threat rules, and system components
 */

import { statfsSync } from "node:fs";
import { join } from "node:path";
import { VerdictCache } from "./cache.js";
import { isAmsiSupported } from "./clients/amsi.js";
import { readAmsiHostRecord } from "./clients/amsi-availability.js";
import { resolveEndpoint } from "./clients/url-check.js";
import { AIDR_DIR, loadConfig, resolvePath } from "./config.js";
import { inspectLocalDlpPolicy } from "./local-dlp-policy.js";
import { inspectRemoteRuntimePolicyCache } from "./remote-policy.js";
import { loadThreats } from "./threat-loader.js";
import { nullLogger } from "./types.js";
import { VERSION } from "./version.js";

/**
 * `not_configured` marks an optional check whose subsystem is intentionally
 * inert (e.g. the URL reputation leg in the default local mode). It is neither
 * a clean result nor a failure, and does not affect the aggregate status.
 */
export type HealthStatusValue = "healthy" | "degraded" | "unhealthy" | "not_configured";

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
	// AIDR_VERSION is an explicit operator override; normal consumer builds
	// use the compile-time/package version exported by the core package.
	return process.env.AIDR_VERSION || VERSION;
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
 * Check URL endpoint availability (optional - not critical for basic operation).
 *
 * The probe targets the same endpoint the URL reputation leg would call
 * (`url_check.endpoint`, else the operator override, else the shared
 * resolver) and runs only when that leg is enabled. In the default local mode
 * the leg is off, so no network request is made and the check reports
 * `not_configured` rather than a misleading healthy or degraded result.
 */
async function checkEndpointHealth(): Promise<HealthCheck> {
	const start = Date.now();
	let urlCheckEndpoint: string;
	try {
		const config = await loadConfig();
		const urlCheck = config.url_check as Partial<typeof config.url_check> | undefined;
		if (urlCheck?.enabled !== true) {
			return {
				name: "url_endpoint",
				status: "not_configured",
				latencyMs: Date.now() - start,
				message: "URL reputation checks are disabled; no endpoint was probed.",
				details: { mode: config.mode ?? "local", urlCheckEnabled: false },
			};
		}
		urlCheckEndpoint =
			urlCheck.endpoint?.trim() ||
			process.env.AIDR_URL_CHECK_ENDPOINT?.trim() ||
			resolveEndpoint("/url-check");
	} catch (error) {
		return {
			name: "url_endpoint",
			status: "degraded",
			latencyMs: Date.now() - start,
			message: `Configuration unavailable: ${error instanceof Error ? error.message : String(error)}`,
		};
	}

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
			status: response.status >= 400 ? "degraded" : "healthy",
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
		const stats = statfsSync(aidrPath);
		const freeBytes = Number(stats.bavail) * Number(stats.bsize);
		if (!Number.isFinite(freeBytes) || freeBytes < 0) {
			throw new Error("Filesystem returned an invalid free-space measurement");
		}

		const freeMB = freeBytes / (1024 * 1024);
		const latencyMs = Date.now() - start;
		const healthy = freeMB > 100;

		return {
			name: "disk_space",
			status: healthy ? "healthy" : "degraded",
			latencyMs,
			message: healthy ? undefined : `Low disk space: ~${Math.floor(freeMB)}MB remaining`,
			details: { aidrDir: AIDR_DIR, freeMB, warningThresholdMB: 100 },
		};
	} catch (error) {
		return {
			name: "disk_space",
			status: "degraded",
			latencyMs: Date.now() - start,
			message: `Disk space unavailable: ${error instanceof Error ? error.message : String(error)}`,
			details: { aidrDir: AIDR_DIR, warningThresholdMB: 100, measurement: "unavailable" },
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
 * Check the optional local-mode DLP policy. An invalid file is skipped at
 * enforcement time, so it must surface here as degraded, never as healthy.
 */
async function checkLocalDlpPolicyHealth(): Promise<HealthCheck> {
	const start = Date.now();
	try {
		const config = await loadConfig();
		if (config.mode === "managed") {
			return {
				name: "local_dlp_policy",
				status: "healthy",
				latencyMs: Date.now() - start,
				message: "Managed mode: DLP policy is accepted only from signed detector bundles.",
				details: { mode: "managed", applies: false },
			};
		}
		const state = await inspectLocalDlpPolicy();
		const latencyMs = Date.now() - start;
		if (state.status === "absent") {
			return {
				name: "local_dlp_policy",
				status: "healthy",
				latencyMs,
				message: "No local DLP policy configured; local DLP is off.",
				details: { mode: "local", configured: false, path: state.path },
			};
		}
		if (state.status === "invalid") {
			return {
				name: "local_dlp_policy",
				status: "degraded",
				latencyMs,
				message: `Local DLP policy is invalid and NOT enforced: ${state.reason}`,
				details: { mode: "local", configured: true, enforced: false, path: state.path },
			};
		}
		return {
			name: "local_dlp_policy",
			status: "healthy",
			latencyMs,
			message: "Local DLP policy loaded and enforced.",
			details: {
				mode: "local",
				configured: true,
				enforced: true,
				path: state.path,
				rules: state.policy.rules.length,
				exceptions: state.policy.exceptions.length,
			},
		};
	} catch (error) {
		return {
			name: "local_dlp_policy",
			status: "degraded",
			latencyMs: Date.now() - start,
			message: `Local DLP policy status unavailable: ${error instanceof Error ? error.message : String(error)}`,
		};
	}
}

/**
 * AMSI availability as last recorded on this host (no probe is run here). A
 * host where AMSI cannot be established is degraded: the AMSI signal is
 * skipped on every call until it is fixed.
 */
async function checkAmsiHealth(): Promise<HealthCheck> {
	const start = Date.now();
	const done = (status: HealthStatusValue, message: string, details?: Record<string, unknown>) => ({
		name: "amsi",
		status,
		latencyMs: Date.now() - start,
		message,
		...(details ? { details } : {}),
	});
	if (!isAmsiSupported()) return done("not_configured", "AMSI is not available on this platform.");
	try {
		const config = await loadConfig();
		if (!config.amsi_check.enabled) {
			return done("not_configured", "AMSI scanning is turned off (amsi_check.enabled: false).");
		}
		const record = await readAmsiHostRecord();
		if (!record) return done("not_configured", "AMSI has not been probed on this host yet.");
		if (record.state === "available") {
			return done("healthy", `AMSI available (${record.backend}).`, {
				backend: record.backend,
				checkedAt: record.checkedAt,
			});
		}
		return done(
			"degraded",
			`AMSI unavailable: ${record.reason}. Content is NOT scanned by AMSI (local rules still apply).`,
			{ kind: record.kind, checkedAt: record.checkedAt },
		);
	} catch (error) {
		return done(
			"degraded",
			`AMSI status unavailable: ${error instanceof Error ? error.message : String(error)}`,
		);
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
		checkLocalDlpPolicyHealth(),
		checkAmsiHealth(),
	]);

	return checks;
}

/**
 * Aggregate check statuses into overall status
 */
function aggregateStatus(checks: HealthCheck[]): HealthStatusValue {
	// `not_configured` checks are intentionally inert and do not affect the aggregate.
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
		const emoji =
			check.status === "healthy"
				? "✅"
				: check.status === "degraded"
					? "⚠️"
					: check.status === "not_configured"
						? "➖"
						: "❌";
		lines.push(`  ${emoji} ${check.name}: ${check.status} (${check.latencyMs}ms)`);
		if (check.message) {
			lines.push(`     └─ ${check.message}`);
		}
	}

	return lines.join("\n");
}
