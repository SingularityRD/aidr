#!/usr/bin/env node

/**
 * Singularity AIDR Health CLI Command
 * Outputs health status with optional --json flag and --check option
 */

import {
	formatHealthStatus,
	getHealthStatus,
	type HealthCheck,
	type HealthStatus,
	runHealthChecks,
	VERSION,
} from "@singularityrd/aidr-core";
import { resolveAssetDir } from "./assets.js";

const args = process.argv.slice(2);
const jsonFlag = args.includes("--json") || args.includes("-j");
const helpFlag = args.includes("--help") || args.includes("-h");
const checkIndex = args.findIndex((arg) => arg === "--check" || arg === "-c");
const specificCheck = checkIndex >= 0 && args[checkIndex + 1] ? args[checkIndex + 1] : null;

const VALID_CHECKS = ["core", "cache", "threat_rules", "api"];

// Core health checks use AIDR_THREATS_DIR when supplied. Resolve packaged
// resources before running them so a clean consumer cwd cannot make a valid
// install look empty/degraded.
if (!process.env.AIDR_THREATS_DIR) {
	process.env.AIDR_THREATS_DIR = resolveAssetDir("threats");
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: complexity inherent in health check orchestration
async function main(): Promise<void> {
	const startTime = Date.now();

	if (helpFlag) {
		console.log(`Usage: aidr-claude-code health [options]

Options:
  -c, --check [name]  Run specific check only (core, cache, threat_rules, api, local_dlp_policy)
  -j, --json          Output health status as JSON
  -h, --help          Show this help message

Exit codes:
  0    All checks healthy
  1    At least one check is degraded or unhealthy

Examples:
  aidr-claude-code health                      # Human-readable output for all checks
  aidr-claude-code health --json               # JSON output for all checks
  aidr-claude-code health --check core         # Check core module only
  aidr-claude-code health --check api --json   # Check API connectivity, JSON output`);
		process.exit(0);
	}

	// Validate check name if provided
	if (specificCheck && !VALID_CHECKS.includes(specificCheck)) {
		const error = `Invalid check name: ${specificCheck}. Valid options: ${VALID_CHECKS.join(", ")}`;
		if (jsonFlag) {
			console.log(
				JSON.stringify(
					{
						status: "error",
						message: error,
					},
					null,
					2,
				),
			);
		} else {
			console.error(`Error: ${error}`);
		}
		process.exit(1);
	}

	try {
		let checks: HealthCheck[];
		let status: HealthStatus["status"];

		if (specificCheck) {
			// Run specific check
			const allChecks = await runHealthChecks();
			const check = allChecks.find((c) => c.name === specificCheck);

			if (!check) {
				// Fall back to the extended checks (`api` is an alias of url_endpoint).
				const { runExtendedHealthChecks } = await import("@singularityrd/aidr-core");
				const extended = await runExtendedHealthChecks();
				const extendedCheck =
					specificCheck === "api"
						? extended.find((c) => c.name === "url_endpoint" || c.name === "api")
						: extended.find((c) => c.name === specificCheck);
				if (extendedCheck) {
					checks = [specificCheck === "api" ? { ...extendedCheck, name: "api" } : extendedCheck];
					status = extendedCheck.status;
				} else if (specificCheck === "api") {
					throw new Error("API check not available");
				} else {
					throw new Error(`Check "${specificCheck}" not found`);
				}
			} else {
				checks = [check];
				status = check.status;
			}
		} else {
			// Run all checks
			const fullStatus = await getHealthStatus();
			checks = fullStatus.checks;
			status = fullStatus.status;
		}

		const totalLatency = Date.now() - startTime;
		const timestamp = new Date().toISOString();
		const version = process.env.AIDR_VERSION || VERSION;

		if (jsonFlag) {
			// JSON output format
			const checkStatuses: Record<string, HealthCheck["status"]> = {};
			for (const check of checks) {
				checkStatuses[check.name] = check.status;
			}
			const result = {
				status,
				timestamp,
				version,
				checks: checkStatuses,
				checkDetails: checks.map((c) => ({
					name: c.name,
					status: c.status,
					latencyMs: c.latencyMs,
					message: c.message,
					details: c.details,
				})),
				totalLatencyMs: totalLatency,
			};
			console.log(JSON.stringify(result, null, 2));
		} else {
			// Human-readable format with table output
			console.log(formatHealthStatus({ status, timestamp, version, checks }));
			console.log(`\nTotal response time: ${totalLatency}ms`);
		}

		// Exit with appropriate code
		if (status === "healthy") {
			process.exit(0);
		} else {
			process.exit(1);
		}
	} catch (error) {
		const message = error instanceof Error ? error.message : String(error);

		if (jsonFlag) {
			console.log(
				JSON.stringify(
					{
						status: "unhealthy",
						timestamp: new Date().toISOString(),
						version: process.env.AIDR_VERSION || VERSION,
						checks: { error: message },
					},
					null,
					2,
				),
			);
		} else {
			console.error(`Health check failed: ${message}`);
		}

		process.exit(1);
	}
}

main();
