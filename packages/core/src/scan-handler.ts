/**
 * Generic scan orchestration for all connectors.
 * Extracts the common runScan + createScanHandler pattern from
 * OpenCode/OpenClaw startup-scan files.
 */

import { formatSessionStartMessage } from "./format.js";
import { runSessionStart } from "./session-start.js";
import type { AgentRuntime, Logger, PluginInfo } from "./types.js";

/**
 * Sanitize error messages by removing file paths and sensitive data.
 */
function sanitizeErrorMessage(e: unknown): string {
	const msg = e instanceof Error ? e.message : String(e);
	// If the message contains file paths, replace entirely for privacy
	const hasPath = /[a-zA-Z]:\\/.test(msg);
	const hasSecret = /\baidr_agent_token_\w+\b/.test(msg);
	if (hasPath || hasSecret) {
		return "Error: scan failed";
	}
	return String(e);
}

/**
 * Run a plugin scan with the given plugins and return a formatted status message.
 * Always returns a message (clean or findings) — callers can always show the result.
 */
export async function runPluginScan(
	logger: Logger,
	context: string,
	plugins: PluginInfo[],
	threatsDir: string,
	allowlistsDir: string,
	version: string,
	agentRuntime: AgentRuntime,
): Promise<string> {
	logger.info(`Singularity AIDR plugin scan started (${context})`, { threatsDir, allowlistsDir });

	const result = await runSessionStart({
		plugins,
		threatsDir,
		allowlistsDir,
		version,
		logger,
		agentRuntime,
	});

	logger.info(`Singularity AIDR plugin scan (${context}) complete`, {
		findings: result.scanResults.length,
		...(result.rulesIncomplete ? { rulesIncomplete: result.rulesIncomplete.files } : {}),
		updateAvailable: result.versionCheck?.updateAvailable ?? false,
	});

	return formatSessionStartMessage(version, result);
}

/**
 * Convenience wrapper for in-process connectors: discovery + self-filter + scan + error handling.
 */
export interface ScanHandlerOptions {
	logger: Logger;
	context: string;
	discoverPlugins: () => Promise<PluginInfo[]>;
	selfPrefix: string;
	threatsDir: string;
	allowlistsDir: string;
	version: string;
	agentRuntime: AgentRuntime;
	onResult?: (msg: string) => void;
}

export function createScanHandler(options: ScanHandlerOptions): () => Promise<void> {
	const {
		logger,
		context,
		discoverPlugins,
		selfPrefix,
		threatsDir,
		allowlistsDir,
		version,
		agentRuntime,
		onResult,
	} = options;

	return async () => {
		try {
			let plugins = await discoverPlugins();

			// Filter out self plugins
			plugins = plugins.filter((p) => !p.key.startsWith(selfPrefix));

			// Filter out malformed plugins (missing required fields)
			const validPlugins = plugins.filter(
				(p): p is PluginInfo =>
					typeof p.key === "string" &&
					typeof p.installPath === "string" &&
					typeof p.version === "string" &&
					typeof p.lastUpdated === "string",
			);
			const malformedCount = plugins.length - validPlugins.length;
			if (malformedCount > 0) {
				logger.warn(`Singularity AIDR plugin scan (${context}): ignored malformed plugins`, {
					count: malformedCount,
				});
			}
			plugins = validPlugins;

			if (plugins.length === 0) {
				logger.warn(
					`Singularity AIDR plugin scan (${context}): no plugins to scan after filtering`,
				);
			}

			const msg = await runPluginScan(
				logger,
				context,
				plugins,
				threatsDir,
				allowlistsDir,
				version,
				agentRuntime,
			);
			onResult?.(msg);
		} catch (e) {
			const sanitized = sanitizeErrorMessage(e);
			logger.error(`Singularity AIDR ${context} scan failed`, { error: sanitized });
		}
	};
}
