/**
 * Startup and session scan handlers for OpenClaw.
 * Thin wrappers over core's createScanHandler.
 */

import { createScanHandler as coreScanHandler, type Logger } from "@singularityrd/aidr-core";
import { getBundledDataDirs, getSageVersion } from "./bundled-dirs.js";
import { discoverOpenClawPlugins } from "./plugin-discovery.js";

function createOpenClawScanHandler(
	logger: Logger,
	context: string,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const version = getSageVersion();

	return coreScanHandler({
		logger,
		context,
		discoverPlugins: () => discoverOpenClawPlugins(logger),
		selfPrefix: "@singularityrd/aidr-openclaw@",
		threatsDir,
		allowlistsDir,
		version,
		agentRuntime: "openclaw",
		onResult,
	});
}

export function createStartupScanHandler(
	logger: Logger,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	return createOpenClawScanHandler(logger, "startup", onResult);
}

export function createSessionScanHandler(
	logger: Logger,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	return createOpenClawScanHandler(logger, "session", onResult);
}

/**
 * Creates a before_prompt_build handler that surfaces plugin scan findings
 * as prepended context. One-shot: clears findings after first delivery.
 */
export function createBeforePromptBuildHandler(
	getFindings: () => string | null,
	clearFindings: () => void,
	logger: Logger,
): () => { prependContext: string } | undefined {
	return () => {
		const findings = getFindings();
		if (!findings) return undefined;

		clearFindings();
		logger.info("AIDR: surfacing plugin scan findings via before_prompt_build");

		const prependContext = [
			'<security-alert source="aidr-plugin-scan">',
			findings,
			"",
			"Inform the user about these security findings.",
			"</security-alert>",
		].join("\n");

		return { prependContext };
	};
}
