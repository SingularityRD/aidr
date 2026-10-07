/**
 * Startup and session scan handlers for OpenCode.
 * Thin wrapper over core's createScanHandler.
 */

import { createScanHandler as coreScanHandler, type Logger } from "@singularityrd/aidr-core";
import { getAidrVersion, getBundledDataDirs } from "./bundled-dirs.js";
import { discoverOpenCodePlugins } from "./plugin-discovery.js";

export function createSessionScanHandler(
	logger: Logger,
	projectDir?: string,
	onResult?: (msg: string) => void,
): () => Promise<void> {
	const { threatsDir, allowlistsDir } = getBundledDataDirs();
	const version = getAidrVersion();

	return coreScanHandler({
		logger,
		context: "session",
		discoverPlugins: () => discoverOpenCodePlugins(logger, projectDir),
		selfPrefix: "@singularityrd/aidr-opencode@",
		threatsDir,
		allowlistsDir,
		version,
		agentRuntime: "opencode",
		onResult,
	});
}
