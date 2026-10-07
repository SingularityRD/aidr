#!/usr/bin/env node
/**
 * Singularity AIDR SessionStart hook entry point.
 * Scans installed Claude Code plugins for threats at session startup.
 * Outputs status JSON and exits non-zero when protection cannot start.
 *
 * A scan that outlives the internal deadline (default 25 s, below the host's
 * 30 s timeout; `AIDR_SESSION_START_DEADLINE_MS`) reports that it did not
 * finish (never a clean result), and the hook exits once its answer is flushed
 * instead of waiting on lingering handles.
 */

import {
	createHookResponder,
	discoverPlugins,
	getLogger,
	initSentry,
	type Logger,
	resolveHookDeadlineMs,
	runPluginScan,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import { pruneStaleSessionFiles } from "./approval-tracker.js";
import { resolveAssetDir, resolvePluginManifest, resolvePluginRoot } from "./assets.js";

// Initialize Sentry
initSentry({ name: "aidr-claude-code-session-start" });

const logger: Logger = getLogger();

const responder = createHookResponder({
	deadlineMs: resolveHookDeadlineMs(
		{ envVar: "AIDR_SESSION_START_DEADLINE_MS", hostTimeoutMs: 30_000, defaultMs: 25_000 },
		process.env,
	),
	onDeadline: () => ({
		stdout: `${JSON.stringify({
			systemMessage:
				"Singularity AIDR could not finish scanning installed plugins in time; the plugin scan result is unavailable. Tool calls are still inspected.",
		})}\n`,
	}),
});

async function main(): Promise<void> {
	await verifyArtifactIntegrityAndLog({
		artifactDir: __dirname,
		artifactId: "claude-code/dist",
		logger,
	});
	await pruneStaleSessionFiles(logger);

	const pluginRoot = resolvePluginRoot();
	const threatsDir = resolveAssetDir("threats");
	const allowlistsDir = resolveAssetDir("allowlists");
	const manifest = resolvePluginManifest(pluginRoot);

	// Discover plugins and filter out self
	let plugins = await discoverPlugins(undefined, logger);
	if (manifest.name) {
		const prefix = `${manifest.name}@`;
		plugins = plugins.filter((p) => !p.key.startsWith(prefix));
	}

	const statusMsg = await runPluginScan(
		logger,
		"session",
		plugins,
		threatsDir,
		allowlistsDir,
		manifest.version,
		"claude-code",
	);
	responder.answer({ stdout: `${JSON.stringify({ systemMessage: statusMsg })}\n` });
}

main().catch(() => {
	responder.answer({
		stdout: `${JSON.stringify({ systemMessage: "Singularity AIDR protection failed to start; the session is not protected." })}\n`,
		exitCode: 1,
	});
});
