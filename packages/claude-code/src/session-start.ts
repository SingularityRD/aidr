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
	amsiSessionStatus,
	createHookResponder,
	discoverPlugins,
	getLogger,
	initSentry,
	integrityFailureMessage,
	type Logger,
	loadConfig,
	resolveHookDeadlineMs,
	runPluginScan,
	t,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import { pruneStaleSessionFiles } from "./approval-tracker.js";
import {
	assetOverrideNotice,
	resolveAssetDir,
	resolvePluginManifest,
	resolvePluginRoot,
} from "./assets.js";

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
			systemMessage: t("hook.sessionScanTimeout"),
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

	const [statusMsg, amsiNotice] = await Promise.all([
		runPluginScan(
			logger,
			"session",
			plugins,
			threatsDir,
			allowlistsDir,
			manifest.version,
			"claude-code",
		),
		amsiStartupNotice(),
	]);
	// A replaced or ignored rule directory (AIDR_THREATS_DIR / AIDR_ALLOWLISTS_DIR)
	// is reported at session start, not only on each verdict.
	const overrideNotice = assetOverrideNotice();
	const systemMessage = [statusMsg, amsiNotice, overrideNotice].filter(Boolean).join("\n");
	responder.answer({ stdout: `${JSON.stringify({ systemMessage })}\n` });
}

/**
 * Probe AMSI once per session (Windows/WSL with `amsi_check` enabled) so the
 * per-call hook finds the host state already recorded, and say once, here,
 * when AMSI cannot run on this computer. Best effort: a failure only drops the
 * notice; the per-call path still reports the leg on every verdict.
 */
async function amsiStartupNotice(): Promise<string | null> {
	try {
		const config = await loadConfig(undefined, logger);
		const record = await amsiSessionStatus(config.amsi_check.enabled, logger);
		return record?.state === "unavailable"
			? t("hook.amsiUnavailable", { reason: record.reason })
			: null;
	} catch (error) {
		logger.debug("AMSI start-up probe skipped", { error: String(error) });
		return null;
	}
}

main().catch((error: unknown) => {
	// A failed release integrity check does not leave the session unprotected:
	// the PreToolUse hook denies every call. The banner says so, with the fix.
	const systemMessage =
		integrityFailureMessage(error)?.sessionStart ?? t("hook.sessionStartFailed");
	responder.answer({
		stdout: `${JSON.stringify({ systemMessage })}\n`,
		exitCode: 1,
	});
});
