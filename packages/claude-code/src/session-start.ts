#!/usr/bin/env node
/**
 * Singularity AIDR SessionStart hook entry point.
 * Scans installed Claude Code plugins for threats at session startup.
 * Outputs status JSON and exits non-zero when protection cannot start.
 */

import { readFileSync } from "node:fs";
import { join } from "node:path";
import {
	discoverPlugins,
	getLogger,
	initSentry,
	type Logger,
	runPluginScan,
	verifyArtifactIntegrityAndLog,
} from "@singularityrd/aidr-core";
import { pruneStaleSessionFiles } from "./approval-tracker.js";
import { resolveAssetDir, resolvePluginRoot } from "./assets.js";

// Initialize Sentry
initSentry({ name: "aidr-claude-code-session-start" });

const logger: Logger = getLogger();

function getPluginManifest(pluginRoot: string): { name: string | null; version: string } {
	try {
		const manifest = readFileSync(join(pluginRoot, ".claude-plugin", "plugin.json"), "utf-8");
		const parsed = JSON.parse(manifest) as Record<string, unknown>;
		return {
			name: (parsed.name as string) ?? null,
			version: (parsed.version as string) ?? "0.0.0",
		};
	} catch {
		return { name: null, version: "0.0.0" };
	}
}

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
	const manifest = getPluginManifest(pluginRoot);

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
	process.stdout.write(`${JSON.stringify({ systemMessage: statusMsg })}\n`);
}

main().catch(() => {
	process.stdout.write(
		`${JSON.stringify({ systemMessage: "Singularity AIDR protection failed to start; the session is not protected." })}\n`,
	);
	process.exitCode = 1;
});
