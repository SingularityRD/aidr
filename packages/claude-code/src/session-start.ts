#!/usr/bin/env node
/**
 * Singularity AIDR SessionStart hook entry point.
 * Scans installed Claude Code plugins for threats at session startup.
 * Always exits 0 — outputs status JSON with systemMessage.
 */

import { readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import {
	discoverPlugins,
	getLogger,
	initSentry,
	type Logger,
	runPluginScan,
} from "@singularityrd/aidr-core";
import { pruneStaleSessionFiles } from "./approval-tracker.js";

// Initialize Sentry
initSentry({ name: "aidr-claude-code-session-start" });

const logger: Logger = getLogger();

function getPluginRoot(): string {
	// When bundled by esbuild into CJS, __dirname points to packages/claude-code/dist/
	// Plugin root is three levels up.
	return resolve(__dirname, "..", "..", "..");
}

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
	await pruneStaleSessionFiles(logger);
	try {
		// biome-ignore lint/suspicious/noExplicitAny: Transitional wiring
		const core = (await import("@singularityrd/aidr-core")) as any;
		const fn = core?.verifyArtifactIntegrityAndLog as
			| ((args: { artifactDir: string; artifactId: string; logger?: unknown }) => Promise<unknown>)
			| undefined;
		if (typeof fn === "function") {
			await fn({
				artifactDir: __dirname,
				artifactId: "claude-code/dist",
				logger,
			});
		}
	} catch {
		// Fail open
	}

	const pluginRoot = getPluginRoot();
	const threatsDir = join(pluginRoot, "threats");
	const allowlistsDir = join(pluginRoot, "allowlists");
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
	process.stdout.write("{}\n");
});
