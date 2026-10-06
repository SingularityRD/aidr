/**
 * Discovers installed OpenCode plugins for plugin scanning.
 * Scans NPM packages from config files and local plugin files.
 */

import { createHash } from "node:crypto";
import { readdir, stat } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, join } from "node:path";
import type { Logger, PluginInfo } from "@singularityrd/aidr-core";
import { getFileContent, parseJsonc } from "@singularityrd/aidr-core";

/** Resolve XDG base directories with fallbacks to homedir defaults */
function getConfigHome(): string {
	return process.env.XDG_CONFIG_HOME ?? join(homedir(), ".config");
}

function getCacheHome(): string {
	return process.env.XDG_CACHE_HOME ?? join(homedir(), ".cache");
}

const CONFIG_NAMES = ["opencode.json", "opencode.jsonc"];

/**
 * Discover OpenCode plugins from the supported local sources:
 * 1. NPM packages from config files
 * 2. Local plugin files (global + project)
 */
export async function discoverOpenCodePlugins(
	logger: Logger,
	projectDir?: string,
): Promise<PluginInfo[]> {
	logger.debug("Singularity AIDR plugin discovery: scanning OpenCode plugins");

	const plugins: PluginInfo[] = [];

	// 1. Discover NPM plugins from config files
	const npmPlugins = await discoverNpmPlugins(logger, projectDir);
	plugins.push(...npmPlugins);

	// 2. Discover local plugin files (global)
	for (const name of ["plugins", "plugin"]) {
		const globalPluginsDir = join(getConfigHome(), "opencode", name);
		plugins.push(...(await discoverLocalPlugins(globalPluginsDir, "global", logger)));
	}

	// 3. Discover local plugin files (project)
	if (projectDir) {
		for (const name of ["plugins", "plugin"]) {
			const projectPluginsDir = join(projectDir, ".opencode", name);
			plugins.push(...(await discoverLocalPlugins(projectPluginsDir, "project", logger)));
		}
	}

	logger.info(`Singularity AIDR plugin discovery: found ${plugins.length} plugin(s)`);
	return plugins;
}

/**
 * Discover NPM plugins listed in config files
 */
async function discoverNpmPlugins(logger: Logger, projectDir?: string): Promise<PluginInfo[]> {
	const plugins: PluginInfo[] = [];

	const configDirs = [join(getConfigHome(), "opencode"), ...(projectDir ? [projectDir] : [])];
	const configPaths = configDirs.flatMap((dir) => CONFIG_NAMES.map((name) => join(dir, name)));
	const pluginNames = new Set(
		(await Promise.all(configPaths.map((path) => readPluginNames(path, logger)))).flat(),
	);

	const npmCacheDir = join(getCacheHome(), "opencode");
	for (const pluginName of pluginNames) {
		// Registry selectors only; path, URL, and alias specs need host resolution.
		const selector = /^(@[^/@\\\s]+\/[^/@\\\s]+|(?!\.)[^/@\\\s]+)(?:@([^/\\]+))?$/.exec(pluginName);
		if (!selector) {
			logger.warn(`Unsupported OpenCode plugin selector for startup scan: ${pluginName}`);
			continue;
		}
		const packageName = selector[1] as string;
		const installSelector = `${packageName}@${selector[2] ?? "latest"}`;
		// OpenCode 1.18.32 isolates installs by selector and sanitizes Windows filenames.
		const cacheSelector =
			process.platform === "win32"
				? installSelector.replace(/[<>:"|?*\u0000-\u001f]/g, "_")
				: installSelector;
		const installPaths = [
			join(npmCacheDir, "packages", cacheSelector, "node_modules", packageName),
			join(npmCacheDir, "node_modules", packageName),
		];
		let found = false;
		for (const installPath of installPaths) {
			try {
				const pkgJsonPath = join(installPath, "package.json");
				const pkgJson = JSON.parse(await getFileContent(pkgJsonPath)) as Record<string, unknown>;

				const stats = await stat(installPath);
				const version = (pkgJson.version as string) ?? "unknown";
				const key = `${packageName}@${version}`;

				plugins.push({
					key,
					installPath,
					version,
					lastUpdated: stats.mtime.toISOString(),
				});

				logger.debug(`Discovered NPM plugin: ${key}`, { installPath });
				found = true;
				break;
			} catch {
				// Try the cache layout used by older hosts before reporting a missing install.
			}
		}
		if (!found) {
			logger.warn(`NPM plugin listed in config but not found: ${pluginName}`);
		}
	}

	return plugins;
}

async function readPluginNames(configPath: string, logger: Logger): Promise<string[]> {
	let parsed: ReturnType<typeof parseJsonc>;
	try {
		parsed = parseJsonc(await getFileContent(configPath));
	} catch {
		logger.debug(`OpenCode config not found or unreadable: ${configPath}`);
		return [];
	}
	if (
		parsed.status !== "ok" ||
		!parsed.value ||
		typeof parsed.value !== "object" ||
		Array.isArray(parsed.value)
	) {
		logger.warn(`Invalid OpenCode config: ${configPath}`);
		return [];
	}
	const configured = (parsed.value as Record<string, unknown>).plugin;
	if (configured === undefined) return [];
	if (!Array.isArray(configured)) {
		logger.warn(`Invalid OpenCode plugin list: ${configPath}`);
		return [];
	}
	const names: string[] = [];
	for (const entry of configured) {
		// Newer hosts also accept [specifier, options] declarations.
		const name = Array.isArray(entry) ? entry[0] : entry;
		if (typeof name === "string" && name.length > 0) names.push(name);
		else logger.warn(`Invalid OpenCode plugin entry: ${configPath}`);
	}
	return names;
}

/**
 * Discover local plugin files (.js/.ts) in a directory
 */
async function discoverLocalPlugins(
	pluginsDir: string,
	context: string,
	logger: Logger,
): Promise<PluginInfo[]> {
	const plugins: PluginInfo[] = [];

	let entries: string[];
	try {
		entries = await readdir(pluginsDir);
	} catch {
		logger.debug(`${context} plugins directory not found: ${pluginsDir}`);
		return [];
	}

	for (const entry of entries) {
		const fullPath = join(pluginsDir, entry);

		// Only scan .js and .ts files
		if (!(entry.endsWith(".js") || entry.endsWith(".ts"))) {
			continue;
		}

		try {
			const stats = await stat(fullPath);
			if (!stats.isFile()) continue;

			// Use filename as plugin name
			const name = basename(entry, entry.endsWith(".ts") ? ".ts" : ".js");
			const version = `local-${stats.mtime.getTime()}`; // Synthetic version from mtime
			// Distinguish equal basenames/mtimes across extensions, directories, and projects.
			const pathId = createHash("sha256").update(fullPath).digest("hex").slice(0, 16);
			const key = `${context}/${name}-${pathId}@${version}`;

			plugins.push({
				key,
				installPath: fullPath,
				version,
				lastUpdated: stats.mtime.toISOString(),
			});

			logger.debug(`Discovered local plugin: ${key}`, { path: fullPath });
		} catch {
			logger.warn(`Failed to read local plugin: ${entry}`);
		}
	}

	return plugins;
}
