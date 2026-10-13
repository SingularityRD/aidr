/**
 * Resolve Claude connector assets for both the repository plugin and a
 * packaged @singularityrd/aidr-claude-code install.
 *
 * The marketplace plugin keeps `threats/` and `allowlists/` at the plugin
 * root. A package consumer cannot rely on the monorepo cwd, so release builds
 * copy the same directories to integrity-covered `dist/resources/` and this resolver prefers
 * that location. The `AIDR_THREATS_DIR` / `AIDR_ALLOWLISTS_DIR` overrides are
 * honoured only in development builds and are always reported (see core
 * `rule-dir-override.ts` and {@link assetOverrideNotice}); a commercial build
 * ignores them and loads its bundled, integrity-checked resources.
 */

import { existsSync, readFileSync, statSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { ruleDirOverride, ruleDirOverrideNotice, ruleDirOverrides } from "@singularityrd/aidr-core";

type AssetKind = "threats" | "allowlists";

const packageRoot = resolve(dirname(__dirname));
const repositoryRoot = resolve(packageRoot, "..", "..");

/**
 * Resolve a connector asset directory without assuming process.cwd() is the
 * repository. The first existing directory wins; if none exists, the
 * packaged resource path is returned so callers still produce a deterministic
 * missing-data signal rather than silently using an unrelated cwd directory.
 */
export function resolveAssetDir(kind: AssetKind): string {
	const override = ruleDirOverride(kind);
	const packaged = join(packageRoot, "dist", "resources", kind);
	const candidates = [
		override?.accepted ? override.path : undefined,
		packaged,
		join(packageRoot, "resources", kind),
		join(packageRoot, kind),
		join(repositoryRoot, kind),
		join(process.cwd(), kind),
		join(homedir(), ".singularity-aidr", kind),
	];

	for (const candidate of candidates) {
		if (candidate && isDirectory(candidate)) return resolve(candidate);
	}

	return packaged;
}

/**
 * The warning to show while an `AIDR_THREATS_DIR` / `AIDR_ALLOWLISTS_DIR`
 * override is set (used or, in a commercial build, ignored), else null.
 */
export function assetOverrideNotice(): string | null {
	return ruleDirOverrideNotice(ruleDirOverrides());
}

/**
 * Resolve the Claude plugin root used for its optional plugin manifest and
 * installed-plugin discovery. `CLAUDE_PLUGIN_ROOT` is authoritative when the
 * host provides it; otherwise the marketplace checkout and package root are
 * considered in that order.
 */
export function resolvePluginRoot(): string {
	const explicit = process.env.CLAUDE_PLUGIN_ROOT || process.env.AIDR_PLUGIN_ROOT;
	if (explicit) return resolve(explicit);

	const candidates = [repositoryRoot, packageRoot, process.cwd()];
	for (const candidate of candidates) {
		if (existsSync(join(candidate, ".claude-plugin", "plugin.json"))) {
			return candidate;
		}
	}

	return packageRoot;
}

const CONNECTOR_PACKAGE_NAME = "@singularityrd/aidr-claude-code";

function readJsonObject(file: string): Record<string, unknown> | null {
	try {
		const parsed = JSON.parse(readFileSync(file, "utf-8")) as unknown;
		return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : null;
	} catch {
		return null;
	}
}

function nonEmptyString(value: unknown): string | null {
	return typeof value === "string" && value.trim() ? value : null;
}

/**
 * Plugin identity for startup status. The marketplace checkout carries
 * `.claude-plugin/plugin.json`; an endpoint install only ships the connector
 * package, so the version falls back to that package's own package.json
 * (matched by name, so an unrelated package.json is never reported).
 */
export function resolvePluginManifest(
	pluginRoot: string,
	connectorRoot: string = packageRoot,
): { name: string | null; version: string } {
	const plugin = readJsonObject(join(pluginRoot, ".claude-plugin", "plugin.json"));
	const name = nonEmptyString(plugin?.name);
	const pluginVersion = nonEmptyString(plugin?.version);
	if (pluginVersion) return { name, version: pluginVersion };

	for (const root of new Set([connectorRoot, pluginRoot])) {
		const pkg = readJsonObject(join(root, "package.json"));
		const version = nonEmptyString(pkg?.version);
		if (pkg?.name === CONNECTOR_PACKAGE_NAME && version) return { name, version };
	}
	return { name, version: "0.0.0" };
}

function isDirectory(candidate: string): boolean {
	try {
		return statSync(candidate).isDirectory();
	} catch {
		return false;
	}
}
