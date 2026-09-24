import { existsSync, lstatSync, readFileSync, readdirSync, statSync } from "node:fs";
import path from "node:path";

import { REQUIRED_RUNTIME_FILES, SIGNED_EVIDENCE_FILES } from "../../packages/claude-code/scripts/ensure-dist.mjs";

export const REQUIRED_RESOURCE_FILES = Object.freeze([
	"packages/claude-code/resources/allowlists/trusted-installer-domains.yaml",
	"packages/claude-code/resources/threats/commands.yaml",
]);

const CLAUDE_PLUGIN_ARCHIVE_BASE_PATHS = Object.freeze([
".claude-plugin",
"hooks",
"packages/claude-code/dist",
	"packages/claude-code/resources",
	"packages/claude-code/package.json",
	"skills",
]);

const PLUGIN_PACKAGE_FILES = Object.freeze([
	".claude-plugin/marketplace.json",
	".claude-plugin/plugin.json",
	"hooks/hooks.json",
	"packages/claude-code/package.json",
	"skills/security-awareness/SKILL.md",
]);

const PACKAGE_EVIDENCE_FILES = SIGNED_EVIDENCE_FILES.filter((name) => name !== "aidr-artifact.manifest.sig");
const PACKAGE_MANIFEST_FILES = Object.freeze([
	"packages/claude-code/aidr-artifact.manifest.json",
	"packages/claude-code/aidr-artifact.manifest.sig",
]);

export function claudePluginArchivePaths({ requireSignedEvidence = true } = {}) {
	return [...CLAUDE_PLUGIN_ARCHIVE_BASE_PATHS, ...(requireSignedEvidence ? PACKAGE_MANIFEST_FILES : [])];
}

export function claudePluginRequiredFiles({ requireSignedEvidence = true } = {}) {
	return [
		...PLUGIN_PACKAGE_FILES,
		...REQUIRED_RUNTIME_FILES.map((name) => `packages/claude-code/dist/${name}`),
		...PACKAGE_EVIDENCE_FILES.map((name) => `packages/claude-code/dist/${name}`),
		...(requireSignedEvidence ? ["packages/claude-code/dist/aidr-artifact.manifest.sig"] : []),
		...(requireSignedEvidence ? PACKAGE_MANIFEST_FILES : []),
		...REQUIRED_RESOURCE_FILES,
	];
}

function readJson(file) {
	try {
		return JSON.parse(readFileSync(file, "utf8"));
	} catch (error) {
		throw new Error(`Claude plugin metadata is invalid: ${file} (${error instanceof Error ? error.message : String(error)})`);
	}
}

function referencedPluginPaths(plugin, hooks) {
	const values = [];
	for (const server of Object.values(plugin.mcpServers ?? {})) {
		if (Array.isArray(server?.args)) values.push(...server.args.filter((value) => typeof value === "string"));
	}
	for (const registrations of Object.values(hooks.hooks ?? {})) {
		for (const registration of Array.isArray(registrations) ? registrations : []) {
			for (const hook of Array.isArray(registration?.hooks) ? registration.hooks : []) {
				if (typeof hook?.command === "string") values.push(hook.command);
			}
		}
	}
	return values.flatMap((value) => [...value.matchAll(/\$\{CLAUDE_PLUGIN_ROOT\}\/([^"'\s]+)/gu)].map((match) => match[1]));
}

export function assertClaudePluginPackage(root, { requireSignedEvidence = true } = {}) {
	const pluginFile = path.join(root, ".claude-plugin", "plugin.json");
	const marketplaceFile = path.join(root, ".claude-plugin", "marketplace.json");
	const hooksFile = path.join(root, "hooks", "hooks.json");
	const plugin = readJson(pluginFile);
	const marketplace = readJson(marketplaceFile);
	const hooks = readJson(hooksFile);
	const registration = marketplace.plugins?.find?.((entry) => entry?.name === plugin.name);
	if (!registration || registration.source !== "./") throw new Error("Claude marketplace must install the packaged plugin root");

	const required = [
		...claudePluginRequiredFiles({ requireSignedEvidence }),
		...referencedPluginPaths(plugin, hooks),
	];
	for (const relative of new Set(required)) {
		if (path.isAbsolute(relative) || relative.split(/[\\/]/u).some((part) => part === ".." || part === "")) {
			throw new Error(`Claude plugin metadata contains an unsafe path: ${relative}`);
		}
		const target = path.resolve(root, relative);
		if (!target.startsWith(`${path.resolve(root)}${path.sep}`) || !existsSync(target) || !statSync(target).isFile()) {
			throw new Error(`Claude plugin package is missing ${relative}`);
		}
	}
	return { plugin: plugin.name, referencedFiles: new Set(required).size };
}

export function assertClaudePluginResourcesCanonical(root) {
	for (const name of ["allowlists", "threats"]) {
		const canonical = path.join(root, name);
		const packaged = path.join(root, "packages", "claude-code", "resources", name);
		const canonicalFiles = listRegularFiles(canonical, `canonical ${name}`);
		const packagedFiles = listRegularFiles(packaged, `packaged ${name}`);
		if (canonicalFiles.join("\n") !== packagedFiles.join("\n")) {
			throw new Error(`Claude plugin packaged ${name} file set does not match the canonical source`);
		}
		for (const relative of canonicalFiles) {
			if (!readFileSync(path.join(canonical, relative)).equals(readFileSync(path.join(packaged, relative)))) {
				throw new Error(`Claude plugin packaged ${name} differs from the canonical source: ${relative}`);
			}
		}
	}
}

function listRegularFiles(root, label) {
	if (!existsSync(root) || !statSync(root).isDirectory()) throw new Error(`Claude plugin is missing ${label} directory`);
	const files = [];
	const stack = [{ absolute: root, relative: "" }];
	while (stack.length > 0) {
		const current = stack.pop();
		for (const entry of readdirSync(current.absolute, { withFileTypes: true })) {
			const absolute = path.join(current.absolute, entry.name);
			const relative = current.relative ? `${current.relative}/${entry.name}` : entry.name;
			const info = lstatSync(absolute);
			if (info.isSymbolicLink()) throw new Error(`Claude plugin ${label} contains a symlink: ${relative}`);
			if (info.isDirectory()) stack.push({ absolute, relative });
			else if (info.isFile()) files.push(relative);
			else throw new Error(`Claude plugin ${label} contains an unsupported entry: ${relative}`);
		}
	}
	return files.sort();
}
