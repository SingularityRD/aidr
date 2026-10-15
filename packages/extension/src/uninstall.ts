/**
 * `vscode:uninstall` hook (bundled to `dist/aidr-uninstall.cjs`). The editor
 * runs it in plain Node after the extension is fully removed, so nothing here
 * may use the `vscode` API (the bundle stubs it out).
 *
 * It removes only this extension's managed hook entries from every hook file
 * it recorded, the shims it generated, and its stable launcher, so an
 * uninstall without "Disable protection" leaves neither a dangling hook nor
 * a deny-everything shim behind. Foreign hooks and settings are untouched.
 */

import { readFileSync } from "node:fs";
import path from "node:path";

import { removeManagedHooksFromFile as removeCursorHooks } from "./cursor_hook_installer.js";
import { findInstalledRunners } from "./hook-launcher.js";
import type { ExtensionHookHost } from "./hook-responses.js";
import { readHostPointer, removeHookRuntime } from "./hook-runtime.js";
import { removeManagedHooksFromFile as removeVsCodeHooks } from "./vscode_hook_installer.js";

declare const __dirname: string;

function readJson(filePath: string): Record<string, unknown> {
	try {
		const parsed: unknown = JSON.parse(readFileSync(filePath, "utf8"));
		return parsed && typeof parsed === "object" && !Array.isArray(parsed)
			? (parsed as Record<string, unknown>)
			: {};
	} catch {
		return {};
	}
}

function extensionIdOf(extensionDir: string): string | undefined {
	const manifest = readJson(path.join(extensionDir, "package.json"));
	return typeof manifest.publisher === "string" && typeof manifest.name === "string"
		? `${manifest.publisher}.${manifest.name}`.toLowerCase()
		: undefined;
}

/** Another copy of the extension that the editor still considers installed. */
function otherInstalledCopy(extensionsDir: string, extensionId: string, self: string): boolean {
	const obsolete = readJson(path.join(extensionsDir, ".obsolete"));
	return findInstalledRunners(extensionsDir, extensionId).some((runner) => {
		const dir = path.resolve(runner, "..", "..");
		return dir !== path.resolve(self) && obsolete[path.basename(dir)] !== true;
	});
}

/** Whether `host`'s recorded hooks belong to this (now removed) extension copy. */
function ownsHostHooks(host: ExtensionHookHost, extensionDir: string): boolean {
	const pointer = readHostPointer(host);
	const extensionsDir = path.resolve(path.dirname(extensionDir));
	if (!pointer.extensions_dir || path.resolve(pointer.extensions_dir) !== extensionsDir) {
		return false;
	}
	const extensionId = pointer.extension_id?.toLowerCase();
	const ownId = extensionIdOf(extensionDir);
	if (!extensionId || (ownId && ownId !== extensionId)) return false;
	return !otherInstalledCopy(extensionsDir, extensionId, extensionDir);
}

export async function runUninstall(
	extensionDir: string = path.resolve(__dirname, ".."),
): Promise<string[]> {
	const cleaned: string[] = [];
	for (const host of ["cursor", "vscode"] as ExtensionHookHost[]) {
		if (!ownsHostHooks(host, extensionDir)) continue;
		const remove = host === "cursor" ? removeCursorHooks : removeVsCodeHooks;
		for (const configPath of readHostPointer(host).config_paths ?? []) {
			try {
				await remove(configPath);
				cleaned.push(configPath);
			} catch {
				// A malformed or unreadable hook file is left as it is, never overwritten.
			}
		}
		await removeHookRuntime(host);
	}
	return cleaned;
}

if (typeof require !== "undefined" && typeof module !== "undefined" && require.main === module) {
	runUninstall().catch(() => {
		process.exitCode = 1;
	});
}
