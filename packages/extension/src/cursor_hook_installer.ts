import { readFile } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { atomicWriteJson } from "@singularityrd/aidr-core";

import * as vscode from "vscode";

import { forgetConfigPath, removeHookShims } from "./hook-runtime.js";
import { describeManagedHooks, prepareManagedHookCommand } from "./installer_common.js";
import {
	inRegistrationOrder,
	type ManagedHookHealth,
	type ManagedHookInstallOptions,
	type ManagedHookScope,
} from "./managedHooks.js";

const MANAGED_MARKER = "--managed-by aidr-cursor";

type HookEntry = Record<string, unknown> & { command?: string };
type HookMap = Record<string, HookEntry[]>;

interface CursorHooksFile {
	version: number;
	hooks: HookMap;
}

export async function installManagedHooks(
	options: ManagedHookInstallOptions,
): Promise<ManagedHookHealth> {
	const configPath = await resolveHooksPath(options.scope);
	const hooksFile = await readHooksFile(configPath);
	const { command } = await prepareManagedHookCommand(
		options.context,
		"cursor",
		configPath,
		MANAGED_MARKER,
	);

	const updated = upsertManagedHooks(hooksFile, command);
	await writeHooksFile(configPath, updated);
	return healthOf(configPath, updated.hooks);
}

export async function removeManagedHooks(scope: ManagedHookScope): Promise<string> {
	const configPath = await resolveHooksPath(scope);
	await removeManagedHooksFromFile(configPath);
	return configPath;
}

/**
 * Remove only this extension's entries (and its shims) from a Cursor hooks
 * file. vscode-free: the uninstall script calls it too.
 */
export async function removeManagedHooksFromFile(configPath: string): Promise<void> {
	const hooksFile = await readHooksFile(configPath);
	if (collectManagedCommands(hooksFile.hooks).length > 0) {
		await writeHooksFile(configPath, removeManagedEntries(hooksFile));
	}
	await removeHookShims(path.join(path.dirname(configPath), "hooks"));
	await forgetConfigPath("cursor", configPath);
}

export async function getHookHealth(
	options: ManagedHookInstallOptions,
): Promise<ManagedHookHealth> {
	const configPath = await resolveHooksPath(options.scope);
	const hooksFile = await readHooksFile(configPath);
	return healthOf(configPath, hooksFile.hooks);
}

/**
 * Re-point every installed managed hook at this extension version (run on
 * activation). Scopes without managed entries are left untouched, so this
 * never enables protection on its own.
 */
export async function repairManagedHooks(
	context: vscode.ExtensionContext,
): Promise<ManagedHookHealth[]> {
	const results: ManagedHookHealth[] = [];
	const seen = new Set<string>();
	for (const scope of ["user", "workspace"] as const) {
		const configPath = await resolveHooksPath(scope).catch(() => undefined);
		if (!configPath || seen.has(configPath)) continue;
		seen.add(configPath);
		const hooksFile = await readHooksFile(configPath).catch(() => undefined);
		if (!hooksFile) continue;
		const managed = collectManagedCommands(hooksFile.hooks);
		if (managed.length === 0) continue;
		const { command } = await prepareManagedHookCommand(
			context,
			"cursor",
			configPath,
			MANAGED_MARKER,
		);
		let hooks = hooksFile.hooks;
		if (managed.some((existing) => existing !== command)) {
			const updated = upsertManagedHooks(hooksFile, command);
			await writeHooksFile(configPath, updated);
			hooks = updated.hooks;
		}
		results.push(await healthOf(configPath, hooks));
	}
	return results;
}

function healthOf(configPath: string, hooks: HookMap): Promise<ManagedHookHealth> {
	return describeManagedHooks(
		"cursor",
		configPath,
		collectInstalledEvents(hooks),
		collectManagedCommands(hooks),
	);
}

async function resolveHooksPath(scope: ManagedHookScope): Promise<string> {
	if (scope === "user") {
		return path.join(os.homedir(), ".cursor", "hooks.json");
	}

	const workspace = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspace) {
		throw new Error("Open a workspace folder to install workspace hooks.");
	}
	return path.join(workspace, ".cursor", "hooks.json");
}

/**
 * Managed Cursor hook events in their documented registration order
 * (docs/how-it-works.md, deploy/native/interception-matrix.json). `installedEvents` is
 * always reported in this order, independent of the key order already present in the
 * customer's hooks.json. `beforeSubmitPrompt` comes first because it fires first: it
 * inspects the user's prompt (prompt protection) before any tool call can happen.
 */
const MANAGED_HOOK_EVENTS: ReadonlyArray<{ event: string; matcher?: string }> = [
	{ event: "beforeSubmitPrompt" },
	{ event: "beforeShellExecution" },
	// No matcher: every tool call reaches the hook (an unmatched tool would skip inspection).
	{ event: "preToolUse" },
	{ event: "postToolUse" },
	{ event: "afterAgentResponse" },
	{ event: "beforeMCPExecution" },
	{ event: "beforeReadFile" },
];

function upsertManagedHooks(existing: CursorHooksFile, command: string): CursorHooksFile {
	const hooks = { ...existing.hooks };
	for (const { event, matcher } of MANAGED_HOOK_EVENTS) {
		hooks[event] = appendManaged(hooks[event], {
			...(matcher ? { matcher } : {}),
			command,
			timeout: 30,
			failClosed: true,
		});
	}

	return {
		...existing,
		version: 1,
		hooks,
	};
}

function collectInstalledEvents(hooks: HookMap): string[] {
	const managedEvents = Object.keys(hooks).filter((eventName) =>
		(hooks[eventName] ?? []).some((entry) => isManagedEntry(entry)),
	);
	return inRegistrationOrder(
		managedEvents,
		MANAGED_HOOK_EVENTS.map(({ event }) => event),
	);
}

function removeManagedEntries(existing: CursorHooksFile): CursorHooksFile {
	const hooks: HookMap = {};
	for (const [eventName, entries] of Object.entries(existing.hooks)) {
		const filtered = (entries ?? []).filter((entry) => !isManagedEntry(entry));
		if (filtered.length > 0) {
			hooks[eventName] = filtered;
		}
	}
	return {
		...existing,
		version: existing.version || 1,
		hooks,
	};
}

function appendManaged(entries: HookEntry[] | undefined, managedEntry: HookEntry): HookEntry[] {
	const retained = (entries ?? []).filter((entry) => !isManagedEntry(entry));
	return [...retained, managedEntry];
}

function collectManagedCommands(hooks: HookMap): string[] {
	const commands = new Set<string>();
	for (const entries of Object.values(hooks)) {
		for (const entry of entries ?? []) {
			if (!isManagedEntry(entry) || typeof entry.command !== "string") {
				continue;
			}
			commands.add(entry.command);
		}
	}
	return [...commands];
}

function isManagedEntry(entry: HookEntry): boolean {
	return typeof entry.command === "string" && entry.command.includes(MANAGED_MARKER);
}

async function readHooksFile(filePath: string): Promise<CursorHooksFile> {
	let contents: string;
	try {
		contents = await readFile(filePath, "utf8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") {
			return { version: 1, hooks: {} };
		}
		throw error;
	}
	const parsed = JSON.parse(contents) as Partial<CursorHooksFile>;
	if (
		!parsed ||
		typeof parsed !== "object" ||
		Array.isArray(parsed) ||
		(parsed.version !== undefined && parsed.version !== 1) ||
		(parsed.hooks !== undefined &&
			(!parsed.hooks ||
				typeof parsed.hooks !== "object" ||
				Array.isArray(parsed.hooks) ||
				Object.values(parsed.hooks).some((entries) => !Array.isArray(entries))))
	) {
		throw new Error("Invalid Cursor hooks configuration.");
	}
	return { ...parsed, version: parsed.version ?? 1, hooks: parsed.hooks ?? {} };
}

async function writeHooksFile(filePath: string, data: CursorHooksFile): Promise<void> {
	await atomicWriteJson(filePath, data);
}
