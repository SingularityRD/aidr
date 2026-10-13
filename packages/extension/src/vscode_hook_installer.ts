import { readFile, writeFile } from "node:fs/promises";
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

export const MANAGED_MARKER = "--managed-by aidr-vscode";
/** Copy of the settings file as it was before AIDR last changed it. */
export const SETTINGS_BACKUP_SUFFIX = ".aidr-backup";

type HookCommandEntry = Record<string, unknown> & { command?: string };
type HookMatcherEntry = Record<string, unknown> & { hooks?: HookCommandEntry[] };
type HookMap = Record<string, HookMatcherEntry[]>;
type SettingsObject = Record<string, unknown>;

/*
 * VS Code Local hooks (chat.useClaudeHooks) are read from the Claude settings
 * files, so the user scope is `~/.claude/settings.json`, which the Claude Code
 * CLI shares. Every write therefore merges: only entries carrying
 * MANAGED_MARKER are added or removed, every other key and hook is kept as
 * read, the previous file is backed up next to it, and a file changed by
 * another writer between read and write is re-read and merged again.
 */

export async function installManagedHooks(
	options: ManagedHookInstallOptions,
): Promise<ManagedHookHealth> {
	const configPath = await resolveSettingsPath(options.scope);
	await readSettingsFile(configPath);
	const { command } = await prepareManagedHookCommand(
		options.context,
		"vscode",
		configPath,
		MANAGED_MARKER,
	);
	const updated = await updateSettingsFile(configPath, (settings) =>
		upsertManagedHooks(settings, command),
	);
	return healthOf(configPath, updated);
}

export async function removeManagedHooks(scope: ManagedHookScope): Promise<string> {
	const configPath = await resolveSettingsPath(scope);
	await removeManagedHooksFromFile(configPath);
	return configPath;
}

/**
 * Remove only this extension's entries (and its shims) from a Claude settings
 * file. vscode-free: the uninstall script calls it too.
 */
export async function removeManagedHooksFromFile(configPath: string): Promise<void> {
	await updateSettingsFile(configPath, removeManagedEntries);
	await removeHookShims(path.join(path.dirname(configPath), "hooks"));
	await forgetConfigPath("vscode", configPath);
}

export async function getHookHealth(
	options: ManagedHookInstallOptions,
): Promise<ManagedHookHealth> {
	const configPath = await resolveSettingsPath(options.scope);
	return healthOf(configPath, await readSettingsFile(configPath));
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
		const configPath = await resolveSettingsPath(scope).catch(() => undefined);
		if (!configPath || seen.has(configPath)) continue;
		seen.add(configPath);
		const settings = await readSettingsFile(configPath).catch(() => undefined);
		if (!settings) continue;
		const managed = collectManagedCommands(normalizeHookMap(settings.hooks));
		if (managed.length === 0) continue;
		const { command } = await prepareManagedHookCommand(
			context,
			"vscode",
			configPath,
			MANAGED_MARKER,
		);
		let current = settings;
		if (managed.some((existing) => existing !== command)) {
			current = await updateSettingsFile(configPath, (value) => upsertManagedHooks(value, command));
		}
		results.push(await healthOf(configPath, current));
	}
	return results;
}

function healthOf(configPath: string, settings: SettingsObject): Promise<ManagedHookHealth> {
	const hooks = normalizeHookMap(settings.hooks);
	return describeManagedHooks(
		"vscode",
		configPath,
		collectInstalledEvents(hooks),
		collectManagedCommands(hooks),
	);
}

async function resolveSettingsPath(scope: ManagedHookScope): Promise<string> {
	if (scope === "user") {
		return path.join(os.homedir(), ".claude", "settings.json");
	}

	const workspace = vscode.workspace.workspaceFolders?.[0]?.uri.fsPath;
	if (!workspace) {
		throw new Error("Open a workspace folder to install workspace hooks.");
	}
	return path.join(workspace, ".claude", "settings.json");
}

function upsertManagedHooks(existing: SettingsObject, command: string): SettingsObject {
	const hooks = cloneHookSettings(existing.hooks);
	// Prompt protection. UserPromptSubmit takes no matcher (VS Code Local ignores
	// matchers and Claude Code does not apply one to this event).
	hooks.UserPromptSubmit = appendManaged(asMatcherEntries(hooks.UserPromptSubmit), {
		hooks: [
			{
				type: "command",
				command,
				timeout: 30,
				statusMessage: "Singularity AIDR: Checking prompt for secrets...",
			},
		],
	});
	hooks.PreToolUse = appendManaged(asMatcherEntries(hooks.PreToolUse), {
		matcher: "*",
		hooks: [
			{
				type: "command",
				command,
				timeout: 30,
				statusMessage: "Singularity AIDR: Checking for threats...",
			},
		],
	});
	hooks.PostToolUse = appendManaged(asMatcherEntries(hooks.PostToolUse), {
		hooks: [
			{
				type: "command",
				command,
				timeout: 30,
				statusMessage: "Singularity AIDR: Inspecting tool output...",
			},
		],
	});

	return {
		...existing,
		hooks,
	};
}

function removeManagedEntries(existing: SettingsObject): SettingsObject {
	const hooks = cloneHookSettings(existing.hooks);
	for (const [eventName, value] of Object.entries(hooks)) {
		if (!Array.isArray(value)) {
			continue;
		}
		const filtered = filterManagedMatcherEntries(asMatcherEntries(value));
		if (filtered.length === 0) {
			delete hooks[eventName];
			continue;
		}
		hooks[eventName] = filtered;
	}

	return {
		...existing,
		hooks,
	};
}

function appendManaged(
	entries: HookMatcherEntry[] | undefined,
	managedEntry: HookMatcherEntry,
): HookMatcherEntry[] {
	const retained = filterManagedMatcherEntries(entries ?? []);
	return [...retained, managedEntry];
}

function filterManagedMatcherEntries(entries: HookMatcherEntry[]): HookMatcherEntry[] {
	const retained: HookMatcherEntry[] = [];
	for (const entry of entries) {
		const commandHooks = asCommandEntries(entry.hooks);
		if (commandHooks.length === 0) {
			retained.push(entry);
			continue;
		}

		const filteredHooks = commandHooks.filter((hook) => !isManagedCommandHook(hook));
		if (filteredHooks.length === 0) {
			continue;
		}
		retained.push({ ...entry, hooks: filteredHooks });
	}
	return retained;
}

/** Managed events in registration order; `installedEvents` is reported in this order. */
const MANAGED_HOOK_EVENTS = ["UserPromptSubmit", "PreToolUse", "PostToolUse"];

function collectInstalledEvents(hooks: HookMap): string[] {
	const managedEvents = Object.keys(hooks).filter((eventName) =>
		(hooks[eventName] ?? []).some((entry) =>
			asCommandEntries(entry.hooks).some((hook) => isManagedCommandHook(hook)),
		),
	);
	return inRegistrationOrder(managedEvents, MANAGED_HOOK_EVENTS);
}

function collectManagedCommands(hooks: HookMap): string[] {
	const commands = new Set<string>();
	for (const entries of Object.values(hooks)) {
		for (const entry of entries) {
			for (const hook of asCommandEntries(entry.hooks)) {
				if (isManagedCommandHook(hook) && typeof hook.command === "string") {
					commands.add(hook.command);
				}
			}
		}
	}
	return [...commands];
}

function isManagedCommandHook(entry: HookCommandEntry): boolean {
	return typeof entry.command === "string" && entry.command.includes(MANAGED_MARKER);
}

async function readSettingsText(filePath: string): Promise<string | undefined> {
	try {
		return await readFile(filePath, "utf8");
	} catch (error) {
		if ((error as NodeJS.ErrnoException).code === "ENOENT") return undefined;
		throw error;
	}
}

function parseSettings(contents: string | undefined): SettingsObject {
	if (contents === undefined) return {};
	const parsed: unknown = JSON.parse(contents);
	if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
		throw new Error("Invalid VS Code hook settings.");
	}
	const settings = parsed as SettingsObject;
	if (
		settings.hooks !== undefined &&
		(!settings.hooks ||
			typeof settings.hooks !== "object" ||
			Array.isArray(settings.hooks) ||
			Object.values(settings.hooks).some((entries) => !Array.isArray(entries)))
	) {
		throw new Error("Invalid VS Code hook settings.");
	}
	return settings;
}

async function readSettingsFile(filePath: string): Promise<SettingsObject> {
	return parseSettings(await readSettingsText(filePath));
}

const MAX_MERGE_ATTEMPTS = 3;

/**
 * Read-merge-write of a (possibly shared) settings file. A no-op merge does not
 * touch the file; otherwise the previous bytes are kept at
 * `<file>.aidr-backup`, and a file another writer changed since it was read is
 * merged again from its new contents instead of being overwritten.
 */
async function updateSettingsFile(
	filePath: string,
	merge: (settings: SettingsObject) => SettingsObject,
): Promise<SettingsObject> {
	for (let attempt = 0; attempt < MAX_MERGE_ATTEMPTS; attempt++) {
		const original = await readSettingsText(filePath);
		const current = parseSettings(original);
		const next = merge(current);
		if (JSON.stringify(next) === JSON.stringify(current)) return current;
		if ((await readSettingsText(filePath)) !== original) continue;
		if (original !== undefined) {
			await writeFile(`${filePath}${SETTINGS_BACKUP_SUFFIX}`, original, {
				encoding: "utf8",
				mode: 0o600,
			});
		}
		await atomicWriteJson(filePath, next);
		return next;
	}
	throw new Error(
		`${filePath} kept changing while Singularity AIDR updated it; no changes were made. Try again.`,
	);
}

function normalizeHookMap(input: unknown): HookMap {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		return {};
	}
	const output: HookMap = {};
	for (const [eventName, entries] of Object.entries(input as Record<string, unknown>)) {
		if (!Array.isArray(entries)) {
			continue;
		}
		output[eventName] = entries.filter(
			(entry): entry is HookMatcherEntry =>
				!!entry && typeof entry === "object" && !Array.isArray(entry),
		);
	}
	return output;
}

function cloneHookSettings(input: unknown): SettingsObject {
	if (!input || typeof input !== "object" || Array.isArray(input)) {
		return {};
	}
	return { ...(input as SettingsObject) };
}

function asMatcherEntries(entries: unknown): HookMatcherEntry[] {
	if (!Array.isArray(entries)) {
		return [];
	}
	return entries.filter(
		(entry): entry is HookMatcherEntry =>
			!!entry && typeof entry === "object" && !Array.isArray(entry),
	);
}

function asCommandEntries(entries: unknown): HookCommandEntry[] {
	if (!Array.isArray(entries)) {
		return [];
	}
	return entries.filter(
		(entry): entry is HookCommandEntry =>
			!!entry && typeof entry === "object" && !Array.isArray(entry),
	);
}
