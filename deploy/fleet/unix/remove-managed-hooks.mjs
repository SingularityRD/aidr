#!/usr/bin/env node
import { existsSync, lstatSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { dirname, isAbsolute, join, parse, resolve } from "node:path";
import { parseArgs } from "node:util";

const { values } = parseArgs({ options: { home: { type: "string" } } });
if (!values.home) throw new Error("--home is required");
if (!isAbsolute(values.home)) throw new Error("--home must be an explicit absolute path");
const home = resolve(values.home);
if (!existsSync(home) || !lstatSync(home).isDirectory() || home === parse(home).root) {
	throw new Error("--home must be an existing home directory, not a symlink or filesystem root");
}
const settingsPath = join(home, ".claude", "settings.json");
const marker = "Singularity AIDR managed installation";

if (existsSync(dirname(settingsPath)) && lstatSync(dirname(settingsPath)).isSymbolicLink()) {
	throw new Error("Claude settings directory is a symlink; no configuration changed");
}

if (!existsSync(settingsPath)) {
	console.log("No Claude settings file; no managed hook was registered.");
	process.exit(0);
}
if (!lstatSync(settingsPath).isFile()) throw new Error("Claude settings is not a regular file; no configuration changed");

const original = readFileSync(settingsPath);
const settings = JSON.parse(original.toString("utf8"));
if (!settings || typeof settings !== "object" || Array.isArray(settings)) {
	throw new Error("Invalid Claude settings; no configuration changed");
}

let removed = 0;
if (settings.hooks !== undefined && (!settings.hooks || typeof settings.hooks !== "object" || Array.isArray(settings.hooks))) {
	throw new Error("Invalid hook configuration; no configuration changed");
}
if (settings.hooks !== undefined) {
	for (const [event, entries] of Object.entries(settings.hooks)) {
		if (!Array.isArray(entries)) throw new Error(`Invalid ${event} hook configuration; no configuration changed`);
		if (entries.some((entry) => !entry || typeof entry !== "object" || Array.isArray(entry) ||
			!Array.isArray(entry.hooks) || entry.hooks.some((hook) => !hook || typeof hook !== "object" || Array.isArray(hook)))) {
			throw new Error(`Invalid ${event} hook configuration; no configuration changed`);
		}
		const kept = entries.flatMap((entry) => {
			if (!Array.isArray(entry?.hooks)) return [entry];
			const remaining = entry.hooks.filter((hook) => {
				if (hook?.statusMessage !== marker) return true;
				removed += 1;
				return false;
			});
			if (remaining.length === entry.hooks.length) return [entry];
			return remaining.length > 0 ? [{ ...entry, hooks: remaining }] : [];
		});
		if (kept.length) settings.hooks[event] = kept;
		else delete settings.hooks[event];
	}
	if (!Object.keys(settings.hooks).length) delete settings.hooks;
}

if (!removed) {
	console.log("No managed AIDR hook entries found; settings preserved.");
	process.exit(0);
}

mkdirSync(dirname(settingsPath), { recursive: true, mode: 0o700 });
writeFileSync(`${settingsPath}.aidr-backup-${process.pid}-${Date.now()}`, original, { flag: "wx", mode: 0o600 });
const temporary = `${settingsPath}.aidr-${process.pid}.tmp`;
writeFileSync(temporary, `${JSON.stringify(settings, null, 2)}\n`, { flag: "wx", mode: 0o600 });
try {
	// ponytail: Claude exposes no atomic compare-and-swap; this catches ordinary edits before replacement.
	if (!lstatSync(settingsPath).isFile() || !readFileSync(settingsPath).equals(original)) throw new Error("Claude settings changed during uninstall; retry after closing other settings editors");
	renameSync(temporary, settingsPath);
} finally {
	rmSync(temporary, { force: true });
}
console.log(`Removed ${removed} managed AIDR hook registration(s). Policy, allowlists and agent configuration were preserved.`);
