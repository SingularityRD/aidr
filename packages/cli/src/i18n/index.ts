/**
 * CLI localization: the `aidr --help` tree and the output of the incident
 * commands. Locale resolution is the shared one from aidr-core (AIDR_LOCALE,
 * the config `locale` key, LC_ALL / LC_MESSAGES / LANG, then English).
 */
import { readFileSync } from "node:fs";
import {
	createTranslator,
	currentLocale,
	DEFAULT_LOCALE,
	type Locale,
	resolvePath,
	setConfiguredLocale,
} from "@singularityrd/aidr-core";
import { type Command, Help, type Option } from "commander";
import { HELP_TR } from "./help-tr.js";
import { CLI_EN, CLI_TR, type CliMessageKey } from "./messages.js";
import { UPDATE_EN, UPDATE_TR, type UpdateMessageKey } from "./update-messages.js";

export { HELP_TR } from "./help-tr.js";
export { CLI_EN, CLI_TR, type CliMessageKey } from "./messages.js";
export { UPDATE_EN, UPDATE_TR, type UpdateMessageKey } from "./update-messages.js";

/** CLI output message in the current locale. */
export const ct = createTranslator<CliMessageKey>({ en: CLI_EN, tr: CLI_TR });

/** `aidr update` output in the current locale. */
export const ut = createTranslator<UpdateMessageKey>({ en: UPDATE_EN, tr: UPDATE_TR });

/** Commander's own help texts, which are not part of the command tree. */
export const BUILTIN_HELP_TEXTS = [
	"output the version number",
	"display help for command",
	"Usage:",
	"Options:",
	"Commands:",
	"Arguments:",
	"Global Options:",
] as const;

/**
 * Pick up `locale` from ~/.singularity-aidr/config.json before any output is
 * written. Commands that run loadConfig set it again; this read only covers
 * help and the commands that never load the configuration. Never throws.
 */
export function initCliLocale(): void {
	try {
		const raw = readFileSync(resolvePath("~/.singularity-aidr/config.json"), "utf8");
		const parsed = JSON.parse(raw) as { locale?: unknown } | null;
		if (parsed && typeof parsed === "object") setConfiguredLocale(parsed.locale);
	} catch {
		// No or unreadable configuration: the environment decides.
	}
}

/**
 * `aidr --help` lists two dozen commands; grouped, a new administrator finds the
 * few they need first. Headings are Commander help-group titles, so the help
 * localizer translates them like every other title.
 */
export const HELP_GROUPS = [
	{ heading: "Setup:", commands: ["setup", "config", "uninstall"] },
	{ heading: "Daily use:", commands: ["status", "verify", "audit", "privacy", "scan"] },
	{ heading: "Approvals:", commands: ["pending", "approve", "allowlist", "exception"] },
	{ heading: "Diagnostics:", commands: ["doctor", "support-bundle", "simulate", "coverage"] },
	{
		heading: "Advanced:",
		commands: [
			"collect",
			"discover",
			"aibom",
			"learning",
			"compliance",
			"quarantine",
			"restore",
			"profile",
			"canary",
		],
	},
] as const;

/**
 * Put every top-level command under its heading, in the order above. A command
 * missing from the table stays under "Advanced:" so it is never hidden; the
 * built-in `help` command joins "Diagnostics:".
 */
export function groupCommands(program: Command): void {
	// Position within the table: group first, then the order listed there.
	const order = new Map<string, { group: number; position: number }>();
	HELP_GROUPS.forEach((group, index) => {
		group.commands.forEach((name, position) => {
			order.set(name, { group: index, position });
		});
	});
	const fallback = { group: HELP_GROUPS.length - 1, position: Number.MAX_SAFE_INTEGER };
	const place = (command: Command) => order.get(command.name()) ?? fallback;
	for (const command of program.commands) {
		command.helpGroup(HELP_GROUPS[place(command).group]?.heading ?? "Advanced:");
	}
	// Commander lists groups, and commands within a group, in this array's order.
	const sorted = [...program.commands].sort(
		(a, b) => place(a).group - place(b).group || place(a).position - place(b).position,
	);
	(program.commands as Command[]).splice(0, sorted.length, ...sorted);
	program.commandsGroup("Diagnostics:");
	program.helpCommand(true);
}

/** Every description in the command tree (commands, options, arguments, group headings). */
export function collectHelpTexts(program: Command): Set<string> {
	const texts = new Set<string>();
	// Only top-level commands carry a help group (see groupCommands).
	for (const command of program.commands) if (command.helpGroup()) texts.add(command.helpGroup());
	const walk = (command: Command): void => {
		if (command.description()) texts.add(command.description());
		for (const option of command.options) if (option.description) texts.add(option.description);
		for (const argument of command.registeredArguments)
			if (argument.description) texts.add(argument.description);
		for (const sub of command.commands) walk(sub);
	};
	walk(program);
	return texts;
}

function translateHelp(text: string, table: Readonly<Record<string, string>>): string {
	return table[text] ?? text;
}

/** Commander appends "(default: …)" / "(choices: …)" after the description. */
function translateSuffixes(text: string): string {
	return text
		.replace(/\(default: /g, "(varsayılan: ")
		.replace(/\(choices: /g, "(seçenekler: ")
		.replace(/\(preset: /g, "(ön ayar: ");
}

/**
 * Show the help of every command in the given locale. English needs nothing:
 * the definitions are English, so the tree is left untouched and the output
 * stays byte-for-byte what it was. Translation happens at display time, so
 * descriptions keep their English source for tests and tooling.
 */
export function localizeHelp(program: Command, locale: Locale = currentLocale()): void {
	if (locale === DEFAULT_LOCALE) return;
	const table = HELP_TR;
	const base = Help.prototype;
	const configuration: Partial<Help> = {
		styleTitle: (title: string) => translateHelp(title, table),
		commandDescription: (command: Command) => translateHelp(command.description(), table),
		subcommandDescription: (command: Command) =>
			translateHelp(command.summary() || command.description(), table),
		optionDescription(this: Help, option: Option) {
			const translated = Object.create(option) as Option;
			translated.description = translateHelp(option.description ?? "", table);
			return translateSuffixes(base.optionDescription.call(this, translated));
		},
		argumentDescription(this: Help, argument) {
			const translated = Object.create(argument);
			translated.description = translateHelp(argument.description ?? "", table);
			return translateSuffixes(base.argumentDescription.call(this, translated));
		},
	};
	const walk = (command: Command): void => {
		command.configureHelp(configuration);
		for (const sub of command.commands) walk(sub);
	};
	walk(program);
}
