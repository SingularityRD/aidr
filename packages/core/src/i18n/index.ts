/**
 * User-facing message catalog shared by the connectors, the CLI and the hook
 * banners.
 *
 * Only human-readable text goes through here. Hook JSON field names, decision
 * values, rule ids and anything a host or script parses stay fixed, so a
 * Turkish locale changes what a person reads and nothing a program reads.
 *
 * Locale resolution, first match wins:
 *   1. `AIDR_LOCALE` (explicit override, e.g. `tr` or `en`)
 *   2. the `locale` key of ~/.singularity-aidr/config.json (set by loadConfig)
 *   3. the POSIX locale: `LC_ALL`, then `LC_MESSAGES`, then `LANG`
 *   4. English
 * An unsupported value at any step is skipped, never an error.
 */
import { en, type MessageKey } from "./en.js";
import { tr } from "./tr.js";

export type { MessageKey } from "./en.js";

export const SUPPORTED_LOCALES = ["en", "tr"] as const;
export type Locale = (typeof SUPPORTED_LOCALES)[number];
export const DEFAULT_LOCALE: Locale = "en";

export type MessageParams = Record<string, string | number | null | undefined>;

const CATALOGS: Record<Locale, Record<MessageKey, string>> = { en, tr };

/** Both catalogs, for the key-parity test and tools that list translations. */
export const MESSAGE_CATALOGS: Readonly<Record<Locale, Readonly<Record<MessageKey, string>>>> =
	CATALOGS;

/**
 * Map a locale-ish string (`tr`, `tr-TR`, `tr_TR.UTF-8`, `en_US`) to a
 * supported locale, or undefined when it names none (`C`, `POSIX`, `de_DE`).
 */
export function normalizeLocale(value: unknown): Locale | undefined {
	if (typeof value !== "string") return undefined;
	const language = value
		.trim()
		.toLowerCase()
		.split(/[-_.@]/, 1)[0];
	return (SUPPORTED_LOCALES as readonly string[]).includes(language ?? "")
		? (language as Locale)
		: undefined;
}

type LocaleEnv = Record<string, string | undefined>;

/** Resolve the display locale from the environment and an optional configured value. */
export function resolveLocale(env: LocaleEnv = processEnv(), configLocale?: unknown): Locale {
	const explicit = normalizeLocale(env.AIDR_LOCALE);
	if (explicit) return explicit;
	const configured = normalizeLocale(configLocale);
	if (configured) return configured;
	// POSIX precedence: the first variable that is set decides, even when it
	// names a locale we do not ship (then English).
	for (const name of ["LC_ALL", "LC_MESSAGES", "LANG"]) {
		const value = env[name];
		if (value && value.trim() !== "") return normalizeLocale(value) ?? DEFAULT_LOCALE;
	}
	return DEFAULT_LOCALE;
}

function processEnv(): LocaleEnv {
	return typeof process !== "undefined" && process.env ? process.env : {};
}

let configuredLocale: Locale | undefined;

/**
 * Record the `locale` from the loaded configuration. loadConfig calls this, so
 * every message built after the configuration was read honours it.
 */
export function setConfiguredLocale(value: unknown): void {
	configuredLocale = normalizeLocale(value);
}

/** The locale messages are rendered in right now. */
export function currentLocale(): Locale {
	return resolveLocale(processEnv(), configuredLocale);
}

/**
 * Render a catalog message. Never throws: it is called on fail-closed paths
 * (hook deadlines, inspection failures) that must always produce a deny, so
 * a missing translation falls back to English and then to the key itself.
 */
export const t = createTranslator<MessageKey>(CATALOGS);

/** Replace `{name}` parameters; a parameter that was not passed stays visible. */
export function formatMessage(template: string, params?: MessageParams): string {
	if (!params) return template;
	return template.replace(/\{(\w+)\}/g, (match, name: string) => {
		const value = params[name];
		return value === undefined || value === null ? match : String(value);
	});
}

/**
 * A `t` function over another package's own en/tr catalogs (the CLI's), using
 * the same locale resolution as the shared catalog.
 */
export function createTranslator<K extends string>(
	catalogs: Record<Locale, Record<K, string>>,
): (key: K, params?: MessageParams, locale?: Locale) => string {
	return (key, params, locale) => {
		const resolved = locale ?? currentLocale();
		const template = catalogs[resolved]?.[key] ?? catalogs[DEFAULT_LOCALE]?.[key] ?? key;
		return formatMessage(template, params);
	};
}

const SEVERITY_KEYS: Record<string, MessageKey> = {
	critical: "severity.critical",
	high: "severity.high",
	medium: "severity.medium",
	low: "severity.low",
	info: "severity.info",
	warning: "severity.warning",
};

/**
 * Localized severity word. English, and any severity the catalog does not
 * know, is shown exactly as given so existing output does not change.
 */
export function severityLabel(severity: string, locale?: Locale): string {
	const resolved = locale ?? currentLocale();
	if (resolved === DEFAULT_LOCALE) return severity;
	const key = SEVERITY_KEYS[severity.toLowerCase()];
	return key ? t(key, undefined, resolved) : severity;
}

/** Upper-case with the locale's rules (Turkish dotted/dotless i). */
export function upperCaseFor(text: string, locale?: Locale): string {
	return text.toLocaleUpperCase(locale ?? currentLocale());
}
