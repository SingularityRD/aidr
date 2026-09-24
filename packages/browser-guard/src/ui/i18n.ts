/**
 * UI localisation.
 *
 * With language "auto" the pages use `chrome.i18n.getMessage`, i.e. the browser
 * UI language. An explicit "en"/"tr" choice in settings loads the bundled
 * `_locales/<lang>/messages.json` and resolves messages from it with the same
 * placeholder semantics Chrome uses, so the pages follow the user's choice.
 */
import type { EntityType, GuardMode } from "../types.js";
import type { LocaleMessages, UiEnv } from "./env.js";

export type Translate = (key: string, substitutions?: string | readonly string[]) => string;

export interface Localizer {
	readonly t: Translate;
	/** BCP 47 tag used for number/time formatting and `<html lang>`. */
	readonly locale: string;
}

function toList(substitutions?: string | readonly string[]): readonly string[] {
	if (substitutions === undefined) return [];
	return typeof substitutions === "string" ? [substitutions] : substitutions;
}

/** Resolves a message from a messages.json object using Chrome's placeholder rules. */
export function formatMessage(
	messages: LocaleMessages,
	key: string,
	substitutions?: string | readonly string[],
): string {
	const entry = messages[key];
	if (!entry) return "";
	const subs = toList(substitutions);
	const positional = (text: string) =>
		text.replace(/\$(\d)/g, (_match, index: string) => subs[Number(index) - 1] ?? "");
	const placeholders = entry.placeholders ?? {};
	const named = entry.message.replace(/\$([A-Za-z0-9_@]+)\$/g, (match, name: string) => {
		const placeholder = placeholders[name.toLowerCase()];
		return placeholder ? positional(placeholder.content) : match;
	});
	return named.replace(/\$\$/g, "$");
}

/** Translator backed by chrome.i18n (browser UI language). */
export function browserLocalizer(env: UiEnv): Localizer {
	return {
		locale: env.uiLanguage() || "en",
		t: (key, subs) => env.getMessage(key, toList(subs)) || key,
	};
}

/** Builds a translator for the requested language setting. */
export async function createLocalizer(
	env: UiEnv,
	language: "auto" | "en" | "tr",
): Promise<Localizer> {
	if (language !== "auto") {
		const messages = await env.loadLocaleMessages(language);
		if (messages) {
			return {
				locale: language,
				t: (key, subs) =>
					formatMessage(messages, key, subs) || env.getMessage(key, toList(subs)) || key,
			};
		}
	}
	return browserLocalizer(env);
}

/**
 * Localises static markup. Supported attributes:
 * data-i18n (textContent), data-i18n-title, data-i18n-aria-label, data-i18n-placeholder.
 * The English text already present in the markup stays when a key is missing.
 */
export function applyI18n(root: ParentNode, t: Translate): void {
	const apply = (attribute: string, set: (element: HTMLElement, text: string) => void) => {
		for (const element of root.querySelectorAll<HTMLElement>(`[${attribute}]`)) {
			const key = element.getAttribute(attribute);
			if (!key) continue;
			const text = t(key);
			if (text && text !== key) set(element, text);
		}
	};
	apply("data-i18n", (element, text) => {
		element.textContent = text;
	});
	apply("data-i18n-title", (element, text) => element.setAttribute("title", text));
	apply("data-i18n-aria-label", (element, text) => element.setAttribute("aria-label", text));
	apply("data-i18n-placeholder", (element, text) => element.setAttribute("placeholder", text));
}

export function entityLabel(t: Translate, type: EntityType): string {
	return t(`entity_${type}`);
}

/**
 * Marks a string literal as a message key used indirectly (through a table).
 * The i18n tests collect every `t("…")` and `msg("…")` literal in src/ui.
 */
export function msg<K extends string>(key: K): K {
	return key;
}

export const MODE_KEYS: Readonly<Record<GuardMode, { label: string; help: string }>> = {
	auto: { label: msg("mode_auto"), help: msg("mode_auto_help") },
	confirm: { label: msg("mode_confirm"), help: msg("mode_confirm_help") },
	block: { label: msg("mode_block"), help: msg("mode_block_help") },
	monitor: { label: msg("mode_monitor"), help: msg("mode_monitor_help") },
};

export function formatNumber(locale: string, value: number): string {
	try {
		return new Intl.NumberFormat(locale).format(value);
	} catch {
		return String(value);
	}
}

export function formatClock(locale: string, timestamp: number): string {
	try {
		return new Intl.DateTimeFormat(locale, { hour: "2-digit", minute: "2-digit" }).format(
			new Date(timestamp),
		);
	} catch {
		const date = new Date(timestamp);
		return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
	}
}
