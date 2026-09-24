import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { ENTITY_TYPES } from "../types";

const PACKAGE_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "..");
const UI_DIR = join(PACKAGE_ROOT, "src", "ui");
const STATIC_DIR = join(PACKAGE_ROOT, "static");
const UI_PAGES = ["popup.html", "options.html", "blocked.html"];

type Messages = Record<
	string,
	{ message: string; description?: string; placeholders?: Record<string, { content: string }> }
>;

function readLocale(lang: string): Messages {
	return JSON.parse(readFileSync(join(PACKAGE_ROOT, "_locales", lang, "messages.json"), "utf8"));
}

const en = readLocale("en");
const tr = readLocale("tr");

/** Keys the manifest references (__MSG_*__); the UI code does not use them all. */
const MANIFEST_KEYS = ["extName", "extDescription", "actionTitle"];

function uiSources(): string {
	return readdirSync(UI_DIR)
		.filter((name) => name.endsWith(".ts"))
		.map((name) => readFileSync(join(UI_DIR, name), "utf8"))
		.join("\n");
}

function htmlKeys(): string[] {
	const keys: string[] = [];
	for (const page of UI_PAGES) {
		const html = readFileSync(join(STATIC_DIR, page), "utf8");
		for (const match of html.matchAll(/data-i18n(?:-[a-z-]+)?="([^"]+)"/g)) keys.push(match[1]);
	}
	return keys;
}

/** Every message key the UI can request: literal t()/msg() calls, markup and entity labels. */
function usedKeys(): Set<string> {
	const keys = new Set<string>(MANIFEST_KEYS);
	for (const match of uiSources().matchAll(/\b(?:t|msg)\(\s*"([A-Za-z0-9_]+)"/g))
		keys.add(match[1]);
	for (const key of htmlKeys()) keys.add(key);
	for (const type of ENTITY_TYPES) keys.add(`entity_${type}`);
	return keys;
}

describe("locale files", () => {
	it("en and tr define the same keys", () => {
		expect(Object.keys(tr).sort()).toEqual(Object.keys(en).sort());
	});

	it("no message is empty and every entry has a description", () => {
		for (const [lang, messages] of [
			["en", en],
			["tr", tr],
		] as const) {
			for (const [key, entry] of Object.entries(messages)) {
				expect(entry.message.trim(), `${lang}:${key}`).not.toBe("");
				expect(entry.description?.trim(), `${lang}:${key} description`).toBeTruthy();
			}
		}
	});

	it("keys use Chrome's allowed characters", () => {
		for (const key of Object.keys(en)) expect(key).toMatch(/^[A-Za-z0-9_@]+$/);
	});

	it("placeholders match between languages and are all defined", () => {
		for (const key of Object.keys(en)) {
			const names = (lang: Messages) =>
				[...lang[key].message.matchAll(/\$([A-Za-z0-9_]+)\$/g)]
					.map((m) => m[1].toLowerCase())
					.sort();
			expect(names(tr), key).toEqual(names(en));
			for (const lang of [en, tr]) {
				const defined = Object.keys(lang[key].placeholders ?? {}).sort();
				expect([...new Set(names(lang))], key).toEqual(defined);
			}
			const contents = (lang: Messages) =>
				Object.fromEntries(
					Object.entries(lang[key].placeholders ?? {}).map(([name, value]) => [
						name,
						value.content,
					]),
				);
			expect(contents(tr), key).toEqual(contents(en));
		}
	});

	it("carries the manifest strings within browser limits", () => {
		expect(en.extName.message).toBe("Singularity AIDR Browser Guard");
		for (const lang of [en, tr]) {
			expect(lang.extName.message.length).toBeLessThanOrEqual(75);
			expect(lang.extDescription.message.length).toBeLessThanOrEqual(132);
			expect(lang.actionTitle.message.length).toBeGreaterThan(0);
		}
	});

	it("Turkish is actually translated", () => {
		const identical = Object.keys(en).filter((key) => en[key].message === tr[key].message);
		// Product names, endonyms and acronyms legitimately stay the same.
		expect(identical.sort()).toEqual(
			[
				"actionTitle",
				"entity_IBAN",
				"extName",
				"language_en",
				"language_tr",
				"product_short",
			].sort(),
		);
		expect(tr.status_protected.message).toBe("Korunuyor");
	});
});

describe("message usage", () => {
	it("every key used in src/ui and the pages exists in both locales", () => {
		const missing = [...usedKeys()].filter((key) => !(key in en) || !(key in tr));
		expect(missing).toEqual([]);
	});

	it("every locale key is used somewhere", () => {
		const used = usedKeys();
		expect(Object.keys(en).filter((key) => !used.has(key))).toEqual([]);
	});
});

describe("extension pages", () => {
	it("contain no inline script, style or handler (CSP 'self')", () => {
		for (const page of UI_PAGES) {
			const html = readFileSync(join(STATIC_DIR, page), "utf8");
			for (const match of html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script>/gi)) {
				expect(match[1], page).toMatch(/\bsrc="(popup|options)\.js"/);
				expect(match[2].trim(), page).toBe("");
			}
			expect(html, page).not.toMatch(/<style\b|\sstyle\s*=|\son[a-z]+\s*=|javascript:|\{\{/i);
			expect(html, page).not.toMatch(/(?:src|href)="(?:https?:)?\/\//i);
			expect(html, page).toContain('<link rel="stylesheet" href="ui.css" />');
		}
	});

	it("ui.css embeds the current brand logo and loads nothing remote", () => {
		const css = readFileSync(join(STATIC_DIR, "ui.css"), "utf8");
		const match = /--logo: url\("data:image\/svg\+xml,([^"]+)"\)/.exec(css);
		expect(match).not.toBeNull();
		const embedded = decodeURIComponent(match?.[1] ?? "").replace(/'/g, '"');
		const source = readFileSync(
			join(PACKAGE_ROOT, "..", "..", "images", "aidr-logo-shaded.svg"),
			"utf8",
		);
		expect(embedded).toBe(source.trim().split(/\s+/).join(" "));
		expect(css.replace(/url\("data:[^"]+"\)/g, "")).not.toMatch(/url\(|@import|https?:\/\//);
		for (const color of ["#3862e8", "#2448bb", "#0a0a0a", "#f8fafc", "#0f172a"]) {
			expect(css.toLowerCase()).toContain(color);
		}
	});
});
