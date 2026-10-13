/**
 * PRD-15: the Cursor / VS Code extension ships English and Turkish manifest
 * strings (package.nls*.json) and a Turkish runtime bundle (l10n/). Every key
 * must exist in both languages, every key must be used, and the VSIX staging
 * must carry the files.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { describe, expect, it, vi } from "vitest";
import {
	VSIX_LOCALIZATION_FILES,
	VSIX_PACKAGE_FILES,
} from "../../../../scripts/lib/vsix-package-files.mjs";
import { buildCursorManifest, buildVsCodeManifest } from "../../scripts/package-vscode-vsix.mjs";

const l10nMock = vi.hoisted(() => ({
	t: undefined as undefined | ((...args: unknown[]) => string),
}));

vi.mock("vscode", () => ({
	get l10n() {
		return l10nMock.t ? { t: l10nMock.t } : undefined;
	},
}));

const EXTENSION_ROOT = resolve(__dirname, "..", "..");
const REPO_ROOT = resolve(EXTENSION_ROOT, "..", "..");

function readJson(path: string): Record<string, unknown> {
	return JSON.parse(readFileSync(path, "utf8")) as Record<string, unknown>;
}

function placeholders(text: string): string[] {
	return [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1] as string).sort();
}

/** Every `%key%` reference in a manifest-shaped value. */
function manifestKeys(value: unknown, out = new Set<string>()): Set<string> {
	if (typeof value === "string") {
		const match = /^%([^%]+)%$/.exec(value);
		if (match?.[1]) out.add(match[1]);
	} else if (Array.isArray(value)) {
		for (const item of value) manifestKeys(item, out);
	} else if (value && typeof value === "object") {
		for (const item of Object.values(value)) manifestKeys(item, out);
	}
	return out;
}

const nlsEn = readJson(join(EXTENSION_ROOT, "package.nls.json")) as Record<string, string>;
const nlsTr = readJson(join(EXTENSION_ROOT, "package.nls.tr.json")) as Record<string, string>;
const bundleTr = readJson(join(EXTENSION_ROOT, "l10n", "bundle.l10n.tr.json")) as Record<
	string,
	string
>;

/** The English messages passed to localize() in the extension sources. */
function localizedMessages(): Set<string> {
	const messages = new Set<string>();
	const dir = join(EXTENSION_ROOT, "src");
	for (const entry of readdirSync(dir)) {
		if (!entry.endsWith(".ts")) continue;
		const source = readFileSync(join(dir, entry), "utf8");
		for (const match of source.matchAll(/\blocalize\(\s*"((?:[^"\\]|\\.)*)"/g)) {
			messages.add(JSON.parse(`"${match[1]}"`) as string);
		}
	}
	return messages;
}

describe("manifest localization (package.nls)", () => {
	it("has the same keys in English and Turkish, all translated", () => {
		expect(Object.keys(nlsTr).sort()).toEqual(Object.keys(nlsEn).sort());
		for (const [key, english] of Object.entries(nlsEn)) {
			expect(nlsTr[key], key).toBeTruthy();
			expect(nlsTr[key], key).not.toBe(english);
			if (english.includes("Singularity AIDR"))
				expect(nlsTr[key], key).toContain("Singularity AIDR");
		}
	});

	it("defines every key the shipped manifests use and has no unused keys", async () => {
		const base = readJson(join(EXTENSION_ROOT, "package.json"));
		const used = new Set([
			...manifestKeys(base),
			...manifestKeys(buildCursorManifest(base)),
			...manifestKeys(buildVsCodeManifest(base)),
		]);
		expect([...used].filter((key) => !(key in nlsEn))).toEqual([]);
		expect(Object.keys(nlsEn).filter((key) => !used.has(key))).toEqual([]);
	});

	it("keeps no hard-coded English command title or setting description", () => {
		const base = readJson(join(EXTENSION_ROOT, "package.json")) as {
			description: string;
			l10n: string;
			contributes: {
				commands: { title: string }[];
				configuration: { properties: Record<string, { description: string }> };
			};
		};
		expect(base.description).toMatch(/^%.+%$/);
		expect(base.l10n).toBe("./l10n");
		for (const command of base.contributes.commands) expect(command.title).toMatch(/^%.+%$/);
		for (const property of Object.values(base.contributes.configuration.properties)) {
			expect(property.description).toMatch(/^%.+%$/);
		}
		const vscode = buildVsCodeManifest(base) as typeof base;
		expect(vscode.description).toMatch(/^%.+%$/);
		for (const property of Object.values(vscode.contributes.configuration.properties)) {
			expect(property.description).toMatch(/^%.+%$/);
		}
	});

	it("packs the localization files into every VSIX", () => {
		const base = readJson(join(EXTENSION_ROOT, "package.json")) as { files: string[] };
		for (const file of VSIX_LOCALIZATION_FILES) {
			expect(VSIX_PACKAGE_FILES).toContain(file);
			expect(base.files).toContain(file);
		}
	});
});

describe("runtime localization (l10n bundle)", () => {
	it("translates every localize() message and has no unused entries", () => {
		const messages = localizedMessages();
		expect(messages.size).toBeGreaterThan(20);
		expect([...messages].filter((message) => !(message in bundleTr))).toEqual([]);
		expect(Object.keys(bundleTr).filter((message) => !messages.has(message))).toEqual([]);
	});

	it("keeps every argument placeholder and the product name", () => {
		for (const [english, turkish] of Object.entries(bundleTr)) {
			expect(placeholders(turkish), english).toEqual(placeholders(english));
			if (english.includes("Singularity AIDR")) expect(turkish).toContain("Singularity AIDR");
			if (english.includes("chat.useClaudeHooks")) expect(turkish).toContain("chat.useClaudeHooks");
		}
	});

	it("formats English directly when the host has no l10n API", async () => {
		l10nMock.t = undefined;
		const { localize } = await import("../l10n.js");
		expect(localize("Singularity AIDR managed hooks removed from {0}.", "/tmp/hooks.json")).toBe(
			"Singularity AIDR managed hooks removed from /tmp/hooks.json.",
		);
	});

	it("uses the editor's l10n API (Turkish bundle) when present", async () => {
		l10nMock.t = (message: unknown, ...args: unknown[]) =>
			String(bundleTr[String(message)] ?? message).replace(/\{(\d+)\}/g, (_m, i: string) =>
				String(args[Number(i)]),
			);
		const { localize } = await import("../l10n.js");
		expect(localize("Singularity AIDR managed hooks removed from {0}.", "/tmp/hooks.json")).toBe(
			"Singularity AIDR yönetilen hook'ları şuradan kaldırıldı: /tmp/hooks.json.",
		);
		l10nMock.t = undefined;
	});

	it("is referenced from the repository root packaging script too", () => {
		const script = readFileSync(join(REPO_ROOT, ".github", "scripts", "package-vsix.mjs"), "utf8");
		expect(script).toContain("package.nls.tr.json");
		expect(script).toContain('"l10n"');
	});
});
