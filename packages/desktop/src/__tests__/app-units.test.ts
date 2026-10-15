import { mkdirSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { CONTENT_SECURITY_POLICY, resolveAppAsset } from "../main/app-protocol.js";
import { findInProfile, manifestName } from "../main/browser-guard.js";
import { lineDiff } from "../main/diff.js";
import { loadPreferences, savePreferences, validatePreferencesPatch } from "../main/prefs.js";
import { auditLogPath, hookFactsFor } from "../main/status.js";
import { DEFAULT_PREFERENCES } from "../shared/contract.js";
import { allKeys, resolveLanguage, translate } from "../shared/i18n.js";
import { tempDir } from "./fixtures.js";

const cleanup: string[] = [];
afterEach(() => {
	for (const path of cleanup.splice(0)) rmSync(path, { recursive: true, force: true });
});
const dir = (prefix: string) => {
	const path = tempDir(prefix);
	cleanup.push(path);
	return path;
};

describe("i18n", () => {
	it("has every English key in Turkish", () => {
		expect(allKeys("tr").sort()).toEqual(allKeys("en").sort());
	});

	it("defaults to Turkish on a Turkish system, English otherwise", () => {
		expect(resolveLanguage("auto", ["tr-TR", "en-US"])).toBe("tr");
		expect(resolveLanguage("auto", ["tr"])).toBe("tr");
		expect(resolveLanguage("auto", ["de-DE", "tr-TR"])).toBe("en");
		expect(resolveLanguage("auto", [])).toBe("en");
		expect(resolveLanguage("en", ["tr-TR"])).toBe("en");
		expect(resolveLanguage("tr", ["en-US"])).toBe("tr");
	});

	it("fills placeholders", () => {
		expect(translate("en", "status.fact.rules")).toBe("Rules loaded by the engine");
		expect(translate("tr", "time.minutesAgo", { n: 3 })).toBe("3 dk önce");
	});
});

describe("preferences", () => {
	it("defaults: start at login off, notifications on, language follows the system", () => {
		expect(DEFAULT_PREFERENCES).toEqual({ language: "auto", theme: "system", notifyOnDeny: true, startAtLogin: false });
		expect(loadPreferences(join(dir("prefs"), "absent.json"))).toEqual(DEFAULT_PREFERENCES);
	});

	it("round-trips and ignores damaged values", () => {
		const path = join(dir("prefs"), "preferences.json");
		savePreferences(path, { ...DEFAULT_PREFERENCES, language: "tr", startAtLogin: true });
		expect(loadPreferences(path)).toMatchObject({ language: "tr", startAtLogin: true });
		writeFileSync(path, JSON.stringify({ language: "xx", theme: "dark", extra: 1 }));
		expect(loadPreferences(path)).toEqual({ ...DEFAULT_PREFERENCES, theme: "dark" });
		writeFileSync(path, "not json");
		expect(loadPreferences(path)).toEqual(DEFAULT_PREFERENCES);
	});

	it("rejects unknown keys and wrong types", () => {
		expect(() => validatePreferencesPatch({ shell: "cmd" })).toThrow(/unknown preference/);
		expect(() => validatePreferencesPatch(["language"])).toThrow();
		expect(() => validatePreferencesPatch(null)).toThrow();
		expect(validatePreferencesPatch({ notifyOnDeny: false })).toEqual({ notifyOnDeny: false });
	});
});

describe("app:// protocol", () => {
	const root = "C:\\app\\dist\\renderer";
	it("serves only files under the renderer root", () => {
		expect(resolveAppAsset(root, "app://aidr/index.html")?.type).toMatch(/text\/html/);
		expect(resolveAppAsset(root, "app://aidr/")?.file).toMatch(/index\.html$/);
		expect(resolveAppAsset(root, "app://aidr/icons/mark.svg")?.type).toBe("image/svg+xml");
	});

	it.each([
		"app://aidr/../main/main.cjs",
		"app://aidr/%2e%2e/%2e%2e/secret.txt",
		"app://aidr/..%5Cmain%5Cmain.cjs",
		"app://other/index.html",
		"https://aidr/index.html",
		"app://aidr/payload.exe",
		"not a url",
	])("refuses %s", (url) => {
		expect(resolveAppAsset(root, url)).toBeNull();
	});

	it("allows no remote origin in the CSP", () => {
		expect(CONTENT_SECURITY_POLICY).toContain("default-src 'none'");
		expect(CONTENT_SECURITY_POLICY).toContain("script-src 'self'");
		expect(CONTENT_SECURITY_POLICY).toContain("connect-src 'none'");
		expect(CONTENT_SECURITY_POLICY).not.toMatch(/https?:|unsafe-inline|unsafe-eval|\*/);
	});
});

describe("lineDiff", () => {
	it("marks additions and removals and keeps common lines", () => {
		expect(lineDiff("a\nb\nc\n", "a\nx\nc\n")).toEqual([
			{ kind: "same", text: "a" },
			{ kind: "remove", text: "b" },
			{ kind: "add", text: "x" },
			{ kind: "same", text: "c" },
		]);
		expect(lineDiff("", "a\n")).toEqual([{ kind: "add", text: "a" }]);
		expect(lineDiff("a\r\nb\r\n", "a\nb\n").every((line) => line.kind === "same")).toBe(true);
	});
});

describe("Browser Guard detection", () => {
	function extension(root: string, name: string, version: string) {
		mkdirSync(join(root, "_locales", "en"), { recursive: true });
		writeFileSync(join(root, "manifest.json"), JSON.stringify({ name: "__MSG_extName__", default_locale: "en", version }));
		writeFileSync(join(root, "_locales", "en", "messages.json"), JSON.stringify({ extName: { message: name } }));
	}

	it("resolves localized manifest names", () => {
		const root = dir("ext");
		extension(root, "Singularity AIDR Browser Guard", "1.0.0");
		expect(manifestName(root)).toEqual({ name: "Singularity AIDR Browser Guard", version: "1.0.0" });
	});

	it("finds Browser Guard among a profile's extensions (store and unpacked), and its state", () => {
		const userData = dir("chrome");
		const profile = join(userData, "Default");
		const unpacked = dir("unpacked");
		extension(unpacked, "Singularity AIDR Browser Guard", "1.0.0");
		extension(join(profile, "Extensions", "storeid", "1.1.0_0"), "Singularity AIDR Browser Guard", "1.1.0");
		extension(join(profile, "Extensions", "otherid", "2.0_0"), "Some Other Extension", "2.0");
		writeFileSync(
			join(profile, "Secure Preferences"),
			JSON.stringify({
				extensions: {
					settings: {
						unpackedid: { path: unpacked, location: 4, disable_reasons: [1] },
						storeid: { path: "storeid\\1.1.0_0", location: 1 },
						otherid: { path: "otherid\\2.0_0", location: 1 },
					},
				},
			}),
		);
		const hits = findInProfile("chrome", userData, "Default");
		expect(hits.map((hit) => [hit.extensionId, hit.version, hit.enabled, hit.unpacked]).sort()).toEqual([
			["storeid", "1.1.0", true, false],
			["unpackedid", "1.0.0", false, true],
		]);
	});
});

describe("status helpers", () => {
	it("follows logging.path from the AIDR config", () => {
		const home = dir("home");
		expect(auditLogPath(home)).toBe(join(home, ".singularity-aidr", "audit.jsonl"));
		mkdirSync(join(home, ".singularity-aidr"), { recursive: true });
		writeFileSync(join(home, ".singularity-aidr", "config.json"), JSON.stringify({ logging: { path: "~/logs/aidr.jsonl" } }));
		expect(auditLogPath(home)).toBe(join(home, "logs", "aidr.jsonl"));
	});

	it("reports a registered hook whose program is gone", () => {
		const home = dir("home");
		mkdirSync(join(home, ".claude"), { recursive: true });
		writeFileSync(
			join(home, ".claude", "settings.json"),
			JSON.stringify({
				hooks: { PreToolUse: [{ hooks: [{ type: "command", command: '"C:/gone/bin/aidr.exe" hook pre-tool-use', statusMessage: "Singularity AIDR managed installation" }] }] },
			}),
		);
		expect(hookFactsFor("claude-code", home)).toMatchObject({ kind: "command", registered: true, binaryPresent: false });
		expect(hookFactsFor("opencode", home)).toMatchObject({ kind: "in_process", registered: null });
	});
});
