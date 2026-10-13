/**
 * Customer-facing claims that must match the code (GA audit BG-12, BG-14, BG-15). Each
 * assertion pins a corrected statement next to the code fact it describes, so a later edit
 * cannot quietly bring back the overstated wording.
 */
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const PACKAGE_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..");
const REPO_ROOT = resolve(PACKAGE_ROOT, "..", "..");
const read = (path: string) => readFileSync(join(REPO_ROOT, path), "utf8");
const EN = read("docs/product/features/en/02-browser-guard-and-privacy.md");
const TR = read("docs/product/features/tr/02-browser-guard-and-privacy.md");
const README = read("packages/browser-guard/README.md");
const CUSTOM_SITES = read("packages/browser-guard/src/background/custom-sites.ts");
const HOOK = read("packages/browser-guard/src/content/file-input-hook.ts");

describe("documentation claims (BG-12, BG-14, BG-15)", () => {
	it("does not promise that only monitor mode and disabledSites let text through unmasked", () => {
		expect(EN).not.toContain("The only ways to let text through unmasked");
		expect(TR).not.toContain("maskelenmeden geçtiği tek durumlar");
		// Every pass-through path is listed with the setting that closes it.
		for (const doc of [EN, TR]) {
			for (const fact of [
				"`allowSendAnyway`",
				"`allowUserPause`",
				"deploy/browser-guard/README.md",
			])
				expect(doc).toContain(fact);
		}
		expect(EN).toContain("voice input, dictation and voice mode");
		expect(EN).not.toMatch(/voice input\) is\s+checked at send time/);
	});

	it("says the optional https://*/* permission is used for customSites and Shadow AI", () => {
		expect(EN).not.toContain("no code path that uses it");
		expect(TR).not.toContain("kullanan bir kod yolu yoktur");
		expect(CUSTOM_SITES).toContain("permissions");
	});

	it("documents that custom sites run in the top frame only", () => {
		expect(CUSTOM_SITES).toMatch(/allFrames: false/);
		expect(EN).toContain("chat widget\n  embedded in an iframe");
		expect(TR).toContain("iframe");
		expect(README).toMatch(/top\s+frame only: a portal whose chat editor lives in an iframe/);
	});

	it("does not claim a page cannot fingerprint the extension", () => {
		expect(README).not.toContain("a page cannot fingerprint the extension");
		expect(HOOK).not.toContain("__aidrFileInputHook");
		expect(README).toContain("observable to a page that looks for it");
	});
});
