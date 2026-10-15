import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { translate } from "../i18n/I18nProvider";
import { describeRule } from "../lib/rule-titles";

const DASHBOARD = resolve(__dirname, "..", "..");
const en = (key: Parameters<typeof translate>[1]) => translate("en", key);
const tr = (key: Parameters<typeof translate>[1]) => translate("tr", key);

describe("bundled rule titles", () => {
	it("match threats/*.yaml (regenerate with scripts/rule-titles.mjs --write)", () => {
		// Exits non-zero, naming the stale file, when the rules changed.
		expect(() =>
			execFileSync(process.execPath, [resolve(DASHBOARD, "scripts", "rule-titles.mjs")], {
				stdio: "pipe",
			}),
		).not.toThrow();
	});

	it("carry titles, categories and severities but never patterns", () => {
		const text = readFileSync(resolve(DASHBOARD, "src", "generated", "rule-titles.json"), "utf8");
		expect(text).not.toContain('"pattern"');
		expect(text).toContain(
			'"CLT-CMD-001": {"title":"Remote code execution via curl pipe to shell"',
		);
	});
});

describe("describeRule", () => {
	it("returns the rule title, a plain-language category and the severity", () => {
		expect(describeRule("CLT-CMD-001", "en", en)).toEqual({
			id: "CLT-CMD-001",
			title: "Remote code execution via curl pipe to shell",
			category: "Dangerous command",
			severity: "critical",
		});
	});

	it("uses the Turkish category label and the rule's title_tr", () => {
		const rule = describeRule("CLT-CRED-004", "tr", tr);
		expect(rule.category).toBe("Gizli bilgiler ve kimlik bilgileri");
		expect(rule.title).toBe("Kimlik bilgisi ya da gizli bilgi içeren dosyayı okuma");
	});

	it("keeps the English title until the rule has title_tr", () => {
		const rule = describeRule("CLT-MAC-CRED-001", "tr", tr);
		expect(rule.category).toBe("Gizli bilgiler ve kimlik bilgileri");
		expect(rule.title).toBe("Keychain password extraction via security find-generic-password");
	});

	it("knows nothing about an unknown id instead of guessing", () => {
		expect(describeRule("T-EXFIL-001", "en", en)).toEqual({
			id: "T-EXFIL-001",
			title: null,
			category: null,
			severity: null,
		});
		expect(describeRule("__proto__", "en", en).title).toBeNull();
	});
});
