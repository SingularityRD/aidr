import { readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
	expectedPrivacyRuleFiles,
	PRIVACY_RULE_FILES,
	PRIVACY_RULES_TARGET_DIR,
	privacyRulesDrift,
	transformPrivacyRuleSource,
} from "../../../../scripts/sync-privacy-rules.mjs";

describe("vendored AIDR Privacy rules", () => {
	it("match packages/privacy/src exactly (run pnpm sync:privacy-rules on drift)", () => {
		expect(privacyRulesDrift()).toEqual([]);
	});

	it("carry the generated-file header on every vendored file", () => {
		for (const file of PRIVACY_RULE_FILES) {
			const content = readFileSync(join(PRIVACY_RULES_TARGET_DIR, file), "utf8");
			expect(
				content.startsWith(
					`// GENERATED from packages/privacy/src/${file} by scripts/sync-privacy-rules.mjs — do not edit\n`,
				),
			).toBe(true);
		}
		expect([...expectedPrivacyRuleFiles().keys()]).toEqual([...PRIVACY_RULE_FILES]);
	});

	it("refuses sources that would pull in anything outside the pure rule set", () => {
		expect(() => transformPrivacyRuleSource("x.ts", 'import { a } from "./engine.js";\n')).toThrow(
			/escapes the vendored privacy rule set/,
		);
		expect(() => transformPrivacyRuleSource("x.ts", 'import { a } from "zod";\n')).toThrow(
			/non-local import/,
		);
		expect(() =>
			transformPrivacyRuleSource("x.ts", 'const c = await import("./types.js");\n'),
		).toThrow(/dynamic imports/);
		expect(() => transformPrivacyRuleSource("x.ts", 'export const h = "node:crypto";\n')).toThrow(
			/node: modules/,
		);
	});
});
