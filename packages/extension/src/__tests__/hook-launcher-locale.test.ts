/**
 * D10: Cursor / VS Code start the hook without the editor's environment, so the
 * editor's display language reaches the hook through the launcher pointer and
 * becomes `AIDR_LOCALE` (Turkish block messages in a Turkish editor).
 */

import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { applyDisplayLanguage } from "../hook-launcher.js";
import { installHookRuntime, readHostPointer } from "../hook-runtime.js";

describe("applyDisplayLanguage", () => {
	it("sets AIDR_LOCALE from the recorded editor language", () => {
		const env: NodeJS.ProcessEnv = {};
		applyDisplayLanguage({ display_language: "tr" }, env);
		expect(env.AIDR_LOCALE).toBe("tr");
		const regional: NodeJS.ProcessEnv = {};
		applyDisplayLanguage({ display_language: "pt-br" }, regional);
		expect(regional.AIDR_LOCALE).toBe("pt-br");
	});

	it("never overrides an AIDR_LOCALE the user or administrator set", () => {
		const env: NodeJS.ProcessEnv = { AIDR_LOCALE: "en" };
		applyDisplayLanguage({ display_language: "tr" }, env);
		expect(env.AIDR_LOCALE).toBe("en");
	});

	it("installHookRuntime writes display_language into the launcher pointer", async () => {
		const scratch = mkdtempSync(join(tmpdir(), "aidr-launcher-lang-"));
		try {
			const launcher = join(scratch, "launcher.cjs");
			writeFileSync(launcher, "// launcher");
			await installHookRuntime({
				host: "cursor",
				runnerPath: join(scratch, "aidr-hook.cjs"),
				launcherSourcePath: launcher,
				displayLanguage: "tr",
			});
			expect(readHostPointer("cursor").display_language).toBe("tr");
		} finally {
			rmSync(scratch, { recursive: true, force: true });
		}
	});

	it("ignores a missing or malformed value", () => {
		for (const value of [undefined, "", "tr;rm -rf", "../../x", "t".repeat(40)]) {
			const env: NodeJS.ProcessEnv = {};
			applyDisplayLanguage({ display_language: value }, env);
			expect(env.AIDR_LOCALE).toBeUndefined();
		}
	});
});
