import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import type { Environment } from "../utils/config-manager.js";

const testHome = mkdtempSync(join(tmpdir(), "aidr-hook-guidance-"));
vi.mock("@singularityrd/aidr-core", () => ({ resolvePath: () => testHome, VERSION: "9.8.7" }));
vi.mock("../utils/config-manager.js", () => ({ updateConfig: vi.fn() }));

const { installHooks } = await import("../utils/install-hooks.js");
const { updateConfig } = await import("../utils/config-manager.js");

afterAll(() => rmSync(testHome, { recursive: true, force: true }));

describe("setup guidance for detected hosts", () => {
	it.each(["openclaw", "opencode", "codex"] as const)(
		"keeps %s protection inactive until its connector is installed",
		async (agent) => {
			const env: Environment = {
				agent,
				hasNode: true,
				nodeVersion: process.version,
				projectRoot: testHome,
			};
			const result = await installHooks(env);
			const guidance = result.followUp.join("\n");

			expect(result.summary).toBe(`${agent} detected - connector install required`);
			expect(guidance).toContain("Protection is NOT yet active");
			expect(guidance).toContain(`@singularityrd/aidr-${agent}`);
			expect(guidance).toContain("host-side deny canary");
			if (agent === "codex") {
				expect(guidance).toMatch(/\[\[hooks\.PreToolUse\]\]\n\s+matcher =/);
				expect(guidance).toMatch(/\[\[hooks\.PreToolUse\.hooks\]\]\n\s+type = "command"/);
				expect(guidance).toMatch(
					/\[\[hooks\.UserPromptSubmit\]\]\n\s+\[\[hooks\.UserPromptSubmit\.hooks\]\]\n\s+type = "command"\n\s+command = "aidr-codex-hook"/,
				);
				expect(guidance).toContain("@singularityrd/aidr-codex@9.8.7");
			} else if (agent === "openclaw") {
				expect(guidance).toContain("npm:@singularityrd/aidr-openclaw@9.8.7");
			} else {
				expect(guidance).toContain('"dependencies":{"@singularityrd/aidr-opencode":"9.8.7"}');
				expect(guidance).toContain('"plugin":["@singularityrd/aidr-opencode"]');
			}
			// No literal placeholder may reach the user: the real version is printed.
			expect(guidance).not.toMatch(/\bVERSION\b/);
			expect(updateConfig).toHaveBeenCalledWith({ hooksInstalled: false });
		},
	);
});
