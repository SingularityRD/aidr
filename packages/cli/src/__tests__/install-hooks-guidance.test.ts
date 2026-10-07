import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it, vi } from "vitest";
import type { Environment } from "../utils/config-manager.js";

const testHome = mkdtempSync(join(tmpdir(), "aidr-hook-guidance-"));
vi.mock("@singularityrd/aidr-core", () => ({ resolvePath: () => testHome }));
vi.mock("../utils/config-manager.js", () => ({ updateConfig: vi.fn() }));

const { installHooks } = await import("../utils/install-hooks.js");
const { updateConfig } = await import("../utils/config-manager.js");

afterAll(() => rmSync(testHome, { recursive: true, force: true }));

describe("setup guidance for detected hosts", () => {
	it("gives the documented Claude Code plugin install steps", async () => {
		const result = await installHooks({
			agent: "claude",
			hasNode: true,
			nodeVersion: process.version,
			projectRoot: testHome,
		});
		const guidance = result.followUp.join("\n");
		expect(guidance).toContain("Protection is NOT yet active");
		expect(guidance).toContain("aidr-claude-plugin-<version>.tar.gz");
		expect(guidance).toContain("Ed25519 public key");
		// The exact commands documented in README.md and docs/getting-started.md.
		const { readFileSync } = await import("node:fs");
		const docs = readFileSync(join(__dirname, "../../../../docs/getting-started.md"), "utf8");
		for (const command of [
			"/plugin marketplace add /absolute/path/to/extracted/aidr-claude-plugin",
			"/plugin install aidr@aidr",
		]) {
			expect(docs).toContain(command);
			expect(guidance).toContain(command);
		}
	});

	it.each(["opencode", "codex"] as const)(
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
			} else {
				expect(guidance).toContain('"dependencies":{"@singularityrd/aidr-opencode":"VERSION"}');
				expect(guidance).toContain('"plugin":["@singularityrd/aidr-opencode"]');
			}
			expect(updateConfig).toHaveBeenCalledWith({ hooksInstalled: false });
		},
	);
});
