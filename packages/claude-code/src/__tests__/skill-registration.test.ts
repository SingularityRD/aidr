import { access } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const REPO_ROOT = resolve(import.meta.dirname, "..", "..", "..", "..");
const MANIFEST_PATH = resolve(REPO_ROOT, ".claude-plugin", "plugin.json");

describe("claude-code skill registration", () => {
	it("declares skills directory in plugin manifest", async () => {
		const manifest = await import(MANIFEST_PATH, { with: { type: "json" } });
		expect(manifest.default.skills).toBe("./skills/");
	});

	it("security-awareness SKILL.md exists at declared path", async () => {
		await expect(
			access(resolve(REPO_ROOT, "skills", "security-awareness", "SKILL.md")),
		).resolves.toBeUndefined();
	});
});
