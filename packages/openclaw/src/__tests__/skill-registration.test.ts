import { access, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const PKG_ROOT = resolve(import.meta.dirname, "..", "..");
const MANIFEST_PATH = resolve(PKG_ROOT, "openclaw.plugin.json");
const SYNCED_SKILL_PATH = resolve(
	PKG_ROOT,
	"resources",
	"skills",
	"security-awareness",
	"SKILL.md",
);

/** Parse simple YAML frontmatter key-value pairs without requiring the yaml package. */
function parseFrontmatter(raw: string): Record<string, string> {
	const result: Record<string, string> = {};
	for (const line of raw.split("\n")) {
		const match = line.match(/^(\S+):\s*"?(.+?)"?\s*$/);
		if (match) result[match[1]] = match[2];
	}
	return result;
}

describe("openclaw skill registration", () => {
	it("declares security-awareness skill in plugin manifest", async () => {
		const manifest = await import(MANIFEST_PATH, { with: { type: "json" } });
		expect(manifest.default.skills).toContain("resources/skills/security-awareness");
	});

	it("synced SKILL.md exists on disk", async () => {
		await expect(access(SYNCED_SKILL_PATH)).resolves.toBeUndefined();
	});

	it("synced SKILL.md has valid frontmatter matching source", async () => {
		const content = await readFile(SYNCED_SKILL_PATH, "utf-8");
		const parts = content.split("---");
		expect(parts.length).toBeGreaterThanOrEqual(3);

		const frontmatter = parseFrontmatter(parts[1]);
		expect(frontmatter.name).toBe("security-awareness");
		expect(frontmatter["user-invocable"]).toBe("false");
		expect(frontmatter["disable-model-invocation"]).toBe("false");
	});
});
