import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import { parse } from "yaml";

const REPO_ROOT = resolve(import.meta.dirname, "..", "..", "..", "..");
const SKILL_PATH = resolve(REPO_ROOT, "skills", "security-awareness", "SKILL.md");

describe("security-awareness skill loading", () => {
	it("has valid YAML frontmatter", async () => {
		const content = await readFile(SKILL_PATH, "utf-8");
		const parts = content.split("---");
		// parts[0] is empty (before first ---), parts[1] is frontmatter, parts[2+] is body
		expect(parts.length).toBeGreaterThanOrEqual(3);

		const frontmatter = parse(parts[1]) as Record<string, unknown>;
		expect(frontmatter.name).toBe("security-awareness");
		expect(frontmatter.description).toBeTypeOf("string");
		expect((frontmatter.description as string).length).toBeGreaterThan(0);
		expect(frontmatter["user-invocable"]).toBe(false);
		expect(frontmatter["disable-model-invocation"]).toBe(false);
	});

	it("has non-empty body content", async () => {
		const content = await readFile(SKILL_PATH, "utf-8");
		const parts = content.split("---");
		const body = parts.slice(2).join("---").trim();
		expect(body.length).toBeGreaterThan(0);
	});
});
