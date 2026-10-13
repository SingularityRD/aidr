// PRD-8: the dashboard's Codex onboarding must register every hook the Codex
// connector ships (tool calls, prompt protection and tool-output inspection),
// exactly as packages/codex/README.md and docs/platform-guides/codex.md do.
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import { CODEX_HOOKS_TOML, RUNTIME_CATALOG } from "../onboarding/runtime-catalog";

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "..");

/** Setting lines of the first ```toml block that registers Codex hooks (comments and blanks dropped). */
function tomlSettings(markdown: string): string[] {
	const block = [...markdown.matchAll(/```toml\n([\s\S]*?)```/g)]
		.map((match) => match[1] ?? "")
		.find((body) => body.includes("[[hooks.PreToolUse]]"));
	if (!block) throw new Error("no Codex hook TOML block found");
	return settings(block);
}

function settings(toml: string): string[] {
	return toml
		.split("\n")
		.map((line) => line.trim())
		.filter((line) => line !== "" && !line.startsWith("#"));
}

describe("Codex onboarding snippet", () => {
	it("registers PreToolUse, UserPromptSubmit and PostToolUse with the shipped matchers", () => {
		const lines = settings(CODEX_HOOKS_TOML);
		for (const table of [
			"[[hooks.PreToolUse]]",
			"[[hooks.UserPromptSubmit]]",
			"[[hooks.PostToolUse]]",
		]) {
			expect(lines).toContain(table);
			expect(lines).toContain(table.replace("]]", ".hooks]]"));
		}
		expect(lines).toContain('matcher = "^(Bash|apply_patch|mcp__.+)$"');
		expect(lines).toContain('matcher = "^(Bash|mcp__.+)$"');
		expect(lines.filter((line) => line === 'command = "aidr-codex-hook"')).toHaveLength(3);
	});

	it("is the snippet the dashboard shows for Codex", () => {
		const codex = RUNTIME_CATALOG.find((entry) => entry.id === "codex");
		const steps = codex?.installSteps(null) ?? [];
		expect(steps.map((step) => step.command)).toContain(CODEX_HOOKS_TOML);
	});

	it.each(["packages/codex/README.md", "docs/platform-guides/codex.md"])(
		"matches the registration documented in %s",
		(path) => {
			expect(settings(CODEX_HOOKS_TOML)).toEqual(
				tomlSettings(readFileSync(resolve(REPO_ROOT, path), "utf8")),
			);
		},
	);
});
