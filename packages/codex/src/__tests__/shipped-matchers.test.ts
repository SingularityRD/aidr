/**
 * CON-12: the Codex registration that ships (README, platform guide, `aidr`
 * setup guidance, `--health`) must name the same matchers, and those matchers
 * must cover MCP tool calls before they run. Codex 0.141.0 names MCP tools
 * `mcp__<server>__<tool>` for PreToolUse and PostToolUse
 * (CODEX_HOOKS_0.141.0_REFERENCE.md, "Tool coverage").
 */

import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";
import {
	CODEX_SHIPPED_MATCHERS,
	CODEX_UNCOVERED_TOOL_PATHS,
	getCodexConnectorCoverageEvidence,
} from "../coverage.js";

const REPO = resolve(__dirname, "..", "..", "..", "..");
const read = (path: string) => readFileSync(resolve(REPO, path), "utf8");

const preToolUse = new RegExp(CODEX_SHIPPED_MATCHERS.PreToolUse);
const postToolUse = new RegExp(CODEX_SHIPPED_MATCHERS.PostToolUse);

describe("Codex shipped matchers", () => {
	it.each(["Bash", "apply_patch", "mcp__fs__read", "mcp__ssh__run"])(
		"PreToolUse reaches the hook for %s",
		(tool) => {
			expect(preToolUse.test(tool)).toBe(true);
		},
	);

	it.each(["update_plan", "WebSearch", "Bashx", "xapply_patch", "mcp__"])(
		"PreToolUse does not claim %s",
		(tool) => {
			expect(preToolUse.test(tool)).toBe(false);
		},
	);

	it("PostToolUse covers Bash and MCP results, not apply_patch", () => {
		expect(postToolUse.test("Bash")).toBe(true);
		expect(postToolUse.test("mcp__docs__lookup")).toBe(true);
		expect(postToolUse.test("apply_patch")).toBe(false);
	});

	it("--health reports the matchers and the uncovered tool paths", () => {
		const evidence = getCodexConnectorCoverageEvidence();
		expect(evidence.toolMatchers).toEqual(CODEX_SHIPPED_MATCHERS);
		expect(evidence.uncoveredToolPaths).toEqual(CODEX_UNCOVERED_TOOL_PATHS);
		expect(evidence.claims.inlineOutputBlocking).toBe(false);
		expect(getCodexConnectorCoverageEvidence(["PreToolUse"]).toolMatchers).toEqual({
			PreToolUse: CODEX_SHIPPED_MATCHERS.PreToolUse,
		});
	});

	it.each([
		"packages/codex/README.md",
		"docs/platform-guides/codex.md",
		"packages/cli/src/utils/install-hooks.ts",
	])("%s registers exactly the shipped matchers", (path) => {
		const text = read(path);
		const toml = (matcher: string) => `matcher = "${matcher}"`;
		expect(text).toContain(toml(CODEX_SHIPPED_MATCHERS.PreToolUse));
		expect(text).toContain(toml(CODEX_SHIPPED_MATCHERS.PostToolUse));
		// The pre-CON-12 matcher left MCP calls uninspected.
		expect(text).not.toContain('"^(Bash|apply_patch)$"');
	});

	it("aidr setup's connector installer registers the shipped matchers", () => {
		// The installer and `aidr machine-hooks` share the Codex hook handlers.
		expect(read("packages/cli/src/utils/connector-install.ts")).toContain('from "./codex-hooks.js"');
		const text = read("packages/cli/src/utils/codex-hooks.ts");
		expect(text).toContain(`matcher: "${CODEX_SHIPPED_MATCHERS.PreToolUse}"`);
		expect(text).toContain(`matcher: "${CODEX_SHIPPED_MATCHERS.PostToolUse}"`);
		expect(text).not.toContain('"^(Bash|apply_patch)$"');
	});

	it("the README's hooks.json form matches the TOML form", () => {
		const readme = read("packages/codex/README.md");
		expect(readme).toContain(`"matcher": "${CODEX_SHIPPED_MATCHERS.PreToolUse}"`);
		expect(readme).toContain(`"matcher": "${CODEX_SHIPPED_MATCHERS.PostToolUse}"`);
	});

	it("no Codex doc claims enforced pre-model output protection", () => {
		const support = JSON.parse(read("deploy/native/support-matrix.json")) as {
			rows: Array<Record<string, unknown>>;
		};
		const codex = support.rows.find((row) => row.connector === "codex");
		expect(codex?.outputInterceptionPoint).toBe("none");
		const bypasses = (codex?.knownBypasses as string[]).join("\n");
		expect(bypasses).toContain("mcp__");
		expect(bypasses).not.toMatch(/covers Bash and apply_patch only/);
	});
});
