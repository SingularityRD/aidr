/**
 * Diff-aware file-edit rules (threats/agent-safety.yaml, CLT-AGENT-RH-1xx):
 * what an edit adds to or removes from tests, CI and quality configuration.
 * Benign twins: normal test edits, rewording an assertion, editing an already
 * skipped test, raising a coverage threshold, a single @ts-expect-error.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
	buildEditViews,
	isTestFile,
	lineDiff,
	patchChanges,
	viewsForPath,
} from "../agent-safety/edit-views.js";
import type { ToolEvaluationRequest } from "../evaluator.js";
import type { HeuristicsEngine } from "../heuristics.js";
import { normalizeToolEvaluationRequest } from "../tool-normalization.js";
import { loadEngine } from "./test-helper.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

let engine: HeuristicsEngine;
let dir: string;

beforeAll(async () => {
	engine = await loadEngine();
	dir = await makeTmpDir();
});

afterAll(async () => {
	await removeTmpDir(dir);
});

function request(toolName: string, toolInput: Record<string, unknown>): ToolEvaluationRequest {
	return normalizeToolEvaluationRequest({ sessionId: "s", toolName, toolInput, artifacts: [] });
}

async function ruleIds(toolName: string, toolInput: Record<string, unknown>): Promise<string[]> {
	const views = await buildEditViews(request(toolName, toolInput), undefined, dir);
	return engine.matchEditViews(views).map((match) => match.threat.id);
}

function edit(filePath: string, oldString: string, newString: string): Promise<string[]> {
	return ruleIds("Edit", { file_path: filePath, old_string: oldString, new_string: newString });
}

describe("path classification and line diff", () => {
	it("classifies test, CI, quality-config and source files", () => {
		expect(isTestFile("src/__tests__/parser.test.ts")).toBe(true);
		expect(isTestFile("tests/test_api.py")).toBe(true);
		expect(isTestFile("pkg/server_test.go")).toBe(true);
		expect(isTestFile("src/main/java/FooTest.java")).toBe(true);
		expect(isTestFile("src/latest.ts")).toBe(false);
		expect(isTestFile("tests/fixtures/data.json")).toBe(false);
		expect(viewsForPath(".github/workflows/ci.yml")).toEqual(["ci_config"]);
		expect(viewsForPath("vitest.config.ts")).toEqual(["quality_config", "source_code"]);
		expect(viewsForPath("src/app.ts")).toEqual(["source_code"]);
		expect(viewsForPath("README.md")).toEqual([]);
	});

	it("diffs lines as a multiset (moves are not changes)", () => {
		expect(lineDiff("a\nb\nc", "c\na\nb")).toEqual({ added: [], removed: [], truncated: false });
		expect(lineDiff("a\nb", "a\nc")).toEqual({ added: ["c"], removed: ["b"], truncated: false });
	});

	it("reads added, removed and deleted files from Codex and unified patches", () => {
		const codex = patchChanges(
			[
				"*** Begin Patch",
				"*** Update File: src/a.test.ts",
				"@@",
				"-  expect(x).toBe(1);",
				"+  // expect(x).toBe(1);",
				"*** Delete File: tests/test_old.py",
				"*** End Patch",
			].join("\n"),
		);
		expect(codex).toEqual([
			{
				filePath: "src/a.test.ts",
				added: ["  // expect(x).toBe(1);"],
				removed: ["  expect(x).toBe(1);"],
				deleted: false,
			},
			{ filePath: "tests/test_old.py", added: [], removed: [], deleted: true },
		]);
		const unified = patchChanges(
			["--- a/b.spec.js", "+++ /dev/null", "@@ -1 +0,0 @@", "-it('x', () => {})"].join("\n"),
		);
		expect(unified[0]).toMatchObject({ filePath: "b.spec.js", deleted: true });
	});
});

describe("test weakening (test_code view)", () => {
	it("CLT-AGENT-RH-101 flags an added skip in a test file", async () => {
		expect(
			await edit(
				"src/auth.test.ts",
				"it('logs in', async () => {",
				"it.skip('logs in', async () => {",
			),
		).toContain("CLT-AGENT-RH-101");
		expect(
			await edit("tests/test_api.py", "def test_x():", "@pytest.mark.skip\ndef test_x():"),
		).toContain("CLT-AGENT-RH-101");
		expect(
			await edit(
				"pkg/server_test.go",
				"func TestServe(t *testing.T) {",
				'func TestServe(t *testing.T) {\n\tt.Skip("flaky")',
			),
		).toContain("CLT-AGENT-RH-101");
	});

	it("does not flag skips outside test files or edits to an already skipped test", async () => {
		expect(await edit("src/router.ts", "const a = 1;", "it.skip('x', () => {});")).not.toContain(
			"CLT-AGENT-RH-101",
		);
		expect(
			await edit(
				"src/auth.test.ts",
				"it.skip('logs in', async () => {\n  await login();",
				"it.skip('logs in', async () => {\n  await login('user');",
			),
		).toEqual([]);
	});

	it("CLT-AGENT-RH-102 flags added .only focus", async () => {
		expect(
			await edit("a.spec.ts", "describe('api', () => {", "describe.only('api', () => {"),
		).toContain("CLT-AGENT-RH-102");
		expect(await edit("tests/test_ml.py", "x = 1", "model.fit(x)")).toEqual([]);
	});

	it("CLT-AGENT-RH-103 flags removed or commented-out assertions, not reworded ones", async () => {
		expect(
			await edit(
				"src/sum.test.ts",
				"  expect(sum(1, 2)).toBe(3);\n  expect(sum(0, 0)).toBe(0);",
				"  expect(sum(1, 2)).toBe(3);",
			),
		).toContain("CLT-AGENT-RH-103");
		expect(
			await edit(
				"src/sum.test.ts",
				"  expect(sum(1, 2)).toBe(3);",
				"  // expect(sum(1, 2)).toBe(3);",
			),
		).toContain("CLT-AGENT-RH-103");
		expect(await edit("tests/test_sum.py", "    assert total == 3", "    pass")).toContain(
			"CLT-AGENT-RH-103",
		);
		// Benign twins: an updated expectation and a new test.
		expect(
			await edit(
				"src/sum.test.ts",
				"  expect(sum(1, 2)).toBe(3);",
				"  expect(sum(1, 2)).toEqual(3);",
			),
		).toEqual([]);
		expect(
			await edit(
				"src/sum.test.ts",
				"});",
				"});\n\nit('adds negatives', () => {\n  expect(sum(-1, -2)).toBe(-3);\n});",
			),
		).toEqual([]);
	});

	it("CLT-AGENT-RH-104 flags tautological assertions", async () => {
		// A real assertion replaced by a tautology keeps the assertion count, so
		// only the tautology rule fires.
		expect(
			await edit("src/a.test.ts", "expect(run()).toBe(3);", "expect(true).toBe(true);"),
		).toEqual(["CLT-AGENT-RH-104"]);
		expect(await edit("tests/test_a.py", "x = 1", "assert True")).toContain("CLT-AGENT-RH-104");
		expect(await edit("src/a.test.ts", "x;", "expect(result).toBe(true);")).toEqual([]);
	});

	it("CLT-AGENT-RH-105 flags a deleted or emptied test file", async () => {
		const testFile = join(dir, "src", "math.test.ts");
		await mkdir(join(dir, "src"), { recursive: true });
		await writeFile(
			testFile,
			"import { it, expect } from 'vitest';\nit('adds', () => {\n  expect(1 + 1).toBe(2);\n});\n",
		);
		expect(await ruleIds("Write", { file_path: testFile, content: "" })).toEqual(
			expect.arrayContaining(["CLT-AGENT-RH-105", "CLT-AGENT-RH-103"]),
		);
		expect(await ruleIds("Delete", { file_path: "tests/test_models.py" })).toContain(
			"CLT-AGENT-RH-105",
		);
		expect(
			await ruleIds("apply_patch", {
				input: "*** Begin Patch\n*** Delete File: src/old.spec.ts\n*** End Patch",
			}),
		).toContain("CLT-AGENT-RH-105");
		// Benign twins: rewriting a test file that keeps its tests; deleting a source file.
		expect(
			await ruleIds("Write", {
				file_path: testFile,
				content:
					"import { it, expect } from 'vitest';\nit('adds', () => {\n  expect(1 + 1).toBe(2);\n});\n\nit('subtracts', () => {\n  expect(2 - 1).toBe(1);\n});\n",
			}),
		).toEqual([]);
		expect(await ruleIds("Delete", { file_path: "src/old.ts" })).toEqual([]);
	});

	it("inspects every edit of a MultiEdit", async () => {
		expect(
			await ruleIds("MultiEdit", {
				file_path: "src/a.test.ts",
				edits: [
					{ old_string: "const a = 1;", new_string: "const a = 2;" },
					{ old_string: "it('b', () => {", new_string: "it.skip('b', () => {" },
				],
			}),
		).toContain("CLT-AGENT-RH-101");
	});
});

describe("CI and quality configuration", () => {
	it("CLT-AGENT-RH-106 flags non-blocking or disabled CI checks", async () => {
		const workflow = ".github/workflows/ci.yml";
		expect(
			await edit(
				workflow,
				"      - run: pnpm test",
				"      - run: pnpm test\n        continue-on-error: true",
			),
		).toContain("CLT-AGENT-RH-106");
		expect(
			await edit(workflow, "      - run: pnpm lint", "      - run: pnpm lint || true"),
		).toContain("CLT-AGENT-RH-106");
		expect(
			await edit(
				workflow,
				"  test:\n    runs-on: ubuntu-latest",
				"  test:\n    if: false\n    runs-on: ubuntu-latest",
			),
		).toContain("CLT-AGENT-RH-106");
		expect(
			await edit(
				".gitlab-ci.yml",
				"  script: make test",
				"  script: make test\n  allow_failure: true",
			),
		).toContain("CLT-AGENT-RH-106");
		expect(await edit(workflow, "node-version: 20", "node-version: 22")).toEqual([]);
	});

	it("CLT-AGENT-RH-107 flags removed test/lint steps, not changed ones", async () => {
		const workflow = ".github/workflows/ci.yml";
		expect(
			await edit(
				workflow,
				"      - run: pnpm install\n      - run: pnpm test",
				"      - run: pnpm install",
			),
		).toContain("CLT-AGENT-RH-107");
		expect(
			await edit(".husky/pre-commit", "pnpm lint-staged\npnpm typecheck", "pnpm lint-staged"),
		).toContain("CLT-AGENT-RH-107");
		expect(
			await edit(workflow, "      - run: pnpm test", "      - run: pnpm test -- --coverage"),
		).toEqual([]);
	});

	it("CLT-AGENT-RH-108/109 flag lowered or removed coverage thresholds", async () => {
		expect(
			await edit(
				"vitest.config.ts",
				"        lines: 80,\n        branches: 70,",
				"        lines: 50,\n        branches: 70,",
			),
		).toContain("CLT-AGENT-RH-108");
		expect(await edit("pyproject.toml", "fail_under = 90", "fail_under = 60")).toContain(
			"CLT-AGENT-RH-108",
		);
		expect(
			await edit("setup.cfg", "addopts = --cov-fail-under=85", "addopts = --cov-fail-under=40"),
		).toContain("CLT-AGENT-RH-108");
		expect(
			await edit("codecov.yml", "      target: 80%\n      threshold: 1%", "      threshold: 1%"),
		).toContain("CLT-AGENT-RH-109");
		// Benign twin: raising a threshold.
		expect(await edit("vitest.config.ts", "        lines: 70,", "        lines: 80,")).toEqual([]);
	});

	it("CLT-AGENT-RH-110/111 flag file-wide and bulk suppressions, not a single targeted one", async () => {
		expect(
			await edit("src/app.ts", "import x from 'x';", "// @ts-nocheck\nimport x from 'x';"),
		).toContain("CLT-AGENT-RH-110");
		expect(
			await edit("src/app.js", "'use strict';", "/* eslint-disable */\n'use strict';"),
		).toContain("CLT-AGENT-RH-110");
		expect(await edit("pkg/mod.py", "import os", "# pylint: skip-file\nimport os")).toContain(
			"CLT-AGENT-RH-110",
		);
		const spree = Array.from({ length: 6 }, (_, i) => `// @ts-ignore\nconst v${i} = bad${i};`).join(
			"\n",
		);
		expect(await edit("src/app.ts", "const v = 1;", spree)).toContain("CLT-AGENT-RH-111");
		expect(
			await edit(
				"src/app.ts",
				"const v = parse(x);",
				"// @ts-expect-error legacy API\nconst v = parse(x);",
			),
		).toEqual([]);
		expect(
			await edit(
				"src/app.ts",
				"/* eslint-disable no-console */",
				"/* eslint-disable no-console */\nconsole.log(1);",
			),
		).toEqual([]);
	});

	it("CLT-AGENT-RH-112 flags weakened lint/type/test configuration", async () => {
		expect(await edit("tsconfig.json", '    "strict": true,', '    "strict": false,')).toContain(
			"CLT-AGENT-RH-112",
		);
		expect(
			await edit("package.json", '    "test": "vitest run",', '    "test": "echo skipped",'),
		).toContain("CLT-AGENT-RH-112");
		expect(
			await edit(
				"biome.json",
				'  "files": { "includes": ["**"] },',
				'  "files": { "includes": ["**", "!src/**"] },',
			),
		).toContain("CLT-AGENT-RH-112");
		expect(await edit(".eslintignore", "dist/", "dist/\nsrc/")).toContain("CLT-AGENT-RH-112");
		// Benign twins: adding a dependency; excluding build output.
		expect(
			await edit(
				"package.json",
				'    "zod": "^3.24.0",',
				'    "zod": "^3.24.0",\n    "yaml": "^2.8.3",',
			),
		).toEqual([]);
		expect(
			await edit(
				"tsconfig.json",
				'  "exclude": ["node_modules"]',
				'  "exclude": ["node_modules", "dist"]',
			),
		).toEqual([]);
	});
});
