/**
 * Relative file targets resolve against the host-reported working directory
 * (never the hook process's cwd), and a diff-aware edit inspection that a size
 * bound cut short is never a clean allow.
 */
import { mkdir, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { lineDiff } from "../agent-safety/edit-views.js";
import { evaluateToolCall, type ToolEvaluationContext } from "../evaluator.js";
import { extractFromToolCall } from "../extractors.js";
import { evaluatePolicy } from "../policy.js";
import { ConfigSchema } from "../types.js";
import { makeTmpDir, removeTmpDir } from "./test-utils.js";

const THREATS_DIR = resolve(__dirname, "..", "..", "..", "..", "threats");
const ALLOWLISTS_DIR = resolve(__dirname, "..", "..", "..", "..", "allowlists");
// Assembled at runtime so the mandatory-skip gate does not read it as a skip here.
const IT_SKIP = ["it", "skip"].join(".");

let homeDir: string;
let workspace: string;

beforeEach(async () => {
	homeDir = await makeTmpDir();
	workspace = await makeTmpDir();
	vi.stubEnv("HOME", homeDir);
	await mkdir(join(homeDir, ".singularity-aidr"), { recursive: true });
});

afterEach(async () => {
	vi.unstubAllEnvs();
	await removeTmpDir(homeDir);
	await removeTmpDir(workspace);
});

async function contextWith(extra: Record<string, unknown> = {}): Promise<ToolEvaluationContext> {
	const configPath = join(homeDir, "config.json");
	await writeFile(
		configPath,
		JSON.stringify({
			mode: "local",
			control_plane: { enabled: false },
			licensing: { require_signed_entitlements: false },
			heuristics_enabled: true,
			url_check: { enabled: false },
			package_check: { enabled: false },
			cache: { enabled: false },
			logging: { enabled: false },
			allowlist: { path: "~/.singularity-aidr/allowlist.json" },
			...extra,
		}),
	);
	return { threatsDir: THREATS_DIR, allowlistsDir: ALLOWLISTS_DIR, configPath };
}

function evaluate(
	toolName: string,
	toolInput: Record<string, unknown>,
	context: ToolEvaluationContext,
) {
	return evaluateToolCall(
		{
			sessionId: "edit-target-cwd",
			toolName,
			toolInput,
			artifacts: extractFromToolCall(toolName, toolInput),
		},
		context,
	);
}

function rootPolicy(root: string) {
	return {
		policy: {
			enabled: true,
			filesystem: { enabled: true, allowed_write_roots: [root], outside_root_action: "block" },
		},
	};
}

describe("relative file targets resolve against the host working directory", () => {
	it("denies Write relative.txt when the hook cwd is inside the allowed root but the host cwd is not", async () => {
		const outside = join(workspace, "outside");
		await mkdir(outside);
		// The hook process cwd (the repository) is the allowed root; the tool runs in `outside`.
		const context = await contextWith(rootPolicy(process.cwd()));
		const verdict = await evaluate(
			"Write",
			{ file_path: "relative.txt", content: "hello" },
			{ ...context, workingDirectory: outside },
		);
		expect(verdict).toMatchObject({ decision: "deny", matchedThreatId: "POL-FS-001" });
	});

	it("allows Write relative.txt when the host cwd is inside the allowed root and the hook cwd is not", async () => {
		const allowed = join(workspace, "allowed");
		await mkdir(allowed);
		const context = await contextWith(rootPolicy(allowed));
		const verdict = await evaluate(
			"Write",
			{ file_path: "relative.txt", content: "hello" },
			{ ...context, workingDirectory: allowed },
		);
		expect(verdict.decision).toBe("allow");
		// Benign twin of the first case: an absolute target is unaffected by either cwd.
		const absolute = await evaluate(
			"Write",
			{ file_path: join(allowed, "absolute.txt"), content: "hello" },
			{ ...context, workingDirectory: workspace },
		);
		expect(absolute.decision).toBe("allow");
	});

	it("matches deny patterns against the target resolved in the host working directory", async () => {
		const protectedDir = join(workspace, "protected-zone");
		await mkdir(protectedDir);
		const config = ConfigSchema.parse({
			policy: {
				enabled: true,
				filesystem: { enabled: true, deny_write_patterns: ["protected-zone"] },
			},
		});
		const input = { file_path: "notes.txt" };
		const artifacts = [{ type: "file_path" as const, value: "notes.txt", context: "edit" }];
		expect(
			await evaluatePolicy(
				"Write",
				artifacts,
				config,
				input,
				{},
				{ workingDirectory: protectedDir },
			),
		).toMatchObject({ decision: "deny", matchedThreatId: "POL-FS-002" });
		expect(
			await evaluatePolicy("Write", artifacts, config, input, {}, { workingDirectory: workspace }),
		).toBeNull();
	});

	it("reads the previous file for diff-aware rules from the host working directory", async () => {
		const original =
			"import { it, expect } from 'vitest';\nit('adds', () => {\n  expect(1 + 1).toBe(2);\n});\n";
		await mkdir(join(workspace, "src"), { recursive: true });
		await writeFile(join(workspace, "src", "sum.test.ts"), original);
		const context = await contextWith();
		const verdict = await evaluate(
			"Write",
			{ file_path: "src/sum.test.ts", content: "export {};\n" },
			{ ...context, workingDirectory: workspace },
		);
		// The removed assertions are only visible when the old content is read from the right place.
		expect(verdict.decision).not.toBe("allow");
		expect(["CLT-AGENT-RH-103", "CLT-AGENT-RH-105"]).toContain(verdict.matchedThreatId);
		// Twin: in a directory where the file does not exist, the same Write creates a new file.
		const elsewhere = join(workspace, "elsewhere");
		await mkdir(elsewhere);
		const fresh = await evaluate(
			"Write",
			{ file_path: "src/sum.test.ts", content: "export {};\n" },
			{ ...context, workingDirectory: elsewhere },
		);
		expect(fresh.decision).toBe("allow");
	});
});

describe("diff-aware edit inspection cut short by a size bound", () => {
	it("keeps a whitespace-padded line whole and reports a real cut", () => {
		const padded = `${" ".repeat(4097)}${IT_SKIP}('x', () => {});`;
		expect(lineDiff("", padded)).toEqual({
			added: [`${IT_SKIP}('x', () => {});`],
			removed: [],
			truncated: false,
		});
		const long = `${"x".repeat(5000)} ${IT_SKIP}('x', () => {});`;
		expect(lineDiff("", long).truncated).toBe(true);
	});

	it("does not allow a skip hidden behind 4097 spaces", async () => {
		const context = await contextWith();
		const plain = await evaluate(
			"Edit",
			{
				file_path: "src/a.test.ts",
				old_string: "it('logs in', async () => {",
				new_string: `${IT_SKIP}('logs in', async () => {`,
			},
			{ ...context, workingDirectory: workspace },
		);
		expect(plain.decision).toBe("ask");
		const padded = await evaluate(
			"Edit",
			{
				file_path: "src/a.test.ts",
				old_string: "it('logs in', async () => {",
				new_string: `${" ".repeat(4097)}${IT_SKIP}('logs in', async () => {`,
			},
			{ ...context, workingDirectory: workspace },
		);
		expect(padded.decision).toBe("ask");
	});

	it("does not allow a skip whose line is cut by the line-length bound", async () => {
		const context = await contextWith();
		const verdict = await evaluate(
			"Edit",
			{
				file_path: "src/a.test.ts",
				old_string: "it('logs in', async () => {",
				new_string: `const pad = "${"x".repeat(5000)}"; ${IT_SKIP}('logs in', async () => {`,
			},
			{ ...context, workingDirectory: workspace },
		);
		expect(verdict.decision).not.toBe("allow");
	});

	it("does not allow a skip past the line-count bound (20001 newlines)", async () => {
		const context = await contextWith();
		const verdict = await evaluate(
			"Write",
			{
				file_path: "src/b.test.ts",
				content: `${"\n".repeat(20_001)}${IT_SKIP}('logs in', () => {});`,
			},
			{ ...context, workingDirectory: workspace },
		);
		expect(verdict.decision).not.toBe("allow");
	});

	it("still allows an ordinary test edit (benign twin)", async () => {
		const context = await contextWith();
		const verdict = await evaluate(
			"Edit",
			{
				file_path: "src/a.test.ts",
				old_string: "expect(sum(1, 2)).toBe(3);",
				new_string: "expect(sum(1, 2)).toEqual(3);",
			},
			{ ...context, workingDirectory: workspace },
		);
		expect(verdict.decision).toBe("allow");
	});
});
