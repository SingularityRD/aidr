import { describe, expect, it } from "vitest";
import { normalizeToolEvaluationRequest } from "../tool-normalization.js";

function request(toolName: string, toolInput: Record<string, unknown>) {
	return {
		sessionId: "normalization-test",
		toolName,
		toolInput,
		artifacts: [],
	};
}

describe("tool evaluation normalization", () => {
	it.each([
		"bash",
		"BASH",
		"shell",
		"local_shell",
		"exec",
		"execute",
	])("maps %s to the canonical Bash operation", (alias) => {
		const normalized = normalizeToolEvaluationRequest(request(alias, { cmd: "npm install x" }));
		expect(normalized.toolName).toBe("Bash");
		expect(normalized.toolInput.command).toBe("npm install x");
	});

	it.each([
		"write",
		"WRITE",
		"write_file",
		"create_file",
	])("maps %s and camelCase fields to the canonical Write shape", (alias) => {
		const normalized = normalizeToolEvaluationRequest(
			request(alias, { filePath: "package.json", content: '{"dependencies":{"x":"1"}}' }),
		);
		expect(normalized.toolName).toBe("Write");
		expect(normalized.toolInput.file_path).toBe("package.json");
		expect(normalized.toolInput.content).toContain("dependencies");
	});

	it.each([
		"edit",
		"EDIT",
		"edit_file",
		"update_file",
	])("maps %s and camelCase fields to the canonical Edit shape", (alias) => {
		const normalized = normalizeToolEvaluationRequest(
			request(alias, {
				filePath: "requirements.txt",
				oldString: "safe==1",
				newString: "risky==1",
			}),
		);
		expect(normalized.toolName).toBe("Edit");
		expect(normalized.toolInput).toMatchObject({
			file_path: "requirements.txt",
			old_string: "safe==1",
			new_string: "risky==1",
		});
	});

	it("does not let an empty canonical field hide a populated connector alias", () => {
		const normalized = normalizeToolEvaluationRequest(
			request("write", { file_path: "", filePath: "/etc/passwd", content: "test" }),
		);
		expect(normalized.toolInput.file_path).toBe("/etc/passwd");
	});

	it("aligns Edit content with the replacement that the evaluator inspects", () => {
		const original = request("edit", {
			filePath: "package.json",
			content: "",
			newString: '{"dependencies":{"blocked-package":"1.0.0"}}',
		});
		const normalized = normalizeToolEvaluationRequest(original);

		expect(normalized.toolInput.new_string).toBe(original.toolInput.newString);
		expect(normalized.toolInput.content).toBe(original.toolInput.newString);
		expect(original.toolInput.content).toBe("");
	});

	it("extracts built-in artifacts after normalizing connector fields", () => {
		const normalized = normalizeToolEvaluationRequest(
			request("write_file", { filePath: "package.json", text: '{"dependencies":{}}' }),
		);

		expect(normalized.artifacts).toContainEqual({
			type: "file_path",
			value: "package.json",
			context: "write",
		});
		expect(normalized.artifacts).toContainEqual({
			type: "content",
			value: '{"dependencies":{}}',
			context: "write",
		});
	});

	it("preserves unknown and MCP tool identifiers while cloning their payload", () => {
		const mcp = normalizeToolEvaluationRequest(
			request("mcp__GitHub__search", { command: "gh search" }),
		);
		expect(mcp.toolName).toBe("mcp__GitHub__search");
		expect(mcp.toolInput).toEqual({ command: "gh search" });
	});
});
