import { describe, expect, it } from "vitest";
import { normalizeToolEvaluationRequest, readFileEditPayload } from "../tool-normalization.js";

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

	it("maps apply_patch to the canonical Edit shape", () => {
		// Authentic Codex payload: packages/codex/src/extractors.ts reads the
		// patch from `command`, and packages/codex/src/__tests__/enforcement.test.ts
		// uses exactly this framing.
		const patch = [
			"*** Begin Patch",
			"*** Update File: src/util.ts",
			"-const a = 1;",
			"+const a = 2;",
			"*** End Patch",
		].join("\n");

		const normalized = normalizeToolEvaluationRequest(request("apply_patch", { command: patch }));

		expect(normalized.toolName).toBe("Edit");
		expect(normalized.toolInput.file_path).toBe("src/util.ts");
		// The text the patch introduces, not the diff scaffolding around it.
		expect(normalized.toolInput.new_string).toBe("const a = 2;");
		expect(normalized.toolInput.content).toBe("const a = 2;");
		expect(normalized.artifacts).toContainEqual({
			type: "file_path",
			value: "src/util.ts",
			context: "edit",
		});
		expect(normalized.artifacts).toContainEqual({
			type: "content",
			value: "const a = 2;",
			context: "edit",
		});
	});

	it("maps an apply_patch Add File manifest onto the canonical Edit shape", () => {
		// The supply-chain case the alias map exists for: a patch that creates a
		// package.json must reach the package leg as a manifest edit.
		const manifest = '{"dependencies":{"synthetic-aidr-package":"1.0.0"}}';
		const patch = [
			"*** Begin Patch",
			"*** Add File: package.json",
			`+${manifest}`,
			"*** End Patch",
		].join("\n");

		const normalized = normalizeToolEvaluationRequest(request("apply_patch", { command: patch }));

		expect(normalized.toolName).toBe("Edit");
		expect(normalized.toolInput.file_path).toBe("package.json");
		expect(normalized.toolInput.content).toBe(manifest);
	});

	it("maps the OpenClaw unified-diff apply_patch payload too", () => {
		// packages/openclaw/src/tool-handler.ts sends the patch in `params.patch`
		// as a unified diff (see packages/openclaw/src/__tests__/e2e-integration.test.ts).
		const patch = [
			"--- a/.ssh/authorized_keys",
			"+++ b/.ssh/authorized_keys",
			"@@ -0,0 +1 @@",
			"+ssh-rsa AAAA injected-key",
		].join("\n");

		const normalized = normalizeToolEvaluationRequest(request("apply_patch", { patch }));

		expect(normalized.toolName).toBe("Edit");
		expect(normalized.toolInput.file_path).toBe(".ssh/authorized_keys");
		expect(normalized.toolInput.new_string).toBe("ssh-rsa AAAA injected-key");
		expect(normalized.artifacts).toContainEqual({
			type: "file_path",
			value: ".ssh/authorized_keys",
			context: "edit",
		});
	});

	it("does not let an unknown tool name hide a manifest payload", () => {
		const manifest = '{"dependencies":{"synthetic-aidr-package":"1.0.0"}}';
		const normalized = normalizeToolEvaluationRequest(
			request("manifest_writer_v2", { filePath: "package.json", content: manifest }),
		);

		// The unknown name is still not mangled into a canonical one, and no
		// field is rewritten: that property is what keeps MCP policy inputs
		// intact.
		expect(normalized.toolName).toBe("manifest_writer_v2");
		expect(normalized.toolInput).toEqual({ filePath: "package.json", content: manifest });
		// The manifest is nevertheless readable as a file edit, which is the
		// signal the package leg routes on now that it no longer keys off the
		// tool name.
		expect(readFileEditPayload(normalized.toolInput)).toEqual({
			filePath: "package.json",
			content: manifest,
			patch: false,
		});
	});
});
