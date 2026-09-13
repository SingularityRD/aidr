import type { ToolEvaluationRequest } from "./evaluator.js";
import { extractFromToolCall } from "./extractors.js";

/**
 * Tool vocabularies differ between agent hosts even when the operation is the
 * same. Normalize the small set of operations whose semantics the core uses
 * directly so policy, package inspection, AMSI and audit logging cannot be
 * bypassed with connector-specific casing or field names.
 *
 * Unknown tools keep their original name and payload. In particular, MCP tool
 * identifiers must remain intact because their server/tool names are policy
 * inputs rather than aliases for a built-in operation.
 */
const CANONICAL_TOOL_NAMES = new Map<string, string>([
	["bash", "Bash"],
	["shell", "Bash"],
	["local_shell", "Bash"],
	["exec", "Bash"],
	["execute", "Bash"],
	["run_command", "Bash"],
	["run_terminal_cmd", "Bash"],
	["write", "Write"],
	["write_file", "Write"],
	["create_file", "Write"],
	["edit", "Edit"],
	["edit_file", "Edit"],
	["update_file", "Edit"],
	["read", "Read"],
	["read_file", "Read"],
	["delete", "Delete"],
	["delete_file", "Delete"],
	["remove_file", "Delete"],
	["webfetch", "WebFetch"],
	["web_fetch", "WebFetch"],
	["fetch_url", "WebFetch"],
	["mcp", "MCP"],
]);

function canonicalToolName(toolName: string): string {
	const trimmed = toolName.trim();
	return CANONICAL_TOOL_NAMES.get(trimmed.toLowerCase()) ?? toolName;
}

/**
 * Prefer a populated value over an empty canonical field. A hostile payload
 * must not be able to hide `filePath` or `cmd` by also sending `file_path: ""`
 * or `command: ""`.
 */
function firstString(input: Record<string, unknown>, keys: readonly string[]): string | undefined {
	let empty: string | undefined;
	for (const key of keys) {
		const value = input[key];
		if (typeof value !== "string") continue;
		if (value.trim() !== "") return value;
		empty ??= value;
	}
	return empty;
}

function setCanonicalField(
	input: Record<string, unknown>,
	canonicalKey: string,
	aliases: readonly string[],
): void {
	const value = firstString(input, [canonicalKey, ...aliases]);
	if (value !== undefined) input[canonicalKey] = value;
}

export function normalizeToolEvaluationRequest(
	request: ToolEvaluationRequest,
): ToolEvaluationRequest {
	const toolName = canonicalToolName(request.toolName);
	const toolInput = { ...request.toolInput };

	switch (toolName) {
		case "Bash":
			setCanonicalField(toolInput, "command", ["cmd", "shellCommand", "shell_command"]);
			break;
		case "Write":
			setCanonicalField(toolInput, "file_path", [
				"filePath",
				"path",
				"target_file",
				"targetFile",
				"filename",
				"fileName",
			]);
			setCanonicalField(toolInput, "content", ["text", "data", "new_string", "newString"]);
			break;
		case "Edit":
			setCanonicalField(toolInput, "file_path", [
				"filePath",
				"path",
				"target_file",
				"targetFile",
				"filename",
				"fileName",
			]);
			setCanonicalField(toolInput, "old_string", ["oldString", "oldText"]);
			setCanonicalField(toolInput, "new_string", [
				"newString",
				"newText",
				"replacement",
				"content",
				"text",
			]);
			// Package and filesystem policy inspect `content` before `new_string`.
			// Keep both fields aligned with the replacement the Edit tool applies.
			if (typeof toolInput.new_string === "string") {
				toolInput.content = toolInput.new_string;
			}
			break;
		case "Read":
		case "Delete":
			setCanonicalField(toolInput, "file_path", [
				"filePath",
				"path",
				"target_file",
				"targetFile",
				"filename",
				"fileName",
			]);
			break;
		case "WebFetch":
			setCanonicalField(toolInput, "url", ["uri", "href"]);
			break;
	}

	const artifacts = [...request.artifacts];
	if (
		toolName === "Bash" ||
		toolName === "Write" ||
		toolName === "Edit" ||
		toolName === "Read" ||
		toolName === "Delete" ||
		toolName === "WebFetch"
	) {
		// Connectors may extract before field normalization, or omit artifacts
		// for an unfamiliar alias. Always include the canonical operation's inputs.
		for (const artifact of extractFromToolCall(toolName, toolInput)) {
			if (!artifacts.some((existing) =>
				existing.type === artifact.type &&
				existing.value === artifact.value &&
				existing.context === artifact.context
			)) {
				artifacts.push(artifact);
			}
		}
	}

	return { ...request, toolName, toolInput, artifacts };
}
