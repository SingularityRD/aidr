import type { ToolEvaluationRequest } from "./evaluator.js";
import { extractFromToolCall } from "./extractors.js";
import { isPackageManifestPath } from "./package-extractor.js";

/**
 * Tool vocabularies differ between agent hosts even when the operation is the
 * same. Normalize the small set of operations whose semantics the core uses
 * directly so policy, package inspection, AMSI and audit logging cannot be
 * bypassed with connector-specific casing or field names.
 *
 * Unknown tools keep their original name and payload. In particular, MCP tool
 * identifiers must remain intact because their server/tool names are policy
 * inputs rather than aliases for a built-in operation.
 *
 * `apply_patch` maps to `Edit` because two connectors emit it as their
 * file-editing tool — Codex (`packages/codex/src/extractors.ts`) and OpenClaw
 * (`packages/openclaw/src/tool-handler.ts`). Leaving it out of this map was a
 * detection hole: the operation *is* a file edit, so package, policy, AMSI and
 * filesystem inspection must treat it as one. No connector in this repo emits a
 * tool literally named `patch`; OpenClaw's `patch` is the *field* that carries
 * the unified diff, so it is handled as a payload field (see
 * `readFileEditPayload`) rather than as a second tool-name alias.
 */
export const CANONICAL_TOOL_NAMES: ReadonlyMap<string, string> = new Map<string, string>([
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
	["apply_patch", "Edit"],
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

export function canonicalToolName(toolName: string): string {
	const trimmed = toolName.trim();
	return CANONICAL_TOOL_NAMES.get(trimmed.toLowerCase()) ?? toolName;
}

/**
 * Field names connectors use for the path of a file operation. Shared by the
 * canonical `Write`/`Edit`/`Read`/`Delete` mapping and by
 * `readFileEditPayload`, so the vocabulary cannot drift between them.
 */
const FILE_PATH_ALIASES = [
	"filePath",
	"path",
	"target_file",
	"targetFile",
	"filename",
	"fileName",
] as const;

/**
 * Field names an unknown connector may use for the text a file operation
 * writes. `new_string` is preferred because it is the explicit Edit field: an
 * Edit request may carry an empty `content` next to a populated `new_string`.
 */
const EDIT_CONTENT_ALIASES = [
	"new_string",
	"content",
	"newString",
	"newText",
	"replacement",
	"text",
	"data",
] as const;

/** Codex patch section header: `*** Add File: <path>` / `*** Update File: <path>`. */
const CODEX_PATCH_HEADER_RE = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/;

/** Unified-diff new-file header: `+++ b/<path>` (OpenClaw's apply_patch dialect). */
const UNIFIED_DIFF_HEADER_RE = /^\+\+\+\s+(.+)$/;

/** Patch framing that carries no file content. */
const PATCH_SCAFFOLD_RE = /^\*\*\* (?:Begin|End) Patch\b/;

/**
 * Strip the `a/`…`b/` prefix and any trailing timestamp a unified diff header
 * carries, so the path names the file rather than the diff.
 */
function normalizeDiffPath(rawPath: string): string {
	const withoutTimestamp = (rawPath.split("\t")[0] ?? "").trim();
	const withoutPrefix = withoutTimestamp.replace(/^[ab]\//, "").trim();
	return withoutPrefix === "/dev/null" ? "" : withoutPrefix;
}

/** True when the text is patch payload rather than a plain file body. */
function looksLikePatch(text: string): boolean {
	for (const line of text.split(/\r?\n/)) {
		if (CODEX_PATCH_HEADER_RE.test(line) || UNIFIED_DIFF_HEADER_RE.test(line)) return true;
	}
	return false;
}

/**
 * Find the patch body inside a payload. A `patch` field is the patch by
 * definition; `command`/`input` are only treated as one when they actually
 * carry patch framing, because those field names are shared with other
 * operations.
 */
function patchBodyFrom(toolInput: Record<string, unknown>): string | undefined {
	const explicit = toolInput.patch;
	if (typeof explicit === "string" && explicit.trim() !== "") return explicit;
	for (const key of ["command", "input"] as const) {
		const value = toolInput[key];
		if (typeof value === "string" && looksLikePatch(value)) return value;
	}
	return undefined;
}

interface PatchSection {
	filePath: string;
	/** The text this section introduces into `filePath`. */
	content: string;
}

/**
 * The text a single patch line introduces into the file, if any.
 *
 * `+` lines are added, a leading space is context the new file keeps, and the
 * rest (`-` removals, `@@` hunks, `--- ` old-file headers) belongs to the old
 * file or to the diff framing. Codex `Add File` bodies are written verbatim
 * without a marker, so anything left over is its own text.
 */
function introducedText(line: string): string[] {
	if (line.startsWith("@@")) return [];
	if (line.startsWith("--- ")) return [];
	if (line.startsWith("-")) return [];
	if (line.startsWith("+")) return [line.slice(1)];
	if (line.startsWith(" ")) return [line.slice(1)];
	return [line];
}

/**
 * Split a patch into the file each section targets and the text that section
 * introduces.
 *
 * Removed lines and the diff framing (`*** Update File:`, `+++ b/…`, `@@`,
 * and the `+`/`-`/space line markers) are not part of the file being written,
 * so they are dropped. The result is the complete new file for an
 * `*** Add File:` section and the rewritten region for an `*** Update File:`
 * section, which is what the package/filesystem legs must inspect: an
 * attacker's payload lives on the added lines, not in the diff scaffolding.
 */
function parsePatchSections(patch: string): PatchSection[] {
	const sections: PatchSection[] = [];
	let current: { filePath: string; lines: string[] } | undefined;

	const startSection = (filePath: string): void => {
		if (current) {
			sections.push({ filePath: current.filePath, content: current.lines.join("\n") });
		}
		current = filePath === "" ? undefined : { filePath, lines: [] };
	};

	for (const line of patch.split(/\r?\n/)) {
		const codexHeader = CODEX_PATCH_HEADER_RE.exec(line);
		if (codexHeader) {
			startSection((codexHeader[1] ?? "").trim());
			continue;
		}
		if (PATCH_SCAFFOLD_RE.test(line)) continue;

		const unifiedHeader = UNIFIED_DIFF_HEADER_RE.exec(line);
		if (unifiedHeader) {
			startSection(normalizeDiffPath(unifiedHeader[1] ?? ""));
			continue;
		}

		if (current) current.lines.push(...introducedText(line));
	}

	// An empty path never starts a section, so this flushes the final one.
	startSection("");
	return sections;
}

export interface FileEditPayload {
	filePath?: string;
	content?: string;
	/** True when the payload was a patch body rather than discrete edit fields. */
	patch: boolean;
}

/**
 * Read the connector-neutral file edit a tool input carries.
 *
 * A patch payload (`apply_patch`) keeps its target paths *inside* the patch, so
 * the discrete `file_path`/`content` fields are absent; without this the
 * package and filesystem legs would see an edit with no path and no content.
 * The section that targets a package manifest is preferred so that a patch
 * touching several files still hands the manifest edit to the package leg.
 * Unknown tool names are not rewritten by this — it only reads the payload.
 */
export function readFileEditPayload(toolInput: Record<string, unknown>): FileEditPayload {
	const patch = patchBodyFrom(toolInput);
	if (patch !== undefined) {
		const explicitPath = firstString(toolInput, ["file_path", ...FILE_PATH_ALIASES]);
		const sections = parsePatchSections(patch);
		const chosen =
			(explicitPath === undefined
				? undefined
				: sections.find((section) => section.filePath === explicitPath)) ??
			sections.find((section) => isPackageManifestPath(section.filePath)) ??
			sections[0];
		return {
			filePath: explicitPath ?? chosen?.filePath,
			// No parseable section (e.g. only hunk markers): keep the raw body so
			// the content is still inspected rather than silently dropped.
			content: sections.length > 0 ? chosen?.content : patch,
			patch: true,
		};
	}

	return {
		filePath: firstString(toolInput, ["file_path", ...FILE_PATH_ALIASES]),
		content: firstString(toolInput, EDIT_CONTENT_ALIASES),
		patch: false,
	};
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

/**
 * Populate the canonical Edit fields from a patch payload. Returns false when
 * the payload is not a patch, so the discrete-field mapping still applies.
 */
function setPatchFields(toolInput: Record<string, unknown>): boolean {
	const patchPayload = readFileEditPayload(toolInput);
	if (!patchPayload.patch) return false;

	if (patchPayload.filePath !== undefined && patchPayload.filePath.trim() !== "") {
		toolInput.file_path = patchPayload.filePath;
	}
	const patchContent = patchPayload.content ?? "";
	if (patchContent.trim() !== "") {
		toolInput.new_string = patchContent;
		// Package and filesystem policy inspect `content` before `new_string`;
		// keep both aligned with the text the patch introduces.
		toolInput.content = patchContent;
	}
	return true;
}

/** Apply the Edit operation's field vocabulary to a tool input. */
function applyEditFields(toolInput: Record<string, unknown>): void {
	if (setPatchFields(toolInput)) return;

	setCanonicalField(toolInput, "file_path", FILE_PATH_ALIASES);
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
			setCanonicalField(toolInput, "file_path", FILE_PATH_ALIASES);
			setCanonicalField(toolInput, "content", ["text", "data", "new_string", "newString"]);
			break;
		case "Edit":
			// `apply_patch` payloads carry their paths and introduced text inside
			// the patch itself, so the canonical Edit fields are derived from the
			// patch when there is one.
			applyEditFields(toolInput);
			break;
		case "Read":
		case "Delete":
			setCanonicalField(toolInput, "file_path", FILE_PATH_ALIASES);
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
