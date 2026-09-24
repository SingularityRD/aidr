import { commandFromValue } from "./command-argv.js";
import type { ToolEvaluationRequest } from "./evaluator.js";
import { extractFromToolCall } from "./extractors.js";
import { isPackageManifestPath } from "./package-extractor.js";
import type { Artifact } from "./types.js";

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
 * `apply_patch` maps to `Edit` because connectors emit it as their file-editing
 * tool. Its patch body may arrive in `command`, `input`, `patch`, or
 * `patchText`; normalize those host shapes before package, policy, AMSI, and
 * filesystem inspection.
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

const BASH_COMMAND_ALIASES = ["cmd", "shellCommand", "shell_command"] as const;
const WRITE_CONTENT_ALIASES = ["text", "data", "new_string", "newString"] as const;
const WEB_FETCH_URL_ALIASES = ["uri", "href"] as const;

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
	"streamContent",
	"stream_content",
	"replacement",
	"text",
	"data",
] as const;

/**
 * Turn argv-array shell commands into the command string the core inspects,
 * in place, for `command` and its aliases. Returns false when any present
 * command field is neither a string nor a well-formed argv: the executed
 * command is then unknowable and the evaluator must deny.
 */
function normalizeCommandFields(input: Record<string, unknown>): boolean {
	let wellFormed = true;
	for (const key of ["command", ...BASH_COMMAND_ALIASES]) {
		if (input[key] === undefined) continue;
		const result = commandFromValue(input[key]);
		if (result.ok) input[key] = result.command;
		else wellFormed = false;
	}
	return wellFormed;
}

/** Conflicting populated aliases make it unknowable which value the host executes. */
function hasConflictingStringAliases(
	input: Record<string, unknown>,
	keys: readonly string[],
): boolean {
	const values = new Set(
		keys
			.map((key) => input[key])
			.filter((value): value is string => typeof value === "string" && value.trim() !== ""),
	);
	return values.size > 1;
}

/** Codex patch section header: `*** Add File: <path>` / `*** Update File: <path>`. */
const CODEX_PATCH_HEADER_RE = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/;

/** Unified-diff new-file header: `+++ b/<path>` (OpenClaw's apply_patch dialect). */
const UNIFIED_DIFF_HEADER_RE = /^\+\+\+\s+(.+)$/;
const UNIFIED_DIFF_OLD_HEADER_RE = /^---\s+(.+)$/;

/** Patch framing that carries no file content. */
const PATCH_SCAFFOLD_RE = /^(?:\*\*\* (?:Begin|End) Patch\b|\*\*\* End of File\b)/;

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
 * Find the patch body inside a payload. `patch` and `patchText` are patch fields
 * by definition; `command`/`input` are only treated as patches when they carry
 * patch framing because those names are shared with other operations.
 */
interface PatchBody {
	body?: string;
	ambiguous: boolean;
}

function patchBodyFrom(toolInput: Record<string, unknown>): PatchBody {
	const explicit: string[] = [];
	for (const key of ["patch", "patchText"] as const) {
		const body = toolInput[key];
		if (typeof body === "string" && body.trim() !== "") explicit.push(body);
	}
	const framed: string[] = [];
	for (const key of ["command", "input"] as const) {
		const value = toolInput[key];
		if (typeof value === "string" && looksLikePatch(value)) framed.push(value);
	}
	// A host may execute `command` even when a second `patch` field exists.
	// Inspecting only the latter would let conflicting aliases hide the write.
	const distinct = new Set([...explicit, ...framed]);
	return {
		body: explicit[0] ?? framed[0],
		ambiguous: distinct.size > 1,
	};
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
interface ParsedPatchSections {
	sections: PatchSection[];
	complete: boolean;
}

function parseCodexPatchSections(lines: string[]): ParsedPatchSections {
	const sections: PatchSection[] = [];
	let current: { filePath: string; lines: string[] } | undefined;
	let complete = true;

	const startSection = (filePath: string): void => {
		if (current) {
			sections.push({ filePath: current.filePath, content: current.lines.join("\n") });
		}
		if (filePath === "") complete = false;
		current = filePath === "" ? undefined : { filePath, lines: [] };
	};

	for (const line of lines) {
		const codexHeader = CODEX_PATCH_HEADER_RE.exec(line);
		if (codexHeader) {
			startSection((codexHeader[1] ?? "").trim());
			continue;
		}
		if (PATCH_SCAFFOLD_RE.test(line)) continue;
		if (line.startsWith("*** ")) {
			// Unknown patch directives (for example a move/rename target) change
			// file semantics that this parser cannot safely represent.
			complete = false;
			continue;
		}

		if (current) {
			current.lines.push(...introducedText(line));
		} else if (line.trim() !== "") {
			complete = false;
		}
	}

	if (current) sections.push({ filePath: current.filePath, content: current.lines.join("\n") });
	return { sections, complete: complete && sections.length > 0 };
}

/**
 * Parse unified diffs only when old/new headers are paired and every hunk is
 * complete. Hunk counts keep an added source line such as `+++ note` from being
 * mistaken for the next file's header.
 */
function parseUnifiedDiffSections(lines: string[]): ParsedPatchSections {
	const sections: PatchSection[] = [];
	let current: { filePath: string; lines: string[] } | undefined;
	let pendingOldPath: string | undefined;
	let awaitingFileHeader = false;
	let oldRemaining: number | undefined;
	let newRemaining: number | undefined;
	let complete = true;

	const flush = (): void => {
		if (current) sections.push({ filePath: current.filePath, content: current.lines.join("\n") });
		current = undefined;
	};

	const diffPath = (rawPath: string): string | undefined => {
		const trimmed = rawPath.trim();
		// Git's quoted path escaping is not decoded here; do not guess a target.
		if (trimmed.startsWith('"')) return undefined;
		return normalizeDiffPath(trimmed);
	};

	for (const line of lines) {
		if (oldRemaining !== undefined && newRemaining !== undefined) {
			if (oldRemaining === 0 && newRemaining === 0) {
				oldRemaining = undefined;
				newRemaining = undefined;
			} else if (line.startsWith("\\")) {
				continue;
			} else if (line.startsWith("+")) {
				current?.lines.push(line.slice(1));
				newRemaining--;
				if (!current || newRemaining < 0) complete = false;
				continue;
			} else if (line.startsWith("-")) {
				oldRemaining--;
				if (oldRemaining < 0) complete = false;
				continue;
			} else if (line.startsWith(" ")) {
				current?.lines.push(line.slice(1));
				oldRemaining--;
				newRemaining--;
				if (!current || oldRemaining < 0 || newRemaining < 0) complete = false;
				continue;
			} else {
				complete = false;
				oldRemaining = undefined;
				newRemaining = undefined;
			}
		}

		if (line.startsWith("diff --git ")) {
			if (pendingOldPath !== undefined) complete = false;
			flush();
			awaitingFileHeader = true;
			continue;
		}

		const oldHeader = UNIFIED_DIFF_OLD_HEADER_RE.exec(line);
		if (oldHeader) {
			if (pendingOldPath !== undefined) complete = false;
			pendingOldPath = diffPath(oldHeader[1] ?? "");
			if (pendingOldPath === undefined) complete = false;
			awaitingFileHeader = true;
			continue;
		}

		const newHeader = UNIFIED_DIFF_HEADER_RE.exec(line);
		if (newHeader) {
			if (pendingOldPath === undefined) {
				complete = false;
				continue;
			}
			const newPath = diffPath(newHeader[1] ?? "");
			if (newPath === undefined) {
				complete = false;
				pendingOldPath = undefined;
				continue;
			}
			const filePath = newPath || pendingOldPath;
			if (filePath === "") {
				complete = false;
			} else {
				flush();
				current = { filePath, lines: [] };
			}
			pendingOldPath = undefined;
			awaitingFileHeader = false;
			continue;
		}

		const hunk = /^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/.exec(line);
		if (hunk) {
			if (!current) {
				complete = false;
				continue;
			}
			oldRemaining = hunk[2] === undefined ? 1 : Number(hunk[2]);
			newRemaining = hunk[4] === undefined ? 1 : Number(hunk[4]);
			continue;
		}

		if (
			line === "" ||
			line.startsWith("\\ No newline at end of file") ||
			line.startsWith("index ") ||
			line.startsWith("new file mode ") ||
			line.startsWith("deleted file mode ") ||
			line.startsWith("old mode ") ||
			line.startsWith("new mode ") ||
			line.startsWith("similarity index ") ||
			line.startsWith("dissimilarity index ")
		) {
			continue;
		}

		// Rename/copy metadata needs more than one target path. Reject rather
		// than inspecting only one side of that operation.
		if (/^(?:rename|copy) (?:from|to) /.test(line)) complete = false;
		else complete = false;
	}

	if (oldRemaining !== undefined && (oldRemaining !== 0 || newRemaining !== 0)) complete = false;
	if (pendingOldPath !== undefined || awaitingFileHeader) complete = false;
	flush();
	return { sections, complete: complete && sections.length > 0 };
}

function parsePatchSections(patch: string): ParsedPatchSections {
	const lines = patch.split(/\r?\n/);
	const isCodexPatch = lines.some(
		(line) => PATCH_SCAFFOLD_RE.test(line) || CODEX_PATCH_HEADER_RE.test(line),
	);
	return isCodexPatch ? parseCodexPatchSections(lines) : parseUnifiedDiffSections(lines);
}

export interface FileEditPayload {
	filePath?: string;
	content?: string;
	/** Every file section represented by a parsed patch, not only the primary edit. */
	edits?: PatchSection[];
	/** True when a patch body could not be completely represented for inspection. */
	parseFailed?: boolean;
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
	const patchBody = patchBodyFrom(toolInput);
	const patch = patchBody.body;
	if (patch !== undefined) {
		const explicitPath = firstString(toolInput, ["file_path", ...FILE_PATH_ALIASES]);
		const parsed = parsePatchSections(patch);
		const sections = parsed.sections;
		const chosen =
			(explicitPath === undefined
				? undefined
				: sections.find((section) => section.filePath === explicitPath)) ??
			sections.find((section) => isPackageManifestPath(section.filePath)) ??
			sections[0];
		return {
			// A patch's own section headers are authoritative. A side-channel path
			// field must not redirect filesystem policy away from the actual target.
			filePath: chosen?.filePath,
			// No parseable section (e.g. only hunk markers): keep the raw body so
			// the content is still inspected rather than silently dropped.
			content: sections.length > 0 ? chosen?.content : patch,
			edits: sections,
			parseFailed: patchBody.ambiguous || !parsed.complete,
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

function addArtifact(artifacts: Artifact[], artifact: Artifact): void {
	if (
		artifacts.some(
			(existing) =>
				existing.type === artifact.type &&
				existing.value === artifact.value &&
				existing.context === artifact.context,
		)
	) {
		return;
	}
	artifacts.push(artifact);
}

/**
 * Populate the canonical Edit fields from a patch payload. Returns false when
 * the payload is not a patch, so the discrete-field mapping still applies.
 */
function setPatchFields(toolInput: Record<string, unknown>): boolean {
	const patchPayload = readFileEditPayload(toolInput);
	if (!patchPayload.patch) return false;
	if (patchPayload.parseFailed) {
		toolInput.__aidr_patch_parse_failed = true;
		return true;
	}

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
	delete toolInput.__aidr_patch_parse_failed;
	return true;
}

/** Apply the Edit operation's field vocabulary to a tool input. */
function applyEditFields(toolInput: Record<string, unknown>): void {
	if (setPatchFields(toolInput)) return;

	setCanonicalField(toolInput, "file_path", FILE_PATH_ALIASES);
	setCanonicalField(toolInput, "old_string", ["oldString", "oldText"]);
	setCanonicalField(
		toolInput,
		"new_string",
		EDIT_CONTENT_ALIASES.filter((key) => key !== "new_string"),
	);
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
	const isApplyPatch = request.toolName.trim().toLowerCase() === "apply_patch";

	switch (toolName) {
		case "Bash":
			if (!normalizeCommandFields(toolInput)) {
				toolInput.__aidr_malformed_command = true;
			}
			if (hasConflictingStringAliases(toolInput, ["command", ...BASH_COMMAND_ALIASES])) {
				toolInput.__aidr_input_normalization_failed = true;
			}
			setCanonicalField(toolInput, "command", BASH_COMMAND_ALIASES);
			break;
		case "Write":
			if (hasConflictingStringAliases(toolInput, ["file_path", ...FILE_PATH_ALIASES])) {
				toolInput.__aidr_input_normalization_failed = true;
			}
			if (hasConflictingStringAliases(toolInput, ["content", ...WRITE_CONTENT_ALIASES])) {
				toolInput.__aidr_input_normalization_failed = true;
			}
			setCanonicalField(toolInput, "file_path", FILE_PATH_ALIASES);
			setCanonicalField(toolInput, "content", WRITE_CONTENT_ALIASES);
			break;
		case "Edit":
			// `apply_patch` payloads carry their paths and introduced text inside
			// the patch itself, so the canonical Edit fields are derived from the
			// patch when there is one.
			const hasPatchPayload = readFileEditPayload(toolInput).patch;
			if (isApplyPatch && !hasPatchPayload) {
				toolInput.__aidr_patch_parse_failed = true;
			} else {
				if (
					!hasPatchPayload &&
					hasConflictingStringAliases(toolInput, ["file_path", ...FILE_PATH_ALIASES])
				) {
					toolInput.__aidr_input_normalization_failed = true;
				}
				if (!hasPatchPayload && hasConflictingStringAliases(toolInput, EDIT_CONTENT_ALIASES)) {
					toolInput.__aidr_input_normalization_failed = true;
				}
				applyEditFields(toolInput);
			}
			break;
		case "Read":
		case "Delete":
			if (hasConflictingStringAliases(toolInput, ["file_path", ...FILE_PATH_ALIASES])) {
				toolInput.__aidr_input_normalization_failed = true;
			}
			setCanonicalField(toolInput, "file_path", FILE_PATH_ALIASES);
			break;
		case "WebFetch":
			if (hasConflictingStringAliases(toolInput, ["url", ...WEB_FETCH_URL_ALIASES])) {
				toolInput.__aidr_input_normalization_failed = true;
			}
			setCanonicalField(toolInput, "url", WEB_FETCH_URL_ALIASES);
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
			addArtifact(artifacts, artifact);
		}
		if (toolName === "Edit") {
			const patchPayload = readFileEditPayload(toolInput);
			if (patchPayload.patch && !patchPayload.parseFailed) {
				for (const edit of patchPayload.edits ?? []) {
					for (const artifact of extractFromToolCall("Edit", {
						file_path: edit.filePath,
						new_string: edit.content,
					})) {
						addArtifact(artifacts, artifact);
					}
				}
			}
		}
	}

	return { ...request, toolName, toolInput, artifacts };
}
