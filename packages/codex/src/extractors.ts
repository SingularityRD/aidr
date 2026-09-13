/**
 * Artifact extraction for Codex tool calls.
 *
 * Codex shares Claude Code's tool vocabulary for shell work (`Bash`) but uses
 * `apply_patch` for file edits, and — verified against codex-cli 0.141.0 — it
 * sends the **patch text in `tool_input.command`**, whereas Claude Code's
 * `Edit`/`Write` tools use `file_path` / `old_string` / `new_string`.
 *
 * Passing `apply_patch` straight to core's `extractFromToolCall` would be a
 * silent detection hole: it would fall through to the unknown-tool path and the
 * patch body would never be inspected. This module closes that gap and then
 * delegates everything else to the shared extractor so all connectors agree on
 * what a given tool call means.
 */

import {
	type Artifact,
	boundArtifact,
	extractFromBash,
	extractFromToolCall,
} from "@singularityrd/aidr-core";

/** `apply_patch` payload: `*** Begin Patch / *** Update File: <path> / +lines`. */
const PATCH_FILE_RE = /^\*\*\* (?:Add|Update|Delete) File: (.+)$/gm;

function asString(value: unknown): string {
	return typeof value === "string" ? value : "";
}

/**
 * Extract from an `apply_patch` call. The patch text is bounded exactly like a
 * shell command so a hostile caller cannot force unbounded matching work.
 */
export function extractFromApplyPatch(toolInput: Record<string, unknown>): Artifact[] {
	const patch = asString(toolInput.command) || asString(toolInput.patch) || asString(toolInput.input);
	if (!patch.trim()) return [];

	const artifacts: Artifact[] = [
		{ type: "content", value: boundArtifact("apply_patch", patch), context: "apply_patch" },
	];

	// Target paths carry their own signal (e.g. writes into ~/.ssh or /etc) and
	// must be inspected independently of the patch body.
	const seen = new Set<string>();
	for (const match of patch.matchAll(PATCH_FILE_RE)) {
		const filePath = match[1]?.trim();
		if (!filePath || seen.has(filePath)) continue;
		seen.add(filePath);
		artifacts.push({ type: "file_path", value: boundArtifact("apply_patch path", filePath) });
	}

	return artifacts;
}

/**
 * Extract artifacts for any Codex tool call. `Shell`/`Bash` are handled in
 * common with the other connectors; `apply_patch` is Codex-specific.
 */
export function extractFromCodexTool(
	toolName: string,
	toolInput: Record<string, unknown>,
): Artifact[] {
	switch (toolName) {
		case "apply_patch":
			return extractFromApplyPatch(toolInput);
		case "shell":
		case "local_shell":
			// Codex has used lower-case shell tool names for the local exec tool.
			return extractFromBash(asString(toolInput.command));
		default:
			return extractFromToolCall(toolName, toolInput);
	}
}
