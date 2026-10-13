/**
 * OpenCode tool input extraction mapped onto @singularityrd/aidr-core artifact extractors.
 */

import {
	type Artifact,
	extractFromBash,
	extractFromEdit,
	extractFromUnknownTool,
	extractFromWebFetch,
	extractFromWrite,
} from "@singularityrd/aidr-core";

function asString(value: unknown): string | undefined {
	return typeof value === "string" ? value : undefined;
}

/** Resolve a relative glob against its search root: `~/.ssh` + `id_*` is `~/.ssh/id_*`. */
function joinSearchPath(root: string, pattern: string): string {
	if (pattern.startsWith("/") || pattern.startsWith("~")) return pattern;
	return `${root.replace(/\/+$/, "")}/${pattern.replace(/^\.\//, "")}`;
}

function asNumber(value: unknown): number | undefined {
	return typeof value === "number" ? value : undefined;
}

export function extractFromOpenCodeTool(
	toolName: string,
	args: Record<string, unknown>,
): Artifact[] | null {
	switch (toolName) {
		case "bash": {
			const command = asString(args.command) ?? "";
			return command ? extractFromBash(command) : null;
		}
		case "webfetch": {
			const url = asString(args.url) ?? "";
			return url ? extractFromWebFetch({ url }) : null;
		}
		case "write": {
			const filePath = asString(args.filePath) ?? "";
			if (!filePath) return null;
			return extractFromWrite({
				file_path: filePath,
				content: asString(args.content) ?? "",
			});
		}
		case "edit": {
			const filePath = asString(args.filePath) ?? "";
			if (!filePath) return null;
			return extractFromEdit({
				file_path: filePath,
				old_string: asString(args.oldString) ?? "",
				new_string: asString(args.newString) ?? "",
			});
		}
		case "read": {
			const filePath = asString(args.filePath) ?? "";
			if (!filePath) return null;
			return [{ type: "file_path", value: filePath, context: "read" }];
		}
		case "glob": {
			// The search root and the pattern resolved against it are both paths
			// the call reads, so both go through the file-path rules.
			const pattern = asString(args.pattern) ?? "";
			const root = asString(args.path) ?? "";
			const artifacts: Artifact[] = [];
			if (pattern) artifacts.push({ type: "file_path", value: pattern, context: "glob_pattern" });
			if (root) {
				artifacts.push({ type: "file_path", value: root, context: "glob_root" });
				if (pattern) {
					artifacts.push({
						type: "file_path",
						value: joinSearchPath(root, pattern),
						context: "glob_pattern",
					});
				}
			}
			return artifacts.length > 0 ? artifacts : null;
		}
		case "grep": {
			const pattern = asString(args.pattern) ?? "";
			const root = asString(args.path) ?? "";
			const include = asString(args.include);
			const artifacts: Artifact[] = [];
			if (pattern) artifacts.push({ type: "content", value: pattern, context: "grep_pattern" });
			if (root) artifacts.push({ type: "file_path", value: root, context: "grep_root" });
			if (include) {
				artifacts.push({ type: "file_path", value: include, context: "grep_include" });
				if (root) {
					artifacts.push({
						type: "file_path",
						value: joinSearchPath(root, include),
						context: "grep_include",
					});
				}
			}
			return artifacts.length > 0 ? artifacts : null;
		}
		case "ls":
		case "list": {
			// `list` is OpenCode's directory-listing tool; `ls` is the older name.
			const dir = asString(args.path) ?? asString(args.directoryPath) ?? "";
			if (!dir) return null;
			return [{ type: "file_path", value: dir, context: "list" }];
		}
		case "codesearch": {
			const query = asString(args.query) ?? "";
			return query ? [{ type: "content", value: query, context: "codesearch_query" }] : null;
		}
		case "websearch": {
			const query = asString(args.query) ?? "";
			return query ? [{ type: "content", value: query, context: "websearch_query" }] : null;
		}
		case "question": {
			const selected = Array.isArray(args.selected) ? args.selected : [];
			const joined = selected
				.map((item) => (typeof item === "string" ? item : null))
				.filter((item): item is string => item !== null)
				.join("\n");
			if (!joined) return null;
			return [{ type: "content", value: joined, context: "question_options" }];
		}
		case "task": {
			const prompt = asString(args.prompt) ?? "";
			const desc = asString(args.description) ?? "";
			const payload = [desc, prompt].filter(Boolean).join("\n\n");
			return payload ? [{ type: "content", value: payload, context: "task" }] : null;
		}
		case "read_lines": {
			const filePath = asString(args.filePath) ?? "";
			if (!filePath) return null;
			const offset = asNumber(args.offset);
			const limit = asNumber(args.limit);
			return [
				{
					type: "file_path",
					value: `${filePath}:${offset ?? 1}:${limit ?? 0}`,
					context: "read_lines",
				},
			];
		}
		case "apply_patch":
		case "patch":
			// `patch` is the same patchText tool under the name some OpenCode builds
			// expose. Keep the bounded generic view for content heuristics; the
			// shared core normalizer aliases both names to Edit and parses patchText
			// into canonical Edit path/content fields.
			return extractFromUnknownTool(`opencode:${toolName}`, args);
		case "multiedit": {
			const filePath = asString(args.filePath) ?? "";
			const edits = Array.isArray(args.edits) ? args.edits : [];
			if (!filePath) return extractFromUnknownTool("opencode:multiedit", args);
			const artifacts: Artifact[] = [{ type: "file_path", value: filePath, context: "edit" }];
			for (const edit of edits) {
				const record = edit && typeof edit === "object" ? (edit as Record<string, unknown>) : {};
				artifacts.push(
					...extractFromEdit({
						file_path: filePath,
						old_string: asString(record.oldString) ?? "",
						new_string: asString(record.newString) ?? "",
					}),
				);
			}
			return artifacts;
		}
		default:
			return extractFromUnknownTool(`opencode:${toolName || "unknown"}`, args);
	}
}
