/**
 * Diff-aware views of a file edit, for the agent-safety rules in
 * `threats/agent-safety.yaml`.
 *
 * ## Why
 *
 * A coding agent that is graded by tests, linters and CI can "pass" by weakening
 * the checks instead of fixing the code: skipping a test, deleting an assertion,
 * marking a CI step `continue-on-error`, lowering a coverage threshold or adding
 * `// @ts-nocheck`. Those strings are ordinary in the right place — a skipped
 * test that was already skipped, `expect(` in any test file — so matching the
 * written content alone would flag every test edit. What matters is the CHANGE:
 * which lines an edit adds and which it removes, and in which kind of file.
 *
 * This module turns a tool call (Write, Edit, MultiEdit, apply_patch, Delete)
 * into that change:
 *   - the lines each file gains and loses (a multiset line diff of the Edit's
 *     `old_string`/`new_string`, the patch's `+`/`-` lines, or — for a Write —
 *     the file on disk against the new content), and
 *   - the file's kind: test code, CI configuration, lint/type/coverage
 *     configuration, or source code.
 *
 * Rules declare `match_on: test_code | ci_config | quality_config |
 * source_code` plus a `diff` mode (see `Threat.diff`), and `deleted_test_file`
 * for a test file that is deleted or emptied. Older engines have no artifacts of
 * these types, so they never match these rules instead of misreading them as
 * plain content rules.
 *
 * ## Bounds
 *
 * Reading the previous version of a written file is local and bounded (regular
 * files up to 1 MiB, never following a symlink, never a FIFO or device); lines
 * are capped in length and count. None of the content leaves this process; the
 * verdict only carries the file path.
 */

import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { isAbsolute, resolve } from "node:path";
import type { ToolEvaluationRequest } from "../evaluator.js";
import { readFileEditPayload } from "../tool-normalization.js";
import type { Logger } from "../types.js";
import { nullLogger } from "../types.js";

/** Line-based views a rule can declare in `match_on`. */
export const EDIT_LINE_VIEWS = ["test_code", "ci_config", "quality_config", "source_code"] as const;
export type EditLineView = (typeof EDIT_LINE_VIEWS)[number];

/** Path view: a test file that the call deletes or empties of test cases. */
export const DELETED_TEST_FILE_VIEW = "deleted_test_file";

export const EDIT_VIEW_TYPES: ReadonlySet<string> = new Set<string>([
	...EDIT_LINE_VIEWS,
	DELETED_TEST_FILE_VIEW,
]);

export interface EditLineViewEntry {
	view: EditLineView;
	filePath: string;
	added: readonly string[];
	removed: readonly string[];
}

export interface EditViews {
	lines: EditLineViewEntry[];
	deletedTestFiles: string[];
	/** True when a bound cut the inspected lines short (reported, never silent). */
	truncated: boolean;
}

/** One file's change. `deleted` covers both deletion and emptying of tests. */
export interface FileChange {
	filePath: string;
	added: string[];
	removed: string[];
	deleted: boolean;
}

const MAX_LINE_LENGTH = 4096;
const MAX_LINES_PER_SIDE = 20_000;
const MAX_FILES_PER_CALL = 256;
const MAX_EXISTING_FILE_BYTES = 1024 * 1024;

const CODE_EXTENSION =
	/\.(?:[cm]?[jt]sx?|py|pyi|go|rb|java|kt|kts|scala|cs|fs|php|rs|swift|m|mm|c|cc|cpp|cxx|h|hh|hpp|ex|exs|erl|dart|lua|clj|cljs|groovy|r|jl|sh|bash|zsh|ps1|vue|svelte|bats)$/i;

/** A directory that, by convention, holds tests. */
const TEST_DIRECTORY = /(?:^|\/)(?:__tests?__|tests?|specs?|e2e|integration[-_]tests?)\//i;

/** File names that are tests by the conventions of the common test runners. */
const TEST_FILE_NAME =
	/(?:[._-](?:test|spec|tests|specs)\.[A-Za-z0-9]{1,5}$|(?:^|\/)test_[^/]{1,200}\.py$|_test\.(?:py|go|rb|exs)$|_spec\.rb$|(?:Test|Tests|Spec|IT)\.(?:java|kt|kts|scala|cs|php|swift|groovy)$|\.bats$)/;

/** Continuous-integration and git-hook definitions. */
const CI_CONFIG =
	/(?:^|\/)(?:\.github\/workflows\/[^/]{1,200}\.ya?ml|\.github\/actions\/[^/]{1,200}\/action\.ya?ml|\.gitlab-ci\.ya?ml|\.gitlab\/ci\/[^/]{1,200}\.ya?ml|\.circleci\/config\.ya?ml|azure-pipelines[^/]{0,100}\.ya?ml|\.azure-pipelines\/[^/]{1,200}\.ya?ml|Jenkinsfile[^/]{0,100}|bitbucket-pipelines\.ya?ml|\.travis\.ya?ml|\.buildkite\/[^/]{1,200}\.ya?ml|\.drone\.ya?ml|appveyor\.ya?ml|cloudbuild\.ya?ml|buildspec\.ya?ml|\.woodpecker(?:\.ya?ml|\/[^/]{1,200}\.ya?ml)|\.husky\/(?!_\/)[^/]{1,100}|\.?lefthook(?:-local)?\.ya?ml|\.pre-commit-config\.ya?ml)$/;

/** Lint, type-check, test-runner and coverage configuration. */
const QUALITY_CONFIG =
	/(?:^|\/)(?:package\.json|tsconfig(?:\.[^/]{1,100})?\.json|jsconfig\.json|biome\.jsonc?|\.eslintrc(?:\.[a-z]{2,5})?|eslint\.config\.[cm]?[jt]s|\.eslintignore|(?:jest|vitest|vite|karma|playwright|cypress)\.config\.[cm]?[jt]s|vitest\.workspace\.[cm]?[jt]s|\.mocharc(?:\.[a-z]{2,5})?|\.nycrc(?:\.[a-z]{2,5})?|\.c8rc(?:\.json)?|\.?codecov\.ya?ml|\.coveragerc|pyproject\.toml|setup\.cfg|tox\.ini|pytest\.ini|\.?mypy\.ini|\.?ruff\.toml|\.flake8|\.?pylintrc|\.golangci\.(?:ya?ml|toml|json)|phpunit\.xml(?:\.dist)?|phpstan\.neon(?:\.dist)?|\.rubocop\.ya?ml|\.?clippy\.toml|\.lintstagedrc(?:\.[a-z]{2,5})?|\.stylelintrc(?:\.[a-z]{2,5})?|sonar-project\.properties|\.semgrepignore)$/;

/**
 * A test case declaration in the common frameworks. Used to tell a test file
 * that still has tests from one whose tests were all removed.
 */
const TEST_DECLARATION =
	/(?:^|[\s;(])(?:it|test|describe|context|suite|specify|scenario)\s{0,2}(?:\.\s{0,2}\w{1,20}\s{0,2})?\(|\bdef\s{1,4}test\w{0,100}\s{0,2}\(|\bfunc\s{1,4}Test\w{0,100}\s{0,2}\(|@(?:Test|ParameterizedTest|RepeatedTest)\b|#\[(?:tokio::|async_std::)?test\b|\[(?:Test|Fact|Theory|TestMethod|TestCase)\b|\bfunction\s{1,4}test\w{0,100}\s{0,2}\(|@test\b/m;

function normalizedPath(filePath: string): string {
	return filePath.replace(/\\/g, "/");
}

export function isTestFile(filePath: string): boolean {
	const path = normalizedPath(filePath);
	return CODE_EXTENSION.test(path) && (TEST_DIRECTORY.test(path) || TEST_FILE_NAME.test(path));
}

/** The line views a file of this path belongs to (empty: not inspected). */
export function viewsForPath(filePath: string): EditLineView[] {
	const path = normalizedPath(filePath);
	const views: EditLineView[] = [];
	if (isTestFile(path)) views.push("test_code");
	if (CI_CONFIG.test(path)) views.push("ci_config");
	if (QUALITY_CONFIG.test(path)) views.push("quality_config");
	if (CODE_EXTENSION.test(path)) views.push("source_code");
	return views;
}

function hasTestDeclaration(text: string): boolean {
	return TEST_DECLARATION.test(text);
}

interface BoundedLines {
	lines: string[];
	truncated: boolean;
}

function splitLines(text: string): BoundedLines {
	if (text === "") return { lines: [], truncated: false };
	const raw = text.split(/\r?\n/);
	const truncated = raw.length > MAX_LINES_PER_SIDE;
	const lines = (truncated ? raw.slice(0, MAX_LINES_PER_SIDE) : raw).map((line) =>
		line.length > MAX_LINE_LENGTH ? line.slice(0, MAX_LINE_LENGTH) : line,
	);
	return { lines, truncated };
}

/**
 * Multiset line difference: the lines `after` gained and the lines it lost.
 * Order-insensitive on purpose — moving a line is not adding or removing it.
 */
export function lineDiff(
	before: string,
	after: string,
): { added: string[]; removed: string[]; truncated: boolean } {
	const old = splitLines(before);
	const next = splitLines(after);
	const remaining = new Map<string, number>();
	for (const line of old.lines) remaining.set(line, (remaining.get(line) ?? 0) + 1);
	const added: string[] = [];
	for (const line of next.lines) {
		const count = remaining.get(line) ?? 0;
		if (count > 0) remaining.set(line, count - 1);
		else added.push(line);
	}
	const removed: string[] = [];
	for (const [line, count] of remaining) {
		for (let i = 0; i < count; i++) removed.push(line);
	}
	return { added, removed, truncated: old.truncated || next.truncated };
}

function stringField(input: Record<string, unknown>, keys: readonly string[]): string | undefined {
	for (const key of keys) {
		const value = input[key];
		if (typeof value === "string") return value;
	}
	return undefined;
}

const OLD_TEXT_KEYS = ["old_string", "oldString", "oldText", "old_str"] as const;
const NEW_TEXT_KEYS = ["new_string", "newString", "newText", "new_str"] as const;
const PATH_KEYS = ["file_path", "filePath", "path", "target_file", "targetFile"] as const;

/** Previous content of a file about to be overwritten, or undefined when unknown. */
async function readExistingFile(filePath: string, cwd: string): Promise<string | undefined> {
	const absolute = isAbsolute(filePath) ? filePath : resolve(cwd, filePath);
	const flags = constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0);
	let handle: Awaited<ReturnType<typeof open>> | undefined;
	try {
		handle = await open(absolute, flags);
		const stats = await handle.stat();
		if (!stats.isFile() || stats.size > MAX_EXISTING_FILE_BYTES) return undefined;
		const buffer = Buffer.alloc(stats.size);
		let offset = 0;
		while (offset < buffer.length) {
			const { bytesRead } = await handle.read(buffer, offset, buffer.length - offset, offset);
			if (bytesRead === 0) break;
			offset += bytesRead;
		}
		return buffer.subarray(0, offset).toString("utf8");
	} catch {
		// Missing (a new file), unreadable, a symlink or a special file: the
		// previous content is unknown and the whole new content counts as added.
		return undefined;
	} finally {
		await handle?.close().catch(() => undefined);
	}
}

/** `*** Add File:` / `*** Update File:` / `*** Delete File:` (Codex apply_patch). */
const CODEX_FILE_HEADER = /^\*\*\* (Add|Update|Delete) File: (.+)$/;

function diffHeaderPath(raw: string): string {
	const path = (raw.split("\t")[0] ?? "").trim().replace(/^"|"$/g, "");
	return path === "/dev/null" ? "" : path.replace(/^[ab]\//, "");
}

/**
 * The per-file added and removed lines of a patch, in either the Codex
 * `*** Begin Patch` dialect or a unified diff. Context lines are ignored.
 */
export function patchChanges(patch: string): FileChange[] {
	const changes: FileChange[] = [];
	let current: FileChange | undefined;
	const lines = patch.split(/\r?\n/);
	const flush = (): void => {
		if (current) changes.push(current);
		current = undefined;
	};
	for (let index = 0; index < lines.length; index++) {
		const line = lines[index] ?? "";
		const codex = CODEX_FILE_HEADER.exec(line);
		if (codex) {
			flush();
			const filePath = (codex[2] ?? "").trim();
			if (codex[1] === "Delete") {
				changes.push({ filePath, added: [], removed: [], deleted: true });
			} else {
				current = { filePath, added: [], removed: [], deleted: false };
			}
			continue;
		}
		if (line.startsWith("--- ") && (lines[index + 1] ?? "").startsWith("+++ ")) {
			flush();
			const oldPath = diffHeaderPath(line.slice(4));
			const newPath = diffHeaderPath((lines[index + 1] ?? "").slice(4));
			index++;
			const filePath = newPath || oldPath;
			if (filePath) current = { filePath, added: [], removed: [], deleted: newPath === "" };
			continue;
		}
		if (line.startsWith("diff --git ") || line.startsWith("*** ")) continue;
		if (!current || line.startsWith("@@")) continue;
		if (line.startsWith("+")) current.added.push(line.slice(1));
		else if (line.startsWith("-")) current.removed.push(line.slice(1));
	}
	flush();
	return changes;
}

function patchBody(input: Record<string, unknown>): string | undefined {
	for (const key of ["patch", "patchText", "input", "command"] as const) {
		const value = input[key];
		if (typeof value === "string" && /^(?:\*\*\* |\+\+\+ |--- |diff --git )/m.test(value)) {
			return value;
		}
	}
	return undefined;
}

function editsFrom(input: Record<string, unknown>): Array<{ old: string; next: string }> | null {
	if (!Array.isArray(input.edits)) return null;
	const edits: Array<{ old: string; next: string }> = [];
	for (const edit of input.edits) {
		if (!edit || typeof edit !== "object") continue;
		const record = edit as Record<string, unknown>;
		edits.push({
			old: stringField(record, OLD_TEXT_KEYS) ?? "",
			next: stringField(record, NEW_TEXT_KEYS) ?? "",
		});
	}
	return edits;
}

function snippetChange(
	filePath: string,
	edits: Array<{ old: string; next: string }>,
): FileChange & { truncated: boolean } {
	const change = { filePath, added: [] as string[], removed: [] as string[], deleted: false };
	let truncated = false;
	for (const edit of edits) {
		const diff = lineDiff(edit.old, edit.next);
		change.added.push(...diff.added);
		change.removed.push(...diff.removed);
		truncated ||= diff.truncated;
	}
	return { ...change, truncated };
}

/** The file changes a normalized tool call makes. */
async function fileChangesFor(
	request: ToolEvaluationRequest,
	cwd: string = process.cwd(),
): Promise<{ changes: FileChange[]; truncated: boolean }> {
	const input = request.toolInput;
	const filePath = stringField(input, PATH_KEYS);
	switch (request.toolName) {
		case "Delete":
			return filePath
				? { changes: [{ filePath, added: [], removed: [], deleted: true }], truncated: false }
				: { changes: [], truncated: false };
		case "Write": {
			if (!filePath || viewsForPath(filePath).length === 0) {
				return { changes: [], truncated: false };
			}
			const content = typeof input.content === "string" ? input.content : "";
			const previous = await readExistingFile(filePath, cwd);
			const diff = lineDiff(previous ?? "", content);
			const emptied =
				previous !== undefined &&
				isTestFile(filePath) &&
				hasTestDeclaration(previous) &&
				!hasTestDeclaration(content);
			return {
				changes: [{ filePath, added: diff.added, removed: diff.removed, deleted: emptied }],
				truncated: diff.truncated,
			};
		}
		case "Edit":
		case "MultiEdit": {
			if (readFileEditPayload(input).patch) {
				const body = patchBody(input);
				return { changes: body ? patchChanges(body) : [], truncated: false };
			}
			if (!filePath) return { changes: [], truncated: false };
			const edits = editsFrom(input) ?? [
				{
					old: stringField(input, OLD_TEXT_KEYS) ?? "",
					next: stringField(input, NEW_TEXT_KEYS) ?? "",
				},
			];
			const { truncated, ...change } = snippetChange(filePath, edits);
			return { changes: [change], truncated };
		}
		default:
			return { changes: [], truncated: false };
	}
}

/**
 * Build the edit views for one tool call. Never throws: a failure is logged and
 * yields no views (the ordinary content rules still inspect the written text).
 */
export async function buildEditViews(
	request: ToolEvaluationRequest,
	logger: Logger = nullLogger,
	cwd: string = process.cwd(),
): Promise<EditViews> {
	const views: EditViews = { lines: [], deletedTestFiles: [], truncated: false };
	try {
		const { changes, truncated } = await fileChangesFor(request, cwd);
		views.truncated = truncated || changes.length > MAX_FILES_PER_CALL;
		for (const change of changes.slice(0, MAX_FILES_PER_CALL)) {
			if (change.deleted && isTestFile(change.filePath)) {
				views.deletedTestFiles.push(change.filePath);
			}
			if (change.added.length === 0 && change.removed.length === 0) continue;
			for (const view of viewsForPath(change.filePath)) {
				views.lines.push({
					view,
					filePath: change.filePath,
					added: change.added,
					removed: change.removed,
				});
			}
		}
	} catch (error) {
		logger.warn("Agent-safety edit inspection did not run; edit-diff rules were skipped", {
			tool: request.toolName,
			errorType: error instanceof Error ? error.name : typeof error,
		});
		return { lines: [], deletedTestFiles: [], truncated: true };
	}
	if (views.truncated) {
		logger.warn(
			"Agent-safety edit inspection covered only part of this edit (size bound reached)",
			{ tool: request.toolName },
		);
	}
	return views;
}
