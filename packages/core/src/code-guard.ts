/**
 * Code guard: language-aware inspection of the code an agent writes or runs.
 *
 * Two rule families share this leg, both defined as data in `threats/*.yaml`
 * with `match_on: "code:<language>"`:
 *
 *  - AI model supply chain (`threats/ai-supply-chain.yaml`): unsafe model
 *    loading and unvetted model sources. Their matches become ordinary
 *    heuristic signals, so the rule's own `action` decides (`ask`/`deny`).
 *  - Secure-code guardrails (`threats/secure-code.yaml`, every category that
 *    starts with `secure_code`): advisory. They never decide a verdict by
 *    themselves; `secure_code.action` turns them into a warning (default) or a
 *    review. Hard-coded credentials (`SCG-SECRET-001`) reuse the shared secret
 *    detectors in `prompt-protection.ts` instead of a pattern of their own.
 *
 * Only text the call ADDS is inspected: a Write's content, the lines of an
 * Edit/MultiEdit `new_string` that are not in its `old_string`, the `+` lines
 * of a patch, a NotebookEdit cell, and code a Bash command runs or writes
 * (`python -c`, Python heredocs, `cat > file <<EOF`). Every rule is gated by
 * the file's language, so documentation that *mentions* `verify=False` is not
 * treated as code.
 *
 * Cost: every pattern is bounded (see the rule files); the text inspected is
 * already capped by the extractors' per-call inspection budget, and a call
 * over that budget is denied before this leg runs.
 */

import { basename, extname } from "node:path";
import { isTrustedModelSourceMatch, type TrustedModelSources } from "./ai-supply-chain.js";
import { locateSecrets } from "./prompt-protection.js";
import type { HeuristicMatch, SecureCodeConfig, Threat, Verdict, VerdictWarning } from "./types.js";

// ── Languages ─────────────────────────────────────────────────────────

/** `match_on` prefix for rules evaluated against code in one language. */
export const CODE_MATCH_PREFIX = "code:";

const LANGUAGE_BY_EXTENSION: Readonly<Record<string, string>> = {
	".py": "python",
	".pyw": "python",
	".pyi": "python",
	".ipynb": "python",
	".js": "javascript",
	".mjs": "javascript",
	".cjs": "javascript",
	".jsx": "javascript",
	".ts": "typescript",
	".mts": "typescript",
	".cts": "typescript",
	".tsx": "typescript",
	".go": "go",
	".java": "java",
	".kt": "kotlin",
	".kts": "kotlin",
	".rb": "ruby",
	".php": "php",
	".cs": "csharp",
	".rs": "rust",
	".sh": "shell",
	".bash": "shell",
	".zsh": "shell",
	".ksh": "shell",
	".ps1": "powershell",
	".psm1": "powershell",
	".yml": "yaml",
	".yaml": "yaml",
	".json": "json",
	".mk": "makefile",
	".dockerfile": "dockerfile",
	".env": "dotenv",
};

const SHELL_DOTFILES: ReadonlySet<string> = new Set([
	".bashrc",
	".bash_profile",
	".zshrc",
	".zprofile",
	".profile",
]);

/** The language rules for `filePath` are gated on, or null when no code rule applies. */
export function codeLanguageForPath(filePath: string): string | null {
	const name = basename(filePath.replace(/\\/g, "/"));
	const lower = name.toLowerCase();
	if (lower === "dockerfile" || lower === "containerfile" || lower.startsWith("dockerfile.")) {
		return "dockerfile";
	}
	if (lower === "makefile" || lower === "gnumakefile") return "makefile";
	if (lower === ".env" || lower.startsWith(".env.")) return "dotenv";
	if (SHELL_DOTFILES.has(lower)) return "shell";
	return LANGUAGE_BY_EXTENSION[extname(lower)] ?? null;
}

// ── Rule set ──────────────────────────────────────────────────────────

/** Built-in secure-code rule backed by the shared secret detectors. */
export const SECRET_RULE_ID = "SCG-SECRET-001";
const SECRET_RULE_CATEGORY = "secure_code_hardcoded_secret";
/** Languages whose source should never carry a literal credential. `.env` files are where they belong. */
const SECRET_LANGUAGES: ReadonlySet<string> = new Set([
	"python",
	"javascript",
	"typescript",
	"go",
	"java",
	"kotlin",
	"ruby",
	"php",
	"csharp",
	"rust",
	"shell",
	"powershell",
	"dockerfile",
	"makefile",
	"yaml",
]);

/** True for advisory secure-code rules; everything else decides through its own action. */
export function isSecureCodeRule(threat: Pick<Threat, "category">): boolean {
	return threat.category.startsWith("secure_code");
}

/** The code rules of a loaded threat set, indexed by language. */
export class CodeRuleSet {
	private readonly byLanguage = new Map<string, Threat[]>();
	/** Global-flag copies of each rule's pattern, for scanning every occurrence. */
	private readonly globalPatterns = new Map<string, RegExp>();
	readonly secretRuleEnabled: boolean;
	readonly size: number;

	constructor(threats: readonly Threat[], disabledThreats: readonly string[] = []) {
		const disabled = new Set(disabledThreats);
		const ids = new Set<string>();
		for (const threat of threats) {
			if (disabled.has(threat.id)) continue;
			for (const matchOn of threat.matchOn) {
				if (!matchOn.startsWith(CODE_MATCH_PREFIX)) continue;
				const language = matchOn.slice(CODE_MATCH_PREFIX.length);
				const list = this.byLanguage.get(language) ?? [];
				if (list.length === 0) this.byLanguage.set(language, list);
				list.push(threat);
				ids.add(threat.id);
			}
		}
		this.secretRuleEnabled = !disabled.has(SECRET_RULE_ID);
		this.size = ids.size + (this.secretRuleEnabled ? 1 : 0);
	}

	rulesFor(language: string): readonly Threat[] {
		return this.byLanguage.get(language) ?? [];
	}

	globalPattern(threat: Threat): RegExp {
		let pattern = this.globalPatterns.get(threat.id);
		if (!pattern) {
			const flags = threat.compiledPattern.flags.replace(/[gy]/g, "");
			pattern = new RegExp(threat.compiledPattern.source, `${flags}g`);
			this.globalPatterns.set(threat.id, pattern);
		}
		return pattern;
	}
}

// ── Code blocks a tool call writes or runs ────────────────────────────

export interface CodeBlock {
	filePath: string;
	language: string;
	text: string;
	/** 1-based file line of the block's first line, when the tool input makes it knowable. */
	firstLine?: number;
	/** 1-based notebook cell the block comes from, for `.ipynb` files. */
	cell?: number;
}

function str(value: unknown): string {
	return typeof value === "string" ? value : "";
}

function block(
	filePath: string,
	language: string | null,
	text: string,
	firstLine?: number,
): CodeBlock[] {
	return language && text.trim() !== "" ? [{ filePath, language, text, firstLine }] : [];
}

/**
 * Code cells of a notebook, or null when the text is not notebook JSON. The
 * raw JSON would hide call syntax behind string escaping (`\"`), so rules run
 * on the decoded cell sources instead.
 */
function notebookCells(content: string): Array<{ cell: number; text: string }> | null {
	let parsed: unknown;
	try {
		parsed = JSON.parse(content);
	} catch {
		return null;
	}
	const cells = (parsed as { cells?: unknown })?.cells;
	if (!Array.isArray(cells)) return null;
	const sources: Array<{ cell: number; text: string }> = [];
	for (const [index, cell] of cells.entries()) {
		if (!cell || typeof cell !== "object") continue;
		const { cell_type: cellType, source } = cell as { cell_type?: unknown; source?: unknown };
		if (cellType !== "code") continue;
		const text = Array.isArray(source) ? source.map(str).join("") : str(source);
		if (text.trim() !== "") sources.push({ cell: index + 1, text });
	}
	return sources;
}

function writeBlocks(filePath: string, content: string): CodeBlock[] {
	const language = codeLanguageForPath(filePath);
	if (language && extname(filePath).toLowerCase() === ".ipynb") {
		const cells = notebookCells(content);
		if (cells) {
			return cells.flatMap(({ cell, text }) =>
				block(filePath, language, text).map((entry) => ({ ...entry, cell })),
			);
		}
	}
	return block(filePath, language, content, 1);
}

/**
 * Runs of lines in `newText` that `oldText` does not contain (a multiset
 * difference, so a duplicated line is new the second time). The host does not
 * say where the edited region sits in the file, so no file line is attached.
 */
function addedRunsBlocks(filePath: string, oldText: string, newText: string): CodeBlock[] {
	const language = codeLanguageForPath(filePath);
	if (!language || newText.trim() === "") return [];
	const remaining = new Map<string, number>();
	for (const line of oldText.split(/\r?\n/)) {
		const key = line.trimEnd();
		remaining.set(key, (remaining.get(key) ?? 0) + 1);
	}
	const blocks: CodeBlock[] = [];
	let run: string[] = [];
	const flush = (): void => {
		blocks.push(...block(filePath, language, run.join("\n")));
		run = [];
	};
	for (const line of newText.split(/\r?\n/)) {
		const key = line.trimEnd();
		const count = remaining.get(key) ?? 0;
		if (count > 0) {
			remaining.set(key, count - 1);
			flush();
		} else {
			run.push(line);
		}
	}
	flush();
	return blocks;
}

const CODEX_FILE_HEADER = /^\*\*\* (Add|Update|Delete) File: (.+)$/;
const UNIFIED_NEW_HEADER = /^\+\+\+ (.+)$/;
const HUNK_HEADER = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@/;
const PATCH_FRAMING = /^(?:\*\*\* (?:Add|Update|Delete) File: |\+\+\+ |--- )/m;

function diffPath(raw: string): string {
	const path = (raw.split("\t")[0] ?? "").trim().replace(/^[ab]\//, "");
	return path === "/dev/null" ? "" : path;
}

/** The raw patch body of an apply_patch-style input, if it carries one. */
function rawPatchBody(toolInput: Record<string, unknown>): string | null {
	for (const key of ["patch", "patchText"]) {
		const value = str(toolInput[key]);
		if (value.trim() !== "") return value;
	}
	for (const key of ["input", "command"]) {
		const value = str(toolInput[key]);
		if (PATCH_FRAMING.test(value)) return value;
	}
	return null;
}

interface PatchCursor {
	filePath: string;
	language: string | null;
	/** Next new-file line number, when the patch format carries one. */
	nextLine?: number;
	/** Remaining new-side lines of the current unified-diff hunk. */
	hunkNewRemaining: number;
	codexAdd: boolean;
}

/**
 * Collects the lines a patch adds, grouped into runs per target file. Handles
 * the Codex `*** Add/Update File:` format and unified diffs. Removed and
 * context lines are not inspected: this call does not write them.
 */
class PatchReader {
	readonly blocks: CodeBlock[] = [];
	private cursor: PatchCursor | null = null;
	private run: string[] = [];
	private runStart: number | undefined;

	read(patch: string): CodeBlock[] {
		for (const line of patch.split(/\r?\n/)) {
			// Inside a unified-diff hunk every line is content, even `+++ x`.
			const inHunk = (this.cursor?.hunkNewRemaining ?? 0) > 0;
			if (inHunk || !this.header(line)) this.body(line);
		}
		this.flush();
		return this.blocks;
	}

	/** File headers and patch framing; false when `line` is not one. */
	private header(line: string): boolean {
		const codex = CODEX_FILE_HEADER.exec(line);
		if (codex) {
			const kind = codex[1];
			this.startFile(kind === "Delete" ? "" : (codex[2] ?? "").trim(), kind === "Add");
			return true;
		}
		const unified = UNIFIED_NEW_HEADER.exec(line);
		if (unified) {
			this.startFile(diffPath(unified[1] ?? ""), false);
			return true;
		}
		const framing =
			line.startsWith("*** ") || line.startsWith("--- ") || line.startsWith("diff --git ");
		if (framing) this.flush();
		return framing;
	}

	private body(line: string): void {
		const cursor = this.cursor;
		if (line.startsWith("@@")) {
			this.flush();
			const hunk = HUNK_HEADER.exec(line);
			if (cursor && hunk) {
				cursor.nextLine = Number(hunk[1]);
				cursor.hunkNewRemaining = hunk[2] === undefined ? 1 : Number(hunk[2]);
			} else if (cursor && !cursor.codexAdd) {
				// Codex hunk anchor: a context hint, not a line number.
				cursor.nextLine = undefined;
			}
			return;
		}
		if (!cursor) return;
		if (line.startsWith("+")) {
			this.add(line.slice(1));
			this.consumeHunkLine();
		} else if (line.startsWith(" ")) {
			this.flush();
			if (cursor.nextLine !== undefined) cursor.nextLine++;
			this.consumeHunkLine();
		} else if (cursor.codexAdd && !line.startsWith("-") && !line.startsWith("\\")) {
			// Codex `Add File` bodies may be written without a `+` marker.
			this.add(line);
		} else {
			this.flush();
		}
	}

	private consumeHunkLine(): void {
		if (this.cursor && this.cursor.hunkNewRemaining > 0) this.cursor.hunkNewRemaining--;
	}

	private add(text: string): void {
		if (!this.cursor) return;
		if (this.run.length === 0) this.runStart = this.cursor.nextLine;
		this.run.push(text);
		if (this.cursor.nextLine !== undefined) this.cursor.nextLine++;
	}

	private flush(): void {
		if (this.cursor && this.run.length > 0) {
			const { filePath, language } = this.cursor;
			this.blocks.push(...block(filePath, language, this.run.join("\n"), this.runStart));
		}
		this.run = [];
		this.runStart = undefined;
	}

	private startFile(filePath: string, codexAdd: boolean): void {
		this.flush();
		this.cursor = filePath
			? {
					filePath,
					language: codeLanguageForPath(filePath),
					nextLine: codexAdd ? 1 : undefined,
					hunkNewRemaining: 0,
					codexAdd,
				}
			: null;
	}
}

function patchAddedBlocks(patch: string): CodeBlock[] {
	return new PatchReader().read(patch);
}

/** `python -c <code>` in a shell command, with the three common quotings. */
const PYTHON_DASH_C =
	/\bpython(?:\d+(?:\.\d+)*)?(?:\s{1,4}-[A-Za-bd-z][A-Za-z]{0,8}){0,4}\s{1,4}-c\s{1,4}(?:"((?:[^"\\]|\\[\s\S]){1,65536})"|'([^']{1,65536})'|\$'((?:[^'\\]|\\[\s\S]){1,65536})')/g;
/** A heredoc opener; `<<<` here-strings are not heredocs. */
const HEREDOC_OPENER = /(?<!<)<<-?[ \t]*(["']?)(\w{1,64})\1([^\n]{0,300})\n/g;
const PYTHON_CONSUMER = /\bpython(?:\d+(?:\.\d+)*)?\b/;
const REDIRECT_TARGET =
	/(?:(?<![<&\d])>{1,2}|\btee\s{1,4}(?:-a\s{1,4})?)\s{0,4}["']?([^\s"'<>|;&()]{1,300})/g;
const MAX_HEREDOCS = 32;

function unescapeDoubleQuoted(text: string): string {
	return text.replace(/\\(["\\$`])/g, "$1");
}

function unescapeAnsiC(text: string): string {
	return text.replace(/\\(.)/g, (_match, char: string) =>
		char === "n" ? "\n" : char === "t" ? "\t" : char,
	);
}

function heredocTarget(consumerLine: string): string | null {
	for (const match of consumerLine.matchAll(REDIRECT_TARGET)) {
		const target = match[1] ?? "";
		if (target.startsWith("/dev/")) continue;
		return target;
	}
	return null;
}

/** End of a heredoc body: index of the newline before the terminator line, or the text end. */
function heredocBodyEnd(command: string, bodyStart: number, word: string): number {
	let lineStart = bodyStart;
	while (lineStart <= command.length) {
		const newline = command.indexOf("\n", lineStart);
		const lineEnd = newline === -1 ? command.length : newline;
		if (command.slice(lineStart, lineEnd).trim() === word)
			return Math.max(bodyStart, lineStart - 1);
		if (newline === -1) break;
		lineStart = newline + 1;
	}
	return command.length;
}

/**
 * Code a Bash command runs or writes: `python -c` bodies, heredocs fed to
 * Python, and heredocs redirected into a source file.
 */
function bashBlocks(command: string): CodeBlock[] {
	return [...pythonDashCBlocks(command), ...heredocBlocks(command)];
}

function pythonDashCBlocks(command: string): CodeBlock[] {
	return [...command.matchAll(PYTHON_DASH_C)].flatMap((match) => {
		const [, doubleQuoted, singleQuoted, ansiC] = match;
		const code =
			doubleQuoted !== undefined
				? unescapeDoubleQuoted(doubleQuoted)
				: (singleQuoted ?? unescapeAnsiC(ansiC ?? ""));
		return block("(python -c)", "python", code);
	});
}

function heredocBlocks(command: string): CodeBlock[] {
	const blocks: CodeBlock[] = [];
	let seen = 0;
	for (const opener of command.matchAll(HEREDOC_OPENER)) {
		if (++seen > MAX_HEREDOCS) break;
		const word = opener[2] ?? "";
		const bodyStart = opener.index + opener[0].length;
		const body = command.slice(bodyStart, heredocBodyEnd(command, bodyStart, word));
		const lineStart = command.lastIndexOf("\n", opener.index - 1) + 1;
		const consumer = `${command.slice(lineStart, opener.index)} ${opener[3] ?? ""}`;
		const target = heredocTarget(consumer);
		if (target) blocks.push(...block(target, codeLanguageForPath(target), body, 1));
		else if (PYTHON_CONSUMER.test(consumer))
			blocks.push(...block("(python heredoc)", "python", body));
	}
	return blocks;
}

function multiEditBlocks(toolInput: Record<string, unknown>): CodeBlock[] {
	const filePath = str(toolInput.file_path) || str(toolInput.filePath) || str(toolInput.path);
	const edits = Array.isArray(toolInput.edits) ? toolInput.edits : [];
	return edits.flatMap((edit) => {
		if (!edit || typeof edit !== "object") return [];
		const fields = edit as Record<string, unknown>;
		return addedRunsBlocks(
			filePath,
			str(fields.old_string) || str(fields.oldString),
			str(fields.new_string) || str(fields.newString),
		);
	});
}

/**
 * The code blocks a (normalized) tool call writes or runs. Unknown tools and
 * files in no supported language produce none.
 */
export function codeBlocksForToolCall(
	toolName: string,
	toolInput: Record<string, unknown>,
): CodeBlock[] {
	switch (toolName.trim().toLowerCase()) {
		case "write":
			return writeBlocks(str(toolInput.file_path), str(toolInput.content));
		case "edit": {
			const patch = rawPatchBody(toolInput);
			if (patch !== null) return patchAddedBlocks(patch);
			return addedRunsBlocks(
				str(toolInput.file_path),
				str(toolInput.old_string),
				str(toolInput.new_string) || str(toolInput.content),
			);
		}
		case "multiedit":
		case "multi_edit":
			return multiEditBlocks(toolInput);
		case "notebookedit":
		case "notebook_edit": {
			if (toolInput.cell_type === "markdown" || toolInput.edit_mode === "delete") return [];
			const path = str(toolInput.notebook_path) || "(notebook)";
			return block(path, "python", str(toolInput.new_source));
		}
		case "bash":
			return bashBlocks(str(toolInput.command));
		default:
			return [];
	}
}

// ── Matching ──────────────────────────────────────────────────────────

export interface CodeFinding {
	ruleId: string;
	title: string;
	category: string;
	severity: Threat["severity"];
	/** The rule, for code rules; absent for the built-in secret rule. */
	threat?: Threat;
	block: CodeBlock;
	/** Offset of the match in `block.text`. */
	index: number;
	/** Matched text; empty for secrets, whose value must never be copied anywhere. */
	matchValue: string;
	/** 1-based line within the block. */
	blockLine: number;
	/** 1-based file line, when the block's position in the file is known. */
	line?: number;
}

export interface MatchOptions {
	/** Report every occurrence (project scan) instead of the first per rule and block. */
	allMatches?: boolean;
	/** Cap on occurrences per rule and block when `allMatches` is set. */
	maxPerRule?: number;
	/** Run the credential detector (advisory secure-code rule). */
	includeSecrets?: boolean;
}

function lineAt(text: string, index: number): number {
	let line = 1;
	for (let i = text.indexOf("\n"); i !== -1 && i < index; i = text.indexOf("\n", i + 1)) line++;
	return line;
}

function finding(
	target: CodeBlock,
	index: number,
	fields: Omit<CodeFinding, "block" | "index" | "blockLine" | "line">,
): CodeFinding {
	const blockLine = lineAt(target.text, index);
	return {
		...fields,
		block: target,
		index,
		blockLine,
		...(target.firstLine !== undefined ? { line: target.firstLine + blockLine - 1 } : {}),
	};
}

function secretTitle(label: string): string {
	return `Hard-coded credential (${label}) in source code; load it from the environment or a secret manager, and rotate it if it was ever committed or shared`;
}

/** Match the code rules (and optionally the credential detector) against one block. */
export function matchCodeBlock(
	target: CodeBlock,
	rules: CodeRuleSet,
	options: MatchOptions = {},
): CodeFinding[] {
	const findings: CodeFinding[] = [];
	const limit = options.allMatches ? (options.maxPerRule ?? 50) : 1;
	for (const threat of rules.rulesFor(target.language)) {
		const pattern = rules.globalPattern(threat);
		pattern.lastIndex = 0;
		let count = 0;
		for (let m = pattern.exec(target.text); m !== null; m = pattern.exec(target.text)) {
			if (m[0] === "") pattern.lastIndex++;
			findings.push(
				finding(target, m.index, {
					ruleId: threat.id,
					title: threat.title,
					category: threat.category,
					severity: threat.severity,
					threat,
					matchValue: m[0],
				}),
			);
			if (++count >= limit) break;
		}
	}
	if (options.includeSecrets && rules.secretRuleEnabled && SECRET_LANGUAGES.has(target.language)) {
		const secrets = locateSecrets(target.text);
		for (const secret of secrets.slice(0, limit)) {
			findings.push(
				finding(target, secret.start, {
					ruleId: SECRET_RULE_ID,
					title: secretTitle(secret.label),
					category: SECRET_RULE_CATEGORY,
					severity: "high",
					matchValue: "",
				}),
			);
		}
	}
	return findings;
}

/** A code finding is a real signal unless it is a model-source rule that matched only trusted sources. */
export function isReportableFinding(item: CodeFinding, sources: TrustedModelSources): boolean {
	return !isTrustedModelSourceMatch(item.ruleId, item.matchValue, sources, item.block.text);
}

// ── Runtime leg ───────────────────────────────────────────────────────

export interface CodeGuardResult {
	/** Supply-chain (non-advisory) rule matches, fed to the decision engine like any heuristic. */
	heuristicMatches: HeuristicMatch[];
	/** Advisory secure-code findings; empty when `secure_code.enabled` is false. */
	warnings: VerdictWarning[];
}

export const EMPTY_CODE_GUARD_RESULT: CodeGuardResult = Object.freeze({
	heuristicMatches: [],
	warnings: [],
});

/** At most this many advisory findings travel with one verdict. */
const MAX_WARNINGS = 20;
/** Occurrences examined per rule and block at runtime. */
const RUNTIME_MATCHES_PER_RULE = 20;
const MAX_EVIDENCE = 160;

function condense(text: string): string {
	const flat = text.replace(/\s+/g, " ").trim();
	return flat.length <= MAX_EVIDENCE ? flat : `${flat.slice(0, MAX_EVIDENCE - 3)}...`;
}

function displayPath(filePath: string): string {
	return filePath.length <= 200 ? filePath : `...${filePath.slice(-197)}`;
}

/**
 * Inspect the code a tool call writes or runs. Supply-chain matches come back
 * as heuristic matches (their rule action decides); secure-code findings come
 * back as warnings for {@link applySecureCodeWarnings}.
 */
export function inspectToolCallCode(
	toolName: string,
	toolInput: Record<string, unknown>,
	rules: CodeRuleSet,
	sources: TrustedModelSources,
	secureCode: SecureCodeConfig,
): CodeGuardResult {
	const blocks = codeBlocksForToolCall(toolName, toolInput);
	if (blocks.length === 0) return EMPTY_CODE_GUARD_RESULT;

	// Every occurrence (bounded) is examined, not just the first: a trusted
	// download listed first must not hide an untrusted one after it.
	const options: MatchOptions = {
		allMatches: true,
		maxPerRule: RUNTIME_MATCHES_PER_RULE,
		includeSecrets: secureCode.enabled,
	};
	const findings = blocks.flatMap((target, blockIndex) =>
		matchCodeBlock(target, rules, options)
			.filter((item) => isReportableFinding(item, sources))
			.map((item) => ({ item, blockIndex })),
	);
	// One signal per rule and file is enough for the decision engine.
	const collected = new Map<string, HeuristicMatch>();
	for (const { item } of findings) {
		if (!item.threat || isSecureCodeRule(item.threat)) continue;
		const key = `${item.ruleId}\u0000${item.block.filePath}`;
		if (!collected.has(key)) collected.set(key, heuristicMatch(item.threat, item));
	}
	const warnings = new Map<string, VerdictWarning>();
	for (const { item, blockIndex } of secureCode.enabled ? findings : []) {
		if (item.threat && !isSecureCodeRule(item.threat)) continue;
		const key = `${item.ruleId}\u0000${item.block.filePath}\u0000${blockIndex}:${item.blockLine}`;
		if (!warnings.has(key)) warnings.set(key, verdictWarning(item));
	}
	return {
		heuristicMatches: [...collected.values()],
		warnings: [...warnings.values()].slice(0, MAX_WARNINGS),
	};
}

function heuristicMatch(threat: Threat, item: CodeFinding): HeuristicMatch {
	return {
		threat,
		artifact: `${displayPath(item.block.filePath)}: ${condense(item.matchValue)}`,
		matchValue: item.matchValue,
	};
}

function verdictWarning(item: CodeFinding): VerdictWarning {
	return {
		source: "secure_code",
		ruleId: item.ruleId,
		title: item.title,
		category: item.category,
		severity: item.severity,
		filePath: displayPath(item.block.filePath),
		language: item.block.language,
		...(item.line !== undefined ? { line: item.line } : {}),
	};
}

/** Verdict category of an allowed call that carries secure-code warnings. */
export const SECURE_CODE_WARNING_CATEGORY = "secure_code_warning";

/**
 * Fold secure-code findings into a verdict.
 *
 * - `warn` (default): the decision is unchanged; the findings travel as
 *   `verdict.warnings`, and an allowed call is re-categorised so the audit log
 *   records it.
 * - `ask`: an allowed call is held for review. A DLP-redacted allow is left
 *   allowed with warnings: an `ask` carries no rewritten input, so approving it
 *   would run the unredacted original.
 *
 * A call that is already `ask` or `deny` keeps its decision and gains the
 * warnings.
 */
export function applySecureCodeWarnings(
	verdict: Verdict,
	warnings: readonly VerdictWarning[],
	config: SecureCodeConfig,
): Verdict {
	if (!config.enabled || warnings.length === 0) return verdict;
	const list = [...warnings];
	if (verdict.decision !== "allow") return { ...verdict, warnings: list };
	if (config.action === "ask" && !verdict.transformedInput) {
		return {
			decision: "ask",
			category: "secure_code",
			confidence: 1,
			severity: "warning",
			source: "secure_code",
			artifacts: [...new Set(list.map((warning) => warning.filePath).filter(Boolean))],
			matchedThreatId: list[0]?.ruleId ?? null,
			reasons: [...new Set(list.map((warning) => warning.title))],
			warnings: list,
		};
	}
	return {
		...verdict,
		category: verdict.category === "none" ? SECURE_CODE_WARNING_CATEGORY : verdict.category,
		severity: verdict.severity === "info" ? "warning" : verdict.severity,
		warnings: list,
	};
}

function describeWarning(warning: VerdictWarning): string {
	const where = warning.filePath
		? ` (${warning.filePath}${warning.line !== undefined ? `:${warning.line}` : ""})`
		: "";
	return `${warning.title}${where} [${warning.ruleId}]`;
}

/**
 * User- and model-facing text for secure-code warnings. Names rule titles and
 * locations only; the matched source text (which may hold a credential) is
 * never included. `allowed` says whether the call itself went through (the
 * default `warn` mode) or was held/blocked for another reason.
 */
export function describeSecureCodeWarnings(
	warnings: readonly VerdictWarning[],
	allowed = true,
): {
	userMessage: string;
	modelContext: string;
} {
	const shown = warnings.slice(0, 3).map(describeWarning);
	const more = warnings.length > shown.length ? ` (+${warnings.length - shown.length} more)` : "";
	const noun = warnings.length === 1 ? "issue" : "issues";
	return {
		userMessage: `⚠️ Singularity AIDR secure-code notice: ${warnings.length} ${noun} in code being written: ${shown.join("; ")}${more}.${allowed ? " The change was allowed." : ""}`,
		modelContext: `Singularity AIDR secure-code notice for the code you are writing: ${shown.join("; ")}${more}. Fix these unless the user explicitly asked for this behaviour, and tell the user about any you keep.`,
	};
}
