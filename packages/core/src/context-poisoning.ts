/**
 * Data and context poisoning protection (OWASP LLM04, Agentic ASI06).
 *
 * An agent's standing context lives in files and stores it re-reads on every
 * session: instruction files (CLAUDE.md, AGENTS.md, .cursorrules, ...), agent
 * memory, agent/IDE/MCP configuration, repository hooks and shell start-up
 * files, plus memory and vector stores reached through MCP tools. A single
 * poisoned write there turns one prompt injection into a permanent one.
 *
 * This module knows the *operation* a plain artifact does not: which file a
 * write, edit, patch, delete or shell command targets, what text lands in it,
 * and whether an MCP tool writes to memory. The detection patterns themselves
 * are data in `threats/context-poisoning.yaml`, selected by dedicated
 * `match_on` values that the generic heuristics engine never produces:
 *
 *   agent_control_path     path of a write/edit/patch/delete or a shell write
 *   agent_control_content  text written into such a path
 *   mcp_tool_metadata      MCP tool name, description and schema strings
 *   memory_write_content   arguments of a memory / vector-store write tool
 *
 * Reads never match a path rule. Read-time poisoning (hidden instructions in a
 * file or document the agent reads) is handled by output inspection, see
 * `output-scanner.ts`.
 */

import { readdir, stat } from "node:fs/promises";
import { join, posix } from "node:path";
import { commandFromValue } from "./command-argv.js";
import { DecisionEngine } from "./engine.js";
import { renderInvisibleCharacters } from "./hidden-unicode.js";
import { loadThreatsFromDirs } from "./threat-loader.js";
import { readFileEditPayload } from "./tool-normalization.js";
import type {
	HeuristicMatch,
	Logger,
	PoisoningProtectionConfig,
	Threat,
	Verdict,
} from "./types.js";
import { nullLogger } from "./types.js";

export const AGENT_CONTROL_PATH = "agent_control_path";
export const AGENT_CONTROL_CONTENT = "agent_control_content";
export const MCP_TOOL_METADATA = "mcp_tool_metadata";
export const MEMORY_WRITE_CONTENT = "memory_write_content";

const POISONING_MATCH_ON = [
	AGENT_CONTROL_PATH,
	AGENT_CONTROL_CONTENT,
	MCP_TOOL_METADATA,
	MEMORY_WRITE_CONTENT,
] as const;
type PoisoningSurface = (typeof POISONING_MATCH_ON)[number];

/** Verdict source for every decision this detector makes. */
export const CONTEXT_POISONING_SOURCE = "context_poisoning";

/** Text inspected per surface; larger inputs are already denied by the extractor limits. */
const MAX_SCANNED_CHARS = 4 * 1024 * 1024;
/** Patterns run over overlapping windows so evaluation stays linear in input size. */
const WINDOW_CHARS = 16 * 1024;
const WINDOW_OVERLAP_CHARS = 2 * 1024;
const MAX_WALK_STRINGS = 20_000;
const MAX_WALK_DEPTH = 32;

// ── Rule loading ──────────────────────────────────────────────────────────

interface CachedRules {
	signature: string;
	rules: Threat[];
}
const ruleCache = new Map<string, CachedRules>();

async function directorySignature(dir: string): Promise<string> {
	try {
		const names = (await readdir(dir)).filter((name) => name.endsWith(".yaml")).sort();
		const parts: string[] = [];
		for (const name of names) {
			const info = await stat(join(dir, name), { bigint: true });
			parts.push(`${name}:${info.size}:${info.mtimeNs}:${info.ino}`);
		}
		return parts.join("|");
	} catch {
		return "missing";
	}
}

/**
 * Load the context-poisoning rules from the rule directories (later directories
 * are additive only: a clashing id keeps the earlier, bundled rule, as for
 * every other rule). Only files that declare
 * one of the dedicated `match_on` values are parsed, and the result is cached
 * until a rule file changes, so the detector does not re-parse the whole rule
 * set on every tool call.
 */
export async function loadContextPoisoningRules(
	dirs: string[],
	logger: Logger = nullLogger,
): Promise<Threat[]> {
	const present = dirs.filter((dir) => dir);
	const key = JSON.stringify(present);
	const signature = (await Promise.all(present.map(directorySignature))).join("\n");
	const cached = ruleCache.get(key);
	if (cached && cached.signature === signature) return cached.rules;
	const threats = await loadThreatsFromDirs(present, logger, {
		includeFile: (content) => POISONING_MATCH_ON.some((name) => content.includes(name)),
	});
	const rules = threats.filter((threat) =>
		POISONING_MATCH_ON.some((name) => threat.matchOn.has(name)),
	);
	ruleCache.set(key, { signature, rules });
	return rules;
}

function rulesFor(rules: readonly Threat[], surface: PoisoningSurface): Threat[] {
	return rules.filter((rule) => rule.matchOn.has(surface));
}

function statelessPattern(threat: Threat): RegExp {
	const { compiledPattern } = threat;
	return compiledPattern.global || compiledPattern.sticky
		? new RegExp(compiledPattern.source, compiledPattern.flags.replace(/[gy]/g, ""))
		: compiledPattern;
}

/** First match of one rule over `text`, scanned in overlapping windows. */
function firstMatch(threat: Threat, text: string): string | null {
	const pattern = statelessPattern(threat);
	const bounded = text.length > MAX_SCANNED_CHARS ? text.slice(0, MAX_SCANNED_CHARS) : text;
	for (let start = 0; start < bounded.length; start += WINDOW_CHARS) {
		const window = bounded.slice(start, start + WINDOW_CHARS + WINDOW_OVERLAP_CHARS);
		try {
			const match = pattern.exec(window);
			if (match) return match[0];
		} catch {
			return null;
		}
		if (start + WINDOW_CHARS + WINDOW_OVERLAP_CHARS >= bounded.length) break;
	}
	return null;
}

function excerpt(value: string): string {
	const visible = renderInvisibleCharacters(value).replace(/\s+/g, " ").trim();
	return visible.length > 160 ? `${visible.slice(0, 160)}…` : visible;
}

/**
 * Characters that render as nothing (or as a plain space) and are dropped from
 * the folded view: soft hyphen, combining grapheme joiner, Hangul fillers,
 * Mongolian and variation selectors, zero-width and direction marks, word
 * joiners and the BOM. The raw view keeps them for the hidden-Unicode rules.
 */
const INVISIBLE_FILLERS = /[­͏ᅟᅠ឴឵᠋-᠏​-‏⁠-⁤ㅤ︀-️﻿ﾠ]/g;

/** Cyrillic and Greek letters that are drawn like Latin ones, folded to the Latin letter. */
const LATIN_LOOKALIKES: Readonly<Record<string, string>> = {
	а: "a",
	в: "b",
	е: "e",
	о: "o",
	р: "p",
	с: "c",
	у: "y",
	х: "x",
	і: "i",
	ј: "j",
	ѕ: "s",
	ԁ: "d",
	һ: "h",
	ԛ: "q",
	ԝ: "w",
	ґ: "r",
	ӏ: "l",
	к: "k",
	м: "m",
	н: "h",
	т: "t",
	А: "A",
	В: "B",
	Е: "E",
	К: "K",
	М: "M",
	Н: "H",
	О: "O",
	Р: "P",
	С: "C",
	Т: "T",
	Х: "X",
	У: "Y",
	І: "I",
	Ј: "J",
	Ѕ: "S",
	Ԁ: "D",
	Һ: "H",
	Ԛ: "Q",
	Ԝ: "W",
	α: "a",
	ο: "o",
	ι: "i",
	κ: "k",
	ν: "v",
	ρ: "p",
	τ: "t",
	υ: "u",
	χ: "x",
	ε: "e",
	Α: "A",
	Β: "B",
	Ε: "E",
	Ζ: "Z",
	Η: "H",
	Ι: "I",
	Κ: "K",
	Μ: "M",
	Ν: "N",
	Ο: "O",
	Ρ: "P",
	Τ: "T",
	Υ: "Y",
	Χ: "X",
};
const LOOKALIKE_PATTERN = new RegExp(`[${Object.keys(LATIN_LOOKALIKES).join("")}]`, "g");

/**
 * The text as a reader sees it: compatibility forms folded (`ｉｇｎｏｒｅ` →
 * `ignore`), invisible fillers removed and Latin look-alike letters mapped to
 * Latin. An instruction written with them reads the same to the model, so the
 * content rules must see the same text. Returns `text` itself when nothing changes.
 */
export function readerView(text: string): string {
	const folded = text
		.normalize("NFKC")
		.replace(INVISIBLE_FILLERS, "")
		.replace(LOOKALIKE_PATTERN, (letter) => LATIN_LOOKALIKES[letter] ?? letter);
	return folded === text ? text : folded;
}

/** Rule ids of `surface` that match `text`, as heuristic matches labelled with `label`. */
export function matchPoisoningRules(
	rules: readonly Threat[],
	surface: PoisoningSurface,
	text: string,
	label: string,
): HeuristicMatch[] {
	if (!text) return [];
	// Content surfaces are also matched as the model reads them; paths are not text.
	const bounded = text.length > MAX_SCANNED_CHARS ? text.slice(0, MAX_SCANNED_CHARS) : text;
	const folded = surface === AGENT_CONTROL_PATH ? bounded : readerView(bounded);
	const matches: HeuristicMatch[] = [];
	for (const threat of rulesFor(rules, surface)) {
		const matched =
			firstMatch(threat, bounded) ?? (folded !== bounded ? firstMatch(threat, folded) : null);
		if (matched !== null) matches.push({ threat, artifact: label, matchValue: excerpt(matched) });
	}
	return matches;
}

// ── Paths ─────────────────────────────────────────────────────────────────

/** Lexically normalised, forward-slash form of a path for path-rule matching. */
function normalizeControlPath(path: string): string {
	let value = path.trim().replace(/^["'`]+|["'`]+$/g, "");
	if (value.startsWith("file://")) value = value.slice("file://".length);
	value = value.replace(/\\/g, "/");
	if (!value) return "";
	return posix.normalize(value);
}

/** The first `agent_control_path` rule the path matches, if any. */
export function matchAgentControlPath(rules: readonly Threat[], path: string): Threat | null {
	const normalized = normalizeControlPath(path);
	if (!normalized) return null;
	for (const threat of rulesFor(rules, AGENT_CONTROL_PATH)) {
		try {
			if (statelessPattern(threat).test(normalized)) return threat;
		} catch {
			// A failing rule is a skipped signal, never a clean result for the rest.
		}
	}
	return null;
}

// ── Write targets ─────────────────────────────────────────────────────────

export interface AgentWriteTarget {
	path: string;
	/** Text the operation writes; for a shell write, the whole command line. */
	content: string;
	via: "file_tool" | "shell";
}

const PATH_KEYS = new Set([
	"file_path",
	"filepath",
	"filePath",
	"path",
	"notebook_path",
	"target_file",
	"targetFile",
	"destination",
	"dest",
	"new_path",
	"newPath",
	"filename",
	"fileName",
	"file",
]);
/** Fields holding the text being replaced, not text being written. */
const REPLACED_TEXT_KEYS = new Set(["old_string", "oldString", "oldText", "old_str", "search"]);
/** Tools outside the canonical set whose name says they change files. */
const WRITER_TOOL =
	/write|edit|patch|create|save|append|insert|replace|update|notebook|move|rename|copy/i;
const READ_ONLY_COMMANDS = new Set(["view", "read", "list", "search", "get"]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
	return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** Every string in `value` (keys excluded), bounded in count and depth. */
function collectStrings(
	value: unknown,
	skipKey: (key: string) => boolean,
	includeKeys = false,
	output: string[] = [],
	depth = 0,
): string[] {
	if (output.length >= MAX_WALK_STRINGS || depth > MAX_WALK_DEPTH) return output;
	if (typeof value === "string") {
		output.push(value);
	} else if (Array.isArray(value)) {
		for (const item of value) collectStrings(item, skipKey, includeKeys, output, depth + 1);
	} else if (isPlainObject(value)) {
		for (const [key, item] of Object.entries(value)) {
			if (skipKey(key)) continue;
			if (includeKeys) output.push(key);
			collectStrings(item, skipKey, includeKeys, output, depth + 1);
		}
	}
	return output;
}

function stringField(input: Record<string, unknown>, key: string): string {
	const value = input[key];
	return typeof value === "string" ? value : "";
}

/** The tool segment of an MCP tool name (`mcp__server__tool` → `tool`), else the name. */
function mcpParts(toolName: string): { server: string; tool: string } | null {
	if (!toolName.startsWith("mcp__")) return null;
	const rest = toolName.slice("mcp__".length);
	const separator = rest.indexOf("__");
	if (separator < 0) return { server: rest, tool: "" };
	return { server: rest.slice(0, separator), tool: rest.slice(separator + 2) };
}

function genericWriteTargets(
	toolName: string,
	toolInput: Record<string, unknown>,
): AgentWriteTarget[] {
	const operation = mcpParts(toolName)?.tool ?? toolName;
	if (!WRITER_TOOL.test(operation) || /\b(?:read|view|get|list|search)_/i.test(operation))
		return [];
	const command = stringField(toolInput, "command").toLowerCase();
	if (READ_ONLY_COMMANDS.has(command)) return [];
	const paths = Object.entries(toolInput)
		.filter(([key, value]) => PATH_KEYS.has(key) && typeof value === "string" && value.trim())
		.map(([, value]) => value as string);
	if (paths.length === 0) return [];
	const content = collectStrings(
		toolInput,
		(key) => PATH_KEYS.has(key) || REPLACED_TEXT_KEYS.has(key),
	).join("\n");
	return paths.map((path) => ({ path, content, via: "file_tool" as const }));
}

/**
 * Files an operation writes, edits, patches or deletes, with the text it
 * writes. Reads produce no targets. `toolName`/`toolInput` are the normalized
 * request (canonical `Write`/`Edit`/`Delete`/`Bash`, other tools unchanged).
 */
export function agentWriteTargets(
	toolName: string,
	toolInput: Record<string, unknown>,
): AgentWriteTarget[] {
	switch (toolName) {
		case "Write":
			return stringField(toolInput, "file_path")
				? [
						{
							path: stringField(toolInput, "file_path"),
							content: stringField(toolInput, "content"),
							via: "file_tool",
						},
					]
				: [];
		case "Edit": {
			const payload = readFileEditPayload(toolInput);
			if (payload.patch && payload.edits && payload.edits.length > 0) {
				return payload.edits
					.filter((edit) => edit.filePath)
					.map((edit) => ({
						path: edit.filePath as string,
						content: edit.content ?? "",
						via: "file_tool" as const,
					}));
			}
			const path = stringField(toolInput, "file_path");
			if (!path) return [];
			const content =
				stringField(toolInput, "new_string") ||
				stringField(toolInput, "content") ||
				collectStrings(toolInput.edits, (key) => REPLACED_TEXT_KEYS.has(key)).join("\n");
			return [{ path, content, via: "file_tool" }];
		}
		case "Delete": {
			const path = stringField(toolInput, "file_path");
			return path ? [{ path, content: "", via: "file_tool" }] : [];
		}
		case "Bash": {
			const parsed = commandFromValue(toolInput.command);
			const command = parsed.ok ? (parsed.command ?? "") : "";
			return shellWriteTargets(command).map((path) => ({ path, content: command, via: "shell" }));
		}
		case "Read":
		case "WebFetch":
			return [];
		default:
			return genericWriteTargets(toolName, toolInput);
	}
}

// ── Shell writes ──────────────────────────────────────────────────────────

const REDIRECT = /^(?:\d*|&)>>?\|?$/;
const TOKEN = /\d*>>?\|?|&>>?|<<-?|<|"(?:[^"\\]|\\.)*"|'[^']*'|[^\s"'<>]+/g;
const WRAPPERS = new Set([
	"sudo",
	"doas",
	"env",
	"command",
	"nohup",
	"time",
	"exec",
	"nice",
	"busybox",
]);
const COPY_COMMANDS = new Set(["cp", "mv", "install", "ln", "rsync", "scp", "ditto", "gcp", "gmv"]);
const ALL_ARGUMENT_TARGETS = new Set([
	"tee",
	"truncate",
	"touch",
	"set-content",
	"add-content",
	"out-file",
	"new-item",
	"copy-item",
	"move-item",
	"sc",
	"ac",
]);
const INTERPRETER_WRITE =
	/(?:writeFile(?:Sync)?|appendFile(?:Sync)?|createWriteStream|WriteAllText|AppendAllText)\s*\(\s*["'`]([^"'`\n]{1,512})["'`]|\bopen\s*\(\s*["'`]([^"'`\n]{1,512})["'`]\s*,\s*["'`][^"'`\n]{0,8}[wax+]|\bPath\s*\(\s*["'`]([^"'`\n]{1,512})["'`]\s*\)\s*\.\s*(?:write_text|write_bytes|touch)/g;

function unquote(token: string): string {
	if (token.length >= 2 && (token[0] === '"' || token[0] === "'") && token.at(-1) === token[0]) {
		return token.slice(1, -1);
	}
	return token;
}

function commandWord(tokens: string[]): { word: string; index: number } {
	let index = 0;
	while (index < tokens.length) {
		const token = tokens[index] ?? "";
		const base = token.split(/[\\/]/).pop()?.toLowerCase() ?? "";
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(token) || token.startsWith("-") || WRAPPERS.has(base)) {
			index += 1;
			continue;
		}
		return { word: base, index };
	}
	return { word: "", index };
}

/** The value following any of `flags` (`-o out.txt`). */
function flagValues(operands: string[], flags: readonly string[]): string[] {
	return operands.flatMap((arg, i) => {
		const value = operands[i + 1];
		return flags.includes(arg) && value ? [value] : [];
	});
}

type OperandTargets = (operands: string[], positional: string[]) => string[];

const copyTargets: OperandTargets = (operands, positional) => [
	...flagValues(operands, ["-t", "--target-directory"]),
	...operands.filter((arg) => arg.startsWith("--target-directory=")).map((arg) => arg.slice(19)),
	...positional.slice(-1),
];
const inPlaceTargets: OperandTargets = (operands, positional) =>
	operands.some((arg) => /^-[a-zA-Z]*i/.test(arg) || arg.startsWith("--in-place"))
		? positional
		: [];
const downloadTargets: OperandTargets = (operands) =>
	flagValues(operands, ["-o", "--output", "-O", "--output-document"]);

/** Which operands of a command word are written to. */
const COMMAND_TARGETS = new Map<string, OperandTargets>([
	...[...ALL_ARGUMENT_TARGETS].map((word): [string, OperandTargets] => [word, (_, p) => p]),
	...[...COPY_COMMANDS].map((word): [string, OperandTargets] => [word, copyTargets]),
	["sed", inPlaceTargets],
	["gsed", inPlaceTargets],
	["perl", inPlaceTargets],
	["dd", (operands) => operands.filter((arg) => arg.startsWith("of=")).map((arg) => arg.slice(3))],
	["curl", downloadTargets],
	["wget", downloadTargets],
]);

/** Split redirections off a token list: `{ redirected, args }`. */
function splitRedirects(tokens: string[]): { redirected: string[]; args: string[] } {
	const redirected: string[] = [];
	const args: string[] = [];
	for (let index = 0; index < tokens.length; index += 1) {
		const token = tokens[index] ?? "";
		const next = tokens[index + 1];
		if (REDIRECT.test(token)) {
			if (next && !next.startsWith("&")) redirected.push(next);
			index += 1;
		} else if (token === "<" || token.startsWith("<<")) {
			index += 1;
		} else {
			args.push(token);
		}
	}
	return { redirected, args };
}

function segmentTargets(segment: string): string[] {
	const { redirected, args } = splitRedirects((segment.match(TOKEN) ?? []).map(unquote));
	const { word, index } = commandWord(args);
	const operands = args.slice(index + 1);
	const positional = operands.filter((arg) => !arg.startsWith("-"));
	const interpreterWrites = [...segment.matchAll(INTERPRETER_WRITE)]
		.map((match) => match[1] ?? match[2] ?? match[3])
		.filter((path): path is string => Boolean(path));
	return [
		...redirected,
		...(COMMAND_TARGETS.get(word)?.(operands, positional) ?? []),
		...interpreterWrites,
	];
}

/**
 * Paths a shell command writes to: redirections, `tee`, copy/move/link
 * destinations, in-place `sed`/`perl`, `dd of=`, download outputs, PowerShell
 * content cmdlets and interpreter one-liners (`open(..., "w")`, `writeFile`).
 * This is a conservative lexical reading, not a shell: it only has to find
 * the paths that the path rules then classify.
 */
export function shellWriteTargets(command: string): string[] {
	if (!command) return [];
	const bounded =
		command.length > MAX_SCANNED_CHARS ? command.slice(0, MAX_SCANNED_CHARS) : command;
	const targets = new Set<string>();
	for (const segment of bounded.split(/\|\||&&|[;|\n]|&(?!>)/)) {
		for (const target of segmentTargets(segment)) {
			if (target.trim()) targets.add(target.trim());
		}
	}
	return [...targets];
}

// ── MCP memory / vector-store writes ──────────────────────────────────────

const MEMORY_STORE_HINT =
	/(?:^|[^a-z])(?:memor(?:y|ies)|mem0|remember|recall|knowledge(?:[_-]?(?:base|graph))?|kb|vector(?:[_-]?(?:store|db))?|vectors|embeddings?|rag|chroma(?:db)?|qdrant|pinecone|weaviate|milvus|pgvector|lancedb|faiss|letta|zep|graphiti|observations?|entities)(?:[^a-z]|$)/i;
const MEMORY_WRITE_VERB =
	/(?:^|[^a-z])(?:add|store|save|remember|memorize|upsert|insert|index|ingest|write|create|put|update|append|embed|persist|record|learn|set)(?:[^a-z]|$)/i;
const MEMORY_DESCRIPTION_HINT =
	/\b(?:long[- ]term memory|memor(?:y|ies)|vector (?:store|database|db|index)|knowledge (?:base|graph)|embeddings?|retrieval[- ]augmented|RAG)\b/i;

/**
 * Whether an MCP tool writes to agent memory or a vector/RAG store, judged by
 * its server and tool names (and its description when the caller has it).
 */
export function isMemoryWriteTool(toolName: string, description?: string): boolean {
	const parts = mcpParts(toolName);
	if (!parts) return false;
	if (!MEMORY_WRITE_VERB.test(parts.tool)) return false;
	return (
		MEMORY_STORE_HINT.test(parts.server) ||
		MEMORY_STORE_HINT.test(parts.tool) ||
		(typeof description === "string" && MEMORY_DESCRIPTION_HINT.test(description.slice(0, 4096)))
	);
}

// ── MCP tool metadata ─────────────────────────────────────────────────────

export interface McpToolMetadataInput {
	name: string;
	description?: string;
	input_schema?: unknown;
	inputSchema?: unknown;
}

export interface McpToolMetadataFinding {
	toolName: string;
	threatId: string;
	title: string;
	action: Threat["action"];
	severity: Threat["severity"];
}

/**
 * Scan MCP tool names, descriptions and input-schema strings (descriptions,
 * enum values, defaults, property names) for hidden or injected instructions.
 */
export function scanMcpToolMetadata(
	tools: readonly McpToolMetadataInput[],
	rules: readonly Threat[],
): McpToolMetadataFinding[] {
	return tools.flatMap((tool) => {
		const schemaText = collectStrings(tool.input_schema ?? tool.inputSchema, () => false, true);
		const text = [tool.name, tool.description ?? "", ...schemaText].join("\n");
		return matchPoisoningRules(rules, MCP_TOOL_METADATA, text, tool.name).map((match) => ({
			toolName: tool.name,
			threatId: match.threat.id,
			title: match.threat.title,
			action: match.threat.action,
			severity: match.threat.severity,
		}));
	});
}

// ── Runtime detector ──────────────────────────────────────────────────────

export interface ContextPoisoningRequest {
	toolName: string;
	toolInput: Record<string, unknown>;
}

export interface ContextPoisoningOptions {
	rules: readonly Threat[];
	settings: PoisoningProtectionConfig;
	sensitivity: string;
	/** The call was allowlisted by the user: keep content findings, drop the path-only ask. */
	allowlisted?: boolean;
	/** MCP tool description, when the caller (for example the MCP gateway) has it. */
	mcpToolDescription?: string;
}

function withAction(threat: Threat, action: Threat["action"]): Threat {
	return threat.action === action ? threat : { ...threat, action };
}

const PATH_REVIEW_REASON =
	"Agent instruction, memory and configuration files are re-read by every future session; a change there needs out-of-band approval.";

/** Path and content matches for every agent control file the call writes. */
function controlFileMatches(
	request: ContextPoisoningRequest,
	options: ContextPoisoningOptions,
): HeuristicMatch[] {
	const { settings, rules } = options;
	const pathReview = settings.agent_control_files !== "off" && !options.allowlisted;
	const pathAction = settings.agent_control_files === "deny" ? "block" : null;
	const matches: HeuristicMatch[] = [];
	for (const target of agentWriteTargets(request.toolName, request.toolInput)) {
		const pathRule = matchAgentControlPath(rules, target.path);
		if (!pathRule) continue;
		const label = normalizeControlPath(target.path);
		if (pathReview) {
			const threat = withAction(pathRule, pathAction ?? pathRule.action);
			matches.push({ threat, artifact: label, matchValue: label });
		}
		if (settings.content_scan) {
			matches.push(...matchPoisoningRules(rules, AGENT_CONTROL_CONTENT, target.content, label));
		}
	}
	return matches;
}

/**
 * Evaluate one normalized tool call for context poisoning. Returns null when
 * nothing matched; otherwise an `ask` or `deny` verdict whose artifacts are the
 * affected paths or the MCP tool name, never the written text.
 */
export async function evaluateContextPoisoning(
	request: ContextPoisoningRequest,
	options: ContextPoisoningOptions,
): Promise<Verdict | null> {
	const { settings, rules } = options;
	if (!settings.enabled || rules.length === 0) return null;
	const matches = controlFileMatches(request, options);
	if (
		settings.memory_write_scan &&
		isMemoryWriteTool(request.toolName, options.mcpToolDescription)
	) {
		const text = collectStrings(request.toolInput, () => false).join("\n");
		matches.push(...matchPoisoningRules(rules, MEMORY_WRITE_CONTENT, text, request.toolName));
	}

	if (matches.length === 0) return null;
	const decided = await new DecisionEngine(options.sensitivity).decide({
		heuristicMatches: matches,
		urlCheckResults: [],
	});
	if (decided.decision === "allow") return null;
	const onlyPath = matches.every((match) => match.threat.matchOn.has(AGENT_CONTROL_PATH));
	return {
		...decided,
		source: CONTEXT_POISONING_SOURCE,
		reasons: onlyPath ? [...decided.reasons, PATH_REVIEW_REASON] : decided.reasons,
	};
}
