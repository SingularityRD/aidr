/**
 * Plugin scanner — discovers and scans installed Claude Code plugins for threats.
 */

import { createHash } from "node:crypto";
import { constants, type Stats } from "node:fs";
import { lstat, open, readdir, realpath } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";
import type { FileCheckBatchResult } from "./clients/file-check.js";
import { FileCheckClient } from "./clients/file-check.js";
import { UrlCheckClient } from "./clients/url-check.js";
import { DetectionLegUnavailableError } from "./detection-leg.js";
import { extractUrls } from "./extractors.js";
import { getFileContent } from "./file-utils.js";
import { HeuristicsEngine } from "./heuristics.js";
import type { IntelMerged } from "./intel/types.js";
import type {
	Artifact,
	Logger,
	PluginFinding,
	PluginInfo,
	PluginScanResult,
	PluginScanUnavailableCheck,
	Threat,
	TrustedDomain,
	UrlCheckResult,
} from "./types.js";
import { nullLogger } from "./types.js";

/**
 * Record that a reputation leg did not run.
 *
 * The point is to keep "we checked and found nothing" distinguishable from "we
 * never checked". Detection internals are allowed to degrade, but the
 * degradation has to be legible to whoever reads the scan result.
 */
function markUnavailable(result: PluginScanResult, entry: PluginScanUnavailableCheck): void {
	if (!result.unavailableChecks) result.unavailableChecks = [];
	result.unavailableChecks.push(entry);
}

/** Turn URL reputation results into findings. Shared by the success and partial paths. */
function pushUrlFindings(result: PluginScanResult, checkResults: UrlCheckResult[]): void {
	for (const ur of checkResults) {
		if (!ur.isMalicious) continue;
		const findingDetails = ur.findings.map((f) => `${f.severityName}/${f.typeName}`).join(", ");
		result.findings.push({
			threatId: "URL_CHECK",
			title: `Malicious URL (${findingDetails})`,
			severity: "critical",
			confidence: 1.0,
			action: "block",
			artifact: ur.url.slice(0, 200),
			sourceFile: "URL check",
		});
	}
}

/** Turn file reputation results into findings. Shared by the success and partial paths. */
function pushFileFindings(
	result: PluginScanResult,
	plugin: PluginInfo,
	checkResults: FileCheckBatchResult[],
	hashToFiles: Map<string, string[]>,
): void {
	for (const fr of checkResults) {
		if (fr.severity !== "SEVERITY_MALWARE") continue;
		for (const filePath of hashToFiles.get(fr.sha256) ?? []) {
			result.findings.push({
				threatId: "FILE_CHECK",
				title: `Malicious file (${fr.detectionNames.join(", ") || "unknown"})`,
				severity: "critical",
				confidence: 1.0,
				action: "block",
				artifact: fr.sha256,
				sourceFile: relative(plugin.installPath, filePath),
			});
		}
	}
}

/**
 * Turn a leg failure into something an operator can act on.
 *
 * `DetectionLegUnavailableError` already carries an operator-readable reason
 * (including the unauthenticated-401 case that caused the original false clean),
 * so it is preferred over re-deriving one from the message.
 */
function describeLegFailure(error: unknown): string {
	if (error instanceof DetectionLegUnavailableError) return error.reason;
	const message = error instanceof Error ? error.message : String(error);
	if (/\b401\b|\b403\b|unauthor|forbidden/i.test(message)) {
		return `endpoint rejected the request as unauthenticated (${message})`;
	}
	if (/ENOTFOUND|EAI_AGAIN|getaddrinfo|fetch failed|ECONNREFUSED|ETIMEDOUT/i.test(message)) {
		return `endpoint unreachable (${message})`;
	}
	return message;
}

const DEFAULT_PLUGINS_REGISTRY = join(homedir(), ".claude", "plugins", "installed_plugins.json");

const SCANNABLE_EXTENSIONS = new Set([
	".py",
	".js",
	".ts",
	".mjs",
	".mts",
	".sh",
	".bash",
	".zsh",
	".json",
	".yaml",
	".yml",
	".md",
	".toml",
	".txt",
	".cfg",
	".ini",
	".conf",
]);

const SKIP_DIRS = new Set(["node_modules", ".git"]);

/**
 * Python bytecode caches are not text-inspected, but they are walked so that
 * bytecode shipped without its source (AIG Skill-Scan T04) can be reported.
 * Bytecode beside its source is the interpreter's normal cache and is neither a
 * finding nor an incomplete path.
 */
const BYTECODE_CACHE_DIR = "__pycache__";
const BYTECODE_EXTENSIONS = new Set([".pyc", ".pyo"]);

/** Max file size to scan (skip large files). */
const MAX_FILE_SIZE = 512 * 1024;

export async function discoverPlugins(
	registryPath = DEFAULT_PLUGINS_REGISTRY,
	logger: Logger = nullLogger,
): Promise<PluginInfo[]> {
	let raw: string;
	try {
		raw = await getFileContent(registryPath);
	} catch {
		logger.debug("Plugin registry not found", { path: registryPath });
		return [];
	}

	let data: Record<string, unknown>;
	try {
		data = JSON.parse(raw) as Record<string, unknown>;
	} catch (e) {
		logger.warn("Failed to read plugin registry", { error: String(e) });
		return [];
	}

	const plugins: PluginInfo[] = [];
	const pluginEntries = (data.plugins ?? {}) as Record<string, unknown>;

	for (const [pluginKey, versions] of Object.entries(pluginEntries)) {
		if (!Array.isArray(versions) || versions.length === 0) continue;
		const entry = versions[versions.length - 1] as Record<string, unknown>;
		const installPath = (entry.installPath ?? "") as string;
		const version = (entry.version ?? "unknown") as string;
		const lastUpdated = (entry.lastUpdated ?? "") as string;

		if (!installPath) continue;

		plugins.push({ key: pluginKey, installPath, version, lastUpdated });
	}

	return plugins;
}

function isWithinPath(root: string, candidate: string): boolean {
	const pathFromRoot = relative(root, candidate);
	return (
		pathFromRoot === "" ||
		(!isAbsolute(pathFromRoot) && pathFromRoot !== ".." && !pathFromRoot.startsWith(`..${sep}`))
	);
}

async function readPluginFileSafely(filePath: string, realRoot: string): Promise<Buffer> {
	const before = await lstat(filePath);
	const beforeRealPath = await realpath(filePath);
	if (
		before.isSymbolicLink() ||
		!before.isFile() ||
		before.size > MAX_FILE_SIZE ||
		!isWithinPath(realRoot, beforeRealPath)
	) {
		throw new Error("Plugin file changed or resolved outside its install directory.");
	}

	const handle = await open(filePath, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
	try {
		const opened = await handle.stat();
		const after = await lstat(filePath);
		const afterRealPath = await realpath(filePath);
		if (
			!opened.isFile() ||
			opened.size > MAX_FILE_SIZE ||
			after.isSymbolicLink() ||
			!after.isFile() ||
			opened.dev !== after.dev ||
			opened.ino !== after.ino ||
			!isWithinPath(realRoot, afterRealPath)
		) {
			throw new Error("Plugin file changed or resolved outside its install directory.");
		}

		const chunks: Buffer[] = [];
		let total = 0;
		while (total <= MAX_FILE_SIZE) {
			const chunk = Buffer.allocUnsafe(Math.min(64 * 1024, MAX_FILE_SIZE + 1 - total));
			const { bytesRead } = await handle.read(chunk, 0, chunk.length, total);
			if (bytesRead === 0) break;
			total += bytesRead;
			if (total > MAX_FILE_SIZE) throw new Error("Plugin file exceeds the scan size limit.");
			chunks.push(chunk.subarray(0, bytesRead));
		}
		return Buffer.concat(chunks, total);
	} finally {
		await handle.close();
	}
}

interface PluginWalk {
	files: string[];
	/** Every regular file seen in the tree, including non-scannable ones. */
	allFiles: Set<string>;
	/** Python bytecode files, inside or outside `__pycache__`. */
	bytecodeFiles: string[];
	incompletePaths: number;
	realRoot: string | null;
}

async function walkPluginFiles(installPath: string, logger: Logger): Promise<PluginWalk> {
	const files: string[] = [];
	const allFiles = new Set<string>();
	const bytecodeFiles: string[] = [];
	let incompletePaths = 0;
	const rootPath = resolve(installPath);
	const unavailable = (): PluginWalk => ({
		files,
		allFiles,
		bytecodeFiles,
		incompletePaths: 1,
		realRoot: null,
	});
	let realRoot: string;
	try {
		const rootStats = await lstat(rootPath);
		if (rootStats.isSymbolicLink()) return unavailable();
		realRoot = await realpath(rootPath);
	} catch {
		return unavailable();
	}

	/**
	 * The path's own (unfollowed) stats when it can be inspected: not a symlink and
	 * resolving inside the plugin root. Anything else counts as an incomplete path.
	 */
	async function inspectable(dirOrFile: string): Promise<Stats | null> {
		const stats = await lstat(dirOrFile).catch(() => null);
		const resolved =
			stats && !stats.isSymbolicLink() ? await realpath(dirOrFile).catch(() => null) : null;
		if (stats && resolved !== null && isWithinPath(realRoot, resolved)) return stats;
		incompletePaths += 1;
		return null;
	}

	function addFile(file: string, size: number, inBytecodeCache: boolean): void {
		const extension = extname(file).toLowerCase();
		allFiles.add(file);
		if (BYTECODE_EXTENSIONS.has(extension)) bytecodeFiles.push(file);
		// Only bytecode is of interest inside an interpreter cache directory.
		if (inBytecodeCache) return;
		if (SCANNABLE_EXTENSIONS.has(extension) && size <= MAX_FILE_SIZE) files.push(file);
		else incompletePaths += 1;
	}

	async function walkDirectory(dir: string, inBytecodeCache: boolean): Promise<void> {
		let entries: string[];
		try {
			entries = await readdir(dir);
		} catch {
			incompletePaths += 1;
			return;
		}
		for (const entry of entries) {
			if (SKIP_DIRS.has(entry)) continue;
			await walk(join(dir, entry), inBytecodeCache || entry === BYTECODE_CACHE_DIR);
		}
	}

	async function walk(dirOrFile: string, inBytecodeCache = false): Promise<void> {
		const stats = await inspectable(dirOrFile);
		if (!stats) return;
		if (stats.isFile()) addFile(dirOrFile, stats.size, inBytecodeCache);
		else if (stats.isDirectory()) await walkDirectory(dirOrFile, inBytecodeCache);
	}
	try {
		await walk(rootPath);
	} catch (e) {
		logger.warn(`Error walking plugin path ${installPath}`, { error: String(e) });
		incompletePaths += 1;
	}
	return { files, allFiles, bytecodeFiles, incompletePaths, realRoot };
}

/** A cached verdict is safe only while the current plugin tree is fully inspectable. */
export async function canReusePluginScanCache(
	plugin: PluginInfo,
	logger: Logger = nullLogger,
): Promise<boolean> {
	const walk = await walkPluginFiles(plugin.installPath, logger);
	return walk.incompletePaths === 0 && walk.files.length > 0;
}

/**
 * Returns true if the line is an echo/printf statement where all pipe characters
 * are inside quotes (i.e., just printing text, not piping to another command).
 */
function isHarmlessEcho(line: string): boolean {
	if (!/^(echo|printf)\b/.test(line)) return false;
	// Strip quoted strings, then check for remaining unquoted pipes
	const withoutQuotes = line.replace(/"(?:[^"\\]|\\.)*"|'[^']*'/g, "");
	return !withoutQuotes.includes("|");
}

const JS_TS_EXTENSIONS = new Set([".js", ".ts", ".mjs", ".mts"]);

/**
 * Strip JS/TS comments while preserving string literals.
 * Uses a single-pass regex that matches strings, template literals, and
 * comments. Only comments are replaced; strings are kept intact so that
 * `//` inside URLs (e.g. "https://...") is not misidentified as a comment.
 */
const STRING_OR_COMMENT_RE =
	/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`|\/\/.*$|\/\*[\s\S]*?\*\//gm;

function stripJsComments(src: string): string {
	return src.replace(STRING_OR_COMMENT_RE, (match) => {
		// Keep strings/templates, blank out comments
		if (match.startsWith("//") || match.startsWith("/*")) return "";
		return match;
	});
}

/**
 * Regex patterns for Node.js/Bun/zx command execution APIs.
 * Each captures the string argument (group 1) from known call sites.
 *
 * String literal sub-patterns are escape-aware ("((?:[^"\\]|\\.)+)") so
 * that escaped quotes inside arguments (e.g. exec("bash -c \"curl ...\""))
 * don't truncate the capture.
 */

// Reusable fragment: capture content of "...", '...', or `...`
// Groups: 1 = double-quoted, 2 = single-quoted, 3 = backtick-quoted
const STR_ARG = `(?:"((?:[^"\\\\]|\\\\.)*)"|'((?:[^'\\\\]|\\\\.)*)'|` + "`([^`]*)`" + `)`;

// exec("..."), execSync("..."), execFile("..."), execFileSync("...")
const JS_EXEC_RE = new RegExp(`\\bexec(?:File)?(?:Sync)?\\s*\\(\\s*${STR_ARG}`, "g");

// spawn("..."), spawnSync("...") — first arg is the executable
const JS_SPAWN_RE = new RegExp(`\\bspawn(?:Sync)?\\s*\\(\\s*${STR_ARG}`, "g");

// spawn/spawnSync array args: spawn("bash", ["-c", "curl ..."])
// Captures the executable (group 1/2/3) and array content (group 4).
const JS_SPAWN_ARGS_RE =
	/\bspawn(?:Sync)?\s*\(\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`([^`]*)`)\s*,\s*\[([^\]]*)\]/g;

// Only extract array args when the executable is a shell — otherwise the
// args are just data passed to the program, not commands to execute.
// Checked by basename so path-qualified forms like /bin/bash also match.
const SHELL_EXECUTABLES = new Set([
	"bash",
	"sh",
	"zsh",
	"dash",
	"ksh",
	"csh",
	"fish",
	"cmd",
	"cmd.exe",
	"powershell",
	"powershell.exe",
	"pwsh",
]);

function isShellExecutable(exe: string): boolean {
	const basename = exe.split("/").pop()?.split("\\").pop() ?? exe;
	return SHELL_EXECUTABLES.has(basename);
}

// execa("...")
const JS_EXECA_RE = new RegExp(`\\bexeca\\s*\\(\\s*${STR_ARG}`, "g");

// execa array args: execa("bash", ["-c", "curl ..."])
const JS_EXECA_ARGS_RE =
	/\bexeca\s*\(\s*(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)'|`([^`]*)`)\s*,\s*\[([^\]]*)\]/g;

// Bun.shell("...")
const JS_BUN_SHELL_RE = new RegExp(`\\bBun\\.shell\\s*\\(\\s*${STR_ARG}`, "g");

// Bun.$`...`
const JS_BUN_DOLLAR_RE = /\bBun\.\$`([^`]+)`/g;

// $`...` (zx tagged template)
const JS_ZX_RE = /(?<!\w)\$`([^`]+)`/g;

/**
 * Extract command artifacts from JS/TS file content.
 *
 * Known limitation: matching runs on flattened source text after comment
 * stripping, so API-call patterns appearing inside string literals (e.g.
 * help text or documentation examples) will produce false-positive artifacts.
 * In practice this is low-risk because the artifact must still match a threat
 * pattern to trigger a finding.
 */
export function extractCommandsFromJsTs(content: string, fileName: string): Artifact[] {
	const commands = new Set<string>();
	const stripped = stripJsComments(content);
	// Collapse newlines to spaces so multi-line calls are matched
	const collapsed = stripped.replace(/\n/g, " ");

	function addMatch(m: RegExpExecArray) {
		// Capture group 1, 2, or 3 (double, single, or backtick quotes)
		const val = m[1] ?? m[2] ?? m[3];
		if (val) commands.add(val.trim());
	}

	for (const re of [JS_EXEC_RE, JS_SPAWN_RE, JS_EXECA_RE, JS_BUN_SHELL_RE]) {
		for (const m of collapsed.matchAll(re)) {
			addMatch(m);
		}
	}

	// Bun.$`...` and $`...` — single capture group
	for (const re of [JS_BUN_DOLLAR_RE, JS_ZX_RE]) {
		for (const m of collapsed.matchAll(re)) {
			if (m[1]) commands.add(m[1].trim());
		}
	}

	// spawn/spawnSync/execa array args — only extract when the executable is a shell
	for (const re of [JS_SPAWN_ARGS_RE, JS_EXECA_ARGS_RE]) {
		for (const arrMatch of collapsed.matchAll(re)) {
			const exe = (arrMatch[1] ?? arrMatch[2] ?? arrMatch[3] ?? "").trim();
			if (!isShellExecutable(exe)) continue;
			const arrayContent = arrMatch[4] ?? "";
			const strLitRe = new RegExp(STR_ARG, "g");
			for (const strMatch of arrayContent.matchAll(strLitRe)) {
				const val = strMatch[1] ?? strMatch[2] ?? strMatch[3];
				if (val) commands.add(val.trim());
			}
		}
	}

	return [...commands].map((value) => ({
		type: "command" as const,
		value,
		context: `plugin_file:${fileName}`,
	}));
}

function extractArtifactsFromFile(filePath: string, content: string): Artifact[] {
	const artifacts: Artifact[] = [];
	const fileName = filePath.split("/").pop() ?? filePath;

	// Extract URLs (skip localhost)
	for (const url of extractUrls(content)) {
		if (url.includes("://127.0.0.1") || url.includes("://localhost")) continue;
		artifacts.push({ type: "url", value: url, context: `plugin_file:${fileName}` });
	}

	// For script files, treat content as potential commands
	const ext = extname(filePath).toLowerCase();
	if ([".sh", ".bash", ".zsh", ".py"].includes(ext)) {
		for (const line of content.split("\n")) {
			const trimmed = line.trim();
			if (
				trimmed &&
				!trimmed.startsWith("#") &&
				!trimmed.startsWith("//") &&
				!isHarmlessEcho(trimmed)
			) {
				artifacts.push({
					type: "command",
					value: trimmed,
					context: `plugin_file:${fileName}`,
				});
			}
		}
	}

	// For JS/TS files, extract commands from known execution APIs
	if (JS_TS_EXTENSIONS.has(ext)) {
		artifacts.push(...extractCommandsFromJsTs(content, fileName));
	}

	return artifacts;
}

// ── Skill / plugin package rules (AIG Skill-Scan T01–T09) ─────────────

export { SKILL_RISK_TYPES, skillRiskTypeForThreatId } from "./skill-risk-types.js";

/** match_on value for rules evaluated against the whole text of a plugin file. */
const PLUGIN_CONTENT_MATCH = "plugin_content";
/** match_on value for rules evaluated against bytecode shipped without source. */
const PLUGIN_ORPHAN_BYTECODE_MATCH = "plugin_orphan_bytecode";

/** Categories whose matched text is a credential and must never be echoed. */
const SECRET_BEARING_CATEGORIES = new Set(["skill_hardcoded_secret"]);
const MAX_CONTENT_EVIDENCE = 160;
const INVISIBLE_CHARACTERS = /[​-‍⁠-⁤‪-‮⁦-⁩﻿]|\uDB40[\uDC00-\uDC7F]/g;

function lineNumberAt(content: string, index: number): number {
	let line = 1;
	for (let position = content.indexOf("\n"); position !== -1 && position < index; ) {
		line += 1;
		position = content.indexOf("\n", position + 1);
	}
	return line;
}

/**
 * Evidence for a content finding: a line number and the matched text with
 * invisible characters rendered as code points, so smuggled text is visible to
 * the reviewer. Credentials are replaced by a short digest.
 */
function contentEvidence(threat: Threat, content: string, index: number, matched: string): string {
	const line = lineNumberAt(content, index);
	if (SECRET_BEARING_CATEGORIES.has(threat.category)) {
		const digest = createHash("sha256").update(matched).digest("hex").slice(0, 12);
		return `line ${line}: [credential redacted, sha256:${digest}]`;
	}
	const visible = matched
		.replace(
			INVISIBLE_CHARACTERS,
			(character) =>
				`<U+${(character.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, "0")}>`,
		)
		.replace(/\s+/g, " ")
		.trim();
	const bounded =
		visible.length > MAX_CONTENT_EVIDENCE ? `${visible.slice(0, MAX_CONTENT_EVIDENCE)}…` : visible;
	return `line ${line}: ${bounded}`;
}

function statelessPattern(threat: Threat): RegExp {
	return threat.compiledPattern.global || threat.compiledPattern.sticky
		? new RegExp(threat.compiledPattern.source, threat.compiledPattern.flags.replace(/[gy]/g, ""))
		: threat.compiledPattern;
}

/**
 * Evaluate whole-file content rules. One finding per rule per file keeps a
 * repeated pattern from flooding the report; the first line is enough to
 * direct a review.
 */
export function matchPluginContent(
	content: string,
	threats: Threat[],
	sourceFile: string,
): { findings: PluginFinding[]; failedThreatIds: string[] } {
	const findings: PluginFinding[] = [];
	const failedThreatIds: string[] = [];
	for (const threat of threats) {
		let match: RegExpExecArray | null;
		try {
			match = statelessPattern(threat).exec(content);
		} catch {
			failedThreatIds.push(threat.id);
			continue;
		}
		if (!match) continue;
		findings.push({
			threatId: threat.id,
			title: threat.title,
			severity: threat.severity,
			confidence: threat.confidence,
			action: threat.action,
			artifact: contentEvidence(threat, content, match.index, match[0]),
			sourceFile,
		});
	}
	return { findings, failedThreatIds };
}

/** Where CPython would have compiled a bytecode file from. */
function bytecodeSourcePath(bytecodePath: string): string {
	const directory = dirname(bytecodePath);
	const stem = basename(bytecodePath).replace(/\.py[co]$/i, "");
	// __pycache__/name.cpython-312.pyc is compiled from ../name.py; module names
	// cannot contain dots, so the interpreter tag is everything after the first.
	if (basename(directory) === BYTECODE_CACHE_DIR) {
		return join(dirname(directory), `${stem.split(".")[0]}.py`);
	}
	return join(directory, `${stem}.py`);
}

function orphanBytecodeFindings(
	plugin: PluginInfo,
	walk: PluginWalk,
	threats: Threat[],
): PluginFinding[] {
	const findings: PluginFinding[] = [];
	if (threats.length === 0) return findings;
	for (const bytecodePath of walk.bytecodeFiles) {
		if (walk.allFiles.has(bytecodeSourcePath(bytecodePath))) continue;
		const sourceFile = relative(plugin.installPath, bytecodePath);
		for (const threat of threats) {
			if (!statelessPattern(threat).test(bytecodePath)) continue;
			findings.push({
				threatId: threat.id,
				title: threat.title,
				severity: threat.severity,
				confidence: threat.confidence,
				action: threat.action,
				artifact: sourceFile,
				sourceFile,
			});
		}
	}
	return findings;
}

export async function scanPlugin(
	plugin: PluginInfo,
	threats: Threat[],
	options: {
		checkUrls?: boolean;
		checkFileHashes?: boolean;
		includeQueryParameters?: boolean;
		trustedDomains?: TrustedDomain[];
		intelMerged?: IntelMerged | null;
		logger?: Logger;
		/**
		 * Bearer key for the first-party reputation endpoints. Optional: an
		 * unauthenticated deployment is legal, and that case is reported through
		 * `unavailableChecks` rather than being mistaken for a clean scan.
		 */
		apiKey?: string;
	} = {},
): Promise<PluginScanResult> {
	const {
		checkUrls = false,
		checkFileHashes = false,
		includeQueryParameters = false,
		trustedDomains,
		intelMerged,
		logger = nullLogger,
	} = options;
	const result: PluginScanResult = { plugin, findings: [] };

	const walk = await walkPluginFiles(plugin.installPath, logger);
	const files = walk.files;
	let unreadableFiles = 0;
	const contentThreats = threats.filter((t) => t.matchOn.has(PLUGIN_CONTENT_MATCH));
	const failedContentThreats = new Set<string>();
	result.findings.push(
		...orphanBytecodeFindings(
			plugin,
			walk,
			threats.filter((t) => t.matchOn.has(PLUGIN_ORPHAN_BYTECODE_MATCH)),
		),
	);
	if (files.length === 0) {
		markUnavailable(result, {
			check: "plugin_files",
			reason: "No scannable plugin files could be inspected.",
			uncheckedCount: Math.max(1, walk.incompletePaths),
		});
		return result;
	}

	// Only run command-type heuristics on plugin files
	const commandThreats = threats.filter((t) => t.matchOn.has("command"));
	const heuristics = new HeuristicsEngine(commandThreats, trustedDomains);

	const allUrls: string[] = [];
	const hashToFiles = new Map<string, string[]>();
	let readableFileCount = 0;

	for (const filePath of files) {
		let content: string;
		let rawBytes: Buffer;
		try {
			if (!walk.realRoot) throw new Error("Plugin root is unavailable.");
			rawBytes = await readPluginFileSafely(filePath, walk.realRoot);
			content = rawBytes.toString("utf-8");
		} catch {
			unreadableFiles += 1;
			continue;
		}
		readableFileCount++;

		// Heuristic matching
		const artifacts = extractArtifactsFromFile(filePath, content);
		if (artifacts.length > 0) {
			const matches = heuristics.match(artifacts);
			for (const match of matches) {
				result.findings.push({
					threatId: match.threat.id,
					title: match.threat.title,
					severity: match.threat.severity,
					confidence: match.threat.confidence,
					action: match.threat.action,
					artifact: match.artifact.slice(0, 200),
					sourceFile: relative(plugin.installPath, filePath),
				});
			}
		}

		if (contentThreats.length > 0) {
			const contentMatches = matchPluginContent(
				content,
				contentThreats,
				relative(plugin.installPath, filePath),
			);
			result.findings.push(...contentMatches.findings);
			for (const threatId of contentMatches.failedThreatIds) failedContentThreats.add(threatId);
		}

		// Collect URLs for URL check
		allUrls.push(...extractUrls(content));

		// Compute file hash for reputation check
		if (checkFileHashes || (intelMerged?.pluginSignatureDeny.size ?? 0) > 0) {
			const sha256 = createHash("sha256").update(rawBytes).digest("hex");
			const existing = hashToFiles.get(sha256);
			if (existing) {
				existing.push(filePath);
			} else {
				hashToFiles.set(sha256, [filePath]);
			}
		}
	}
	if (failedContentThreats.size > 0) {
		// A rule that failed to evaluate is a skipped signal, never a clean one.
		markUnavailable(result, {
			check: "plugin_files",
			reason: `Content rules could not be evaluated: ${[...failedContentThreats].sort().join(", ")}`,
			uncheckedCount: failedContentThreats.size,
		});
		logger.warn("Plugin scan: content rules failed to evaluate", {
			threatIds: [...failedContentThreats],
		});
	}
	const incompletePaths = walk.incompletePaths + unreadableFiles;
	if (incompletePaths > 0) {
		markUnavailable(result, {
			check: "plugin_files",
			reason:
				"Some plugin paths could not be inspected safely; local detection coverage is incomplete.",
			uncheckedCount: incompletePaths,
		});
	}

	if (!checkUrls && allUrls.length > 0) {
		markUnavailable(result, {
			check: "url_reputation",
			reason: "disabled to avoid sending plugin URLs to an external reputation provider",
			uncheckedCount: new Set(allUrls).size,
		});
	}
	if (!checkFileHashes && readableFileCount > 0) {
		markUnavailable(result, {
			check: "file_reputation",
			reason: "disabled to avoid sending plugin file hashes to an external reputation provider",
			uncheckedCount: readableFileCount,
		});
	}

	// Offline intel: plugin signature denylist (sha256 of suspicious files).
	if (intelMerged && intelMerged.pluginSignatureDeny.size > 0 && hashToFiles.size > 0) {
		for (const sha256 of hashToFiles.keys()) {
			if (!intelMerged.pluginSignatureDeny.has(sha256.toLowerCase())) continue;
			const filePaths = hashToFiles.get(sha256) ?? [];
			for (const filePath of filePaths) {
				result.findings.push({
					threatId: "INTEL-PLUGIN-SIGNATURE-001",
					title: "Plugin file hash is denied by offline intel packs",
					severity: "critical",
					confidence: 1.0,
					action: "block",
					artifact: sha256,
					sourceFile: relative(plugin.installPath, filePath),
				});
			}
		}
	}

	// Run URL check and file hash check in parallel
	const urlCheckPromise =
		checkUrls && allUrls.length > 0
			? (async () => {
					try {
						const uniqueUrls = [...new Set(allUrls)];
						// Pass the configured API key. Without it the first-party
						// endpoint answers 401 and the leg silently produced nothing -
						// a false clean. The key is optional; an unauthenticated
						// deployment is legal, so a failure is reported rather than
						// thrown (see the catch below).
						const client = new UrlCheckClient(
							{ include_query_parameters: includeQueryParameters },
							logger,
							options.apiKey,
						);
						const checkResults = await client.checkUrls(uniqueUrls);
						pushUrlFindings(result, checkResults);
					} catch (error) {
						// The leg could not run (or ran only partly). Detection internals
						// are allowed to degrade, but the degradation MUST be visible:
						// silently continuing makes "unchecked" indistinguishable from
						// "clean". Detections from any batch that did succeed are kept.
						const partial =
							error instanceof DetectionLegUnavailableError ? error.partialResults : [];
						pushUrlFindings(result, partial as UrlCheckResult[]);
						markUnavailable(result, {
							check: "url_reputation",
							reason: describeLegFailure(error),
							uncheckedCount:
								error instanceof DetectionLegUnavailableError && error.uncheckedCount > 0
									? error.uncheckedCount
									: [...new Set(allUrls)].length,
						});
						logger.warn("Plugin scan: URL reputation leg did not run", {
							reason: describeLegFailure(error),
							uncheckedCount: [...new Set(allUrls)].length,
						});
					}
				})()
			: Promise.resolve();

	const fileCheckPromise =
		checkFileHashes && hashToFiles.size > 0
			? (async () => {
					try {
						const client = new FileCheckClient(undefined, logger, options.apiKey);
						const uniqueHashes = [...hashToFiles.keys()];
						const checkResults = await client.checkHashes(uniqueHashes);
						pushFileFindings(result, plugin, checkResults, hashToFiles);
					} catch (error) {
						const partial =
							error instanceof DetectionLegUnavailableError ? error.partialResults : [];
						pushFileFindings(result, plugin, partial as FileCheckBatchResult[], hashToFiles);
						markUnavailable(result, {
							check: "file_reputation",
							reason: describeLegFailure(error),
							uncheckedCount:
								error instanceof DetectionLegUnavailableError && error.uncheckedCount > 0
									? error.uncheckedCount
									: hashToFiles.size,
						});
						logger.warn("Plugin scan: file reputation leg did not run", {
							reason: describeLegFailure(error),
							uncheckedCount: hashToFiles.size,
						});
					}
				})()
			: Promise.resolve();

	await Promise.all([urlCheckPromise, fileCheckPromise]);

	return result;
}
