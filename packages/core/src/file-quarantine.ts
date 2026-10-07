/**
 * Post-tool file quarantine: a file an agent tool call wrote or downloaded that
 * the content scan classifies as malicious is moved into the per-user quarantine
 * vault (`AutoQuarantine`).
 *
 * Every connector calls `quarantineAgentWrittenFiles` from the hook its host runs
 * after a tool completed (Claude Code / VS Code / Codex `PostToolUse`, Cursor
 * `postToolUse`, OpenClaw `after_tool_call`, OpenCode `tool.execute.after`).
 *
 * Rules of the road:
 * - OFF by default (`response.quarantine.enabled`). With it off this returns
 *   after reading the config and touches nothing.
 * - Only paths the call itself names are considered: the target of a
 *   write/edit tool, or the output of a recognised download command (`curl -o`,
 *   `wget -O`, `Invoke-WebRequest -OutFile`, a redirect of `curl`/`wget`, ...).
 *   Nothing else on disk is scanned or moved.
 * - "Malicious" means a `block` rule at or above `min_severity` matched the file:
 *   the command rules over a script's lines and the whole-file content rules,
 *   from the same rule set the runtime enforces. An `ask` rule never moves a file.
 * - Nothing is executed. The file is read (bounded by `max_scan_bytes`) and, when
 *   malicious, moved; a file too large to scan is reported, never called clean.
 * - Never throws: a post-tool hook must answer the host regardless.
 */

import { lstat, readFile } from "node:fs/promises";
import { extname, isAbsolute, relative, resolve } from "node:path";
import { loadConfig, resolvePath } from "./config.js";
import { HeuristicsEngine } from "./heuristics.js";
import { extractCommandsFromJsTs, matchPluginContent } from "./plugin-scanner.js";
import { AutoQuarantine } from "./quarantine.js";
import { DEFAULT_RESPONSE_AUDIT_CONFIG, responseAuditorFromConfig } from "./response-audit.js";
import { loadThreatsFromDirs } from "./threat-loader.js";
import type { Artifact, Config, Logger, Threat, Verdict } from "./types.js";
import { nullLogger } from "./types.js";

/** At most this many paths are considered per tool call. */
const MAX_CANDIDATES = 8;

const SEVERITY_RANK: Record<Threat["severity"], number> = {
	low: 0,
	medium: 1,
	high: 2,
	critical: 3,
};

/** Tools whose target file is written by the call. Lower-cased. */
const WRITE_TOOLS = new Set([
	"write",
	"edit",
	"multiedit",
	"notebookedit",
	"create_file",
	"createfile",
	"write_file",
	"writefile",
	"edit_file",
	"editfile",
	"editfiles",
	"str_replace_editor",
	"str_replace_based_edit_tool",
	"apply_patch",
	"patch",
]);

/** Tools that run a shell command. Lower-cased. */
const SHELL_TOOLS = new Set([
	"bash",
	"shell",
	"execute",
	"exec",
	"run_terminal_cmd",
	"runinterminal",
	"run_in_terminal",
	"terminal",
	"powershell",
	"local_shell",
	"container.exec",
]);

const PATH_KEYS = ["file_path", "filePath", "path", "target_file", "filename", "notebook_path"];

/** Extensions whose lines are evaluated as shell commands. */
const SCRIPT_EXTENSIONS = new Set([
	".sh",
	".bash",
	".zsh",
	".ksh",
	".py",
	".ps1",
	".psm1",
	".bat",
	".cmd",
	".command",
	".rb",
	".pl",
]);
const JS_EXTENSIONS = new Set([".js", ".cjs", ".mjs", ".ts", ".mts", ".cts"]);

// ── Which files did this call write? ───────────────────────────────

/** Split a command line into words, honouring single/double quotes and backslashes. */
export function shellWords(segment: string): string[] {
	const words: string[] = [];
	let current = "";
	let quote: '"' | "'" | null = null;
	let has = false;
	for (let i = 0; i < segment.length; i++) {
		const ch = segment[i] as string;
		if (quote) {
			if (ch === quote) quote = null;
			else if (ch === "\\" && quote === '"' && i + 1 < segment.length) current += segment[++i];
			else current += ch;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			has = true;
			continue;
		}
		if (/\s/.test(ch)) {
			if (has || current) words.push(current);
			current = "";
			has = false;
			continue;
		}
		if (ch === ">") {
			if (has || current) words.push(current);
			current = "";
			has = false;
			words.push(segment[i + 1] === ">" ? (i++, ">>") : ">");
			continue;
		}
		current += ch;
		has = true;
	}
	if (has || current) words.push(current);
	return words;
}

/** Command segments split on unquoted `;`, `&`, `|` and newlines. */
function commandSegments(command: string): string[] {
	const segments: string[] = [];
	let current = "";
	let quote: '"' | "'" | null = null;
	for (const ch of command) {
		if (quote) {
			if (ch === quote) quote = null;
			current += ch;
			continue;
		}
		if (ch === "'" || ch === '"') {
			quote = ch;
			current += ch;
			continue;
		}
		if (ch === ";" || ch === "&" || ch === "|" || ch === "\n") {
			if (current.trim()) segments.push(current);
			current = "";
			continue;
		}
		current += ch;
	}
	if (current.trim()) segments.push(current);
	return segments;
}

function programName(word: string | undefined): string {
	if (!word) return "";
	const base = word.split(/[\\/]/).pop() ?? word;
	return base.toLowerCase().replace(/\.exe$/, "");
}

/** The URL's last path segment, the name `curl -O` / plain `wget` save under. */
function remoteName(words: string[]): string | null {
	for (const word of [...words].reverse()) {
		if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(word)) continue;
		try {
			const name = decodeURIComponent(new URL(word).pathname.split("/").pop() ?? "");
			return name && name !== "." && name !== ".." && !/[\\/]/.test(name) ? name : null;
		} catch {
			return null;
		}
	}
	return null;
}

function valueAfter(words: string[], index: number): string | null {
	const value = words[index + 1];
	return value && value !== ">" && value !== ">>" ? value : null;
}

/** Output paths of the download commands in one command segment. */
function downloadOutputs(words: string[]): string[] {
	const outputs: string[] = [];
	let start = 0;
	while (
		start < words.length &&
		/^(?:sudo|env|nohup|time|command|\w+=\S*)$/i.test(words[start] ?? "")
	) {
		start++;
	}
	const program = programName(words[start]);
	const args = words.slice(start + 1);
	const isCurl = program === "curl";
	const isWget = program === "wget";
	const isIwr =
		program === "invoke-webrequest" ||
		program === "iwr" ||
		program === "invoke-restmethod" ||
		program === "irm";
	const isBits = program === "start-bitstransfer";
	const isCertutil = program === "certutil";
	const redirectable = isCurl || isWget || isIwr || program === "fetch";
	if (!isCurl && !isWget && !isIwr && !isBits && !isCertutil && !redirectable) return outputs;

	let wgetPrefix: string | null = null;
	let wgetNamed = false;
	let curlRemote = false;
	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		if ((arg === ">" || arg === ">>") && redirectable) {
			const target = valueAfter(args, i);
			if (target && target !== "/dev/null") outputs.push(target);
			i++;
			continue;
		}
		if (isCurl) {
			if (arg === "-o" || arg === "--output") {
				const value = valueAfter(args, i);
				if (value && value !== "-") outputs.push(value);
				i++;
			} else if (arg.startsWith("--output=")) outputs.push(arg.slice("--output=".length));
			else if (/^-o./.test(arg)) outputs.push(arg.slice(2));
			else if (arg === "-O" || arg === "--remote-name" || /^-[a-zA-Z]*O[a-zA-Z]*$/.test(arg))
				curlRemote = true;
		} else if (isWget) {
			if (arg === "-O" || arg === "--output-document") {
				const value = valueAfter(args, i);
				if (value && value !== "-") outputs.push(value);
				wgetNamed = true;
				i++;
			} else if (arg.startsWith("--output-document=")) {
				outputs.push(arg.slice("--output-document=".length));
				wgetNamed = true;
			} else if (/^-O./.test(arg)) {
				if (arg.slice(2) !== "-") outputs.push(arg.slice(2));
				wgetNamed = true;
			} else if (arg === "-P" || arg === "--directory-prefix") {
				wgetPrefix = valueAfter(args, i);
				i++;
			} else if (arg.startsWith("--directory-prefix=")) {
				wgetPrefix = arg.slice("--directory-prefix=".length);
			}
		} else if (isIwr) {
			if (/^-outf(?:ile)?$/i.test(arg) || /^-o(?:utfile)?$/i.test(arg)) {
				const value = valueAfter(args, i);
				if (value) outputs.push(value);
				i++;
			}
		} else if (isBits) {
			if (/^-destination$/i.test(arg)) {
				const value = valueAfter(args, i);
				if (value) outputs.push(value);
				i++;
			}
		}
	}
	if (isCurl && curlRemote) {
		const name = remoteName(args);
		if (name) outputs.push(name);
	}
	if (isWget && !wgetNamed && !args.includes("-") && !args.includes("-qO-")) {
		const name = remoteName(args) ?? null;
		if (name) outputs.push(wgetPrefix ? `${wgetPrefix}/${name}` : name);
	}
	if (isCertutil && args.some((arg) => /^[-/]urlcache$/i.test(arg))) {
		const operands = args.filter((arg) => !/^[-/]/.test(arg));
		const last = operands.at(-1);
		if (last && operands.length >= 2 && !/^[a-z]+:\/\//i.test(last)) outputs.push(last);
	}
	return outputs;
}

/** Output files of every recognised download command in `command`. */
export function downloadTargetsFromCommand(command: string): string[] {
	const out: string[] = [];
	for (const segment of commandSegments(command))
		out.push(...downloadOutputs(shellWords(segment.trim())));
	return out;
}

function stringValue(value: unknown): string | null {
	return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/**
 * Paths this call wrote, as named by the call itself. Relative paths resolve
 * against the host-reported working directory (else the process's).
 */
export function writtenFilePaths(
	toolName: string,
	toolInput: Record<string, unknown>,
	workingDirectory?: string,
): string[] {
	const tool = toolName.toLowerCase();
	const raw: string[] = [];
	if (WRITE_TOOLS.has(tool)) {
		for (const key of PATH_KEYS) {
			const value = stringValue(toolInput[key]);
			if (value) {
				raw.push(value);
				break;
			}
		}
		const edits = toolInput.edits ?? toolInput.files;
		if (Array.isArray(edits)) {
			for (const edit of edits.slice(0, MAX_CANDIDATES)) {
				if (!edit || typeof edit !== "object") continue;
				const record = edit as Record<string, unknown>;
				const value = stringValue(record.filePath ?? record.file_path ?? record.path);
				if (value) raw.push(value);
			}
		}
	} else if (SHELL_TOOLS.has(tool)) {
		const command = stringValue(toolInput.command) ?? stringValue(toolInput.cmd);
		if (command) raw.push(...downloadTargetsFromCommand(command));
	}
	const base = workingDirectory && isAbsolute(workingDirectory) ? workingDirectory : process.cwd();
	const resolved = raw.map((path) => {
		const expanded = resolvePath(path);
		return isAbsolute(expanded) ? resolve(expanded) : resolve(base, expanded);
	});
	return [...new Set(resolved)].slice(0, MAX_CANDIDATES);
}

// ── Is it malicious? ───────────────────────────────────────────────

export interface FileContentFinding {
	threatId: string;
	title: string;
	severity: Threat["severity"];
	action: Threat["action"];
}

function commandArtifacts(path: string, content: string): Artifact[] {
	const ext = extname(path).toLowerCase();
	const name = path.split(/[\\/]/).pop() ?? path;
	const isScript = SCRIPT_EXTENSIONS.has(ext) || (ext === "" && content.startsWith("#!"));
	if (JS_EXTENSIONS.has(ext)) return extractCommandsFromJsTs(content, name);
	if (!isScript) return [];
	const artifacts: Artifact[] = [];
	for (const line of content.split(/\r?\n/)) {
		const trimmed = line.trim();
		if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("//") || /^rem\b/i.test(trimmed))
			continue;
		artifacts.push({ type: "command", value: trimmed, context: `written_file:${name}` });
	}
	return artifacts;
}

/**
 * The rule matches for one file's content. Command rules run over the lines of a
 * script (and over the calls a JS/TS file makes); whole-file content rules run
 * over every text file.
 */
export function classifyFileContent(
	path: string,
	content: string,
	threats: Threat[],
): FileContentFinding[] {
	const findings = new Map<string, FileContentFinding>();
	const add = (threat: Threat) => {
		if (!findings.has(threat.id)) {
			findings.set(threat.id, {
				threatId: threat.id,
				title: threat.title,
				severity: threat.severity,
				action: threat.action,
			});
		}
	};
	const commandThreats = threats.filter((threat) => threat.matchOn.has("command"));
	const artifacts = commandArtifacts(path, content);
	if (artifacts.length > 0 && commandThreats.length > 0) {
		for (const match of new HeuristicsEngine(commandThreats).match(artifacts)) add(match.threat);
	}
	const contentThreats = threats.filter(
		(threat) => threat.matchOn.has("plugin_content") || threat.matchOn.has("content"),
	);
	const byId = new Map(threats.map((threat) => [threat.id, threat]));
	for (const finding of matchPluginContent(content, contentThreats, path).findings) {
		const threat = byId.get(finding.threatId);
		if (threat) add(threat);
	}
	return [...findings.values()];
}

/** The findings that make a file malicious: `block` rules at or above the floor. */
export function maliciousFindings(
	findings: FileContentFinding[],
	minSeverity: "medium" | "high" | "critical",
): FileContentFinding[] {
	return findings
		.filter((f) => f.action === "block" && SEVERITY_RANK[f.severity] >= SEVERITY_RANK[minSeverity])
		.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
}

// ── The post-tool entry point ──────────────────────────────────────

export interface PostToolQuarantineRequest {
	sessionId: string;
	toolName: string;
	toolInput: Record<string, unknown>;
	workingDirectory?: string;
	agentRuntime: string;
	/** The connector's bundled rule directory. */
	threatsDir: string;
	logger?: Logger;
	configPath?: string;
	/** Tests: skip loading the config. */
	config?: Config;
}

export interface QuarantinedFileNotice {
	id: string;
	originalPath: string;
	threatId: string;
	title: string;
}

export interface PostToolQuarantineResult {
	enabled: boolean;
	/** Paths that were read and classified. */
	scanned: string[];
	quarantined: QuarantinedFileNotice[];
	/** Paths that could not be classified or moved, and why. Never treated as clean. */
	skipped: Array<{ path: string; reason: string }>;
	/** Text for the agent, or null when nothing was quarantined or skipped as malicious. */
	agentNotice: string | null;
}

function isWithin(root: string, target: string): boolean {
	const fold = (value: string) => (process.platform === "win32" ? value.toLowerCase() : value);
	const rel = relative(fold(resolve(root)), fold(resolve(target)));
	return rel === "" || (!rel.startsWith("..") && !isAbsolute(rel));
}

const threatCache = new Map<string, Promise<Threat[]>>();

function threatsFor(dir: string, logger: Logger): Promise<Threat[]> {
	let cached = threatCache.get(dir);
	if (!cached) {
		cached = loadThreatsFromDirs([dir], logger).catch((error) => {
			threatCache.delete(dir);
			throw error;
		});
		threatCache.set(dir, cached);
	}
	return cached;
}

function agentNoticeFor(result: PostToolQuarantineResult): string | null {
	const lines: string[] = [];
	for (const item of result.quarantined) {
		lines.push(
			`Singularity AIDR quarantined ${item.originalPath}: after this tool call wrote it, its content matched ${item.threatId} (${item.title}). The file was moved into the AIDR quarantine vault and is no longer at that path. Do not recreate, re-download or run it; only a human operator can release it.`,
		);
	}
	for (const skip of result.skipped) {
		if (skip.reason.startsWith("quarantine_failed")) {
			lines.push(
				`Singularity AIDR classified ${skip.path} as malicious but could not quarantine it (${skip.reason}). Do not run or open it; tell the user.`,
			);
		}
	}
	return lines.length > 0 ? lines.join("\n") : null;
}

/**
 * Classify the files a completed tool call wrote and quarantine the malicious
 * ones. Never throws.
 */
export async function quarantineAgentWrittenFiles(
	request: PostToolQuarantineRequest,
): Promise<PostToolQuarantineResult> {
	const logger = request.logger ?? nullLogger;
	const result: PostToolQuarantineResult = {
		enabled: false,
		scanned: [],
		quarantined: [],
		skipped: [],
		agentNotice: null,
	};
	try {
		const config = request.config ?? (await loadConfig(request.configPath, logger));
		const settings = config.response?.quarantine;
		if (!settings?.enabled) return result;
		result.enabled = true;

		const candidates = writtenFilePaths(
			request.toolName,
			request.toolInput,
			request.workingDirectory,
		);
		if (candidates.length === 0) return result;

		const stateDir = resolvePath("~/.singularity-aidr");
		const disabled = new Set(config.disabled_threats ?? []);
		const threats = (await threatsFor(request.threatsDir, logger)).filter(
			(t) => !disabled.has(t.id),
		);
		let store: AutoQuarantine | null = null;

		for (const path of candidates) {
			// AIDR's own state (and the vault itself) is never a quarantine target.
			if (isWithin(stateDir, path)) continue;
			const info = await lstat(path).catch(() => null);
			if (!info) continue; // the call did not leave a file there
			if (info.isSymbolicLink() || !info.isFile()) {
				result.skipped.push({ path, reason: "not_a_regular_file" });
				continue;
			}
			if (info.size > settings.max_scan_bytes) {
				result.skipped.push({ path, reason: `too_large_to_scan (${info.size} bytes)` });
				continue;
			}
			let content: string;
			try {
				content = (await readFile(path)).toString("utf8");
			} catch (error) {
				result.skipped.push({
					path,
					reason: `unreadable: ${error instanceof Error ? error.message : String(error)}`,
				});
				continue;
			}
			result.scanned.push(path);
			const malicious = maliciousFindings(
				classifyFileContent(path, content, threats),
				settings.min_severity,
			);
			const top = malicious[0];
			if (!top) continue;

			const verdict: Verdict = {
				decision: "deny",
				category: "malicious_file",
				confidence: 1,
				severity: "critical",
				source: "file-quarantine",
				artifacts: [path],
				matchedThreatId: top.threatId,
				reasons: [`${top.title} (${malicious.map((f) => f.threatId).join(", ")})`],
			};
			try {
				if (!store) {
					const { auditor } = responseAuditorFromConfig(
						config.response?.audit ?? DEFAULT_RESPONSE_AUDIT_CONFIG,
						logger,
					);
					store = new AutoQuarantine(
						{
							quarantineDir: settings.dir,
							retentionDays: settings.retention_days,
							notifyChannels: [],
						},
						logger,
						config.logging,
						auditor,
					);
				}
				const item = await store.quarantine(
					path,
					top.threatId,
					{
						reason: "agent_written_file_classified_malicious",
						rule_ids: malicious.map((f) => f.threatId),
						tool: request.toolName,
						agent_runtime: request.agentRuntime,
						session_id: request.sessionId,
					},
					{ tool: request.toolName, input: path, verdict },
				);
				result.quarantined.push({
					id: item.id,
					originalPath: item.originalPath,
					threatId: top.threatId,
					title: top.title,
				});
			} catch (error) {
				result.skipped.push({
					path,
					reason: `quarantine_failed: ${error instanceof Error ? error.message : String(error)}`,
				});
				logger.warn("A malicious agent-written file could not be quarantined", {
					path,
					threatId: top.threatId,
					error: String(error),
				});
			}
		}

		if (store && result.quarantined.length > 0) {
			// Housekeeping after the move: retention first, then the size bound.
			await store.cleanupExpired().catch(() => []);
			await store.enforceSizeLimit(settings.max_total_bytes).catch(() => []);
		}
		result.agentNotice = agentNoticeFor(result);
		return result;
	} catch (error) {
		logger.warn("Post-tool file quarantine failed", { error: String(error) });
		result.agentNotice = agentNoticeFor(result);
		return result;
	}
}

/** The quarantine vault configured for this install (operator CLI). */
export async function openConfiguredQuarantine(
	options: { configPath?: string; logger?: Logger } = {},
): Promise<{ store: AutoQuarantine; settings: Config["response"]["quarantine"] }> {
	const logger = options.logger ?? nullLogger;
	const config = await loadConfig(options.configPath, logger);
	const settings = config.response.quarantine;
	const { auditor } = responseAuditorFromConfig(config.response.audit, logger);
	return {
		store: new AutoQuarantine(
			{ quarantineDir: settings.dir, retentionDays: settings.retention_days, notifyChannels: [] },
			logger,
			config.logging,
			auditor,
		),
		settings,
	};
}
