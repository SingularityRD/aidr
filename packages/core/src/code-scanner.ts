/**
 * Project code scan: the code-guard rules (AI model supply chain and
 * secure-code guardrails) over the files of a project on disk, with a
 * file:line location for every finding. Used by `aidr scan --code <path>`.
 *
 * Nothing is executed and nothing leaves the machine. Symbolic links are not
 * followed (a link can point anywhere, including outside the project), and
 * build output, dependency and VCS directories are skipped. Files that could
 * not be inspected are counted so a partial scan is never reported as clean.
 * Evidence lines are shown with every credential masked by the shared secret
 * detectors, so the report itself cannot leak a secret it found.
 */

import type { Dirent } from "node:fs";
import { lstat, readdir, readFile } from "node:fs/promises";
import { join, relative, resolve } from "node:path";
import { NO_TRUSTED_MODEL_SOURCES, type TrustedModelSources } from "./ai-supply-chain.js";
import {
	type CodeFinding,
	CodeRuleSet,
	codeBlocksForToolCall,
	codeLanguageForPath,
	isReportableFinding,
	isSecureCodeRule,
	matchCodeBlock,
	SECRET_RULE_ID,
} from "./code-guard.js";
import { locateSecrets } from "./prompt-protection.js";
import type { Threat } from "./types.js";

export interface CodeScanOptions {
	trustedModelSources?: TrustedModelSources;
	/** Rule ids to skip (the configuration's `disabled_threats`). */
	disabledThreats?: readonly string[];
	/** Stop after this many files (default 20 000); the rest are counted as skipped. */
	maxFiles?: number;
	/** Skip files larger than this (default 1 MiB). */
	maxFileBytes?: number;
	/** Stop recording findings after this many (default 1 000). */
	maxFindings?: number;
}

export interface CodeScanFinding {
	ruleId: string;
	title: string;
	category: string;
	severity: Threat["severity"];
	/** `ai_supply_chain` rules ask/deny at runtime; `secure_code` rules are advisory. */
	kind: "ai_supply_chain" | "secure_code";
	/** Path relative to the scanned root (the file name when a single file was scanned). */
	file: string;
	/** 1-based line (within the cell, for notebooks). */
	line: number;
	/** 1-based notebook cell, for .ipynb files. */
	cell?: number;
	language: string;
	/** The source line, whitespace-condensed, with credentials masked. */
	evidence: string;
}

export interface CodeScanReport {
	root: string;
	/** False when the path does not exist or cannot be read at all. */
	exists: boolean;
	filesScanned: number;
	/** Files in a supported language that were not inspected (too large, unreadable, binary, over the cap). */
	filesSkipped: number;
	/** Symbolic links and special files that were not followed. */
	linksSkipped: number;
	/** Code rules applied (including the built-in credential rule). */
	rules: number;
	findings: CodeScanFinding[];
	/** True when `maxFindings` cut the list short. */
	truncated: boolean;
}

/** Dependency, build-output, cache and VCS directories: not the project's own code. */
const SKIP_DIRS: ReadonlySet<string> = new Set([
	"node_modules",
	".git",
	".hg",
	".svn",
	"__pycache__",
	".venv",
	"venv",
	".tox",
	".nox",
	".mypy_cache",
	".pytest_cache",
	".ruff_cache",
	"site-packages",
	"dist",
	"build",
	".next",
	".turbo",
	"coverage",
	"target",
	"vendor",
]);

const MAX_EVIDENCE = 160;

function maskedEvidence(line: string): string {
	let masked = "";
	let cursor = 0;
	for (const secret of locateSecrets(line)) {
		masked += `${line.slice(cursor, secret.start)}[REDACTED ${secret.label}]`;
		cursor = secret.end;
	}
	const flat = `${masked}${line.slice(cursor)}`.replace(/\s+/g, " ").trim();
	return flat.length <= MAX_EVIDENCE ? flat : `${flat.slice(0, MAX_EVIDENCE - 3)}...`;
}

function sourceLine(text: string, index: number): string {
	const start = text.lastIndexOf("\n", index - 1) + 1;
	const end = text.indexOf("\n", index);
	return text.slice(start, end === -1 ? text.length : end);
}

function toScanFinding(item: CodeFinding, file: string): CodeScanFinding {
	const secureCode =
		item.ruleId === SECRET_RULE_ID || (item.threat !== undefined && isSecureCodeRule(item.threat));
	return {
		ruleId: item.ruleId,
		title: item.title,
		category: item.category,
		severity: item.severity,
		kind: secureCode ? "secure_code" : "ai_supply_chain",
		file,
		line: item.line ?? item.blockLine,
		...(item.block.cell !== undefined ? { cell: item.block.cell } : {}),
		language: item.block.language,
		evidence: maskedEvidence(sourceLine(item.block.text, item.index)),
	};
}

/** Every reportable finding in one file's content (the whole file counts as written). */
function fileFindings(
	file: string,
	content: string,
	rules: CodeRuleSet,
	sources: TrustedModelSources,
): CodeScanFinding[] {
	return codeBlocksForToolCall("Write", { file_path: file, content })
		.flatMap((target) => matchCodeBlock(target, rules, { allMatches: true, includeSecrets: true }))
		.filter((item) => isReportableFinding(item, sources))
		.map((item) => toScanFinding(item, file));
}

/** The files a scan will read, and what it could not. */
class FileWalk {
	readonly files: string[] = [];
	skipped = 0;
	links = 0;

	constructor(
		private readonly maxFiles: number,
		private readonly maxBytes: number,
	) {}

	/** A regular file in a supported language, subject to the size and count caps. */
	offerFile(path: string, size: number): void {
		if (!codeLanguageForPath(path)) return;
		if (size > this.maxBytes || this.files.length >= this.maxFiles) this.skipped += 1;
		else this.files.push(path);
	}

	/** Walk a directory tree without following symbolic links. */
	async walk(root: string): Promise<void> {
		const stack = [root];
		for (let dir = stack.pop(); dir !== undefined; dir = stack.pop()) {
			const entries = await readdir(dir, { withFileTypes: true }).catch(() => null);
			if (entries === null) {
				this.skipped += 1;
				continue;
			}
			// Reverse order so the stack pops (and the file cap applies) alphabetically.
			entries.sort((left, right) => right.name.localeCompare(left.name));
			for (const entry of entries) await this.visit(dir, entry, stack);
		}
	}

	private async visit(dir: string, entry: Dirent, stack: string[]): Promise<void> {
		const path = join(dir, entry.name);
		if (entry.isDirectory()) {
			if (!SKIP_DIRS.has(entry.name)) stack.push(path);
		} else if (entry.isFile()) {
			const size = await lstat(path).then(
				(stats) => stats.size,
				() => Number.POSITIVE_INFINITY,
			);
			this.offerFile(path, size);
		} else {
			// Symbolic links, sockets, devices: not followed.
			this.links += 1;
		}
	}
}

/**
 * Scan a project directory (or a single file) with the code rules in `threats`.
 */
export async function scanCodePath(
	path: string,
	threats: readonly Threat[],
	options: CodeScanOptions = {},
): Promise<CodeScanReport> {
	const root = resolve(path);
	const rules = new CodeRuleSet(threats, options.disabledThreats ?? []);
	const sources = options.trustedModelSources ?? NO_TRUSTED_MODEL_SOURCES;
	const maxFindings = options.maxFindings ?? 1000;
	const report: CodeScanReport = {
		root,
		exists: true,
		filesScanned: 0,
		filesSkipped: 0,
		linksSkipped: 0,
		rules: rules.size,
		findings: [],
		truncated: false,
	};

	const walk = new FileWalk(options.maxFiles ?? 20_000, options.maxFileBytes ?? 1024 * 1024);
	const rootStats = await lstat(root).catch(() => null);
	if (!rootStats) return { ...report, exists: false };
	if (rootStats.isDirectory()) {
		await walk.walk(root);
	} else if (rootStats.isFile()) {
		walk.offerFile(root, rootStats.size);
		// An explicitly named file in no supported language is not silently clean.
		if (walk.files.length === 0) walk.skipped = 1;
	} else {
		walk.links += 1;
	}
	report.filesSkipped = walk.skipped;
	report.linksSkipped = walk.links;

	for (const file of walk.files) {
		const content = await readFile(file, "utf8").catch(() => null);
		// Unreadable or binary: counted, never presented as scanned clean.
		if (content === null || content.includes("\u0000")) {
			report.filesSkipped += 1;
			continue;
		}
		report.filesScanned += 1;
		// Root-relative paths use `/` on every platform so reports are stable.
		const display = rootStats.isDirectory() ? relative(root, file).replaceAll("\\", "/") : file;
		const findings = fileFindings(display, content, rules, sources);
		const room = maxFindings - report.findings.length;
		if (findings.length > room) report.truncated = true;
		report.findings.push(...findings.slice(0, Math.max(0, room)));
	}
	report.findings.sort(
		(left, right) =>
			left.file.localeCompare(right.file) ||
			(left.cell ?? 0) - (right.cell ?? 0) ||
			left.line - right.line ||
			left.ruleId.localeCompare(right.ruleId),
	);
	return report;
}
