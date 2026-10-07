#!/usr/bin/env node
/**
 * verify-repo-hygiene.mjs — machine gate for AIDR-012 (root repository hygiene).
 *
 * Acceptance criteria enforced here:
 *   "No scratch output tracked at root; .gitignore prevents recurrence; no host-path
 *    strings in tracked text files outside vendored/generated content."
 *
 * Two checks, both driven by the git index (`git ls-files`) — never by a filesystem walk,
 * so untracked scratch files and intentionally ignored files stay out of scope:
 *
 *   1. Root scratch check
 *      The scratch-related patterns declared in `.gitignore` are parsed out of that file and
 *      every one of them must be genuinely untracked at the repository root. The pattern list
 *      is therefore derived from `.gitignore` itself, so the gate and `.gitignore` cannot
 *      drift apart.
 *
 *   2. Host-path scan
 *      Every tracked text file is scanned for absolute host paths that must never be committed:
 *      a Windows drive path (`C:\Users\<name>\...`, including the JSON/TS string-escaped
 *      `C:\\Users\\<name>\\...` form) and a POSIX `/home/<name>/` or `/Users/<name>/` absolute
 *      path. Binary files are skipped by extension and by a NUL-byte probe. Anonymous
 *      placeholder identities (`user`, `u`, `Target_User`, `Public`) are reported as
 *      non-identifying. A bare Windows UNC rule is deliberately omitted — see the note above
 *      HOST_PATH_PATTERNS.
 *
 *      Vendored/generated content is NOT silently skipped. A file is exempt only when it is
 *      listed in ALLOWLIST below with a written reason, and the gate self-checks every entry:
 *      an entry whose reason is missing or too short to be an explanation fails the gate.
 *
 * Exit codes: 0 clean, 1 violations, 2 the gate could not run (bad usage / not a git repo).
 *
 * Usage:  node scripts/verify-repo-hygiene.mjs [--json] [--repo <dir>]
 */

import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { dirname, isAbsolute, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));

/** Minimum length for an allowlist reason before it can count as an explanation. */
export const MIN_ALLOWLIST_REASON_LENGTH = 24;

/* ------------------------------------------------------------------ *
 * Allowlist
 * ------------------------------------------------------------------ */

/**
 * Files that legitimately contain an absolute host path in a non-identifying form.
 *
 * Rules for adding an entry — an entry without a real reason FAILS the gate's self-check:
 *   - "path"   exact repository-relative file path, or a `dir/**` prefix form.
 *   - "reason" a written explanation of why the path is intentional and anonymous.
 *   - "owner"  the tracking issue/record id for the exemption.
 *
 * Anything not listed here must be genuinely free of absolute host paths. "It is generated"
 * is not sufficient by itself: a generator that embeds a contributor's home directory is a
 * real leak and was fixed rather than allowlisted (see scripts/generate-next-agent-execution-prompt.mjs).
 */
export const ALLOWLIST = [
	{
		path: "scripts/verify-repo-hygiene.mjs",
		owner: "AIDR-012",
		reason:
			"The gate's own documentation and regular-expression examples contain anonymous paths such as `C:\\Users\\name` and `/home/node` to define the strings it must reject; they are rule fixtures, not observed host paths.",
	},
	{
		path: "scripts/verify-repo-hygiene.test.mjs",
		owner: "AIDR-012",
		reason:
			"The gate's test suite writes synthetic `C:\\Users\\someone` and `/home/someone` fixture paths and asserts they are reported; removing those canaries would make the security gate untested.",
	},
	{
		path: "docs/**",
		owner: "AIDR-012",
		reason:
			"Product documentation examples use the anonymous placeholder identities `/home/u/`, `/Users/User/` and `/home/user/` to illustrate behaviour. They identify no real machine or contributor, and rewriting them would make the documented examples less readable.",
	},
	{
		path: "deploy/helm/images/edge-functions.Dockerfile",
		owner: "AIDR-012",
		reason:
			"`/home/deno/functions` is the in-container path the pinned supabase/edge-runtime image and its upstream router hard-code for function sources; it is an image filesystem path, not a host or contributor path.",
	},
	{
		path: "deploy/fleet/windows/README.md",
		owner: "AIDR-012",
		reason:
			"Fleet runbook snippets ship the literal template `-TargetHome C:\\Users\\TARGET_USER`; `TARGET_USER` is a documented operator substitution placeholder, not a host identity.",
	},
	{
		path: "packages/core/src/__tests__/**",
		owner: "AIDR-012",
		reason:
			"Detection-engine unit tests must feed realistic absolute paths through the extractors and heuristics; every identity is a synthetic placeholder (`user`, `u`, `alice`, `admin`, `HELLO`, `jaja`, `Public`) and no contributor path is present.",
	},
	{
		path: "packages/claude-code/src/__tests__/**",
		owner: "AIDR-012",
		reason:
			"Claude Code connector integration fixtures assert behaviour on synthetic `/home/user/...` paths; the identity is a placeholder and no contributor path is present.",
	},
	{
		path: "packages/openclaw/src/__tests__/**",
		owner: "AIDR-012",
		reason:
			"OpenClaw connector E2E fixtures assert behaviour on synthetic `/home/user/...` paths; the identity is a placeholder and no contributor path is present.",
	},
	{
		path: "packages/extension/src/__tests__/**",
		owner: "AIDR-012",
		reason:
			"Cursor/VS Code extension fixtures assert behaviour on synthetic `/home/user/...` paths; the identity is a placeholder and no contributor path is present.",
	},
	{
		path: "deploy/fleet/unix/aidr-fleet.sh",
		owner: "AIDR-012",
		reason:
			"macOS fleet script resolves the home directory with `dscl . -read \"/Users/$TARGET_USER\"`; `$TARGET_USER` is an unexpanded shell variable, so no host or user identity is committed.",
	},
	{
		path: "scripts/release-evidence-regression.mjs",
		owner: "AIDR-012",
		reason:
			"The regression test writes an `/home/demo/node_modules/...` path into a fixture to prove release-evidence scanning rejects absolute-path leaks; `demo` is a synthetic fixture identity.",
	},
	{
		path: "scripts/verify-support-bundle.mjs",
		owner: "AIDR-012",
		reason:
			"The `--self-test` fixture deliberately plants `C:\\Users\\Alice` as an absolute-path canary and then asserts support-bundle redaction removes it; the synthetic identity is what makes the redaction assertion meaningful.",
	},
	{
		path: "scripts/generate-v8-evidence-index.test.mjs",
		owner: "AIDR-012",
		reason:
			"The log-normalization tests must feed a synthetic personal home directory through `normalizeCapturedLog` to prove the capture replaces it with the anonymous placeholder `user`; `somebody` identifies no contributor, and without the fixture the redaction that keeps real home directories out of captured evidence would be untested.",
	},
	{
		path: "threats/commands.yaml",
		owner: "AIDR-012",
		reason:
			"Threat definitions are detection data, not code: the rule regex carries a `/home/user/projects/` example inside a comment describing a realistic `cat -n` path for the rule author.",
	},
	{
		path: "threats/self-defense.yaml",
		owner: "AIDR-012",
		reason:
			"Self-defense threat rule matches the installed-config path pattern; the documented example uses the anonymous placeholder `/home/user/.singularity-aidr`.",
	},
	{
		path: "threats/mitre.yaml",
		owner: "AIDR-012",
		reason:
			"The SSH credential detector deliberately matches any remote `/home/<account>/.ssh/` path with a regex character class; it does not contain a contributor's home directory.",
	},
	{
		path: "threats/context-poisoning.yaml",
		owner: "AIDR-012",
		reason:
			"The poisoning rules match instructions to read another user's files with regex character classes such as `/home/[^/\\s]{1,64}` and `/Users/[^/\\s]{1,64}`; they name no real account.",
	},
];

/* ------------------------------------------------------------------ *
 * Path patterns
 * ------------------------------------------------------------------ */

/** Identity segments that are anonymous placeholders rather than a real personal home directory. */
export const PLACEHOLDER_IDENTITIES = new Set([
	"u",
	"user",
	"user.name",
	"username",
	"you",
	"target_user",
	"public", // C:\Users\Public — the shared world-writable Windows staging directory
	"default",
	"default user",
]);

/**
 * `C:\Users\<name>\...` and the JSON/TS string-escaped `C:\\Users\\<name>\\...` form.
 * A drive path always wins over any overlapping match (handled by the scanner's overlap
 * resolution), so no lookahead is needed here.
 */
const WIN_DRIVE_RE = /[A-Za-z]:\\{1,2}Users\\{1,2}[^\\/\s"'<>|,;)\]]+/g;
/** POSIX absolute home path: `/home/<name>/...` or `/Users/<name>/...`. */
// A complete bounded [^\s/] username class is detection data, including its
// JSON-escaped spelling. It names no account; concrete paths still match.
const POSIX_HOME_RE = /\/(?:home|Users)\/(?!\[\^\\{1,2}s\/\]\{\d+(?:,\d+)?\}\/)[^/\s"'<>|,;)\]]+/g;

/*
 * A UNC rule (`\\host\share`) is deliberately NOT included. In tracked source, `\\` is the
 * normal spelling of a regex escape, so a UNC pattern matches `\\bexport\\s`, `\\bBun\\.shell`
 * and similar hundreds of times across `threats/*.yaml` and bundled CJS. There is no reliable
 * way to tell those from a real share without parsing the host language, and a gate that cries
 * wolf gets disabled. Personal host layouts are covered by the three patterns above.
 */
export const HOST_PATH_PATTERNS = [
	{ id: "windows_drive_path", re: WIN_DRIVE_RE, description: "Windows drive path C:\\Users\\<name>\\..." },
	{ id: "posix_home_path", re: POSIX_HOME_RE, description: "POSIX absolute home path /home/<name>/ or /Users/<name>/" },
];

/** Extensions always treated as binary (skipped without inspection). */
export const BINARY_EXTENSIONS = new Set([
	".7z", ".a", ".avi", ".bin", ".bmp", ".bz2", ".class", ".db", ".dll", ".dylib", ".eot",
	".exe", ".flac", ".gif", ".gz", ".ico", ".jar", ".jpeg", ".jpg", ".lockb", ".mov", ".mp3",
	".mp4", ".node", ".o", ".otf", ".pdf", ".png", ".pyc", ".so", ".sqlite", ".sqlite3", ".tar",
	".tgz", ".ttf", ".wav", ".webm", ".webp", ".woff", ".woff2", ".xls", ".xlsx", ".xz", ".zip",
]);

/** Extensions always treated as text (scanned even when the heuristic is inconclusive). */
export const TEXT_EXTENSIONS = new Set([
	".c", ".cc", ".cfg", ".cjs", ".conf", ".cpp", ".cs", ".css", ".csv", ".cts", ".env", ".go",
	".h", ".hpp", ".htm", ".html", ".ini", ".java", ".js", ".json", ".jsonc", ".jsx", ".kt", ".kts",
	".less", ".m", ".md", ".mdx", ".mjs", ".mts", ".php", ".properties", ".ps1", ".psd1", ".psm1",
	".py", ".rb", ".rs", ".rst", ".scss", ".sh", ".sql", ".svg", ".swift", ".toml", ".ts", ".tsx",
	".tsv", ".txt", ".vue", ".xml", ".yaml", ".yml", ".zsh",
]);

/* ------------------------------------------------------------------ *
 * File classification
 * ------------------------------------------------------------------ */

/** Extract the lowercase extension including the dot, or "" when there is none. */
export function extensionOf(file) {
	const base = String(file).split(/[\\/]/).pop() ?? "";
	const index = base.lastIndexOf(".");
	return index > 0 ? base.slice(index).toLowerCase() : "";
}

/**
 * Is this buffer binary? Extension decides first; otherwise a NUL-byte probe (git's rule).
 */
export function isBinaryBuffer(buffer, file = "") {
	const ext = extensionOf(file);
	if (BINARY_EXTENSIONS.has(ext)) return true;
	if (TEXT_EXTENSIONS.has(ext)) return false;
	return buffer.includes(0);
}

/** Decode a text buffer deterministically, tolerating non-UTF-8 source files. */
function decodeText(buffer) {
	const bytes = buffer.subarray(0, 65536);
	try {
		new TextDecoder("utf-8", { fatal: true }).decode(bytes);
		return buffer.toString("utf8");
	} catch {
		return buffer.toString("latin1");
	}
}

/** 1-based line number of `index`, counting LF bytes only. */
function lineNumberAt(text, index) {
	let line = 1;
	for (let i = 0; i < index; i += 1) {
		if (text.charCodeAt(i) === 10) line += 1;
	}
	return line;
}

/* ------------------------------------------------------------------ *
 * .gitignore scratch-pattern parsing
 * ------------------------------------------------------------------ */

/**
 * Classify a gitignore pattern as scratch/diagnostic output.
 * Returns the category id, or null when the pattern is not a scratch pattern.
 */
export function classifyScratchPattern(pattern) {
	const body = String(pattern).trim();
	if (body === "" || body.startsWith("#")) return null;
	const normalized = body.replace(/^\//, "").replace(/\/$/, "");
	const segments = normalized.split("/");
	const leaf = segments[segments.length - 1];
	const base = leaf.replace(/[*?[\]]+$/, "");
	const ext = extensionOf(leaf);
	if (ext === ".log" || ext === ".cpuprofile") return "diagnostic-log";
	if (ext === ".txt" || ext === ".out" || ext === ".err") return "text-dump";
	if (base === "coverage" || base === ".nyc_output") return "coverage-report";
	if (base === "diagnostics") return "diagnostics-dir";
	if (base === "test_output" || base.startsWith("test_output.") || base.startsWith("test-output.")) {
		return "test-output";
	}
	if (base.startsWith(".tmp") || base.startsWith("tmp-") || base.startsWith("temp-")) return "temp-dir";
	if (base === "__pycache__" || base === ".pytest_cache") return "python-cache";
	if (segments.includes(".e2e-artifacts")) return "e2e-artifacts";
	return null;
}

/**
 * Parse scratch-related patterns out of `.gitignore` content.
 * Negations are dropped: a negation is an explicit "keep this tracked" statement.
 */
export function parseGitignoreScratchPatterns(content) {
	const patterns = [];
	for (const rawLine of String(content).split(/\r?\n/)) {
		const line = rawLine.trim();
		if (line === "" || line.startsWith("#") || line.startsWith("!")) continue;
		const category = classifyScratchPattern(line);
		if (!category) continue;
		const negated = line.startsWith("!");
		patterns.push({
			pattern: line,
			directoryOnly: line.endsWith("/"),
			scoped: line.startsWith("/"),
			category,
			negated,
		});
	}
	return patterns;
}

/** Translate one gitignore pattern into a RegExp matched against a root-relative path. */
export function gitignorePatternToRegExp(pattern, { directoryOnly = false } = {}) {
	let body = String(pattern).replace(/^\//, "");
	if (directoryOnly) body = body.replace(/\/+$/, "");
	const anchored = String(pattern).startsWith("/") || body.includes("/");
	const escaped = body.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*\*/g, "\u0000").replace(/\*/g, "[^/]*").replace(/\?/g, "[^/]").replace(/\u0000/g, ".*");
	return new RegExp(`^${anchored ? "" : "(?:.*/)?"}${escaped}${directoryOnly ? "(?:/.*)?" : ""}$`);
}

/** Is this tracked path a direct child of the repository root (no directory separator)? */
export function isRootLevelPath(file) {
	const value = String(file);
	return value !== "" && !value.includes("/") && !value.includes("\\");
}

/** Ask `git check-ignore` whether the repository's own rules ignore `candidate`. */
export function isIgnoredByGit(repoRoot, candidate) {
	try {
		const out = execFileSync("git", ["check-ignore", "--no-index", "--stdin"], {
			cwd: repoRoot,
			input: `${candidate}\n`,
			encoding: "utf8",
			stdio: ["pipe", "pipe", "ignore"],
		});
		return out.split(/\r?\n/).some((line) => line.trim() !== "");
	} catch (error) {
		if (error?.status === 1) return false; // checked, not ignored
		return null; // git unavailable for this path
	}
}

/* ------------------------------------------------------------------ *
 * Index enumeration
 * ------------------------------------------------------------------ */

/** Enumerate tracked files with `git ls-files` (never a filesystem walk). */
export function listTrackedFiles(repoRoot) {
	const out = execFileSync("git", ["ls-files", "-z"], { cwd: repoRoot, encoding: "utf8", maxBuffer: 1024 * 1024 * 512 });
	return out.split("\0").filter((entry) => entry !== "");
}

/* ------------------------------------------------------------------ *
 * Checks
 * ------------------------------------------------------------------ */

/** Check 1 — no scratch/diagnostic output tracked at the repository root. */
export function checkRootScratch({ rootFiles, gitignoreContent, repoRoot }) {
	const violations = [];
	const patterns = parseGitignoreScratchPatterns(gitignoreContent);
	const effective = patterns.filter((entry) => !entry.negated);

	for (const entry of effective) {
		const matcher = gitignorePatternToRegExp(entry.pattern, { directoryOnly: entry.directoryOnly });
		const matches = rootFiles.filter((file) => matcher.test(file));
		// For an exact `.tmp-test/`-style directory rule we additionally verify the repository's
		// own ignore behaviour, which is what actually prevents recurrence.
		for (const file of matches) {
			const ignored = isIgnoredByGit(repoRoot, file);
			violations.push({
				check: "root-scratch",
				kind: "tracked-scratch-at-root",
				category: entry.category,
				file,
				pattern: entry.pattern,
				gitignoreConfirmsIgnored: ignored,
				message: `tracked scratch output at repository root: ${file} (matched .gitignore pattern ${JSON.stringify(entry.pattern)})`,
			});
		}
	}

	return { violations, patterns: effective };
}

/**
 * Check 1b — repository-wide residue of the scratch *directory* rules.
 *
 * The finding is scoped to the root, but `git add -A` can bury the same junk one directory
 * deeper (`.tmp-test/<timestamp>/...`), so a rule that says "this directory is scratch" must
 * hold at every depth. Only directory-valued patterns are applied repo-wide: an unanchored
 * `*.txt`/`*.log` file pattern is very often intentional below the root (golden files,
 * fixtures), so those stay root-anchored in check 1.
 */
export function checkScratchResidue({ trackedFiles, gitignoreContent }) {
	const violations = [];
	const patterns = parseGitignoreScratchPatterns(gitignoreContent ?? "").filter(
		(entry) => !entry.negated && entry.directoryOnly,
	);

	for (const entry of patterns) {
		const matcher = gitignorePatternToRegExp(entry.pattern, { directoryOnly: true });
		for (const file of trackedFiles) {
			if (!matcher.test(file)) continue;
			if (isRootLevelPath(file)) continue; // already reported by the root check
			if (entry.scoped && !String(file).startsWith(entry.pattern.replace(/^\//, "").replace(/\/$/, "") + "/")) {
				// A `/dir/` rule is root-scoped by definition; ignore deeper same-named directories.
				continue;
			}
			violations.push({
				check: "scratch-residue",
				kind: "tracked-scratch-below-root",
				category: entry.category,
				file,
				pattern: entry.pattern,
				message: `tracked scratch output below the repository root: ${file} (must be untracked per .gitignore pattern ${JSON.stringify(entry.pattern)})`,
			});
		}
	}

	return { violations };
}

/** Check 2 — no absolute host paths in tracked text files. */
export function scanHostPaths({ repoRoot, trackedFiles, allowlist = ALLOWLIST }) {
	const violations = [];
	const scanned = [];
	const allowlistProblems = checkAllowlistSelfCheck(allowlist);
	const allowlisted = new Set();

	for (const file of trackedFiles) {
		const entry = matchAllowlistEntry(file, allowlist);
		if (entry) {
			allowlisted.add(file);
			continue;
		}
		let buffer;
		try {
			buffer = readFileSync(join(repoRoot, file));
		} catch {
			continue;
		}
		if (isBinaryBuffer(buffer, file)) continue;
		scanned.push(file);

		const text = decodeText(buffer);
		// Collect every candidate first, then resolve overlaps. A drive path and the `\\Public\\a.exe`
		// tail of its escaped form are one leak: the later, shorter match must not be reported too.
		const candidates = [];
		for (const hostPattern of HOST_PATH_PATTERNS) {
			hostPattern.re.lastIndex = 0;
			let match;
			while ((match = hostPattern.re.exec(text)) !== null) {
				const matched = match[0];
				// This declared Alpine account home belongs to the container. Keep the
				// rest of the Dockerfile scanned, including COPY host paths.
				const bridgeContainerHome = file === "services/aig-bridge/Dockerfile"
					&& hostPattern.id === "posix_home_path" && matched === "/home/bridge"
					&& text.slice(text.lastIndexOf("\n", match.index) + 1, text.indexOf("\n", match.index) < 0 ? text.length : text.indexOf("\n", match.index)).trim()
						=== "adduser -S -D -u 1000 -G bridge -h /home/bridge bridge && \\";
				if (isAnonymousIdentity(matched) || bridgeContainerHome) {
					if (match.index === hostPattern.re.lastIndex) hostPattern.re.lastIndex += 1;
					continue;
				}
				candidates.push({
					patternId: hostPattern.id,
					matched,
					start: match.index,
					end: match.index + matched.length,
				});
				if (match.index === hostPattern.re.lastIndex) hostPattern.re.lastIndex += 1;
			}
		}

		// Longest, earliest match wins; anything fully or partly inside a reported span is the
		// Longest, earliest match wins. A candidate that starts inside an already-reported span is
		// the tail of that same leak seen through another pattern (e.g. the `\\Public\\x.exe` half
		// of an escaped `C:\\Users\\Public\\x.exe`), so it is not a separate violation.
		candidates.sort((a, b) => a.start - b.start || b.end - a.end || a.patternId.localeCompare(b.patternId));
		const reportedSpans = [];
		for (const candidate of candidates) {
			if (reportedSpans.some((span) => candidate.start < span[1])) continue;
			reportedSpans.push([candidate.start, candidate.end]);
			const line = lineNumberAt(text, candidate.start);
			violations.push({
				check: "host-path",
				kind: matchKindFor(candidate.patternId, candidate.matched),
				patternId: candidate.patternId,
				file,
				line,
				match: candidate.matched,
				message: `${file}:${line} matches ${candidate.patternId}: ${candidate.matched}`,
			});
		}
	}

	return { violations, scanned, allowlisted: [...allowlisted].sort(), allowlistProblems };
}

/**
 * Is the segment following `Users`/`home` an anonymous placeholder rather than a real identity?
 * Handles `C:\Users\name\...`, the escaped `C:\\Users\\name\\...`, `/home/name/...` and
 * `/Users/name/...` alike.
 */
function isAnonymousIdentity(matched) {
	const segments = matched.split(/[\\/]+/).filter((segment) => segment !== "");
	const usersIndex = segments.findIndex((segment) => /^(?:users|home)$/i.test(segment));
	const name = usersIndex >= 0 ? (segments[usersIndex + 1] ?? "") : "";
	return PLACEHOLDER_IDENTITIES.has(name.toLowerCase());
}

function matchKindFor(patternId, matched) {
	if (patternId === "windows_drive_path") {
		return /Users/i.test(matched) ? "personal-windows-home" : "absolute-windows-path";
	}
	return "absolute-posix-home";
}

/**
 * Resolve the allowlist entry covering `file`, or null.
 *
 * Only entries that pass the self-check are honoured: an entry with no path, no owner or no
 * real written reason is inert, so a blank reason can never silently exempt a file. The
 * self-check reports it separately, which is what actually fails the gate.
 */
export function matchAllowlistEntry(file, allowlist = ALLOWLIST) {
	const normalized = String(file).replace(/\\/g, "/");
	const valid = validAllowlistEntries(allowlist);
	for (const entry of valid) {
		const pattern = String(entry.path).replace(/\\/g, "/");
		if (pattern.endsWith("/**")) {
			const prefix = pattern.slice(0, -3).replace(/\/$/, "");
			if (normalized === prefix || normalized.startsWith(`${prefix}/`)) return entry;
			continue;
		}
		if (pattern === normalized) return entry;
	}
	return null;
}

/** Allowlist entries that carry a path, an owner and a real written reason. */
export function validAllowlistEntries(allowlist = ALLOWLIST) {
	return (allowlist ?? []).filter(
		(entry) =>
			entry &&
			typeof entry.path === "string" &&
			entry.path.trim() !== "" &&
			typeof entry.owner === "string" &&
			entry.owner.trim() !== "" &&
			typeof entry.reason === "string" &&
			entry.reason.trim().length >= MIN_ALLOWLIST_REASON_LENGTH,
	);
}

/**
 * Self-check the allowlist itself: every entry must carry a real written reason and an owner.
 * An entry with a missing/blank/too-short reason is a gate failure, not a silent skip.
 */
export function checkAllowlistSelfCheck(allowlist = ALLOWLIST) {
	const problems = [];
	const seen = new Set();
	for (const [index, entry] of allowlist.entries()) {
		const label = entry?.path ? String(entry.path) : `<entry ${index}>`;
		if (!entry || typeof entry.path !== "string" || entry.path.trim() === "") {
			problems.push({ kind: "allowlist-missing-path", entry: label, message: `allowlist entry ${index} has no path` });
			continue;
		}
		if (seen.has(entry.path)) {
			problems.push({ kind: "allowlist-duplicate-path", entry: label, message: `allowlist path ${label} is listed more than once` });
		}
		seen.add(entry.path);
		const reason = typeof entry.reason === "string" ? entry.reason.trim() : "";
		if (reason.length < MIN_ALLOWLIST_REASON_LENGTH) {
			problems.push({
				kind: "allowlist-missing-reason",
				entry: label,
				message: `allowlist entry ${label} must carry a written reason of at least ${MIN_ALLOWLIST_REASON_LENGTH} characters`,
			});
		}
		if (typeof entry.owner !== "string" || entry.owner.trim() === "") {
			problems.push({ kind: "allowlist-missing-owner", entry: label, message: `allowlist entry ${label} must name an owner` });
		}
	}
	return problems;
}

/* ------------------------------------------------------------------ *
 * Orchestration
 * ------------------------------------------------------------------ */

/** Run every check and return a machine-readable report. */
export function runGate({ repoRoot = resolve(MODULE_DIR, ".."), allowlist = ALLOWLIST, trackedFiles, gitignoreContent, gitignorePath, now } = {}) {
	const root = isAbsolute(repoRoot) ? repoRoot : resolve(repoRoot);
	const files = trackedFiles ?? listTrackedFiles(root);
	const gitignore = gitignoreContent ?? readFileSync(gitignorePath ?? join(root, ".gitignore"), "utf8");

	const rootFiles = files.filter(isRootLevelPath);
	const scratch = checkRootScratch({ rootFiles, gitignoreContent: gitignore, repoRoot: root });
	const residue = checkScratchResidue({ trackedFiles: files, gitignoreContent: gitignore });
	const hosts = scanHostPaths({ repoRoot: root, trackedFiles: files, allowlist });

	const violations = [...scratch.violations, ...residue.violations, ...hosts.violations];
	const allowlistProblems = hosts.allowlistProblems;
	const ok = violations.length === 0 && allowlistProblems.length === 0;

	return {
		ok,
		finding: "AIDR-012",
		gate: "verify-repo-hygiene",
		generatedAt: now ?? new Date().toISOString(),
		repoRoot: root,
		summary: {
			trackedFiles: files.length,
			rootFiles: rootFiles.length,
			textFilesScanned: hosts.scanned.length,
			allowlistedFiles: hosts.allowlisted.length,
			scratchPatternsFromGitignore: scratch.patterns.length,
			violations: violations.length,
			allowlistProblems: allowlistProblems.length,
		},
		scratchPatterns: scratch.patterns.map((entry) => ({ pattern: entry.pattern, category: entry.category })),
		allowlistedFiles: hosts.allowlisted,
		violations,
		allowlistProblems,
	};
}

/* ------------------------------------------------------------------ *
 * CLI
 * ------------------------------------------------------------------ */

function parseArgs(argv) {
	const options = { json: false, repo: null };
	for (let i = 0; i < argv.length; i += 1) {
		const arg = argv[i];
		if (arg === "--json") options.json = true;
		else if (arg === "--repo") options.repo = argv[++i] ?? null;
		else if (arg === "--help" || arg === "-h") options.help = true;
		else if (arg.startsWith("--repo=")) options.repo = arg.slice("--repo=".length);
		else throw new Error(`unknown argument: ${arg}`);
	}
	return options;
}

function printHumanReport(report) {
	const { summary } = report;
	if (report.ok) {
		console.log(`repo hygiene OK (AIDR-012)`);
	} else {
		console.log(`repo hygiene FAILED (AIDR-012)`);
	}
	console.log(
		`  tracked files: ${summary.trackedFiles} | root entries: ${summary.rootFiles} | text files scanned: ${summary.textFilesScanned} | allowlisted: ${summary.allowlistedFiles} | scratch patterns from .gitignore: ${summary.scratchPatternsFromGitignore}`,
	);
	if (report.allowlistProblems.length > 0) {
		console.log(`  allowlist self-check problems: ${report.allowlistProblems.length}`);
		for (const problem of report.allowlistProblems) console.log(`    - [${problem.kind}] ${problem.message}`);
	}
	if (report.violations.length > 0) {
		console.log(`  violations: ${report.violations.length}`);
		for (const violation of report.violations) console.log(`    - [${violation.check}/${violation.kind}] ${violation.message}`);
	}
	console.log(report.ok ? "  result: PASS" : "  result: FAIL");
}

function main(argv) {
	let options;
	try {
		options = parseArgs(argv);
	} catch (error) {
		console.error(`verify-repo-hygiene: ${error.message}`);
		console.error("Usage: node scripts/verify-repo-hygiene.mjs [--json] [--repo <dir>]");
		return 2;
	}
	if (options.help) {
		console.log("Usage: node scripts/verify-repo-hygiene.mjs [--json] [--repo <dir>]");
		return 0;
	}

	let report;
	try {
		report = runGate(options.repo ? { repoRoot: options.repo } : {});
	} catch (error) {
		console.error(`verify-repo-hygiene: gate could not run: ${error.message}`);
		return 2;
	}

	if (options.json) console.log(JSON.stringify(report, null, 2));
	else printHumanReport(report);
	return report.ok ? 0 : 1;
}

const invokedDirectly = process.argv[1] ? resolve(process.argv[1]) === resolve(fileURLToPath(import.meta.url)) : false;
if (invokedDirectly) process.exit(main(process.argv.slice(2)));

export { main, printHumanReport };
