/**
 * Matching primitives for agent permission profiles: path globs, shell command
 * prefixes and network domains.
 *
 * Every helper is written for a restriction layer, so an input it cannot read
 * exactly is treated as "does not match an allow entry" and "may match a deny
 * entry". A command whose segments cannot be proven to start with an allowed
 * prefix is unmatched; a deny prefix is searched in several over-approximated
 * views of the command (quotes removed, wrappers stripped, substitutions split).
 */
import { isIP } from "node:net";
import { normalizeShellText } from "./shell-normalize.js";

// ── Paths ──────────────────────────────────────────────────────────

/** Case-insensitive filesystems by default; a deny match must not miss `.ENV`. */
function pathMatchingIsCaseInsensitive(platform: NodeJS.Platform = process.platform) {
	return platform === "win32" || platform === "darwin";
}

function toPosixPath(path: string): string {
	return path.replace(/\\/g, "/");
}

const globCache = new Map<string, RegExp>();

/**
 * `**` matches across directories, `*` within one segment and `?` one character.
 * Every other character, including `[` and `{`, is literal.
 */
function compileGlob(pattern: string, caseInsensitive: boolean): RegExp {
	const key = `${caseInsensitive ? "i" : "s"}\0${pattern}`;
	const cached = globCache.get(key);
	if (cached) return cached;
	const source = toPosixPath(pattern);
	let out = "";
	for (let i = 0; i < source.length; i++) {
		const char = source[i] as string;
		if (char === "*") {
			if (source[i + 1] === "*") {
				i++;
				if (source[i + 1] === "/") {
					i++;
					out += "(?:.*/)?";
				} else {
					out += ".*";
				}
			} else {
				out += "[^/]*";
			}
		} else if (char === "?") {
			out += "[^/]";
		} else {
			out += char.replace(/[.+^${}()|[\]\\]/g, "\\$&");
		}
	}
	const compiled = new RegExp(`^${out}$`, caseInsensitive ? "i" : "");
	if (globCache.size > 512) globCache.clear();
	globCache.set(key, compiled);
	return compiled;
}

/** The path itself followed by each of its ancestors, all POSIX-separated. */
function pathAndAncestors(path: string): string[] {
	const posix = toPosixPath(path).replace(/\/+$/, "") || "/";
	const out = [posix];
	let current = posix;
	for (;;) {
		const cut = current.lastIndexOf("/");
		if (cut <= 0) break;
		current = current.slice(0, cut);
		// Keep a Windows drive root (`C:`) as `C:/`.
		out.push(/^[A-Za-z]:$/.test(current) ? `${current}/` : current);
	}
	if (posix.startsWith("/") && posix !== "/") out.push("/");
	return out;
}

/**
 * True when `path` or one of its ancestors matches `pattern`. A pattern without
 * a `/` is compared with each path segment's name (`*.pem`, `.env`, `.ssh`).
 */
export function pathMatchesGlob(
	path: string,
	pattern: string,
	caseInsensitive = pathMatchingIsCaseInsensitive(),
): boolean {
	const normalizedPattern = toPosixPath(pattern);
	const regex = compileGlob(normalizedPattern, caseInsensitive);
	if (!normalizedPattern.includes("/")) {
		return toPosixPath(path)
			.split("/")
			.some((segment) => segment !== "" && regex.test(segment));
	}
	return pathAndAncestors(path).some((candidate) => regex.test(candidate));
}

/** Lexical containment of two absolute paths (both already resolved). */
export function isPathWithin(
	path: string,
	root: string,
	caseInsensitive = pathMatchingIsCaseInsensitive(),
): boolean {
	const fold = (value: string) => {
		const posix = toPosixPath(value).replace(/\/+$/, "") || "/";
		return caseInsensitive ? posix.toLowerCase() : posix;
	};
	const candidate = fold(path);
	const base = fold(root);
	if (candidate === base) return true;
	return candidate.startsWith(base.endsWith("/") ? base : `${base}/`);
}

// ── Commands ───────────────────────────────────────────────────────

interface CommandSegment {
	/** Whitespace-collapsed segment text. */
	text: string;
	/** An unquoted output redirection to anything other than /dev/null or a descriptor. */
	writesFile: boolean;
}

export interface ParsedCommand {
	segments: CommandSegment[];
	/**
	 * The command uses command/process substitution or an unterminated quote,
	 * so its executed segments cannot be listed exactly.
	 */
	complex: boolean;
}

function collapse(text: string): string {
	return text.replace(/\s+/g, " ").trim();
}

const SAFE_REDIRECT_TARGET = /^\s*(?:\/dev\/null\b|&\s*\d+|&-)/;

/**
 * Quote-aware split of a shell command on `;`, `&&`, `||`, `|`, `&` and
 * newlines. Command substitution (`$(…)`, backticks), process substitution
 * (`<(…)`, `>(…)`) and unterminated quotes mark the command complex.
 */
export function parseShellCommand(command: string): ParsedCommand {
	const segments: CommandSegment[] = [];
	let complex = false;
	let current = "";
	let writesFile = false;
	let quote: "'" | '"' | null = null;
	const flush = () => {
		const text = collapse(current);
		if (text) segments.push({ text, writesFile });
		current = "";
		writesFile = false;
	};
	for (let i = 0; i < command.length; i++) {
		const char = command[i] as string;
		const next = command[i + 1];
		if (quote === "'") {
			current += char;
			if (char === "'") quote = null;
			continue;
		}
		if (char === "\\") {
			if (next === "\n") {
				current += " ";
				i++;
				continue;
			}
			current += char + (next ?? "");
			i++;
			continue;
		}
		if (quote === '"') {
			current += char;
			if (char === '"') quote = null;
			else if (char === "`" || (char === "$" && next === "(")) complex = true;
			continue;
		}
		if (char === "'" || char === '"') {
			quote = char;
			current += char;
			continue;
		}
		if (char === "`" || (char === "$" && next === "(")) complex = true;
		if ((char === "<" || char === ">") && next === "(") complex = true;
		if (char === ">" && next !== "(") {
			const rest = command.slice(i + 1).replace(/^>/, "");
			if (!SAFE_REDIRECT_TARGET.test(rest)) writesFile = true;
		}
		if (char === ";" || char === "\n" || char === "\r") {
			flush();
			continue;
		}
		if (char === "&" || char === "|") {
			// `>&`, `&>` and `2>&1` are redirections, not separators.
			const previous = command[i - 1];
			if (char === "&" && (previous === ">" || previous === "<" || next === ">")) {
				current += char;
				continue;
			}
			flush();
			if (next === char) i++;
			continue;
		}
		current += char;
	}
	if (quote) complex = true;
	flush();
	return { segments, complex };
}

/** Wrappers that run their arguments as a command. */
const COMMAND_WRAPPERS = new Set([
	"sudo",
	"doas",
	"env",
	"command",
	"builtin",
	"exec",
	"nohup",
	"time",
	"nice",
	"ionice",
	"timeout",
	"xargs",
	"stdbuf",
	"setsid",
	"chroot",
	"unbuffer",
]);
const ENV_ASSIGNMENT = /^[A-Za-z_][A-Za-z0-9_]*=/;

/** Leading `NAME=value` words, wrapper commands and their options removed. */
function unwrap(segment: string): string {
	const words = segment.split(" ");
	let index = 0;
	while (index < words.length) {
		const word = words[index] as string;
		const base = word.slice(word.lastIndexOf("/") + 1);
		if (ENV_ASSIGNMENT.test(word)) {
			index++;
		} else if (COMMAND_WRAPPERS.has(base)) {
			index++;
			// Options and numeric arguments (`timeout 5`, `nice -n 10`, `sudo -u root`).
			while (index < words.length) {
				const option = words[index] as string;
				if (option.startsWith("-") || /^\d+[smhd]?$/.test(option)) {
					index++;
					if ((option === "-u" || option === "-g" || option === "-n") && index < words.length)
						index++;
				} else break;
			}
		} else break;
	}
	return words.slice(index).join(" ");
}

function firstWordBasename(segment: string): string {
	const space = segment.indexOf(" ");
	const first = space === -1 ? segment : segment.slice(0, space);
	const rest = space === -1 ? "" : segment.slice(space);
	const base = first.slice(Math.max(first.lastIndexOf("/"), first.lastIndexOf("\\")) + 1);
	return base + rest;
}

function startsWithPrefix(segment: string, prefix: string): boolean {
	return segment === prefix || segment.startsWith(`${prefix} `);
}

/** Over-approximated views of every segment a deny prefix is checked against. */
function denyCandidateSegments(command: string): string[] {
	const views = new Set<string>();
	const texts = [command];
	try {
		const normalized = normalizeShellText(command);
		if (normalized !== command) texts.push(normalized);
	} catch {
		// The raw text is still checked.
	}
	for (const text of texts) {
		for (const piece of text.split(/\$\(|[;&|\n\r()`{}]/)) {
			const raw = collapse(piece);
			if (!raw) continue;
			const unquoted = collapse(raw.replace(/["'\\]/g, ""));
			for (const view of [raw, unquoted]) {
				const unwrapped = unwrap(view);
				for (const candidate of [
					view,
					unwrapped,
					firstWordBasename(view),
					firstWordBasename(unwrapped),
				]) {
					if (candidate) views.add(candidate);
				}
			}
		}
	}
	return [...views];
}

/** The first deny prefix that any view of the command starts with. */
export function findDeniedPrefix(command: string, denyPrefixes: readonly string[]): string | null {
	if (denyPrefixes.length === 0) return null;
	const candidates = denyCandidateSegments(command);
	for (const prefix of denyPrefixes) {
		if (candidates.some((segment) => startsWithPrefix(segment, prefix))) return prefix;
	}
	return null;
}

/**
 * The command is allowed only when it is not complex and every segment starts
 * with an allowed prefix and does not redirect output into a file.
 */
export function commandMatchesAllowPrefixes(
	command: string,
	allowPrefixes: readonly string[],
): { matched: boolean; offending: string | null } {
	const parsed = parseShellCommand(command);
	if (parsed.complex) return { matched: false, offending: "command substitution" };
	if (parsed.segments.length === 0) return { matched: false, offending: null };
	for (const segment of parsed.segments) {
		if (segment.writesFile) return { matched: false, offending: segment.text };
		if (!allowPrefixes.some((prefix) => startsWithPrefix(segment.text, prefix))) {
			return { matched: false, offending: segment.text };
		}
	}
	return { matched: true, offending: null };
}

// ── Network ────────────────────────────────────────────────────────

/** Lowercased host of an absolute URL, or null when the URL cannot be read. */
export function urlHost(raw: string): string | null {
	const attempt = (value: string): string | null => {
		try {
			const host = new URL(value).hostname.toLowerCase().replace(/\.+$/, "");
			return host || null;
		} catch {
			return null;
		}
	};
	const trimmed = raw.trim();
	if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) return attempt(trimmed);
	return attempt(`http://${trimmed}`);
}

/**
 * `example.com` matches the domain and its subdomains, `*.example.com` only the
 * subdomains, and an IP address only itself.
 */
export function hostMatchesDomain(host: string, entry: string): boolean {
	const h = host.toLowerCase().replace(/^\[|\]$/g, "");
	const e = entry.toLowerCase().replace(/\.+$/, "");
	if (isIP(h) !== 0 || isIP(e) !== 0) return h === e;
	if (e.startsWith("*.")) return h.endsWith(e.slice(1));
	return h === e || h.endsWith(`.${e}`);
}
