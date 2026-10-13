/**
 * Credential-location reads that do not spell out the credential file.
 *
 * The file rules in `threats/` (CLT-FILE-003, CLT-FILE-008, …) and the
 * command rule CLT-CRED-004 match a literal path such as `~/.ssh/id_rsa`. An
 * agent reaches the same bytes without ever writing that string:
 *
 *   cd ~/.ssh && cat id_rsa            (working directory + relative name)
 *   cat ~/.ss?/id_*                    (a glob the shell expands)
 *   grep -r . ~/.ssh                   (a recursive read of the directory)
 *   find ~/.aws -type f -exec cat {} + (find walking the directory)
 *   Grep{path:"~/.aws"} / Glob{pattern:"**\/id_rsa"} / list{path:"~/.ssh"}
 *
 * This module turns those forms back into the canonical paths they read, so
 * the existing YAML file rules judge them. It only decides *which paths are
 * touched*; whether touching one is allowed, asked or denied stays data in
 * `threats/` (plus `threats/credential-reads.yaml` for the stores the older
 * rules did not name). Nothing here is emitted for paths outside the
 * credential locations below, so ordinary reads gain no artifacts.
 */

/**
 * A credential location. `home` locations only count when the path is
 * anchored at the home directory: a project may well contain its own
 * `.docker/` or `.config/` directory, but not its own `~/.docker`.
 */
interface CredentialDir {
	/** Path relative to the home directory, `/`-separated. */
	readonly rel: string;
	readonly homeOnly: boolean;
}

const CREDENTIAL_DIRS: readonly CredentialDir[] = [
	{ rel: ".ssh", homeOnly: false },
	{ rel: ".aws", homeOnly: false },
	{ rel: ".gnupg", homeOnly: false },
	{ rel: ".config/gcloud", homeOnly: true },
	{ rel: ".azure", homeOnly: true },
	{ rel: ".kube", homeOnly: true },
	{ rel: ".docker", homeOnly: true },
	{ rel: "Library/Keychains", homeOnly: true },
	{ rel: ".config/google-chrome", homeOnly: true },
	{ rel: ".config/chromium", homeOnly: true },
	{ rel: ".config/BraveSoftware/Brave-Browser", homeOnly: true },
	{ rel: ".config/microsoft-edge", homeOnly: true },
	{ rel: ".mozilla/firefox", homeOnly: true },
	{ rel: "Library/Application Support/Google/Chrome", homeOnly: true },
	{ rel: "Library/Application Support/Firefox", homeOnly: true },
	{ rel: "Library/Application Support/Microsoft Edge", homeOnly: true },
];

/**
 * Concrete files a read of a credential location exposes, in canonical form.
 * They are what a glob or a directory read is resolved to, so the YAML file
 * rules see the file they protect. Browser profile names are placeholders: a
 * glob such as `~/.mozilla/firefox/*\/logins.json` matches them, and the rules
 * match any profile directory.
 */
const CREDENTIAL_FILES: readonly string[] = [
	"~/.ssh/id_rsa",
	"~/.ssh/id_ed25519",
	"~/.ssh/id_ecdsa",
	"~/.ssh/id_dsa",
	"~/.aws/credentials",
	"~/.gnupg/private-keys-v1.d",
	"~/.config/gcloud/application_default_credentials.json",
	"~/.config/gcloud/credentials.db",
	"~/.config/gcloud/access_tokens.db",
	"~/.azure/msal_token_cache.json",
	"~/.azure/accessTokens.json",
	"~/.kube/config",
	"~/.docker/config.json",
	"~/Library/Keychains/login.keychain-db",
	"~/.config/google-chrome/Default/Login Data",
	"~/.config/google-chrome/Default/Cookies",
	"~/.config/chromium/Default/Login Data",
	"~/.config/BraveSoftware/Brave-Browser/Default/Login Data",
	"~/.config/microsoft-edge/Default/Login Data",
	"~/.mozilla/firefox/default/logins.json",
	"~/.mozilla/firefox/default/key4.db",
	"~/Library/Application Support/Google/Chrome/Default/Login Data",
	"~/Library/Application Support/Google/Chrome/Default/Cookies",
	"~/Library/Application Support/Firefox/Profiles/default/logins.json",
	"~/Library/Application Support/Firefox/Profiles/default/key4.db",
	"~/Library/Application Support/Microsoft Edge/Default/Login Data",
	"~/.netrc",
	"~/.pgpass",
	"~/.git-credentials",
	"/etc/shadow",
	"/etc/gshadow",
];

/**
 * File names that are secrets wherever they live, including inside the
 * project (`.env`). `.env.example` and friends are deliberately absent.
 */
const CREDENTIAL_BASENAMES: readonly string[] = [
	".env",
	".env.local",
	".env.production",
	".env.prod",
	".env.staging",
	".env.development",
	".env.dev",
	".env.test",
	".netrc",
	".pgpass",
	".git-credentials",
	"id_rsa",
	"id_ed25519",
	"id_ecdsa",
	"id_dsa",
];

/** Context of every artifact this module produces. */
export const CREDENTIAL_READ_CONTEXT = "credential_read";

const GLOB_CHARS = /[*?[{]/;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/**
 * Canonical `/`-separated form: home directory spellings become `~`, `.`
 * segments vanish and `..` is folded where a parent is known.
 */
export function canonicalPath(raw: string): string {
	let path = raw.trim().replace(/\\/g, "/");
	path = path
		.replace(/^\$\{HOME\}(?=\/|$)/, "~")
		.replace(/^\$HOME(?=\/|$)/, "~")
		.replace(/^%USERPROFILE%(?=\/|$)/i, "~")
		.replace(/^\$env:USERPROFILE(?=\/|$)/i, "~")
		.replace(/^~[A-Za-z0-9._-]+(?=\/|$)/, "~")
		.replace(/^\/(?:home|Users)\/[^/]+(?=\/|$)/, "~")
		.replace(/^\/root(?=\/|$)/, "~")
		.replace(/^[A-Za-z]:\/Users\/[^/]+(?=\/|$)/i, "~");
	const absolute = path.startsWith("/");
	const out: string[] = [];
	for (const segment of path.split("/")) {
		if (segment === "" || segment === ".") continue;
		if (segment === "..") {
			const last = out[out.length - 1];
			if (last !== undefined && last !== ".." && !(last === "~" && out.length === 1)) {
				out.pop();
				continue;
			}
		}
		out.push(segment);
	}
	const joined = out.join("/");
	return absolute ? `/${joined}` : joined || ".";
}

function isAnchored(path: string): boolean {
	return path.startsWith("/") || path === "~" || path.startsWith("~/");
}

/** Resolve `path` against a known working directory (canonical form). */
function resolveAgainst(cwd: string | undefined, path: string): string {
	const canonical = canonicalPath(path);
	if (isAnchored(canonical) || cwd === undefined) return canonical;
	return canonicalPath(`${cwd}/${canonical}`);
}

/** The home directory itself or one of its ancestors. */
function isHomeOrAncestor(path: string): boolean {
	return path === "~" || path === "/" || path === "/home" || path === "/Users";
}

function escapeRegExp(text: string): string {
	return text.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Canonical home-anchored form of each credential directory. */
const CREDENTIAL_DIR_PATHS: readonly string[] = CREDENTIAL_DIRS.map((dir) => `~/${dir.rel}`);

/** Matches a path equal to (group 1 undefined) or inside a credential directory. */
const CREDENTIAL_DIR_PATTERNS: ReadonlyArray<readonly [CredentialDir, RegExp]> =
	CREDENTIAL_DIRS.map((dir) => [
		dir,
		new RegExp(`${dir.homeOnly ? "^~/" : "(?:^|/)"}${escapeRegExp(dir.rel)}(/.*)?$`),
	]);

/**
 * Globs longer than this, or whose `{a,b}` alternatives expand to more than
 * {@link MAX_BRACE_EXPANSIONS} patterns, are not evaluated; they are assumed
 * to reach every credential file below their literal prefix.
 */
const MAX_GLOB_LENGTH = 512;
const MAX_BRACE_EXPANSIONS = 64;

/** Credential files under a credential directory, re-rooted at `prefix`. */
function filesUnder(dir: CredentialDir, prefix: string): string[] {
	const home = `~/${dir.rel}/`;
	return CREDENTIAL_FILES.filter((file) => file.startsWith(home)).map(
		(file) => `${prefix}${file.slice(home.length)}`,
	);
}

/**
 * Credential paths a literal (glob-free) path touches. `recursive` is true
 * when the operation reads everything below the path (grep -r, find -exec,
 * tar, …), so the home directory itself exposes every credential file.
 */
function literalHits(path: string, recursive: boolean): string[] {
	const hits: string[] = [];
	if (recursive) {
		// Everything below the path is read: the home directory, an ancestor
		// of it, or a parent such as `~/.config` exposes the files inside.
		hits.push(
			...CREDENTIAL_FILES.filter((file) =>
				isHomeOrAncestor(path) ? file.startsWith("~/") : file.startsWith(`${path}/`),
			),
		);
	}
	for (const [dir, pattern] of CREDENTIAL_DIR_PATTERNS) {
		const match = pattern.exec(path);
		if (!match) continue;
		hits.push(path);
		// The directory itself: everything in it is exposed.
		if (match[1] === undefined) hits.push(...filesUnder(dir, `${path}/`));
	}
	const base = path.slice(path.lastIndexOf("/") + 1);
	// A project's own `.env` named literally (`grep API_URL .env`) is routine
	// work; sending it anywhere is what the exfiltration rules catch. Home
	// and absolute paths, globs and recursive reads are still reported.
	const projectEnv = base.startsWith(".env") && !isAnchored(path) && !recursive;
	if ((CREDENTIAL_BASENAMES.includes(base) && !projectEnv) || CREDENTIAL_FILES.includes(path))
		hits.push(path);
	return hits;
}

/** Expand `{a,b}` alternatives; undefined when there are too many. */
// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one scan for the outermost brace pair
function expandBraces(glob: string): string[] | undefined {
	const open = glob.indexOf("{");
	if (open === -1) return [glob];
	let depth = 0;
	let close = -1;
	const commas: number[] = [];
	for (let i = open; i < glob.length; i++) {
		const ch = glob[i];
		if (ch === "{") depth++;
		else if (ch === "}" && --depth === 0) {
			close = i;
			break;
		} else if (ch === "," && depth === 1) commas.push(i);
	}
	if (close === -1) return [glob];
	const head = glob.slice(0, open);
	const tail = glob.slice(close + 1);
	const bounds = [open, ...commas, close];
	const out: string[] = [];
	for (let k = 0; k < bounds.length - 1; k++) {
		const option = glob.slice((bounds[k] as number) + 1, bounds[k + 1]);
		const expanded = expandBraces(`${head}${option}${tail}`);
		if (!expanded) return undefined;
		out.push(...expanded);
		if (out.length > MAX_BRACE_EXPANSIONS) return undefined;
	}
	return out;
}

type GlobToken =
	| { kind: "char"; ch: string }
	| { kind: "star"; dotSafe: boolean }
	| { kind: "one"; dotSafe: boolean }
	| { kind: "class"; dotSafe: boolean; negated: boolean; body: string }
	| { kind: "globstar" }
	| { kind: "globstarSlash" };

/**
 * Tokenize a brace-free glob. As in the shell, `*`, `?` and `[...]` at the
 * start of a segment do not match a leading dot (`~/*` does not expand to
 * `~/.ssh`); `**` crosses dot directories, because search tools such as Glob
 * may include hidden files.
 */
// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one linear scan over the glob syntax
function tokenizeGlob(glob: string): GlobToken[] {
	const tokens: GlobToken[] = [];
	for (let i = 0; i < glob.length; i++) {
		const ch = glob[i] as string;
		const dotSafe = i === 0 || glob[i - 1] === "/";
		if (ch === "*" && glob[i + 1] === "*") {
			while (glob[i + 1] === "*") i++;
			if (glob[i + 1] === "/") {
				i++;
				tokens.push({ kind: "globstarSlash" });
			} else {
				tokens.push({ kind: "globstar" });
			}
		} else if (ch === "*") {
			tokens.push({ kind: "star", dotSafe });
		} else if (ch === "?") {
			tokens.push({ kind: "one", dotSafe });
		} else if (ch === "[" && glob.indexOf("]", i + 2) !== -1) {
			const end = glob.indexOf("]", i + 2);
			let body = glob.slice(i + 1, end);
			const negated = body.startsWith("!") || body.startsWith("^");
			if (negated) body = body.slice(1);
			tokens.push({ kind: "class", dotSafe, negated, body });
			i = end;
		} else {
			tokens.push({ kind: "char", ch });
		}
	}
	return tokens;
}

function classMatches(body: string, ch: string): boolean {
	for (let i = 0; i < body.length; i++) {
		const from = body[i] as string;
		if (body[i + 1] === "-" && i + 2 < body.length) {
			if (ch >= from && ch <= (body[i + 2] as string)) return true;
			i += 2;
		} else if (from === ch) {
			return true;
		}
	}
	return false;
}

/**
 * Whether `tokens` match the whole of `text`. Memoized over (token, position),
 * so the cost is O(tokens × text) however many wildcards the glob has.
 */
function matchTokens(tokens: readonly GlobToken[], text: string): boolean {
	// Every non-star token consumes one character.
	let fixed = 0;
	for (const token of tokens) {
		if (token.kind === "char" || token.kind === "one" || token.kind === "class") fixed++;
	}
	if (fixed > text.length) return false;
	const width = text.length + 1;
	// 0 = unknown, 1 = match, 2 = no match.
	const memo = new Uint8Array((tokens.length + 1) * width);
	const leadingDot = (j: number) => text[j] === "." && (j === 0 || text[j - 1] === "/");
	// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one case per glob token kind
	const at = (i: number, j: number): boolean => {
		const key = i * width + j;
		if (memo[key] !== 0) return memo[key] === 1;
		let result: boolean;
		const token = tokens[i];
		if (token === undefined) {
			result = j === text.length;
		} else if (token.kind === "char") {
			result = text[j] === token.ch && at(i + 1, j + 1);
		} else if (token.kind === "globstar") {
			result = at(i + 1, j) || (j < text.length && at(i, j + 1));
		} else if (token.kind === "globstarSlash") {
			result = at(i + 1, j);
			for (let k = j; !result && k < text.length; k++) {
				if (text[k] === "/") result = at(i + 1, k + 1);
			}
		} else {
			const ch = text[j];
			const blocked = ch === undefined || ch === "/" || (token.dotSafe && leadingDot(j));
			if (token.kind === "star") {
				result = at(i + 1, j) || (!blocked && at(i, j + 1));
			} else if (token.kind === "one") {
				result = !blocked && at(i + 1, j + 1);
			} else {
				result =
					!blocked && classMatches(token.body, ch as string) !== token.negated && at(i + 1, j + 1);
			}
		}
		memo[key] = result ? 1 : 2;
		return result;
	};
	return at(0, 0);
}

/** All proper segment prefixes of a canonical path (`~/a/b` → `~`, `~/a`). */
function ancestors(path: string): string[] {
	const parts = path.split("/");
	return parts
		.slice(0, -1)
		.map((_, i) => parts.slice(0, i + 1).join("/"))
		.filter(Boolean);
}

/** Every directory above a credential file, with the files it contains. */
const CREDENTIAL_ANCESTORS: ReadonlyMap<string, readonly string[]> = (() => {
	const map = new Map<string, string[]>();
	for (const file of CREDENTIAL_FILES) {
		for (const dir of ancestors(file)) map.set(dir, [...(map.get(dir) ?? []), file]);
	}
	return map;
})();

/**
 * Credential paths a glob that is not evaluated is assumed to reach: every
 * credential file below the last directory before its first wildcard. It
 * fails towards inspection, not past it.
 */
function conservativeGlobHits(glob: string): string[] {
	if (!isAnchored(glob)) return [...CREDENTIAL_FILES];
	const literal = glob.slice(0, glob.search(GLOB_CHARS));
	const directory = literal.slice(0, literal.lastIndexOf("/") + 1);
	return CREDENTIAL_FILES.filter((file) => file.startsWith(directory));
}

/**
 * Credential paths a glob can expand to. An anchored glob is matched against
 * the canonical credential paths. A relative glob may sit in any directory, so
 * it is matched as a path suffix, and only when it carries at least two
 * literal letters or digits: `*` or `*.*` name nothing in particular.
 */
function globHits(glob: string, recursive: boolean): string[] {
	const anchored = isAnchored(glob);
	if (!anchored && (glob.replace(/[*?]|\[[^\]]*\]/g, "").match(/[A-Za-z0-9]/g) ?? []).length < 2) {
		return [];
	}
	const expanded = glob.length <= MAX_GLOB_LENGTH ? expandBraces(glob) : undefined;
	if (!expanded) return conservativeGlobHits(glob);
	// A relative glob matches from any segment boundary: `(?:.*/)?glob`.
	const patterns = expanded.map((part) => {
		const tokens = tokenizeGlob(part);
		return anchored ? tokens : [{ kind: "globstarSlash" } as GlobToken, ...tokens];
	});
	const matches = (text: string) => patterns.some((tokens) => matchTokens(tokens, text));
	// A glob naming a credential directory, or (recursively) any directory
	// above a credential file, exposes the files inside.
	const exposedByDirectory = [...CREDENTIAL_ANCESTORS]
		.filter(([dir]) => (recursive || CREDENTIAL_DIR_PATHS.includes(dir)) && matches(dir))
		.flatMap(([, files]) => files);
	return [
		...new Set([
			...CREDENTIAL_FILES.filter(matches),
			...exposedByDirectory,
			...CREDENTIAL_DIR_PATHS.filter(matches),
			...(anchored ? [] : CREDENTIAL_BASENAMES.filter(matches)),
		]),
	];
}

/**
 * Credential paths touched by reading `path` (resolved against `cwd` when
 * relative). Globs are expanded against the credential catalogue.
 */
export function credentialPathsFor(path: string, options: PathOptions = {}): string[] {
	if (!path.trim()) return [];
	const resolved = resolveAgainst(options.cwd, path);
	const recursive = options.recursive ?? false;
	if (!GLOB_CHARS.test(resolved)) return literalHits(resolved, recursive);
	if (options.budget && options.budget.globs-- <= 0) return conservativeGlobHits(resolved);
	return globHits(resolved, recursive);
}

/** Globs one tool call may still evaluate; the rest are treated conservatively. */
export interface GlobBudget {
	globs: number;
}

/** A fresh per-call glob budget. */
export function newGlobBudget(): GlobBudget {
	return { globs: MAX_GLOBS_PER_CALL };
}

interface PathOptions {
	cwd?: string;
	recursive?: boolean;
	budget?: GlobBudget;
}

/**
 * Globs evaluated per tool call. A call with more glob operands than this
 * (far beyond any hand-written command) has the rest treated conservatively,
 * which bounds the work a crafted command can cause.
 */
const MAX_GLOBS_PER_CALL = 64;

/** A filename filter (`*.env`, `id_*`) applied below `root` (or anywhere). */
function filterHits(root: string | undefined, filter: string, options: PathOptions): string[] {
	if (!filter.trim()) return [];
	const glob = filter.includes("/") || root === undefined ? filter : `**/${filter}`;
	const joined = root === undefined ? glob : `${root.replace(/\/+$/, "")}/${glob}`;
	return credentialPathsFor(joined, { cwd: options.cwd, budget: options.budget });
}

// ---------------------------------------------------------------------------
// Shell commands
// ---------------------------------------------------------------------------

/** Commands whose path operands are read (contents, or copied / archived). */
const PLAIN_READERS = new Set([
	"cat",
	"tac",
	"nl",
	"head",
	"tail",
	"less",
	"more",
	"bat",
	"batcat",
	"od",
	"xxd",
	"hexdump",
	"strings",
	"base64",
	"base32",
	"basenc",
	"cut",
	"sort",
	"uniq",
	"paste",
	"diff",
	"cmp",
	"comm",
	"ls",
	"tree",
	"dir",
	"cp",
	"scp",
	"rsync",
	"tar",
	"zip",
	"7z",
	"gzip",
	"bzip2",
	"xz",
	"zstd",
	"source",
	".",
	"type",
	"get-content",
	"gc",
	"dd",
	"curl",
]);

/** Commands whose first operand is a pattern or program, not a file. */
const PATTERN_FIRST = new Set([
	"grep",
	"egrep",
	"fgrep",
	"rg",
	"ag",
	"ack",
	"awk",
	"sed",
	"jq",
	"yq",
]);

/** Commands that always read below a directory operand. */
const COPY_COMMANDS = new Set(["cp", "scp", "rsync"]);

const ALWAYS_RECURSIVE = new Set(["rg", "ag", "ack", "tar", "rsync", "zip", "7z"]);

/** Prefix words that run the next word as the command. */
const WRAPPERS = new Set(["sudo", "doas", "nohup", "time", "nice", "command", "builtin", "exec"]);

/** Split one command line into simple commands (pipelines, lists, subshells). */
// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one linear scan over shell quoting and separators
function simpleCommands(command: string): string[][] {
	const commands: string[][] = [];
	let words: string[] = [];
	let word = "";
	let inWord = false;
	const endWord = () => {
		if (inWord) words.push(word);
		word = "";
		inWord = false;
	};
	const endCommand = () => {
		endWord();
		if (words.length > 0) commands.push(words);
		words = [];
	};
	for (let i = 0; i < command.length; i++) {
		const ch = command[i] as string;
		if (ch === "'") {
			const end = command.indexOf("'", i + 1);
			word += command.slice(i + 1, end === -1 ? command.length : end);
			inWord = true;
			i = end === -1 ? command.length : end;
		} else if (ch === '"') {
			let j = i + 1;
			while (j < command.length && command[j] !== '"') {
				if (command[j] === "\\" && j + 1 < command.length) j++;
				word += command[j];
				j++;
			}
			inWord = true;
			i = j;
		} else if (ch === "\\" && i + 1 < command.length) {
			if (command[i + 1] !== "\n") word += command[i + 1];
			inWord = true;
			i++;
		} else if (ch === "$" && command[i + 1] === "(") {
			endCommand();
			i++;
		} else if (/[;&|\n()`]/.test(ch)) {
			endCommand();
		} else if (/\s/.test(ch)) {
			endWord();
		} else {
			word += ch;
			inWord = true;
		}
	}
	endCommand();
	return commands;
}

function commandName(word: string): string {
	return (word.split(/[\\/]/).pop() ?? word).toLowerCase();
}

/** Drop wrappers and leading `VAR=value` assignments. */
function stripPrefix(words: string[]): string[] {
	let index = 0;
	const skipOptions = () => {
		while ((words[index] ?? "").startsWith("-")) index++;
	};
	while (index < words.length) {
		const word = words[index] as string;
		const name = commandName(word);
		if (/^[A-Za-z_][A-Za-z0-9_]*=/.test(word)) {
			index++;
		} else if (WRAPPERS.has(name) || name === "env") {
			index++;
			skipOptions();
		} else {
			break;
		}
	}
	return words.slice(index);
}

interface ReadOperands {
	paths: string[];
	/** Filename filters applied below the path operands (`--include`, `-name`). */
	filters: string[];
	recursive: boolean;
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one linear scan over grep-family options
function grepOperands(name: string, args: string[]): ReadOperands {
	const paths: string[] = [];
	const filters: string[] = [];
	let recursive = ALWAYS_RECURSIVE.has(name);
	let patternGiven = false;
	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		if (arg === "--") {
			paths.push(...args.slice(i + 1));
			break;
		}
		const include = /^--(?:include|glob|iglob)=(.*)$/.exec(arg);
		if (include) {
			filters.push(include[1] as string);
			continue;
		}
		if (["--include", "--glob", "--iglob", "-g", "-G"].includes(arg)) {
			filters.push(args[++i] ?? "");
			continue;
		}
		if (["-e", "--regexp", "-f", "--file"].includes(arg)) {
			patternGiven = true;
			i++;
			continue;
		}
		if (/^--(?:regexp|file)=/.test(arg)) {
			patternGiven = true;
			continue;
		}
		if (arg === "--recursive" || arg === "--dereference-recursive") {
			recursive = true;
			continue;
		}
		if (/^-[A-Za-z]+$/.test(arg)) {
			if (/[rR]/.test(arg)) recursive = true;
			continue;
		}
		if (arg.startsWith("-")) continue;
		if (!patternGiven) {
			patternGiven = true;
			continue;
		}
		paths.push(arg);
	}
	return { paths, filters, recursive };
}

function findOperands(args: string[]): ReadOperands {
	const paths: string[] = [];
	const filters: string[] = [];
	let i = 0;
	while (i < args.length && !/^[-(!]/.test(args[i] as string)) paths.push(args[i++] as string);
	let recursive = false;
	for (; i < args.length; i++) {
		const arg = args[i] as string;
		if (["-name", "-iname", "-path", "-ipath", "-wholename"].includes(arg)) {
			filters.push(args[++i] ?? "");
		} else if (/^-(?:exec|execdir|ok|okdir)$/.test(arg)) {
			recursive = true;
		}
	}
	return { paths: paths.length > 0 ? paths : ["."], filters, recursive };
}

// biome-ignore lint/complexity/noExcessiveCognitiveComplexity: one linear scan over reader options
function plainOperands(name: string, args: string[]): ReadOperands {
	const paths: string[] = [];
	let recursive = ALWAYS_RECURSIVE.has(name);
	let skipFirst = PATTERN_FIRST.has(name);
	for (let i = 0; i < args.length; i++) {
		const arg = args[i] as string;
		if (arg.startsWith("if=")) {
			paths.push(arg.slice(3));
			continue;
		}
		if (name === "curl") {
			// `file://` URLs and `@file` / `name=@file` uploads read local files.
			const local = /^file:\/\/(.+)$|^(?:[^=\s]*=)?[@<](.+)$/.exec(arg);
			if (local) paths.push((local[1] ?? local[2]) as string);
			else if (args[i - 1] === "-T" || args[i - 1] === "--upload-file") paths.push(arg);
			continue;
		}
		if (arg === "-f" && skipFirst) {
			skipFirst = false;
			i++;
			continue;
		}
		if (/^-[A-Za-z]*[rRa][A-Za-z]*$/.test(arg) && ["cp", "scp", "zip", "ls"].includes(name)) {
			if (name !== "ls") recursive = true;
			continue;
		}
		if (arg.startsWith("-") && arg !== "-") continue;
		if (skipFirst) {
			skipFirst = false;
			continue;
		}
		if (name === "curl") continue;
		paths.push(arg);
	}
	// The last operand of a copy is its destination: written, not read.
	if (COPY_COMMANDS.has(name) && paths.length >= 2) paths.pop();
	return { paths, filters: [], recursive };
}

function readOperands(name: string, args: string[]): ReadOperands | null {
	if (name === "grep" || name === "egrep" || name === "fgrep" || name === "rg" || name === "ag")
		return grepOperands(name, args);
	if (name === "ack") return grepOperands(name, args);
	if (name === "find") return findOperands(args);
	if (PLAIN_READERS.has(name) || PATTERN_FIRST.has(name)) return plainOperands(name, args);
	return null;
}

/**
 * Credential paths a shell command reads, after following `cd`/`pushd`,
 * expanding globs and treating recursive reads of a directory as reads of the
 * credential files inside it.
 */
export function credentialReadsInCommand(
	command: string,
	budget: GlobBudget = newGlobBudget(),
): string[] {
	const hits = new Set<string>();
	let cwd: string | undefined;
	for (const raw of simpleCommands(command)) {
		const words = stripPrefix(raw);
		if (words.length === 0) continue;
		const name = commandName(words[0] as string);
		const args = words.slice(1);
		if (CHANGE_DIRECTORY.has(name)) {
			const target = args.find((arg) => !arg.startsWith("-"));
			cwd = target === undefined ? "~" : resolveAgainst(cwd, target);
			continue;
		}
		for (const hit of simpleCommandReads(name, args, cwd, budget)) hits.add(hit);
	}
	return [...hits];
}

const CHANGE_DIRECTORY = new Set(["cd", "pushd", "chdir", "set-location"]);

/** Credential paths one simple command reads, relative to `cwd`. */
function simpleCommandReads(
	name: string,
	args: string[],
	cwd: string | undefined,
	budget: GlobBudget,
): string[] {
	// `cmd < file` reads the file whatever the command is.
	const hits = inputRedirections(args).flatMap((path) => credentialPathsFor(path, { cwd, budget }));
	const operands = readOperands(name, args);
	if (!operands) return hits;
	const options = { cwd, recursive: operands.recursive, budget };
	for (const path of operands.paths) {
		hits.push(...credentialPathsFor(path, options));
		for (const filter of operands.filters) hits.push(...filterHits(path, filter, options));
	}
	return hits;
}

/** Files read through `< file` / `0<file` (here-documents and here-strings excluded). */
function inputRedirections(args: string[]): string[] {
	const paths: string[] = [];
	args.forEach((arg, i) => {
		const inline = /^0?<([^<&].*)$/.exec(arg);
		if (inline) paths.push(inline[1] as string);
		else if ((arg === "<" || arg === "0<") && args[i + 1] !== undefined) {
			paths.push(args[i + 1] as string);
		}
	});
	return paths;
}

// ---------------------------------------------------------------------------
// Search / list tools
// ---------------------------------------------------------------------------

/** Tools whose `pattern` is a filename glob. */
const GLOB_TOOLS = new Set([
	"glob",
	"find",
	"find_files",
	"file_search",
	"search_files",
	"glob_files",
]);
/** Tools that read file contents below a directory; `pattern` is a content regex. */
const GREP_TOOLS = new Set(["grep", "ripgrep", "rg", "search_text", "grep_search", "search_code"]);
/** Tools that list a directory. */
const LIST_TOOLS = new Set([
	"ls",
	"list",
	"list_dir",
	"list_directory",
	"list_files",
	"directory_tree",
]);

const ROOT_KEYS = [
	"path",
	"dir",
	"directory",
	"directoryPath",
	"directory_path",
	"dir_path",
	"root",
	"cwd",
	"search_path",
	"searchPath",
	"target_directory",
	"targetDirectory",
	"relative_workspace_path",
];
const FILTER_KEYS = ["glob", "include", "includes", "file_pattern", "filePattern", "glob_pattern"];

/** `mcp__fs__search_files` → `search_files`; `opencode:list` → `list`. */
function baseToolName(toolName: string): string {
	const afterPrefix = toolName.slice(toolName.lastIndexOf(":") + 1);
	const mcp = /^mcp__.+?__(.+)$/.exec(afterPrefix);
	return (mcp ? (mcp[1] as string) : afterPrefix).toLowerCase();
}

function stringValues(input: Record<string, unknown>, keys: readonly string[]): string[] {
	const out: string[] = [];
	for (const key of keys) {
		const value = input[key];
		if (typeof value === "string" && value.trim()) out.push(value);
		else if (Array.isArray(value))
			for (const item of value) if (typeof item === "string" && item.trim()) out.push(item);
	}
	return out;
}

/**
 * Credential paths a Grep/Glob/LS-style tool call touches through its search
 * root or filename filter. Null when the tool is not a search or list tool.
 */
export function credentialReadsInSearchTool(
	toolName: string,
	toolInput: Record<string, unknown>,
): string[] | null {
	const name = baseToolName(toolName);
	const isGlob = GLOB_TOOLS.has(name);
	const isGrep = GREP_TOOLS.has(name);
	if (!isGlob && !isGrep && !LIST_TOOLS.has(name)) return null;
	const roots = stringValues(toolInput, ROOT_KEYS);
	const filters = stringValues(toolInput, isGlob ? ["pattern", ...FILTER_KEYS] : FILTER_KEYS);
	const hits = new Set<string>();
	const budget = newGlobBudget();
	for (const root of roots) {
		for (const hit of credentialPathsFor(root, { recursive: isGrep, budget })) hits.add(hit);
	}
	for (const filter of filters) {
		const scoped = roots.length > 0 ? roots : [undefined];
		for (const root of scoped)
			for (const hit of filterHits(root, filter, { budget })) hits.add(hit);
	}
	return [...hits];
}
