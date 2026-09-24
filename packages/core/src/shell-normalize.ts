/**
 * A "what would the shell see" view of a command, for self-defense matching.
 *
 * ## Why this exists
 *
 * Threat patterns run against the literal command string. The shell does not:
 * it removes quotes and backslash escapes, expands variables, substitutes
 * `$(which aidr)` with a path, and expands globs against the filesystem. Each of
 * those let an agent name something a rule looks for without writing it
 * literally:
 *
 *   aidr 'approve' <id>            "aidr" approve <id>        aidr ap\prove <id>
 *   $(which aidr) approve <id>     A=appr; aidr ${A}ove <id>  cat ~/.singul*\/*.key
 *   node -e "fs.readFileSync(home + '/.singular' + 'ity-aidr/approvals.json')"
 *
 * {@link normalizeShellText} produces a second view of the text with those
 * layers peeled off. The heuristics engine runs rules that declare
 * `match_on: <type>_normalized` against this view (see `heuristics.ts`), so the
 * patterns stay data in `threats/*.yaml`.
 *
 * ## What it is — and is not
 *
 * It is an over-approximation for matching, not a shell: the output is never
 * executed or shown, and removing a quote that was itself quoted only makes a
 * match more likely. It is linear in the input length. It cannot see through
 * run-time computation (a path assembled by arithmetic, fetched from the
 * network, or read from a file); that residual gap is why the approval key
 * itself lives in the OS credential vault rather than relying on these rules.
 */

/** The AIDR state directory name that the glob step resolves wildcards against. */
export const AIDR_STATE_DIR_NAME = ".singularity-aidr";

const MAX_VARIABLES = 32;
const MAX_VARIABLE_VALUE = 256;
const MAX_GLOB_SEGMENT = 256;
const MAX_BRACE_EXPANSIONS = 64;

/** `'a' + 'b'`, `"a"+"b"`, `'a' + "b"`: a string built from literal pieces. */
const LITERAL_CONCATENATION = /(['"`])[ \t]{0,20}\+[ \t]{0,20}(['"`])/g;

/** `$'…'` ANSI-C quoting, whose escapes the shell decodes. */
const ANSI_C_QUOTED = /\$'((?:[^'\\]|\\[\s\S])*)'/g;

/** A command substitution that only looks up where an executable lives. */
const EXECUTABLE_LOOKUP =
	/\$\([ \t]{0,20}(?:which|command[ \t]{1,20}-[vV]|type[ \t]{1,20}-[pPa]|whence[ \t]{1,20}-p|whereis(?:[ \t]{1,20}-b)?|where(?:\.exe)?|Get-Command)[ \t]{1,20}([^\s()`$]{1,200})[ \t]{0,20}\)|`[ \t]{0,20}(?:which|command[ \t]{1,20}-[vV]|type[ \t]{1,20}-[pPa]|whereis(?:[ \t]{1,20}-b)?)[ \t]{1,20}([^\s()`$]{1,200})[ \t]{0,20}`/g;

/** `NAME=value` at the start of a word (plain, `export`, `local`, `set`). */
const ASSIGNMENT =
	/(?:^|[\s;&|(])(?:export[ \t]+|local[ \t]+|declare[ \t]+|set[ \t]+)?([A-Za-z_][A-Za-z0-9_]{0,63})=([^\s;&|()]{0,256})/g;

/** A path segment (between separators) that starts with `.` or a glob/brace opener. */
const PATH_SEGMENT = /(^|[\s/\\;|&<>()=:,[\]{}])([.[{][^\s/\\;|&<>()=:]{0,256})/g;

/** A home-directory anchor directly before a path segment. */
const HOME_ANCHOR =
	/(?:~|\$HOME|\$\{HOME\}|\$env:USERPROFILE|%USERPROFILE%|\/home\/[^/\s]{1,64}|\/Users\/[^/\s]{1,64}|\/root|[A-Za-z]:\\?Users\\?[^\\/\s]{1,64})[\\/]?$/;

function decodeAnsiC(body: string): string {
	return body.replace(
		/\\(x[0-9A-Fa-f]{1,2}|u[0-9A-Fa-f]{1,4}|U[0-9A-Fa-f]{1,8}|[0-7]{1,3}|[\s\S])/g,
		(_match, escape: string) => {
			const kind = escape[0];
			if (kind === "x" || kind === "u" || kind === "U") {
				const code = Number.parseInt(escape.slice(1), 16);
				return code <= 0x10ffff ? String.fromCodePoint(code) : "";
			}
			if (/^[0-7]/.test(escape)) return String.fromCharCode(Number.parseInt(escape, 8) & 0xff);
			if (escape === "n") return "\n";
			if (escape === "t") return "\t";
			if (escape === "r") return "\r";
			return escape;
		},
	);
}

/**
 * Remove shell quoting and backslash escapes in one left-to-right pass.
 *
 * Every quote character is dropped, including one nested inside the other kind
 * of quote: `script -qc "aidr 'approve' …"` and `pty.spawn(['aidr', 'approve'])`
 * hand their inner quoting to a second shell or an argv list, so the view peels
 * both layers at once (a word's quoted and unquoted pieces join, as the shell
 * joins them). For the same reason a backslash escapes the next character in
 * every quoting state, and a backslash-newline is a line continuation and
 * disappears. With `keepBackslashes` they stay (Windows paths).
 */
function stripQuoting(text: string, keepBackslashes = false): string {
	let out = "";
	for (let i = 0; i < text.length; i++) {
		const character = text[i] as string;
		if (character === "\\" && !keepBackslashes && i + 1 < text.length) {
			const next = text[i + 1] as string;
			i++;
			if (next !== "\n") out += next;
		} else if (character !== "'" && character !== '"') {
			out += character;
		}
	}
	return out;
}

/** Substitute `$NAME` / `${NAME}` with values assigned earlier in the same text. */
function substituteVariables(text: string): string {
	const values = new Map<string, string>();
	for (const match of text.matchAll(ASSIGNMENT)) {
		if (values.size >= MAX_VARIABLES) break;
		const [, name, value] = match as unknown as [string, string, string];
		if (value.length <= MAX_VARIABLE_VALUE) values.set(name, value);
	}
	if (values.size === 0) return text;
	return text.replace(
		/\$\{([A-Za-z_][A-Za-z0-9_]{0,63})\}|\$([A-Za-z_][A-Za-z0-9_]{0,63})/g,
		(whole, braced: string | undefined, bare: string | undefined) =>
			values.get((braced ?? bare) as string) ?? whole,
	);
}

/** Expand simple, non-nested `{a,b}` groups; returns the input when there are none. */
function expandBraces(segment: string): string[] {
	let results = [segment];
	for (let round = 0; round < 3; round++) {
		const next: string[] = [];
		let changed = false;
		for (const item of results) {
			const group = /\{([^{}]{0,256})\}/.exec(item);
			if (!group || !group[1]?.includes(",")) {
				next.push(item);
				continue;
			}
			changed = true;
			const before = item.slice(0, group.index);
			const after = item.slice(group.index + group[0].length);
			for (const option of group[1].split(",")) next.push(`${before}${option}${after}`);
			if (next.length > MAX_BRACE_EXPANSIONS) return results;
		}
		results = next;
		if (!changed) break;
	}
	return results;
}

type GlobToken =
	| { kind: "star" }
	| { kind: "one" }
	| { kind: "set"; negated: boolean; body: string }
	| { kind: "char"; value: string };

function tokenizeGlob(glob: string): GlobToken[] {
	const tokens: GlobToken[] = [];
	for (let i = 0; i < glob.length; i++) {
		const character = glob[i] as string;
		const end = character === "[" ? glob.indexOf("]", i + 2) : -1;
		if (character === "*") {
			if (tokens.at(-1)?.kind !== "star") tokens.push({ kind: "star" });
		} else if (character === "?") {
			tokens.push({ kind: "one" });
		} else if (end !== -1) {
			const body = glob.slice(i + 1, end);
			const negated = body.startsWith("!") || body.startsWith("^");
			tokens.push({ kind: "set", negated, body: negated ? body.slice(1) : body });
			i = end;
		} else {
			tokens.push({ kind: "char", value: character.toLowerCase() });
		}
	}
	return tokens;
}

function setContains(body: string, character: string): boolean {
	for (let i = 0; i < body.length; i++) {
		const low = (body[i] as string).toLowerCase();
		if (body[i + 1] === "-" && i + 2 < body.length) {
			const high = (body[i + 2] as string).toLowerCase();
			if (character >= low && character <= high) return true;
			i += 2;
		} else if (character === low) {
			return true;
		}
	}
	return false;
}

function tokenMatches(token: GlobToken, character: string): boolean {
	if (token.kind === "one") return true;
	if (token.kind === "char") return token.value === character;
	if (token.kind === "set") return setContains(token.body, character) !== token.negated;
	return false;
}

/**
 * Case-insensitive shell-glob match (`*`, `?`, `[…]`) of `glob` against `name`.
 *
 * Dynamic programming over (token, character) pairs, so the work is
 * O(glob × name) whatever the glob looks like: a regular expression built from
 * an agent-supplied glob (`.*?*?*?…`) could backtrack exponentially.
 */
function globMatches(glob: string, name: string): boolean {
	const tokens = tokenizeGlob(glob);
	const subject = name.toLowerCase();
	// reachable[j]: the tokens consumed so far can match subject[0, j).
	let reachable = new Array<boolean>(subject.length + 1).fill(false);
	reachable[0] = true;
	for (const token of tokens) {
		const next = new Array<boolean>(subject.length + 1).fill(false);
		for (let j = 0; j <= subject.length; j++) {
			if (token.kind === "star") {
				next[j] = reachable[j] === true || (j > 0 && next[j - 1] === true);
			} else if (j > 0 && reachable[j - 1] && tokenMatches(token, subject[j - 1] as string)) {
				next[j] = true;
			}
		}
		reachable = next;
	}
	return reachable[subject.length] === true;
}

/** True when the segment is a glob that can match only a few names, not every dotfile. */
function isSpecificGlob(segment: string): boolean {
	return /[A-Za-z0-9-]/.test(segment.slice(1).replace(/\[[^\]]*\]/g, ""));
}

/** Whether one brace/comma alternative of a path segment names the state directory. */
function candidateNamesStateDir(candidate: string, anchored: boolean): boolean {
	if (candidate.toLowerCase() === AIDR_STATE_DIR_NAME) return true;
	// Only a glob whose first character can be the leading dot expands to a dotfile.
	if (!/[*?[]/.test(candidate) || !/^[.[]/.test(candidate)) return false;
	// `.*` alone matches every dotfile; count it only right under a home directory.
	if (!anchored && !isSpecificGlob(candidate)) return false;
	return globMatches(candidate, AIDR_STATE_DIR_NAME);
}

/**
 * Rewrite path segments that the shell would expand to the AIDR state directory
 * (`.singul*`, `.s?ngularity-aidr`, `.{singularity-aidr,x}`, `~/.*`) to its
 * literal name, so a rule on the literal sees them.
 */
function resolveStateDirGlobs(text: string): string {
	return text.replace(PATH_SEGMENT, (whole, separator: string, segment: string, offset: number) => {
		if (segment.length > MAX_GLOB_SEGMENT) return whole;
		if (segment.toLowerCase() === AIDR_STATE_DIR_NAME) return whole;
		const hasBrace = segment.includes("{") && segment.includes(",");
		if (!hasBrace && !/[*?[]/.test(segment)) return whole;
		const anchored = HOME_ANCHOR.test(
			text.slice(Math.max(0, offset - 80), offset + separator.length),
		);
		const candidates = hasBrace ? expandBraces(segment) : segment.split(",");
		return candidates.some((candidate) => candidateNamesStateDir(candidate, anchored))
			? `${separator}${AIDR_STATE_DIR_NAME}`
			: whole;
	});
}

/**
 * The shell-normalized view of `text`: literal concatenations joined, ANSI-C
 * strings decoded, quotes and backslash escapes removed, executable lookups
 * (`$(which aidr)`) replaced by the executable name, variables assigned in the
 * same text substituted, and globs that would expand to the AIDR state
 * directory replaced by its name. Returns `text` unchanged when there is
 * nothing to peel off.
 */
export function normalizeShellText(text: string): string {
	const decoded = text
		.replace(LITERAL_CONCATENATION, "")
		.replace(ANSI_C_QUOTED, (_whole, body: string) => decodeAnsiC(body));
	const view = peel(stripQuoting(decoded));
	// A backslash is an escape to a POSIX shell but a path separator to cmd and
	// PowerShell. When there is one, add the view with backslashes kept, so a
	// Windows path (`C:\Users\me\.s*\x`) keeps its separators for the glob step.
	if (!decoded.includes("\\")) return view;
	return `${view}\n;\n${peel(stripQuoting(decoded, true))}`;
}

function peel(unquoted: string): string {
	let out = unquoted.replace(
		EXECUTABLE_LOOKUP,
		(_whole, dollar: string | undefined, tick: string | undefined) => dollar ?? tick ?? "",
	);
	out = substituteVariables(out);
	out = out.replace(/\(Get-Command[ \t]{1,20}([^\s()]{1,200})\)(?:\.\w{1,20})?/gi, "$1");
	return resolveStateDirGlobs(out);
}
