/**
 * Redaction for MCP server launch details (command and arguments) before they
 * are written into an inventory export such as the AI-BOM.
 *
 * MCP configurations routinely carry credentials inline: `--api-key sk-…`,
 * `--header "Authorization: Bearer …"`, `GITHUB_TOKEN=…` passed through `env`,
 * or `postgres://user:pass@host/db`. Environment maps and headers are never
 * read into the inventory at all; this module handles what is left, the command
 * line. It layers these rules on top of the shared telemetry redaction
 * (`redactTelemetryString`: bearer tokens, `key=value` credentials, URL
 * userinfo, secret query parameters, JWTs and well-known token formats):
 *
 * 1. the value after a credential-named flag (`--token X`) or a header flag
 *    (`-H X`) is replaced whole, as is the value of `NAME=value` / `--flag=value`
 *    when the name says credential;
 * 2. URLs keep scheme, host and path only: userinfo, query and fragment are
 *    removed, because a non-standard query name (`?k=`) can still be a secret;
 * 3. long opaque tokens (32+ characters of a base64/hex alphabet mixing letters
 *    and digits) are replaced, because an API key of unknown format looks
 *    exactly like that.
 */

import { REDACTED_TELEMETRY_VALUE, redactTelemetryString } from "./telemetry-redaction.js";

const REDACTED_LAUNCH_VALUE = REDACTED_TELEMETRY_VALUE;

const CREDENTIAL_NAME =
	"(?:api[_-]?key|apikey|access[_-]?key|key|token|secret|pass(?:word|wd|phrase)?|pwd|credential|auth|bearer|cookie|signature|dsn|connection[_-]?string)";
/** `"apiKey": "…"` / `'token':'…'` inside a JSON (or JSON-like) argument. */
const QUOTED_CREDENTIAL_PAIR_RE = new RegExp(
	`(["'])([a-z0-9_.-]*${CREDENTIAL_NAME}[a-z0-9_.-]*)\\1(\\s*:\\s*)(["'])(?:(?!\\4)[^\\n]){1,512}\\4`,
	"gi",
);
const CREDENTIAL_FLAG_RE = new RegExp(`^--?[a-z0-9_.-]*${CREDENTIAL_NAME}[a-z0-9_.-]*$`, "i");
const CREDENTIAL_ASSIGNMENT_RE = new RegExp(
	`^(-{0,2}[a-z0-9_.-]*${CREDENTIAL_NAME}[a-z0-9_.-]*=).+$`,
	"i",
);
const HEADER_FLAG_RE = /^(?:-H|--header|--headers)$/;
const OPAQUE_TOKEN_RE = /^[A-Za-z0-9+_=-]{32,}$/;
const URL_IN_TEXT_RE = /\b[a-z][a-z0-9+.-]{1,20}:\/\/[^\s"'<>]+/gi;
const MAX_TOKEN_LENGTH = 512;

function isOpaqueToken(value: string): boolean {
	return OPAQUE_TOKEN_RE.test(value) && /[0-9]/.test(value) && /[A-Za-z]/.test(value);
}

/** Scheme, host and path of a URL; userinfo, query and fragment are dropped. */
function stripUrl(raw: string): string {
	try {
		const url = new URL(raw);
		const path = url.pathname === "/" ? "" : url.pathname;
		return `${url.protocol}//${url.host}${path}`;
	} catch {
		return REDACTED_LAUNCH_VALUE;
	}
}

/** Redact one launch token: the command, or an argument that is not a flag value. */
export function redactLaunchToken(value: string): string {
	const assignment = CREDENTIAL_ASSIGNMENT_RE.exec(value);
	if (assignment) return `${assignment[1]}${REDACTED_LAUNCH_VALUE}`;
	const safe = redactTelemetryString(
		value
			.replace(URL_IN_TEXT_RE, (match) => stripUrl(match))
			.replace(
				QUOTED_CREDENTIAL_PAIR_RE,
				(_match, quote: string, name: string, colon: string, valueQuote: string) =>
					`${quote}${name}${quote}${colon}${valueQuote}${REDACTED_LAUNCH_VALUE}${valueQuote}`,
			),
		MAX_TOKEN_LENGTH,
	);
	return safe
		.split(/([\s,;:=/?&])/)
		.map((part) => (isOpaqueToken(part) ? REDACTED_LAUNCH_VALUE : part))
		.join("");
}

/**
 * Redact an MCP server command line. The value after a credential-named flag
 * and every header value are replaced whole; everything else goes through
 * {@link redactLaunchToken}.
 */
export function redactMcpLaunch(
	command: string | null,
	args: readonly string[],
): { command: string | null; args: string[] } {
	const safeArgs: string[] = [];
	for (let index = 0; index < args.length; index++) {
		const arg = args[index] as string;
		safeArgs.push(redactLaunchToken(arg));
		const next = args[index + 1];
		// A value may itself start with `-` (random tokens do); only something that
		// is plainly the next option (`--verbose`, `-v`) is not taken as the value.
		if (next === undefined || next.startsWith("--") || /^-[A-Za-z]$/.test(next)) continue;
		if (CREDENTIAL_FLAG_RE.test(arg) || HEADER_FLAG_RE.test(arg)) {
			safeArgs.push(REDACTED_LAUNCH_VALUE);
			index++;
		}
	}
	return { command: command === null ? null : redactLaunchToken(command), args: safeArgs };
}
